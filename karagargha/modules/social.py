"""Social and Public Footprint Module for KaraQargha.

Performs direct Gravatar MD5 profile verification and HaveIBeenPwned
paste search to detect leaked credentials or public avatars.
"""

from __future__ import annotations

from typing import Any, Dict, List, Union


def scan_social(
    email: str,
    raw: bool = False,
    timeout: int = 10,
) -> Union[str, Dict[str, Any]]:
    """Check Gravatar public profiles and HaveIBeenPwned paste leaks for an email.

    Args:
        email: Email address to analyze.
        raw: If True, returns structured dictionary of results.
        timeout: Request timeout in seconds.

    Returns:
        Formatted string summarizing social and paste findings, or dict if raw=True.
    """
    clean_email = email.strip()
    if not clean_email:
        err = "[!] Please provide an email address."
        return {"error": err} if raw else err

    try:
        # Lazy imports inside function
        import hashlib
        import os
        import urllib.parse
        import requests
        from karagargha.core import colors
    except ImportError as imp_err:
        err = f"[!] Missing dependency: {imp_err}. Run: pip install requests"
        return {"error": err} if raw else err

    headers = {"User-Agent": "karagargha-cli/1.0"}
    norm_email = clean_email.lower()
    md5_hash = hashlib.md5(norm_email.encode("utf-8")).hexdigest()

    gravatar_found = False
    gravatar_data: Dict[str, Any] = {
        "hash": md5_hash,
        "avatar_url": f"https://www.gravatar.com/avatar/{md5_hash}",
        "profile_url": f"https://gravatar.com/{md5_hash}",
        "exists": False,
    }

    # 1. Gravatar check
    try:
        # Check avatar existence (d=404 returns 404 if no custom avatar)
        avatar_resp = requests.get(
            f"https://www.gravatar.com/avatar/{md5_hash}?d=404",
            headers=headers,
            timeout=timeout,
        )
        if avatar_resp.status_code == 200:
            gravatar_found = True
            gravatar_data["exists"] = True

        # Check profile JSON endpoint
        profile_resp = requests.get(
            f"https://en.gravatar.com/{md5_hash}.json",
            headers=headers,
            timeout=timeout,
        )
        if profile_resp.status_code == 200:
            gravatar_found = True
            gravatar_data["exists"] = True
            try:
                profile_json = profile_resp.json()
                entries = profile_json.get("entry", [])
                if entries:
                    entry = entries[0]
                    gravatar_data["display_name"] = entry.get("displayName")
                    gravatar_data["preferred_username"] = entry.get("preferredUsername")
                    gravatar_data["about"] = entry.get("aboutMe")
                    gravatar_data["location"] = entry.get("currentLocation")
            except Exception:
                pass
    except Exception:
        pass

    # 2. HIBP Paste Search
    paste_results: List[Dict[str, Any]] = []
    paste_status_msg = ""
    hibp_key = os.getenv("HIBP_API_KEY", "").strip()

    if hibp_key:
        encoded_email = urllib.parse.quote(clean_email)
        paste_url = f"https://haveibeenpwned.com/api/v3/pasteaccount/{encoded_email}"
        paste_headers = {
            "hibp-api-key": hibp_key,
            "user-agent": "karagargha-cli/1.0",
        }
        try:
            p_resp = requests.get(paste_url, headers=paste_headers, timeout=timeout)
            if p_resp.status_code == 200:
                paste_results = p_resp.json()
            elif p_resp.status_code == 404:
                paste_status_msg = "No public paste leaks found on HIBP."
            elif p_resp.status_code == 401:
                paste_status_msg = "HIBP API key is invalid or unauthorized for paste search."
            else:
                paste_status_msg = f"HIBP paste search returned HTTP {p_resp.status_code}."
        except Exception as exc:
            paste_status_msg = f"HIBP paste query failed: {exc}"
    else:
        paste_status_msg = "HIBP paste search skipped (HIBP_API_KEY not set)."

    data: Dict[str, Any] = {
        "email": clean_email,
        "gravatar": gravatar_data,
        "pastes": paste_results,
        "paste_message": paste_status_msg,
    }

    if raw:
        return data

    lines: List[str] = []

    # Format Gravatar
    if gravatar_found:
        lines.append(colors.found("Gravatar Profile Detected:"))
        lines.append(f"  • Profile URL:  {gravatar_data['profile_url']}")
        lines.append(f"  • Avatar URL:   {gravatar_data['avatar_url']}")
        if gravatar_data.get("display_name"):
            lines.append(f"  • Display Name: {gravatar_data['display_name']}")
        if gravatar_data.get("preferred_username"):
            lines.append(f"  • Username:     {gravatar_data['preferred_username']}")
        if gravatar_data.get("location"):
            lines.append(f"  • Location:     {gravatar_data['location']}")
        if gravatar_data.get("about"):
            lines.append(f"  • About/Bio:    {gravatar_data['about']}")
    else:
        lines.append(colors.info("Gravatar: No profile found for this email hash."))

    # Format Pastes
    lines.append("")
    if paste_results:
        lines.append(colors.breach(f"Leaked Pastes Detected ({len(paste_results)}):"))
        for p in paste_results:
            source = p.get("Source", "Unknown")
            title = p.get("Title") or "(Untitled)"
            p_date = p.get("Date", "N/A")
            count = p.get("EmailCount", 0)
            lines.append(f"  • [{source}] {title} (Date: {p_date}, Accounts: {count})")
    else:
        lines.append(colors.info(f"Paste Check: {paste_status_msg}"))

    return "\n".join(lines)

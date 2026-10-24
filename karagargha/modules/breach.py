"""HaveIBeenPwned Breach Scan Module for KaraQargha.

Queries the HaveIBeenPwned API v3 for compromised account breaches.
Requires the HIBP_API_KEY environment variable.
"""

from __future__ import annotations

from typing import Any, Dict, List, Union


def scan_breaches(
    email: str,
    raw: bool = False,
) -> Union[str, List[Dict[str, Any]]]:
    """Check an email address against HaveIBeenPwned API v3.

    Args:
        email: Email address to search for known data breaches.
        raw: If True, returns the parsed raw breach list instead of formatted string.

    Returns:
        Plain string summarizing breach status, or list of dicts if raw=True.
    """
    # Lazy imports inside function
    import os
    import urllib.parse
    import requests
    from karagargha.core import colors

    api_key = os.getenv("HIBP_API_KEY", "").strip()

    if not api_key:
        msg = (
            f"{colors.info('HaveIBeenPwned API key (HIBP_API_KEY) not found in environment.')}\n"
            "    To enable breach scanning, obtain an API key from https://haveibeenpwned.com/API/Key\n"
            "    Then set the environment variable:\n"
            "      Windows CMD:   set HIBP_API_KEY=your_api_key_here\n"
            "      PowerShell:    $env:HIBP_API_KEY='your_api_key_here'\n"
            "      Linux / macOS: export HIBP_API_KEY='your_api_key_here'\n"
            "    Skipping HaveIBeenPwned breach scan."
        )
        return [] if raw else msg

    clean_email = email.strip()
    encoded_email = urllib.parse.quote(clean_email)
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{encoded_email}?truncateResponse=true"
    headers = {
        "hibp-api-key": api_key,
        "user-agent": "karagargha-cli/1.0",
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 404:
            return [] if raw else colors.found("No breaches found.")

        if response.status_code == 401:
            err = colors.breach("HaveIBeenPwned API: 401 Unauthorized (Invalid API key).")
            return [] if raw else err

        if response.status_code == 429:
            err = colors.breach("HaveIBeenPwned API: 429 Rate Limit Exceeded. Try again later.")
            return [] if raw else err

        if response.status_code != 200:
            err = colors.breach(f"HaveIBeenPwned API error: HTTP {response.status_code}")
            return [] if raw else err

        breaches: List[Dict[str, Any]] = response.json()
        if not isinstance(breaches, list):
            return [] if raw else colors.info("Unexpected response format from HaveIBeenPwned.")

        if raw:
            return breaches

        if not breaches:
            return colors.found("No breaches found.")

        lines = [colors.breach(f"Found in {len(breaches)} breach(es):")]
        for item in breaches:
            name = item.get("Name", "Unknown Breach")
            breach_date = item.get("BreachDate", "N/A")
            data_classes = item.get("DataClasses", [])
            data_str = ", ".join(data_classes) if data_classes else "N/A"

            lines.append(f"  • Name: {name}")
            lines.append(f"    Breach Date:  {breach_date}")
            lines.append(f"    Compromised:  {data_str}")

        return "\n".join(lines)

    except Exception as exc:
        err_msg = colors.breach(f"Breach check encountered an error: {exc}")
        return [] if raw else err_msg

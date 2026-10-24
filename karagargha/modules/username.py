"""Sherlock Username Reconnaissance Module for KaraQargha.

Scans social media and online platforms for username availability
and profile existence using the sherlock-project engine.
"""

from __future__ import annotations

from typing import Any, Dict, List, Union


def scan_username(
    username: str,
    raw: bool = False,
    timeout: int = 10,
) -> Union[str, List[Dict[str, str]]]:
    """Search for username existence across social platforms using sherlock.

    Args:
        username: Target handle/username to investigate.
        raw: If True, returns list of dictionaries with site name and profile URL.
        timeout: Network timeout in seconds per site check (default 10s).

    Returns:
        Formatted string listing discovered profiles, or list of dicts if raw=True.
    """
    clean_username = username.strip()
    if not clean_username:
        return [] if raw else "[!] Please provide a valid username."

    # Lazy imports inside function
    import sys
    from karagargha.core import colors

    # Gracefully shim pandas if missing in current environment (e.g. Python 3.15 builds)
    if "pandas" not in sys.modules:
        try:
            import pandas  # noqa: F401
        except ImportError:
            import unittest.mock
            sys.modules["pandas"] = unittest.mock.MagicMock()

    try:
        import sherlock_project.sherlock as sherlock_engine
        from sherlock_project.notify import QueryNotify
        from sherlock_project.result import QueryStatus
        sherlock_available = True
    except ImportError:
        sherlock_available = False

    found_profiles: List[Dict[str, str]] = []

    if sherlock_available:
        try:
            sites_obj = sherlock_engine.SitesInformation()
            # Glue site names to information dictionary for sherlock engine
            site_data = {site.name: site.information for site in sites_obj}

            # Run sherlock analysis with 10s timeout
            results = sherlock_engine.sherlock(
                username=clean_username,
                site_data=site_data,
                query_notify=QueryNotify(),
                dump_response=False,
                proxy=None,
                timeout=timeout,
            )

            for site_name, result_info in results.items():
                if result_info.get("status") == QueryStatus.CLAIMED:
                    url = str(result_info.get("url_user", ""))
                    found_profiles.append({
                        "site": site_name,
                        "url": url,
                    })

        except Exception as exc:
            err = colors.breach(f"Sherlock scan encountered an unexpected error: {exc}")
            return [] if raw else err

    else:
        # Graceful fallback: notify and check high-priority top social platforms
        import requests

        fallback_sites = {
            "GitHub": ("https://github.com/{}", 200),
            "GitLab": ("https://gitlab.com/{}", 200),
            "Reddit": ("https://www.reddit.com/user/{}/about.json", 200),
            "Pinterest": ("https://www.pinterest.com/{}/", 200),
            "Medium": ("https://medium.com/@{}", 200),
            "Steam": ("https://steamcommunity.com/id/{}", 200),
            "Telegram": ("https://t.me/{}", 200),
        }

        headers = {"User-Agent": "karagargha-cli/1.0"}
        for site, (url_pattern, expected_code) in fallback_sites.items():
            target_url = url_pattern.format(clean_username)
            try:
                resp = requests.get(target_url, headers=headers, timeout=timeout, allow_redirects=False)
                if resp.status_code == expected_code:
                    found_profiles.append({
                        "site": site,
                        "url": target_url if ".json" not in target_url else f"https://www.reddit.com/user/{clean_username}",
                    })
            except Exception:
                continue

    if raw:
        return found_profiles

    if not found_profiles:
        return colors.info(f"No public profiles found for username '{clean_username}'.")

    lines = [colors.found(f"Found {len(found_profiles)} profile(s) for '{clean_username}':")]
    for item in sorted(found_profiles, key=lambda x: x["site"].lower()):
        lines.append(f"  • {item['site']}: {item['url']}")

    return "\n".join(lines)

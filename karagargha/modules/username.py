"""Username reconnaissance module using the WhatsMyName dataset."""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Union

WMN_URL = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
CACHE_PATH = os.path.join(os.path.expanduser("~"), ".karagargha_wmn.json")

DISCLAIMER = "False positives possible: some sites return 200 for unknown users."


def _load_dataset() -> List[Dict[str, Any]]:
    # Try cache first
    if os.path.exists(CACHE_PATH):
        try:
            with open(CACHE_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                sites = data.get("sites", data) if isinstance(data, dict) else data
                if isinstance(sites, list):
                    return sites
        except Exception:
            pass
    import requests
    try:
        r = requests.get(WMN_URL, timeout=20, headers={"User-Agent": "karagargha/2.0"})
        if r.status_code == 200:
            data = r.json()
            sites = data.get("sites", data) if isinstance(data, dict) else data
            if isinstance(sites, list):
                try:
                    with open(CACHE_PATH, "w", encoding="utf-8") as f:
                        json.dump({"sites": sites}, f)
                except Exception:
                    pass
                return sites
    except Exception:
        pass
    return []


def scan_username(username: str, raw: bool = False, timeout: float = 10.0) -> Union[str, List[Dict[str, str]]]:
    clean = username.strip()
    if not clean:
        return [] if raw else "[!] Please provide a valid username."

    sites = _load_dataset()
    found: List[Dict[str, str]] = []

    if not sites:
        msg = "[!] WhatsMyName dataset unavailable; username scan skipped."
        return [] if raw else msg

    # normalize site entries
    targets = []
    for s in sites:
        if not isinstance(s, dict):
            continue
        url_template = s.get("uri_check") or s.get("url") or s.get("uri")
        if not url_template or "{}" not in str(url_template):
            continue
        targets.append((s.get("name", "Unknown"), str(url_template).format(clean)))

    # Concurrent checks
    import httpx
    import asyncio

    async def _run() -> None:
        sem = asyncio.Semaphore(50)
        limits = httpx.Limits(max_connections=50, max_keepalive_connections=20)
        async with httpx.AsyncClient(timeout=timeout, limits=limits, follow_redirects=False) as client:
            async def _check(name, url):
                async with sem:
                    try:
                        resp = await client.get(url, headers={"User-Agent": "karagargha/2.0"})
                        if resp.status_code == 200:
                            found.append({"site": name, "url": url})
                    except Exception:
                        pass
            await asyncio.gather(*[_check(n, u) for n, u in targets], return_exceptions=True)

    try:
        asyncio.run(_run())
    except Exception:
        pass

    if raw:
        return found

    from karagargha.core import colors
    if not found:
        return colors.info(f"No public profiles found for username '{clean}'.")
    lines = [colors.found(f"Found {len(found)} profile(s) for '{clean}':")]
    for item in sorted(found, key=lambda x: x["site"].lower()):
        lines.append(f"  • {item['site']}: {item['url']}")
    lines.append(colors.warning(DISCLAIMER))
    return "\n".join(lines)

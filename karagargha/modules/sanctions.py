"""Sanctions screening (OFAC SDN) module."""

from __future__ import annotations
import csv
import os
from typing import Any, Dict, List, Union

SDN_URL = "https://www.treasury.gov/ofac/downloads/sdn.csv"
CACHE_PATH = os.path.join(os.path.expanduser("~"), ".karagargha_sdn.csv")


def _ensure_cache() -> str:
    if not os.path.exists(CACHE_PATH):
        import requests
        r = requests.get(SDN_URL, timeout=60, headers={"User-Agent": "karagargha/2.0"})
        if r.status_code == 200:
            with open(CACHE_PATH, "w", encoding="utf-8") as f:
                f.write(r.text)
    return CACHE_PATH


def scan_sanctions(name: str, raw: bool = False) -> Union[str, List[Dict[str, Any]]]:
    clean = name.strip()
    if not clean:
        err = "[!] Please provide a name or entity."
        return {"error": err} if raw else err  # type: ignore[return-value]

    path = _ensure_cache()
    matches: List[Dict[str, Any]] = []
    needle = clean.lower()
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f)
            for row in reader:
                if not row:
                    continue
                # row: id, name, type?, program, ...
                row_name = row[1] if len(row) > 1 else ""
                if needle in row_name.lower():
                    matches.append({
                        "id": row[0] if len(row) > 0 else "",
                        "name": row_name,
                        "details": row[2] if len(row) > 2 else "",
                        "program": row[3] if len(row) > 3 else "",
                    })
    except Exception as exc:
        err = f"[!] Failed to read SDN cache: {exc}"
        return {"error": str(exc)} if raw else err  # type: ignore[return-value]

    if raw:
        return matches

    from karagargha.core import colors
    if not matches:
        return colors.found(f"No OFAC SDN match found for '{clean}'.")
    lines = [colors.breach(f"OFAC SDN possible matches ({len(matches)}) for '{clean}':")]
    for m in matches[:25]:
        lines.append(f"  • {m.get('name')} (Program: {m.get('program')})")
    lines.append(colors.warning("Review matches manually; name collisions are common."))
    return "\n".join(lines)

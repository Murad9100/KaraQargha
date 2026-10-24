"""Email intelligence module for KaraQargha."""

from __future__ import annotations

import re
import socket
from typing import Any, Dict, List, Union

try:
    import dns.resolver
    DNS_AVAILABLE = True
except Exception:  # pragma: no cover
    DNS_AVAILABLE = False

DISPOSABLE_DOMAINS = {
    "mailinator.com", "10minutemail.com", "guerrillamail.com", "trashmail.com",
    "tempmail.com", "yopmail.com", "sharklasers.com", "getnada.com",
    "dispostable.com", "fakeinbox.com", "maildrop.cc", "throwawaymail.com",
}

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


def _is_disposable(domain: str) -> bool:
    domain = domain.lower()
    if domain in DISPOSABLE_DOMAINS:
        return True
    return any(domain.endswith("." + d) for d in DISPOSABLE_DOMAINS)


def _mx_records(domain: str) -> List[str]:
    out = []
    if not DNS_AVAILABLE:
        return out
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
        resolver.timeout = 5
        resolver.lifetime = 10
        answers = resolver.resolve(domain, "MX")
        for a in answers:
            out.append(str(a.exchange).rstrip("."))
    except Exception:
        pass
    return out


def _xposedornot(email: str) -> Dict[str, Any]:
    import requests
    url = f"https://api.xposedornot.com/v1/check-email/{email}"
    try:
        r = requests.get(url, timeout=15, headers={"User-Agent": "karagargha/2.0"})
        if r.status_code == 404:
            return {"breaches": [], "message": "No breaches found (XposedOrNot)."}
        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code}"}
        j = r.json()
        breaches = []
        data = j.get("breaches", [])
        if isinstance(data, list):
            for item in data:
                if isinstance(item, list):
                    for name in item:
                        breaches.append({"name": str(name), "date": None, "data_classes": []})
                elif isinstance(item, str):
                    breaches.append({"name": item, "date": None, "data_classes": []})
                elif isinstance(item, dict):
                    breaches.append({
                        "name": item.get("breach") or item.get("name") or item.get("site"),
                        "date": item.get("breached_date") or item.get("date") or item.get("xposed_date"),
                        "data_classes": item.get("xposed_data") or item.get("data_classes") or [],
                    })
        return {"breaches": breaches, "raw": j}
    except Exception as exc:
        return {"error": str(exc)}


def _hudson_rock(email: str) -> Dict[str, Any]:
    import requests
    url = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email"
    try:
        r = requests.get(url, params={"email": email}, timeout=15, headers={"User-Agent": "karagargha/2.0"})
        if r.status_code != 200:
            return {"status": f"HTTP {r.status_code}"}
        j = r.json()
        # status only, no plaintext
        info = {}
        if isinstance(j, dict):
            info["total_corporate_services"] = j.get("total_corporate_services")
            info["total_user_services"] = j.get("total_user_services")
            info["stealer"] = "infostealer exposure reported" if j.get("stealer_logs") or j.get("computers") else "none detected"
        return {"status": info}
    except Exception as exc:
        return {"error": str(exc)}


def scan_email(email: str, raw: bool = False, timeout: float = 10.0) -> Union[str, Dict[str, Any]]:
    clean_email = email.strip().lower()
    if not clean_email:
        err = "[!] Please provide an email address."
        return {"error": err} if raw else err

    import os
    syntax_ok = bool(EMAIL_RE.match(clean_email))
    domain = clean_email.split("@")[-1] if "@" in clean_email else ""
    disposable = _is_disposable(domain) if domain else False
    mx = _mx_records(domain) if domain else []
    xon = _xposedornot(clean_email)
    hudson = _hudson_rock(clean_email)

    # holehe registrations (optional, keep existing engine if available)
    registered = []
    holehe_available = True
    try:
        import holehe  # noqa: F401
    except Exception:
        holehe_available = False

    data = {
        "email": clean_email,
        "syntax_valid": syntax_ok,
        "domain": domain,
        "disposable": disposable,
        "mx_records": mx,
        "xposedornot": xon,
        "hudson_rock": hudson,
        "holehe_available": holehe_available,
        "holehe_registered": registered,
    }

    # Attempt holehe scan if installed
    if holehe_available:
        try:
            import asyncio
            import httpx
            from holehe.core import import_submodules, get_functions

            modules = import_submodules("holehe.modules")
            websites = get_functions(modules)
            out: List[Dict[str, Any]] = []

            async def _runner() -> None:
                sem = asyncio.Semaphore(25)
                limits = httpx.Limits(max_connections=25, max_keepalive_connections=10)
                async with httpx.AsyncClient(timeout=timeout, limits=limits) as client:
                    async def _check(fn) -> None:
                        async with sem:
                            try:
                                await fn(clean_email, client, out)
                            except Exception:
                                pass
                    await asyncio.gather(*[_check(fn) for fn in websites], return_exceptions=True)

            try:
                asyncio.run(_runner())
            except RuntimeError:
                pass
            registered = [item for item in out if item.get("exists") is True]
            data["holehe_registered"] = registered
        except Exception:
            pass

    if raw:
        return data

    from karagargha.core import colors
    lines = [colors.found(f"Email intelligence for {clean_email}:")]
    lines.append(f"  • Syntax Valid: {'Yes' if syntax_ok else 'No'}")
    lines.append(f"  • Domain: {domain}")
    lines.append(f"  • Disposable: {'YES (disposable)' if disposable else 'No'}")
    lines.append(f"  • MX Records: {', '.join(mx) if mx else 'None found'}")

    # XposedOrNot breaches
    breaches = (xon.get("breaches") if isinstance(xon, dict) else []) or []
    if xon.get("error"):
        lines.append(f"  • Breaches (XposedOrNot): error {xon['error']}")
    elif breaches:
        lines.append(f"  • Breaches (XposedOrNot): {len(breaches)}")
        for b in breaches:
            name = b.get("name", "Unknown")
            date = b.get("date", "N/A")
            classes = b.get("data_classes") or []
            lines.append(f"      - {name} (Date: {date})")
            if classes:
                lines.append(f"        Exposed: {', '.join(classes)}")
    else:
        lines.append("  • Breaches (XposedOrNot): No breaches found.")

    # Hudson Rock
    hr = hudson.get("status")
    if isinstance(hr, dict):
        lines.append(f"  • Infostealer exposure (Hudson Rock): {hr.get('stealer', 'n/a')}")
    elif hudson.get("error"):
        lines.append(f"  • Infostealer (Hudson Rock): error {hudson['error']}")
    else:
        lines.append(f"  • Infostealer (Hudson Rock): {hudson.get('status', 'unknown')}")

    # holehe
    reg = data.get("holehe_registered") or []
    if reg:
        lines.append(colors.found(f"  Registered accounts ({len(reg)}):"))
        for item in sorted(reg, key=lambda x: str(x.get("name", "")).lower()):
            lines.append(f"      • {item.get('name')}")
    else:
        lines.append(colors.info("  No registered accounts found (holehe)."))
    lines.append(colors.warning("  Note: false positives possible on registration checks."))

    # HIBP optional note
    import os
    if not os.getenv("HIBP_API_KEY", "").strip():
        lines.append(colors.info("  HIBP breach/paste scan disabled (HIBP_API_KEY not set)."))
    return "\n".join(lines)


def scan_email_headers(filepath: str, raw: bool = False) -> Union[str, Dict[str, Any]]:
    """Parse raw email headers from a file."""
    from email import policy
    from email.parser import BytesParser
    path = filepath.strip()
    try:
        with open(path, "rb") as f:
            msg = BytesParser(policy=policy.default).parse(f)
    except Exception as exc:
        err = f"[!] Failed to read headers file: {exc}"
        return {"error": str(exc)} if raw else err

    received = msg.get_all("Received", [])
    originating_ip = None
    ip_re = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
    for r in received:
        m = ip_re.search(r)
        if m:
            originating_ip = m.group(1)
            break

    spf = msg.get("Received-SPF")
    dkim = msg.get("DKIM-Signature")
    auth_results = msg.get("Authentication-Results")

    data = {
        "received_chain": received,
        "originating_ip": originating_ip,
        "spf": spf,
        "dkim": bool(dkim),
        "authentication_results": auth_results,
        "from": msg.get("From"),
        "to": msg.get("To"),
        "subject": msg.get("Subject"),
        "date": msg.get("Date"),
    }
    if raw:
        return data

    from karagargha.core import colors
    lines = [colors.found("Email header analysis:")]
    lines.append(f"  • From: {msg.get('From')}")
    lines.append(f"  • To: {msg.get('To')}")
    lines.append(f"  • Subject: {msg.get('Subject')}")
    lines.append(f"  • Date: {msg.get('Date')}")
    lines.append(f"  • Originating IP: {originating_ip or 'N/A'}")
    lines.append(f"  • SPF: {spf or 'N/A'}")
    lines.append(f"  • DKIM present: {'Yes' if dkim else 'No'}")
    lines.append(f"  • Authentication-Results: {auth_results or 'N/A'}")
    lines.append(f"  • Received hops: {len(received)}")
    return "\n".join(lines)

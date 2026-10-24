"""Domain & DNS intelligence module for KaraQargha."""

from __future__ import annotations

import socket
import ssl
from typing import Any, Dict, List, Union
from urllib.parse import urlparse

try:
    import dns.resolver
    DNS_AVAILABLE = True
except Exception:  # pragma: no cover
    DNS_AVAILABLE = False


def _rdap(domain: str) -> Dict[str, Any]:
    import requests
    url = f"https://rdap.org/domain/{domain}"
    r = requests.get(url, timeout=15, headers={"User-Agent": "karagargha/2.0"})
    if r.status_code != 200:
        return {"error": f"RDAP HTTP {r.status_code}"}
    return r.json()


def scan_domain(domain: str, raw: bool = False, timeout: int = 15) -> Union[str, Dict[str, Any]]:
    clean = domain.strip().lower()
    clean = clean.replace("http://", "").replace("https://", "").split("/")[0]
    if not clean:
        err = "[!] Please provide a domain."
        return {"error": err} if raw else err

    import requests
    from karagargha.core import colors

    data: Dict[str, Any] = {"domain": clean}

    # RDAP
    try:
        data["rdap"] = _rdap(clean)
    except Exception as exc:
        data["rdap"] = {"error": str(exc)}

    # DNS records
    dns_records: Dict[str, List[str]] = {}
    if DNS_AVAILABLE:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"):
            try:
                answers = resolver.resolve(clean, rtype)
                dns_records[rtype] = [str(a) for a in answers]
            except Exception:
                dns_records[rtype] = []
    data["dns"] = dns_records

    # Subdomains via crt.sh
    subdomains: List[str] = []
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{clean}&output=json", timeout=timeout)
        if r.status_code == 200:
            for entry in r.json():
                name = entry.get("name_value", "")
                for n in name.split("\n"):
                    n = n.strip().lower()
                    if n and n not in subdomains and n.endswith(clean):
                        subdomains.append(n)
    except Exception:
        pass
    data["subdomains"] = sorted(subdomains)

    # SSL cert
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((clean, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=clean) as ssock:
                cert = ssock.getpeercert()
                data["ssl"] = {
                    "subject": cert.get("subject"),
                    "issuer": cert.get("issuer"),
                    "notBefore": cert.get("notBefore"),
                    "notAfter": cert.get("notAfter"),
                }
    except Exception as exc:
        data["ssl"] = {"error": str(exc)}

    # Wayback Machine snapshots count
    wayback = None
    try:
        r = requests.get(
            f"https://web.archive.org/web/*/{clean}", timeout=timeout
        )
        # Use CDX API instead for count
        r2 = requests.get(
            f"http://web.archive.org/cdx/search/cdx?url={clean}/*&output=json&limit=1",
            timeout=timeout,
        )
        if r2.status_code == 200:
            # just store status
            wayback = {"available": True}
    except Exception:
        wayback = {"available": False}
    data["wayback"] = wayback

    if raw:
        return data

    lines = [colors.found(f"Domain intelligence for {clean}:")]
    # RDAP summary
    rdap = data.get("rdap", {})
    if isinstance(rdap, dict) and "error" not in rdap:
        lines.append("  • RDAP: retrieved")
        # registrar
        for ent in rdap.get("entities", []) or []:
            roles = ent.get("roles", [])
            if "registrar" in roles:
                lines.append(f"    Registrar: {ent.get('vcardArray', [''])[1] if isinstance(ent.get('vcardArray'), list) else ''}")
    else:
        lines.append(f"  • RDAP: {rdap.get('error') if isinstance(rdap, dict) else rdap}")
    # DNS
    lines.append("  • DNS records:")
    for k, v in dns_records.items():
        if v:
            lines.append(f"      {k}: {', '.join(v)}")
    # Subdomains
    lines.append(f"  • Subdomains (crt.sh): {len(subdomains)}")
    for s in subdomains[:25]:
        lines.append(f"      - {s}")
    # SSL
    sslinfo = data.get("ssl", {})
    if isinstance(sslinfo, dict) and "error" not in sslinfo:
        lines.append(f"  • SSL valid from {sslinfo.get('notBefore')} to {sslinfo.get('notAfter')}")
    else:
        lines.append(f"  • SSL: {sslinfo.get('error') if isinstance(sslinfo, dict) else sslinfo}")
    lines.append(f"  • Wayback Machine: {'available' if (wayback or {}).get('available') else 'n/a'}")
    return "\n".join(lines)

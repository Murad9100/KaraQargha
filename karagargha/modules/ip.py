"""IP Geolocation and Threat Intelligence Module for KaraQargha.

Queries the ip-api.com free endpoint for geographical coordinates, ISP,
organization, AS number, and proxy/hosting/cloud detection flags.
"""

from __future__ import annotations

from typing import Any, Dict, Union


def scan_ip(
    ip_address: str,
    raw: bool = False,
    timeout: int = 10,
) -> Union[str, Dict[str, Any]]:
    """Geolocate an IP address and detect proxy/hosting characteristics.

    Args:
        ip_address: IPv4 or IPv6 address or domain to resolve.
        raw: If True, returns the structured API dictionary.
        timeout: Request timeout in seconds.

    Returns:
        Formatted string summarizing geolocation and security flags, or dict if raw=True.
    """
    clean_ip = ip_address.strip()
    if not clean_ip:
        err = "[!] Please provide an IP address or domain."
        return {"error": err} if raw else err

    try:
        # Lazy imports inside function
        import os
        import requests
        from karagargha.core import colors
    except ImportError as imp_err:
        err = f"[!] Missing dependency: {imp_err}. Run: pip install requests"
        return {"error": err} if raw else err

    fields = "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query,proxy,hosting,mobile"
    url = f"http://ip-api.com/json/{clean_ip}?fields={fields}"
    headers = {"User-Agent": "karagargha-cli/1.0"}

    try:
        response = requests.get(url, headers=headers, timeout=timeout)
        if response.status_code != 200:
            err = colors.breach(f"IP-API returned HTTP status {response.status_code}")
            return {"error": err} if raw else err

        data: Dict[str, Any] = response.json()

        if data.get("status") != "success":
            message = data.get("message", "Unknown error")
            err = colors.breach(f"IP Geolocation failed for '{clean_ip}': {message}")
            return {"error": message, "raw": data} if raw else err

        # Reverse DNS
        import socket as _socket
        try:
            _socket.setdefaulttimeout(timeout)
            rdns = _socket.gethostbyaddr(clean_ip)[0]
        except Exception:
            rdns = None

        # Shodan InternetDB (free, no key)
        internetdb = {"ports": [], "vulns": [], "hostnames": [], "tags": []}
        try:
            idb_resp = requests.get(f"https://internetdb.shodan.io/{clean_ip}", timeout=timeout, headers=headers)
            if idb_resp.status_code == 200:
                idb_json = idb_resp.json()
                internetdb = {
                    "ports": idb_json.get("ports", []) or [],
                    "vulns": idb_json.get("vulns", []) or [],
                    "hostnames": idb_json.get("hostnames", []) or [],
                    "tags": idb_json.get("tags", []) or [],
                }
        except Exception:
            pass

        # Optional AbuseIPDB
        abuse = None
        abuse_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
        if abuse_key:
            try:
                ab_resp = requests.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={"Key": abuse_key, "Accept": "application/json"},
                    params={"ipAddress": clean_ip, "maxAgeInDays": 90},
                    timeout=timeout,
                )
                if ab_resp.status_code == 200:
                    abuse = ab_resp.json().get("data")
            except Exception:
                abuse = None

        data["reverse_dns"] = rdns
        data["shodan_internetdb"] = internetdb
        data["abuseipdb"] = abuse

        if raw:
            return data

        country = data.get("country", "Unknown")
        country_code = data.get("countryCode", "")
        region = data.get("regionName", "Unknown")
        city = data.get("city", "Unknown")
        postal = data.get("zip", "N/A")
        lat = data.get("lat")
        lon = data.get("lon")
        tz = data.get("timezone", "Unknown")
        isp = data.get("isp", "Unknown")
        org = data.get("org", "Unknown")
        asn = data.get("as", "Unknown")

        is_proxy = data.get("proxy", False)
        is_hosting = data.get("hosting", False)
        is_mobile = data.get("mobile", False)

        proxy_str = colors.colorize("YES (Proxy/VPN/Tor)", "red", bright=True) if is_proxy else colors.colorize("No", "green")
        hosting_str = colors.colorize("YES (Data Center/Cloud)", "yellow") if is_hosting else colors.colorize("No", "green")
        mobile_str = colors.colorize("YES (Cellular)", "yellow") if is_mobile else colors.colorize("No", "green")

        lines = [
            colors.found(f"IP Geolocation Report for {data.get('query', clean_ip)}:"),
            f"  • Country:        {country} ({country_code})",
            f"  • Region / State: {region}",
            f"  • City / Zip:     {city} / {postal}",
            f"  • Coordinates:    {lat}, {lon}",
            f"  • Timezone:       {tz}",
            f"  • ISP:            {isp}",
            f"  • Organization:   {org}",
            f"  • AS Number:      {asn}",
            f"  • Proxy / VPN:    {proxy_str}",
            f"  • Hosting / Cloud: {hosting_str}",
            f"  • Mobile Network: {mobile_str}",
            f"  • Reverse DNS:    {rdns or 'N/A'}",
            f"  • Open Ports:     {', '.join(map(str, internetdb.get('ports', []))) or 'N/A'}",
            f"  • Vulnerabilities: {', '.join(internetdb.get('vulns', [])) or 'None'}",
        ]
        if abuse:
            lines.append(f"  • AbuseIPDB Score: {abuse.get('abuseConfidenceScore')}")
        return "\n".join(lines)

    except Exception as exc:
        err = f"[!] IP lookup encountered an error: {exc}"
        return {"error": str(exc)} if raw else err

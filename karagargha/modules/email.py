"""Holehe Email Registration Scan Module for KaraQargha.

Performs async verification of email account registrations across
120+ platforms using the holehe library.
"""

from __future__ import annotations

from typing import Any, Dict, List, Union


def scan_email(
    email: str,
    raw: bool = False,
    timeout: float = 10.0,
    max_workers: int = 25,
) -> Union[str, List[Dict[str, Any]]]:
    """Check email registration across web services using holehe via asyncio.

    Args:
        email: Email address to investigate.
        raw: If True, returns list of dictionary records where exists is True.
        timeout: HTTP request timeout in seconds.
        max_workers: Maximum concurrent network requests.

    Returns:
        Formatted string listing services where account exists, or raw data list.
    """
    clean_email = email.strip()

    try:
        # Lazy imports inside function
        import asyncio
        import httpx
        from holehe.core import import_submodules, get_functions
        from karagargha.core import colors
    except ImportError as imp_err:
        fallback_msg = (
            f"[!] Holehe library is not installed or missing dependencies ({imp_err}).\n"
            "    Install it using: pip install holehe"
        )
        return [] if raw else fallback_msg

    try:
        modules = import_submodules("holehe.modules")
        websites = get_functions(modules)
    except Exception as exc:
        return [] if raw else f"[!] Failed to load holehe modules: {exc}"

    out: List[Dict[str, Any]] = []

    async def _runner() -> None:
        semaphore = asyncio.Semaphore(max_workers)
        limits = httpx.Limits(max_connections=max_workers, max_keepalive_connections=10)

        async with httpx.AsyncClient(timeout=timeout, limits=limits) as client:
            async def _check_service(fn) -> None:
                async with semaphore:
                    try:
                        await fn(clean_email, client, out)
                    except Exception:
                        pass

            tasks = [_check_service(fn) for fn in websites]
            await asyncio.gather(*tasks, return_exceptions=True)

    try:
        # Run under asyncio
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            # If already inside an event loop (e.g. jupyter or test harness), run in thread
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as executor:
                executor.submit(asyncio.run, _runner()).result()
        else:
            asyncio.run(_runner())

        # Filter only exists: True services as specified in requirements
        registered = [item for item in out if item.get("exists") is True]

        if raw:
            return registered

        if not registered:
            return colors.info(f"No registered accounts found across {len(websites)} checked services.")

        lines = [colors.found(f"Account exists on {len(registered)} platform(s):")]
        for item in sorted(registered, key=lambda x: str(x.get("name", "")).lower()):
            name = item.get("name", "Unknown")
            domain = item.get("domain", "")
            domain_suffix = f" ({domain})" if domain else ""
            lines.append(f"  • {name}{domain_suffix}")

            recovery_mail = item.get("emailrecovery")
            phone = item.get("phoneNumber")
            others = item.get("others")

            if recovery_mail:
                lines.append(f"      Recovery Email: {recovery_mail}")
            if phone:
                lines.append(f"      Recovery Phone: {phone}")
            if others:
                lines.append(f"      Info: {others}")

        return "\n".join(lines)

    except Exception as exc:
        err = f"[!] Email registration scan encountered an error: {exc}"
        return [] if raw else err

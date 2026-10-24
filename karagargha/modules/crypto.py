"""Cryptocurrency (Bitcoin) intelligence module."""

from __future__ import annotations
from typing import Any, Dict, Union


def scan_crypto(address: str, raw: bool = False, timeout: int = 15) -> Union[str, Dict[str, Any]]:
    clean = address.strip()
    if not clean:
        err = "[!] Please provide a BTC address."
        return {"error": err} if raw else err

    import requests
    from karagargha.core import colors

    url = f"https://mempool.space/api/address/{clean}"
    try:
        r = requests.get(url, timeout=timeout, headers={"User-Agent": "karagargha/2.0"})
        if r.status_code != 200:
            err = f"HTTP {r.status_code}"
            return {"error": err} if raw else colors.breach(f"Bitcoin lookup failed: {err}")
        data = r.json()
        chain = data.get("chain_stats", {})
        mempool = data.get("mempool_stats", {})
        summary = {
            "address": clean,
            "funded_txo_count": chain.get("funded_txo_count"),
            "spent_txo_count": chain.get("spent_txo_count"),
            "tx_count": chain.get("tx_count"),
            "funded_sat": chain.get("funded_sat"),
            "spent_sat": chain.get("spent_sat"),
            "balance_sat": (chain.get("funded_sat", 0) or 0) - (chain.get("spent_sat", 0) or 0),
            "mempool_tx_count": mempool.get("tx_count"),
        }
        if raw:
            return summary
        lines = [colors.found(f"Bitcoin address summary for {clean}:")]
        lines.append(f"  • Balance (sat): {summary['balance_sat']}")
        lines.append(f"  • Total received (sat): {summary['funded_sat']}")
        lines.append(f"  • Total spent (sat): {summary['spent_sat']}")
        lines.append(f"  • Transactions: {summary['tx_count']}")
        lines.append(f"  • Funded outputs: {summary['funded_txo_count']}")
        lines.append(f"  • Spent outputs: {summary['spent_txo_count']}")
        lines.append(f"  • Pending (mempool) tx: {summary['mempool_tx_count']}")
        return "\n".join(lines)
    except Exception as exc:
        err = str(exc)
        return {"error": err} if raw else colors.breach(f"Bitcoin lookup error: {err}")

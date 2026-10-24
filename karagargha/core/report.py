"""KaraQargha Report Core Module.

Handles exporting OSINT scan results to .txt and .json files with
automatic format detection based on file extension.
"""

from __future__ import annotations

import datetime
import json
import os
from typing import Any, Dict, Optional

from karagargha.core.colors import strip_ansi


def generate_json_report(
    target_type: str,
    target_value: str,
    module_data: Dict[str, Any],
) -> Dict[str, Any]:
    """Assemble a structured JSON dictionary for scan results.

    Args:
        target_type: Type of target ('email', 'username', 'phone', 'ip', 'all').
        target_value: Target identifier (e.g. email address or username).
        module_data: Dict mapping module names to structured data or parsed results.

    Returns:
        Structured dictionary ready for JSON serialization.
    """
    return {
        "tool": "KaraQargha",
        "version": "1.0.0",
        "scan_time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "target": {
            "type": target_type,
            "value": target_value,
        },
        "results": module_data,
    }


def generate_txt_report(
    target_type: str,
    target_value: str,
    text_sections: Dict[str, str],
) -> str:
    """Assemble a clean plain-text report from module text outputs.

    Args:
        target_type: Target category name.
        target_value: Target string.
        text_sections: Dict mapping module names to raw/colored string outputs.

    Returns:
        Clean ANSI-stripped text report.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "=" * 60,
        "  KARAQARGHA OSINT INVESTIGATION REPORT",
        "=" * 60,
        f"Generated: {timestamp}",
        f"Target Type: {target_type.upper()}",
        f"Target Value: {target_value}",
        "=" * 60,
        "",
    ]

    for title, content in text_sections.items():
        lines.append(f"--- [ {title.upper()} ] ---")
        lines.append(strip_ansi(content).strip())
        lines.append("")

    lines.append("=" * 60)
    lines.append("End of KaraQargha Report. Generated for authorized OSINT analysis.")
    lines.append("=" * 60)

    return "\n".join(lines)


def generate_html_report(
    target_type: str,
    target_value: str,
    module_data: Dict[str, Any],
    text_sections: Optional[Dict[str, str]] = None,
) -> str:
    """Generate a simple HTML report."""
    import html as _html
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    parts = [
        "<!DOCTYPE html>", "<html><head><meta charset='utf-8'>",
        f"<title>KaraQargha Report - {_html.escape(target_value)}</title>",
        "<style>body{font-family:monospace;background:#111;color:#eee;padding:20px;} h1{color:#0ff;} section{margin:16px 0;padding:12px;border:1px solid #333;border-radius:8px;} pre{white-space:pre-wrap;}</style>",
        "</head><body>",
        f"<h1>KARAQARGHA OSINT REPORT</h1>",
        f"<p>Target: {_html.escape(target_type)} / {_html.escape(target_value)}<br>Generated: {ts}</p>",
    ]
    if text_sections:
        for title, content in text_sections.items():
            parts.append(f"<section><h2>{_html.escape(title)}</h2><pre>{_html.escape(content)}</pre></section>")
    parts.append(f"<section><h2>Raw JSON</h2><pre>{_html.escape(json.dumps(module_data, indent=2, ensure_ascii=False))}</pre></section>")
    parts.append("</body></html>")
    return "\n".join(parts)


def save_report(
    filepath: str,
    json_data: Dict[str, Any],
    text_content: str,
) -> str:
    """Save scan results to a file, auto-detecting .txt or .json.

    Args:
        filepath: Target file destination path.
        json_data: Structured data dictionary for JSON export.
        text_content: Text output to save if extension is not .json.

    Returns:
        Human-readable status string confirming save or error.
    """
    try:
        abs_path = os.path.abspath(filepath)
        dir_name = os.path.dirname(abs_path)
        if dir_name and not os.path.exists(dir_name):
            os.makedirs(dir_name, exist_ok=True)

        _, ext = os.path.splitext(filepath)
        ext = ext.lower()

        if ext == ".json":
            with open(abs_path, "w", encoding="utf-8") as f:
                json.dump(json_data, f, indent=2, ensure_ascii=False)
            return f"[+] Report successfully saved to JSON: {abs_path}"

        # Default to clean .txt
        clean_text = strip_ansi(text_content)
        with open(abs_path, "w", encoding="utf-8") as f:
            f.write(clean_text)
        return f"[+] Report successfully saved to text file: {abs_path}"

    except Exception as exc:
        return f"[!] Failed to save report to '{filepath}': {exc}"

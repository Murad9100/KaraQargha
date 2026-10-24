"""KaraQargha Report Core Module.

Handles exporting OSINT scan results to .txt and .json files with
automatic format detection based on file extension.
"""

from __future__ import annotations

import datetime
import json
import os
from typing import Any, Dict

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

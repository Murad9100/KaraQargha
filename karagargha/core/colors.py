"""KaraQargha Colors Core Module.

Provides colorama-based terminal colors, prefixes, and ANSI manipulation
compatible with Windows Command Prompt, PowerShell, and Unix terminals.
"""

from __future__ import annotations

import re
import sys
from typing import Optional

try:
    import colorama
    from colorama import Fore, Style

    colorama.init(autoreset=True)
    COLOR_AVAILABLE = True
except ImportError:  # pragma: no cover
    COLOR_AVAILABLE = False

    class _Dummy:
        def __getattr__(self, name: str) -> str:
            return ""

    Fore = _Dummy()  # type: ignore
    Style = _Dummy()  # type: ignore

ANSI_ESCAPE_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

# Standard Prefixes
PREFIX_FOUND = f"{Fore.GREEN}[+]{Style.RESET_ALL} " if COLOR_AVAILABLE else "[+] "
PREFIX_BREACH = f"{Fore.RED}[!]{Style.RESET_ALL} " if COLOR_AVAILABLE else "[!] "
PREFIX_INFO = f"{Fore.YELLOW}[i]{Style.RESET_ALL} " if COLOR_AVAILABLE else "[i] "
PREFIX_SCAN = f"{Fore.CYAN}[~]{Style.RESET_ALL} " if COLOR_AVAILABLE else "[~] "
PREFIX_ERROR = f"{Fore.RED}[x]{Style.RESET_ALL} " if COLOR_AVAILABLE else "[x] "


def init_colors() -> None:
    """Initialize terminal color support, especially on Windows CMD."""
    if COLOR_AVAILABLE:
        try:
            colorama.just_fix_windows_console()
        except AttributeError:
            colorama.init(autoreset=True)


def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences from a string.

    Args:
        text: String containing potential ANSI escape sequences.

    Returns:
        Clean plain text without escape sequences.
    """
    if not text:
        return ""
    return ANSI_ESCAPE_RE.sub("", text)


def colorize(text: str, color: str, bright: bool = False) -> str:
    """Apply ANSI color styling to text if color is available.

    Args:
        text: Text to colorize.
        color: Name of the color ('green', 'red', 'yellow', 'cyan', 'blue', 'magenta').
        bright: Whether to apply Style.BRIGHT.

    Returns:
        Styled string or original string if color is unavailable.
    """
    if not COLOR_AVAILABLE:
        return text

    colors = {
        "green": Fore.GREEN,
        "red": Fore.RED,
        "yellow": Fore.YELLOW,
        "cyan": Fore.CYAN,
        "blue": Fore.BLUE,
        "magenta": Fore.MAGENTA,
        "white": Fore.WHITE,
    }
    selected_color = colors.get(color.lower(), "")
    style = Style.BRIGHT if bright else ""
    return f"{style}{selected_color}{text}{Style.RESET_ALL}"


def found(msg: str) -> str:
    """Format message with green [+] found prefix."""
    return f"{PREFIX_FOUND}{msg}"


def breach(msg: str) -> str:
    """Format message with red [!] breach/leak prefix."""
    return f"{PREFIX_BREACH}{msg}"


def info(msg: str) -> str:
    """Format message with yellow [i] info prefix."""
    return f"{PREFIX_INFO}{msg}"


def header(title: str) -> str:
    """Format a section header in bright cyan."""
    bar = "=" * (len(title) + 4)
    if COLOR_AVAILABLE:
        return (
            f"\n{Fore.CYAN}{Style.BRIGHT}{bar}\n"
            f"  {title}\n"
            f"{bar}{Style.RESET_ALL}"
        )
    return f"\n{bar}\n  {title}\n{bar}"


def get_banner() -> str:
    """Return the ASCII art banner with color styling."""
    raw_banner = r"""
  _  __                    ___                       _       
 | |/ /__ _  __ _ _ __    / _ \ _ __ __ _ _ __   __| | __ _ 
 | ' // _` |/ _` | '_ \  | | | | '__/ _` | '_ \ / _` |/ _` |
 | . \ (_| | (_| | | | | | |_| | | | (_| | | | | (_| | (_| |
 |_|\_\__,_|\__,_|_| |_|  \___/|_|  \__,_|_| |_|\__,_|\__,_|
          Mini OSINT Framework v1.0 — by YOU
"""
    if COLOR_AVAILABLE:
        return f"{Fore.CYAN}{Style.BRIGHT}{raw_banner}{Style.RESET_ALL}"
    return raw_banner

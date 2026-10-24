"""KaraQargha Spinner Core Module.

Provides a lightweight, thread-based terminal spinner context manager
compatible with Windows CMD, PowerShell, and Unix terminals.
"""

from __future__ import annotations

import itertools
import sys
import threading
import time
from typing import Optional


class Spinner:
    """Thread-based terminal spinner context manager.

    Example:
        with Spinner("[~] Scanning breaches for test@mail.com ..."):
            result = do_scan()
    """

    FRAMES = ["|", "/", "-", "\\"]

    def __init__(
        self,
        message: str = "Processing...",
        delay: float = 0.1,
        enabled: bool = True,
    ) -> None:
        """Initialize the spinner.

        Args:
            message: Text displayed alongside the animated spinner.
            delay: Interval in seconds between frame animations.
            enabled: If False, the spinner is completely disabled (e.g. for JSON mode).
        """
        self.message = message
        self.delay = delay
        self.enabled = enabled
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def __enter__(self) -> Spinner:
        """Start the spinner thread upon entering context."""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Stop and clear the spinner upon exiting context."""
        self.stop()

    def start(self) -> None:
        """Start spinner animation thread if enabled."""
        if not self.enabled:
            return
        if not getattr(sys.stderr, "isatty", lambda: True)():
            return

        self._stop_event.clear()
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop the spinner thread and clear the line."""
        if not self.enabled:
            return

        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=0.5)

        # Clear line on stderr
        sys.stderr.write("\r" + " " * (len(self.message) + 10) + "\r")
        sys.stderr.flush()

    def update_message(self, new_message: str) -> None:
        """Update the spinner text while running."""
        self.message = new_message

    def _spin(self) -> None:
        """Worker loop that prints frames to stderr."""
        for frame in itertools.cycle(self.FRAMES):
            if self._stop_event.is_set():
                break
            # Write to stderr so stdout redirection remains clean
            line = f"\r{self.message} {frame}"
            sys.stderr.write(line)
            sys.stderr.flush()
            time.sleep(self.delay)

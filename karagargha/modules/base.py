"""Common base class for all KaraQargha OSINT modules."""

from __future__ import annotations

import asyncio
import os
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


@dataclass
class ModuleResult:
    name: str
    target: Any
    ok: bool
    data: Any = None
    text: str = ""
    error: str = ""
    skipped: bool = False


class BaseModule(ABC):
    """Base class for a single data source module."""

    name: str = "base"
    input_types: Set[str] = set()  # e.g. {"email","username","ip","phone","domain","image","crypto","sanctions"}
    requires_key: Optional[str] = None  # env var name, or None

    def __init__(self, timeout: float = 15.0, max_retries: int = 2, rate_limit: float = 0.0):
        self.timeout = timeout
        self.max_retries = max_retries
        self.rate_limit = rate_limit
        self._last_call = 0.0

    def is_available(self) -> bool:
        if self.requires_key:
            return bool(os.getenv(self.requires_key, "").strip())
        return True

    async def _throttle(self) -> None:
        if self.rate_limit > 0:
            now = time.monotonic()
            wait = self.rate_limit - (now - self._last_call)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_call = time.monotonic()

    async def run(self, target: Any, **kwargs: Any) -> ModuleResult:
        if not self.is_available():
            return ModuleResult(
                name=self.name,
                target=target,
                ok=False,
                skipped=True,
                text=f"[!] {self.name} skipped: missing {self.requires_key} in .env",
            )
        await self._throttle()
        last_exc = None
        for attempt in range(self.max_retries + 1):
            try:
                data, text = await asyncio.wait_for(self._run(target, **kwargs), timeout=self.timeout)
                return ModuleResult(name=self.name, target=target, ok=True, data=data, text=text)
            except asyncio.TimeoutError:
                last_exc = TimeoutError(f"{self.name} timed out after {self.timeout}s")
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
            if attempt < self.max_retries:
                await asyncio.sleep(0.5 * (attempt + 1))
        return ModuleResult(name=self.name, target=target, ok=False, error=str(last_exc), text=f"[!] {self.name} failed: {last_exc}")

    @abstractmethod
    async def _run(self, target: Any, **kwargs: Any):
        """Return (raw_data, text_str)."""
        raise NotImplementedError


def discover_modules(package: str = "karagargha.modules") -> List[BaseModule]:
    """Auto-discover BaseModule subclasses in the modules package."""
    import importlib
    import pkgutil
    found: List[BaseModule] = []
    try:
        mod = importlib.import_module(package)
    except Exception:
        return found
    for info in pkgutil.iter_modules(mod.__path__):
        if info.name in ("base",):
            continue
        try:
            m = importlib.import_module(f"{package}.{info.name}")
        except Exception:
            continue
        for attr in dir(m):
            obj = getattr(m, attr)
            if isinstance(obj, type) and issubclass(obj, BaseModule) and obj is not BaseModule:
                try:
                    found.append(obj())
                except Exception:
                    pass
    return found

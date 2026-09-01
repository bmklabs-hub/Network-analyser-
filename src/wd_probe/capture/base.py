"""The CaptureEngine seam.

Stage 1 of the pipeline. Its only job is to get packets onto disk as fast as
the wire delivers them. It must never parse, never analyse, never block.

Any work done here becomes packet loss — and packet loss is silent corruption,
not a performance problem. That constraint is why this interface is so small:
there is deliberately nowhere to put clever logic.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol, runtime_checkable

from wd_probe.contracts import CaptureSession


@runtime_checkable
class CaptureEngine(Protocol):
    name: str

    def preflight(self) -> list[str]:
        """Return a list of problems. Empty list means good to go.

        Called before every capture. Catching 'the adapter is not in monitor
        mode' here costs a second; catching it after a 20-minute customer-site
        capture costs the engagement.
        """
        ...

    def capture(self, out_dir: Path, duration_s: int) -> CaptureSession:
        """Capture to disk and return the session, including drop counters."""
        ...


class CaptureError(RuntimeError):
    pass

"""The Reducer seam.

Stage 2 of the pipeline (design v0.3 §4.2). A reducer turns a completed pcap
file into Envelopes. It never touches a live interface — that is stage 1's job,
and mixing them is how you turn a CPU spike into dropped packets.

There are two implementations planned:

    WifiTsharkReducer   802.11 pcap  -> frame stats + station stats   [built]
    ZeekReducer         wired pcap   -> conn / dns / ssl / ...        [stub]

They share nothing but this Protocol, which is exactly the point.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator, Protocol, runtime_checkable

from wd_probe.contracts import CaptureSession, Envelope


@runtime_checkable
class Reducer(Protocol):
    """Turn a pcap into a stream of Envelopes."""

    name: str

    def supports(self, session: CaptureSession) -> bool:
        """Can this reducer handle this session's capture kind?"""
        ...

    def reduce(self, pcap: Path, session: CaptureSession) -> Iterator[Envelope]:
        """Yield Envelopes. Streaming, so a 2 GB pcap does not become 2 GB of RAM."""
        ...


class ReducerError(RuntimeError):
    pass

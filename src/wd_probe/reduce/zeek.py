"""Wired reducer — Zeek. NOT IMPLEMENTED YET.

This stub exists on purpose. It is 40 lines that cost nothing today and buy
two things:

  1. It proves the Reducer seam is real. A Protocol with exactly one
     implementation is not an abstraction, it is a guess. Writing the second
     signature — even unimplemented — is what verifies the first one wasn't
     shaped around 802.11 by accident.

  2. It documents the plan where the next person (you, in three months) will
     actually look for it: in the code, not in a design document.

When the server hardware arrives, this file is the only place that needs real
work. Nothing in contracts.py, spool.py or cli.py should have to change — and
if it does, the seam was drawn in the wrong place and that is worth knowing.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

from wd_probe.contracts import CaptureKind, CaptureSession, Envelope
from wd_probe.reduce.base import ReducerError


class ZeekReducer:
    """Planned: run `zeek -r <pcap>`, parse the emitted .log files.

    Mapping from Zeek output to SampleType:

        conn.log   -> SampleType.CONN
        dns.log    -> SampleType.DNS
        ssl.log    -> SampleType.SSL
        dhcp.log   -> SampleType.DHCP
        weird.log  -> SampleType.WEIRD

    Note it emits the same Envelope as the wireless reducer, into the same
    spool, over the same uploader. That is the payoff for writing contracts.py
    first.
    """

    name = "zeek"

    def supports(self, session: CaptureSession) -> bool:
        return session.capture_point.kind in {
            CaptureKind.SPAN,
            CaptureKind.RSPAN,
            CaptureKind.ERSPAN,
            CaptureKind.TAP,
            CaptureKind.INLINE,
        }

    def reduce(self, pcap: Path, session: CaptureSession) -> Iterator[Envelope]:
        raise ReducerError(
            "ZeekReducer is not implemented yet — wired capture is blocked on "
            "server hardware. The wireless path works today; see "
            "wd_probe.reduce.wifi_tshark.WifiTsharkReducer."
        )
        yield  # pragma: no cover  (makes the signature a generator)

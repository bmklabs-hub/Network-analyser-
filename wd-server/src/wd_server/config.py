"""Server configuration — read once, from environment variables.

    WD_PROBE_TOKENS   comma-separated  probe_id=token  pairs, e.g.
                      "kali-lab=s3cret,minipc-01=an0ther"
    WD_DB_PATH        SQLite file (default ~/.wd-server/server.db)

Environment variables, not a config file, because that is what Docker Compose
(ADR-10) passes most naturally, and because secrets in a file inside the repo
eventually get committed. Ask anyone who has rotated a leaked key.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    db_path: Path
    probe_tokens: dict[str, str] = field(default_factory=dict)   # token -> probe_id

    @classmethod
    def from_env(cls) -> Settings:
        return cls(
            db_path=Path(os.environ.get("WD_DB_PATH", "~/.wd-server/server.db")).expanduser(),
            probe_tokens=parse_tokens(os.environ.get("WD_PROBE_TOKENS", "")),
        )


def parse_tokens(raw: str) -> dict[str, str]:
    """'kali-lab=abc,minipc=def'  →  {'abc': 'kali-lab', 'def': 'minipc'}

    Keyed by token because that is what arrives on every request. A bare token
    with no '=' is accepted and named after its position, so a quick lab setup
    (WD_PROBE_TOKENS=abc) still works.
    """
    out: dict[str, str] = {}
    for i, item in enumerate(p.strip() for p in raw.split(",")):
        if not item:
            continue
        if "=" in item:
            probe_id, token = (x.strip() for x in item.split("=", 1))
        else:
            probe_id, token = f"probe-{i + 1}", item
        if token:
            out[token] = probe_id
    return out

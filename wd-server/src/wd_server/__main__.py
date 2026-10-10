"""`wd-server` / `python -m wd_server` — run the server with uvicorn."""

from __future__ import annotations

import argparse


def main() -> None:
    import uvicorn

    from wd_server.app import create_app

    ap = argparse.ArgumentParser(prog="wd-server")
    ap.add_argument("--host", default="127.0.0.1",
                    help="Bind address. Keep 127.0.0.1 or a lab IP until Phase 6 adds login.")
    ap.add_argument("--port", type=int, default=8000)
    args = ap.parse_args()
    uvicorn.run(create_app(), host=args.host, port=args.port)


if __name__ == "__main__":
    main()

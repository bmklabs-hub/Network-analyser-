# wd-server

Ingest API and web UI for WiFi-Diagnose. **Phase 2** — rebuilt 10 Oct 2026
from ADR-26…29 after the original code was lost before it was ever pushed.

```
wd-probe ──HTTPS batch POST──► /api/v1/ingest ──► SQLite ──► /  (sessions page)
          bearer token                                      /sessions/<id>
```

## Run it (Kali or any Linux/Mac)

```bash
pip install -e "./wd-server[dev]"
export WD_PROBE_TOKENS="kali-lab=pick-a-long-random-string"
wd-server --host 127.0.0.1 --port 8000
# open http://127.0.0.1:8000
```

With no `WD_PROBE_TOKENS` the server **refuses all ingest** (503) — fail closed, ADR-27.

⚠️ The web pages have **no login yet** (human auth is Phase 6, ADR-09). Keep the
server on `127.0.0.1` or a lab network. Never expose it to the internet.

## Send data from the probe

```bash
export WD_PROBE_TOKEN="pick-a-long-random-string"
wd-probe upload --server http://127.0.0.1:8000
```

Safe to re-run any time: samples carry probe-generated UUIDs and the server
upserts, so a retry never duplicates anything (ADR-08).

## Layout

```
src/wd_server/
  config.py     environment → Settings (tokens, DB path)
  auth.py       bearer token → ProbeIdentity(probe_id, tenant_id)   ADR-27
  schemas.py    the wire contract, duplicated from the probe        ADR-28
  db.py         SQLite store; tenant_id in every key and query      ADR-05/12
  app.py        FastAPI: /api/v1/ingest, /healthz, two HTML pages
  templates/    Jinja2 — the same templates will render PDF reports later
tests/
  test_auth.py         fail-closed, 401s, tenant from token not payload
  test_ingest.py       idempotency, orphan samples, verdict display
  test_parity.py       probe vs server envelope must not drift      ADR-28
  test_end_to_end.py   real pcap → reducer → spool → HTTP → HTML    ADR-29
```

## Decisions this code implements

| ADR | In one line |
|-----|-------------|
| 26 | One repo, two deployables — `wd-probe/` (root) and `wd-server/` |
| 27 | Minimal auth seam now; identity already carries `tenant_id` |
| 28 | Server duplicates the Envelope; a parity test guards against drift |
| 29 | The verdict lives on the session, so the page can't show a bad capture as trustworthy |

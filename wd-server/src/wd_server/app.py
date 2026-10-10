"""wd-server — FastAPI application.  Phase 2: ingest + one page.

    POST /api/v1/ingest        probe → server, bearer token (ADR-08, ADR-27)
    GET  /healthz              liveness, no auth
    GET  /                     sessions list (HTML)
    GET  /sessions/{id}        one session (HTML)

⚠️ The two HTML pages have NO user login yet. Human auth (email + password →
session, ADR-09) is Phase 6. Until then, run the server on a lab network or
bind it to 127.0.0.1 — never expose it to the internet.

Every handler receives a tenant from somewhere trustworthy:
  * ingest  → from the probe's token (ProbeIdentity)
  * pages   → the constant DEFAULT_TENANT, until Phase 6 adds user sessions
The code paths already pass tenant_id everywhere, so Phase 6 changes where
the value comes from, not every line that uses it. That is ADR-27's point.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from wd_server import __version__
from wd_server.auth import DEFAULT_TENANT, ProbeIdentity, require_probe
from wd_server.config import Settings
from wd_server.db import Store
from wd_server.schemas import IngestBatch, IngestResult, SampleType

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def create_app(settings: Settings | None = None) -> FastAPI:
    """App factory — tests build an app with their own settings and temp DB."""
    settings = settings or Settings.from_env()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.store = Store(settings.db_path)
        yield
        app.state.store.close()

    app = FastAPI(title="wd-server", version=__version__, lifespan=lifespan)
    app.state.settings = settings

    # ── API ─────────────────────────────────────────────────────────────────

    @app.get("/healthz")
    def healthz() -> dict:
        return {"status": "ok", "version": __version__,
                "ingest_enabled": bool(settings.probe_tokens)}

    @app.post("/api/v1/ingest", response_model=IngestResult)
    def ingest(
        batch: IngestBatch,
        request: Request,
        probe: ProbeIdentity = Depends(require_probe),
    ) -> IngestResult:
        store: Store = request.app.state.store

        # Every sample must belong to a session the server knows — either sent
        # in this batch or stored earlier. An orphan sample has no capture
        # point, so no verdict, so it cannot be interpreted honestly. Reject
        # the batch loudly rather than store data we can't explain.
        in_batch = {s.id for s in batch.sessions}
        referenced = {e.session_id for e in batch.samples}
        unknown = referenced - in_batch - store.known_session_ids(
            probe.tenant_id, referenced - in_batch)
        if unknown:
            raise HTTPException(
                422,
                f"samples reference unknown session(s): {sorted(unknown)[:5]}",
            )

        inserted, duplicates = store.ingest(
            probe.tenant_id, probe.probe_id, batch.sessions, batch.samples)
        return IngestResult(
            accepted=[e.sample_uuid for e in batch.samples],
            inserted=inserted,
            duplicates=duplicates,
            sessions_upserted=len(batch.sessions),
        )

    # ── pages ───────────────────────────────────────────────────────────────

    @app.get("/", response_class=HTMLResponse)
    def sessions_page(request: Request):
        store: Store = request.app.state.store
        return TEMPLATES.TemplateResponse(request, "sessions.html", {
            "sessions": store.list_sessions(DEFAULT_TENANT),
            "ingest_enabled": bool(settings.probe_tokens),
            "version": __version__,
        })

    @app.get("/sessions/{session_id}", response_class=HTMLResponse)
    def session_page(session_id: str, request: Request):
        store: Store = request.app.state.store
        s = store.get_session(DEFAULT_TENANT, session_id)
        if s is None:
            raise HTTPException(404, f"No session {session_id}")
        return TEMPLATES.TemplateResponse(request, "session.html", {
            "s": s,
            "frames": store.samples(DEFAULT_TENANT, session_id,
                                    SampleType.WIFI_FRAME_STAT.value, limit=300),
            "stations": store.samples(DEFAULT_TENANT, session_id,
                                      SampleType.WIFI_STATION_STAT.value, limit=25),
            "version": __version__,
        })

    return app

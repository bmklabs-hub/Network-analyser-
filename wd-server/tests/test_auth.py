"""ADR-27 — the minimal auth seam, and failing closed."""

from wd_server.config import parse_tokens

from .conftest import AUTH, sample_dict, session_dict


def _batch():
    return {"sessions": [session_dict()], "samples": [sample_dict()]}


def test_no_tokens_configured_means_ingest_is_closed(closed_client):
    """An open ingest endpoint is a nuisance in a lab and an incident in
    production. With nothing configured, refuse everyone — and say how to fix it."""
    r = closed_client.post("/api/v1/ingest", json=_batch(), headers=AUTH)
    assert r.status_code == 503
    assert "WD_PROBE_TOKENS" in r.json()["detail"]


def test_missing_token_is_401(client):
    assert client.post("/api/v1/ingest", json=_batch()).status_code == 401


def test_wrong_token_is_401(client):
    r = client.post("/api/v1/ingest", json=_batch(),
                    headers={"Authorization": "Bearer wrong"})
    assert r.status_code == 401


def test_valid_token_is_accepted(client):
    assert client.post("/api/v1/ingest", json=_batch(), headers=AUTH).status_code == 200


def test_tenant_comes_from_the_token_not_the_payload(client):
    """A probe that claims another tenant in its payload must not get it.
    (ADR-12: trusting a client-controlled field is the opposite of RLS.)"""
    batch = _batch()
    batch["sessions"][0]["tenant_id"] = "someone-else"
    batch["samples"][0]["tenant_id"] = "someone-else"
    assert client.post("/api/v1/ingest", json=batch, headers=AUTH).status_code == 200
    store = client.app.state.store
    assert store.get_session("default", "sess-abc") is not None
    assert store.get_session("someone-else", "sess-abc") is None


def test_token_parsing():
    assert parse_tokens("kali=abc, minipc=def") == {"abc": "kali", "def": "minipc"}
    assert parse_tokens("abc") == {"abc": "probe-1"}
    assert parse_tokens("") == {}


def test_healthz_needs_no_auth(client):
    assert client.get("/healthz").json()["ingest_enabled"] is True

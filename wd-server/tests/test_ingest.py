"""Ingest behaviour — idempotency, honesty, and the pages."""

from datetime import datetime

from .conftest import AUTH, sample_dict, session_dict


def _post(client, batch):
    return client.post("/api/v1/ingest", json=batch, headers=AUTH)


def test_retried_batch_is_harmless(client):
    """ADR-08: the probe retries blindly, so the server must upsert."""
    batch = {"sessions": [session_dict()],
             "samples": [sample_dict("u-00000001"), sample_dict("u-00000002")]}
    first = _post(client, batch).json()
    again = _post(client, batch).json()
    assert (first["inserted"], first["duplicates"]) == (2, 0)
    assert (again["inserted"], again["duplicates"]) == (0, 2)
    # Both replies acknowledge everything, so the probe marks all as sent.
    assert sorted(again["accepted"]) == ["u-00000001", "u-00000002"]
    assert client.app.state.store.get_session("default", "sess-abc")["sample_count"] == 2


def test_sample_for_unknown_session_is_rejected(client):
    """An orphan sample has no capture point and no verdict — it cannot be
    interpreted honestly, so refuse it loudly."""
    r = _post(client, {"sessions": [], "samples": [sample_dict(sid="sess-ghost")]})
    assert r.status_code == 422
    assert "sess-ghost" in r.json()["detail"]


def test_session_sent_in_an_earlier_batch_is_enough(client):
    _post(client, {"sessions": [session_dict()], "samples": []})
    assert _post(client, {"sessions": [], "samples": [sample_dict()]}).status_code == 200


def test_naive_timestamp_is_rejected_at_the_server_too(client):
    """Never assume the other side of a network boundary obeyed the contract."""
    naive = datetime.now().isoformat()          # no timezone
    r = _post(client, {"sessions": [session_dict()],
                       "samples": [sample_dict(ts=naive)]})
    assert r.status_code == 422


def test_unknown_sample_type_is_rejected(client):
    r = _post(client, {"sessions": [session_dict()],
                       "samples": [sample_dict(sample_type="made_up")]})
    assert r.status_code == 422


def test_later_upload_updates_the_session_verdict(client):
    """A session can be uploaded before reduction finishes; the later upload
    carrying the verdict must replace the earlier quality."""
    _post(client, {"sessions": [session_dict(quality={"packets_captured": 0})], "samples": []})
    s = client.app.state.store.get_session("default", "sess-abc")
    assert s["verdict"] == "not reduced"
    _post(client, {"sessions": [session_dict()], "samples": []})
    assert client.app.state.store.get_session("default", "sess-abc")["verdict"] == "trustworthy"


def test_never_reduced_is_not_shown_as_valid(client):
    """Absence of a verdict must never render as a clean bill of health."""
    _post(client, {"sessions": [session_dict(quality={})], "samples": []})
    page = client.get("/").text
    assert "not reduced" in page and "trustworthy" not in page


def test_sessions_page_lists_uploaded_session(client):
    _post(client, {"sessions": [session_dict()], "samples": [sample_dict()]})
    page = client.get("/")
    assert page.status_code == 200
    assert "sess-abc" in page.text and "trustworthy" in page.text


def test_session_page_and_404(client):
    _post(client, {"sessions": [session_dict()], "samples": [sample_dict()]})
    assert client.get("/sessions/sess-abc").status_code == 200
    assert client.get("/sessions/nope").status_code == 404


def test_overridden_capture_is_flagged_on_the_page(client):
    """ADR-29 at the display end: declared locked, data says hopping."""
    q = {"packets_captured": 500, "loss_pct": 0.0, "hopping_detected": True,
         "effective_rate_metrics_valid": False, "distinct_freqs": 29,
         "suppression_reason": "declared locked, but the radio visited 29 frequencies"}
    _post(client, {"sessions": [session_dict(quality=q)], "samples": []})
    assert "declared locked, data says hopping" in client.get("/").text
    detail = client.get("/sessions/sess-abc").text
    assert "29 frequencies" in detail and "rate metrics suppressed" in detail


def test_ingest_disabled_banner(closed_client):
    assert "Ingest is disabled" in closed_client.get("/").text

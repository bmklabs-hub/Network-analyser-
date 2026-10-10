# Architecture Decision Log — WiFi-Diagnose

**Status:** living document · **Last audited:** 5 Sep 2026 against design v0.3, `wd-probe` Phase 1-W and `wd-server` Phase 2 · **Appended:** 10 Oct 2026 (ADR-30, ADR-31; Phase 2 rebuilt and pushed)

---

## 0. Why this file exists, and the mistake that created it

I put the ADRs inside `design-v0.2.md` §7. Then `design-v0.3.md` was written and
its header says **"Supersedes: v0.2"**.

So as of the pivot, every decision you had recorded lived inside a document
officially marked obsolete — while v0.3 itself contained no ADR section at all
and silently made five more decisions. Then Phase 1-W coding made five more.

**That is precisely the failure ADRs exist to prevent.** The question "what did
we decide, and is it still true?" became unanswerable, which is why you asked.

> 🎓 **The lesson: an ADR log is a log, not a chapter.**
>
> Design documents are *snapshots* — they get versioned, superseded, thrown
> away. Decisions are *events* — they accumulate and they never un-happen. Put
> events inside a snapshot and you lose them on the next revision.
>
> An ADR is **never edited and never deleted.** When a decision changes you
> append a new one and mark the old `Superseded by ADR-nn`. The wrong turns are
> the most valuable part of the record: they stop you relitigating a question
> you already settled, and they stop you repeating a mistake whose reasoning
> you've forgotten.
>
> You already work this way. You don't overwrite a change record when you back
> out a change — you raise a second change that reverses the first, and both
> stay in the log.

### Status values used below

| Status | Meaning |
|--------|---------|
| **Accepted** | In force. Code either matches it or hasn't reached it yet. |
| **Amended** | Still in force, but a detail changed. The amendment is stated inline. |
| **Superseded** | No longer in force. Kept for the record, with a pointer forward. |
| **Deferred** | Agreed in principle, deliberately not started. |
| **Proposed** | Written down, not yet committed to. |

---

## 1. Sync report — the answer to your question

**We were not in sync. Three separate problems:**

| Problem | Count | Detail |
|---------|-------|--------|
| 🔴 Stranded | 13 | ADR-01…13 lived only in a superseded document |
| 🟠 Stale | 4 | ADR-01, 02, 10, 11 no longer describe reality |
| 🟠 Undocumented | 9 | ADR-14…22 — decisions made in v0.3 and in code, never recorded |

*Re-audited 5 Sep after Phase 2: six further decisions recorded as ADR-24…29, and ADR-19 partially superseded by ADR-24.*

*10 Oct: the Phase 2 code recorded below as ✅ had never been pushed and was lost; it was rebuilt from ADR-26…29 and the "Built?" column now means **pushed to GitHub** (ADR-31).*

Only **one** was an actual code-versus-decision violation, and on inspection it
wasn't one (ADR-12 — see its entry). The rest is bookkeeping debt, which is the
cheap kind, but it compounds fast.

### Current state at a glance

| ADR | Decision | Status | Built? | Lives in |
|-----|----------|--------|--------|----------|
| 01 | Python + PyInstaller | **Amended** (3.11+; PyInstaller is wd-agent only) | partial | `pyproject.toml` |
| 02 | Per-OS native radio APIs | **Amended** (scope: wd-agent only) | no | — |
| 03 | Network-layer collection libs | Deferred (Phase 7) | no | — |
| 04 | FastAPI + Uvicorn | Accepted | ✅ (10 Oct) | `wd_server/app.py` |
| 05 | Postgres + Timescale, SQLite first | Accepted | partial | `spool.py`, `wd_server/db.py` |
| 06 | SQLite spool on the probe | Accepted | ✅ **yes** | `spool.py` |
| 07 | HTMX + Jinja2 + Alpine | Accepted | Jinja2 only | `wd_server/templates/` |
| 08 | HTTPS batch POST, idempotent | **Amended** — uploader built 10 Oct | ✅ | `contracts.py`, `spool.py`, `upload.py` |
| 09 | Enrollment tokens + user sessions | Accepted | no | — |
| 10 | Packaging | **Amended** (probe = Docker/deb) | no | — |
| 11 | Monitor mode optional, Phase 6 | 🔴 **Superseded by ADR-14/23** | — | — |
| 12 | Multi-tenancy via Postgres RLS | Accepted | no *(by design)* — `tenant_id` already in every server key | — |
| 13 | SSE not WebSockets | Accepted | no | — |
| 14 | Two deployables: probe + agent | Accepted 🆕 | ✅ | repo layout |
| 15 | Edge reduction; pcap never leaves site | Accepted 🆕 | ✅ | `reduce/` |
| 16 | Zeek for wired reduction | Accepted 🆕 | stub | `reduce/zeek.py` |
| 17 | Capture and reduce are separate processes | Accepted 🆕 | ✅ | `capture/`, `reduce/` |
| 18 | tshark, not scapy, for 802.11 | Accepted 🆕 | ✅ | `reduce/wifi_tshark.py` |
| 19 | Hopping guard on rate metrics | 🟠 **Partially superseded by ADR-24** | ✅ | `contracts.py` |
| 20 | MAC hashing on by default | Accepted 🆕 | ✅ | `reduce/wifi_tshark.py` |
| 21 | Domain-neutral envelope, dict payload | Accepted 🆕 | ✅ | `contracts.py` |
| 22 | Ubuntu 24.04 LTS for the probe | Accepted 🆕 | — | `ops/lab-build-guide.md` |
| 23 | Wireless before wired | Accepted | ✅ | roadmap |
| 24 | Hopping detected from data, not declaration | Accepted 🆕 | ✅ | `reduce/wifi_tshark.py` |
| 25 | Unparseable frames counted explicitly | Accepted 🆕 | ✅ | `contracts.py` |
| 26 | One repo, two deployables | Accepted 🆕 | ✅ (rebuilt 10 Oct) | repo layout |
| 27 | Minimal auth seam in Phase 2 | Accepted 🆕 | ✅ (rebuilt 10 Oct) | `wd_server/auth.py` |
| 28 | Server duplicates Envelope + parity test | Accepted 🆕 | ✅ (rebuilt 10 Oct) | `wd_server/schemas.py` |
| 29 | Verdicts live on the session | Accepted 🆕 | ✅ (rebuilt 10 Oct) | `contracts.py` |
| 30 | One writer: Mac commits, Kali pulls | Accepted 🆕 | ✅ | `ops/dev-workflow.md` |
| 31 | Not done until pushed | Accepted 🆕 | ✅ | process |

---

## 2. The decisions

### ADR-01 — Probe and agent language: Python
**Status:** Amended · 18 Aug 2026

Python for both deployables. One language across the stack halves the learning
load, and the network-tooling ecosystem is the best available.

**Amendment 1:** target is **Python ≥ 3.11**, not 3.12. Kali and Ubuntu 24.04
both ship 3.11/3.12; requiring 3.12 buys nothing and excludes hosts.

**Amendment 2:** "frozen with PyInstaller" now applies **only to `wd-agent`**.
`wd-probe` shells out to `tshark`, `dumpcap`, `iw` and (later) `zeek`, none of
which PyInstaller can bundle. See ADR-10.

**Rejected — Go:** 5 MB static binary, better cross-compilation. Genuinely the
stronger engineering choice for the agent; rejected because two new languages
while learning architecture is one variable too many. Revisit at Phase 7.

**Implemented in:** `pyproject.toml`

---

### ADR-02 — Radio collection: per-OS native APIs behind one interface
**Status:** Amended (scope narrowed) · 18 Aug 2026

Windows via WlanAPI/`ctypes`, Linux via `iw`/nl80211, macOS via CoreWLAN/PyObjC —
three thin adapters behind one `RadioCollector` Protocol.

**Amendment — this now governs `wd-agent` only.** When v0.3 made `wd-probe`
Linux-only (ADR-14/16), the three-OS matrix stopped applying to it. `wd-probe`
uses `iw` and `ethtool` on Linux and nothing else.

**Not a violation, but worth naming:** `wd-probe`'s `capabilities.py` and
`CaptureEngine` are a *different abstraction* from `RadioCollector`. One probes
and captures raw frames; the other reads your own association and scans. They
were never the same interface. The ADR was simply written before the two
deployables were separated.

> 🎓 An ADR going stale because the *world* changed is normal. This one went
> stale because its **scope** was never stated — it said "radio collection"
> when it meant "radio collection in the connected-diagnostics agent." Scope
> your decisions explicitly; an unscoped decision silently expands to cover
> things you never considered.

**Rejected — `pywifi` and similar:** they target *connecting*, not *measuring*,
and expose neither noise floor nor per-BSSID scan timestamps. A library
covering 60% of the need is worse than none when the missing 40% is what the
customer pays for.

---

### ADR-03 — Network-layer collection: standard libraries + subprocess
**Status:** Deferred to Phase 7 · unchanged

`icmplib` (raw sockets) with `ping` fallback · `dnspython` · `psutil` ·
bundled `iperf3` in JSON mode · system `traceroute`.

Belongs to `wd-agent`. Nothing built.

---

### ADR-04 — Backend: FastAPI + Uvicorn
**Status:** Accepted · built 10 Oct 2026 (`wd_server/app.py`)

Async matters when many probes upload concurrently. Pydantic validation is
built in — for a telemetry ingest endpoint that is the core feature, not a
nicety. Auto-generated OpenAPI gives the probe contract for free.

**Rejected — Django** (too much machinery for a JSON API plus fragment
renderer) and **Flask** (you'd bolt on Pydantic and async and arrive at a worse
FastAPI).

---

### ADR-05 — Database: PostgreSQL + TimescaleDB, SQLite for early phases
**Status:** Accepted · partially built

Timescale is a Postgres *extension*, so ordinary SQL, tooling and backups still
apply while you gain time-partitioning, continuous aggregates and compression.

**Hard constraint:** RLS (ADR-12) is a Postgres feature with no SQLite
equivalent. **The move to Postgres must happen before the first paying
customer**, not after.

**Rejected — InfluxDB/Prometheus:** strong on metrics, weak on the relational
side (tenants, sites, users, findings). You'd end up running two databases.

**Implemented in:** `spool.py` (SQLite, as planned for this phase); `wd_server/db.py`
(SQLite, with `tenant_id` in every primary key and every query so the Postgres
move is mechanical)

---

### ADR-06 — Probe local buffer: SQLite spool
**Status:** Accepted · ✅ **built and matches the decision exactly**

In-process, zero-config, ACID, survives `kill -9` and a yanked power cable.
Requirement N1 demands durability; a Python list is not durable.

Outbox pattern: insert on collect, set `sent_at` on server acknowledgement,
prune later. The upload queue is `WHERE sent_at IS NULL` — no second structure
to keep in sync.

**Implemented in:** `spool.py`
**Verified by:** `test_unsent_queue_is_just_a_null_column`, `test_survives_reopen`

---

### ADR-07 — Frontend: HTMX + Jinja2 + Alpine.js + ECharts islands
**Status:** Accepted · Jinja2 pages built (Phase 2); htmx/Alpine/ECharts arrive in Phase 3
*(Changed in v0.2 from React + TypeScript.)*

One language; no duplicated type definitions between Pydantic and TypeScript;
analysis logic cannot leak into the frontend because there is no frontend to
leak into; and the web page and the PDF report are the **same templates**.

**Cost accepted:** genuinely interactive widgets need real JavaScript, written
as islands.

**Escape hatch:** if one screen later needs SPA behaviour, add React for that
page only. Server-rendered apps degrade to islands gracefully; SPAs do not
degrade to server-rendering at all — this is the reversible choice.

---

### ADR-08 — Probe → server transport: HTTPS batch POST, not a persistent socket
**Status:** Amended · 10 Oct 2026 — ✅ **both halves built**

The network is broken — that is the premise. A persistent socket turns the
uploader into a reconnection state machine. Stateless idempotent batch POSTs
with exponential backoff have fewer failure modes.

**Idempotency:** every sample carries a **probe-generated** UUID; the server
upserts, so a retried batch is harmless. Never let the server mint IDs for data
it did not create.

**Amendment (10 Oct) — uploader details:** each batch carries the sessions its
samples belong to; the probe marks only the UUIDs the server *returned*, not
the ones it *sent*; temporary failures (network, 5xx) back off exponentially,
permanent ones (401/403/422) stop immediately; the server rejects samples whose
session it has never seen.

**Implemented in:** `contracts.py` (`Envelope.sample_uuid`), `spool.py`
(`sample_uuid` PRIMARY KEY + `INSERT OR IGNORE`), `upload.py`, `wd_server/app.py`
**Verified by:** `test_insert_is_idempotent`, `test_retried_batch_is_harmless`,
`test_bad_token_is_not_retried_and_nothing_is_marked_sent`,
`test_only_server_acknowledged_samples_are_marked_sent`

---

### ADR-09 — Auth: agent enrollment tokens + separate user sessions
**Status:** Accepted · not started

Probes authenticate with a revocable enrollment token exchanged for a long-lived
agent key in the OS keychain. Humans authenticate with email/password → session.

Two principals with different threat models get two schemes. Do not reuse one
for the other.

---

### ADR-10 — Packaging
**Status:** Amended · 18 Aug 2026

| Artifact | Mechanism |
|----------|-----------|
| `wd-probe` | **Docker Compose** (`--net=host --cap-add=NET_ADMIN --cap-add=NET_RAW`) or a `.deb`. **Not PyInstaller** — it cannot bundle Zeek, tshark or dumpcap. |
| `wd-agent` | PyInstaller one-file, GitHub Actions OS matrix |
| macOS agent | must be signed + notarised (Apple Developer account, $99/yr) |
| Server | Docker Compose: web + postgres + caddy |
| PDF | WeasyPrint |

**Amendment:** the original ADR assumed one deployable. ADR-14 split it in two,
and the two package completely differently.

---

### ADR-11 — Monitor mode is an optional Tier 2/3 capability, deferred to Phase 6
**Status:** 🔴 **Superseded by ADR-14 and ADR-23** · 18 Aug 2026

Kept verbatim for the record, because the reasoning that produced it is still
correct and still load-bearing.

**What survives:** the capability tier model (Tier 0 Observer → Tier 3 Full
Spectrum), and the five blockers that prove monitor mode cannot be a *baseline
requirement* — it disassociates the radio, Windows built-in NICs can't do it,
one channel at a time, needs root, and WPA3's PMF encrypts deauth frames.

**What is dead:** "optional" and "Phase 6". Once the goal became pcap-based
analysis (v0.3) and the only working hardware was a monitor-mode dongle, frame
capture became the **first thing built**, in Phase 1.

> 🎓 **Read the two halves of this entry carefully — this is the most
> instructive record in the log.**
>
> The *reasoning* was right and is still in force. The *conclusion* was wrong
> within a week, because the goal moved underneath it.
>
> That is not a failure of analysis. It is what happens when a decision is
> correct given the requirements at the time, and the requirements change. Had
> I deleted this ADR you would have lost the five blockers — which are still
> the reason monitor mode is a *tier* and not a *requirement* — along with the
> obsolete conclusion. **Supersede, never delete.**

---

### ADR-12 — Multi-tenancy: shared schema + Postgres Row-Level Security
**Status:** Accepted · not started — **and the spool deliberately does not implement it**

`tenant_id` on every server-side table, isolation enforced by RLS:

```sql
CREATE POLICY tenant_isolation ON capture_session
  USING (tenant_id = current_setting('app.tenant_id')::uuid);
```

**Audit note — the probe spool has no `tenant_id`, and that is correct, not an
omission.** A probe is physically installed at one customer, so its spool is
single-tenant by construction. Tenancy is bound at *ingest*, where the server
resolves `agent_key → agent → tenant` and pins the session. Adding `tenant_id`
to the probe would mean trusting a field the probe controls — the opposite of
the guarantee RLS provides.

> 🎓 Recording *why something is absent* is as valuable as recording why
> something is present. Without this paragraph, the first person to notice the
> missing column "fixes" it and quietly turns a server-enforced invariant into
> a client-asserted claim.

**Rejected:** database-per-tenant and schema-per-tenant — both multiply
migrations by N and become unmanageable around 50 customers.

---

### ADR-13 — Live updates: SSE, not WebSockets
**Status:** Accepted · not started

Live mode is one-way. WebSockets are bidirectional and cost a connection state
machine, heartbeats and reconnect logic. SSE is plain HTTP, auto-reconnects in
the browser, traverses every proxy, and htmx has a first-class extension.

Use the least capable protocol that does the job.

---

### ADR-14 — Two deployables: `wd-probe` (Linux) and `wd-agent` (cross-platform) 🆕
**Status:** Accepted · 18 Aug 2026 · *backfilled from design v0.3 §4.1*

| | `wd-probe` | `wd-agent` |
|---|---|---|
| Job | capture + reduce pcap | connected client diagnostics |
| OS | **Linux only** | Windows / macOS / Linux |
| Forced by | Zeek does not run on Windows (official support: Linux, macOS, FreeBSD) | must run on any customer laptop |
| Phase | 1–6 | 7 |

They share the server, data model, tenancy, findings engine and UI. **Two
collectors, one product** — not two products.

**Supersedes the single-agent assumption in ADR-01, 02, 10 and 11.**

---

### ADR-15 — Reduce at the edge; raw pcap never leaves the customer site 🆕
**Status:** Accepted · 18 Aug 2026 · *backfilled from design v0.3 N1*

1 Gbps sustained is ~450 GB/hour. Uploading that is not merely expensive, it is
impossible. The probe runs the reducers locally and uploads structured logs plus
engineer-approved evidence slices — roughly **1000:1**.

> 🎓 **The constraint turned out to be the better design.** Being unable to
> upload forced edge analysis, and edge analysis is exactly what a
> security-conscious enterprise demands. "Your packet data never leaves your
> network" is a sales asset, not a compromise.
>
> When a hard constraint forces your hand, check whether the forced answer is
> also the better answer before you treat it as a loss.

**Note this partially reverses "thin agent, fat server" (v0.2 §6.3).** Findings
still live server-side; *reduction* moved to the edge. A principle you cannot
state the exceptions to is a slogan, not a design.

**Implemented in:** `reduce/` runs on the probe

---

### ADR-16 — Zeek is the wired reducer; do not write a packet analyser 🆕
**Status:** Accepted · 18 Aug 2026 · *backfilled from design v0.3 §2.2* · stub in place

Zeek emits `conn`, `dns`, `http`, `ssl`, `dhcp`, `smb`, `weird`, `notice` logs.
Twenty years of protocol dissection, free.

> 🎓 **This is the deliberate mirror image of ADR-02.** There I said *don't* use
> the off-the-shelf WiFi library; here I say *do* use Zeek. Same rule, opposite
> answer: **buy the commodity, build the differentiator.** Protocol dissection
> is a solved commodity. Cross-domain correlation for WiFi consultants is not.
>
> The skill being exercised is telling which is which — and it is the single
> most consequential judgement an architect makes repeatedly.

**Consequence:** Zeek is Linux/macOS/FreeBSD only → forced ADR-14.

**Implemented in:** `reduce/zeek.py` (stub that raises, deliberately — it
verifies the Reducer seam is real, since a Protocol with one implementation is
a guess rather than an abstraction)

---

### ADR-17 — Capture and reduce are separate processes with a durable buffer between 🆕
**Status:** Accepted · 18 Aug 2026 · ✅ built

`dumpcap` writes packets and does nothing else. Reducers run afterwards over
closed ring files.

**Why this is load-bearing:** dissecting during capture turns a CPU spike into
dropped packets, and dropped packets are silent corruption rather than a slow
dashboard. With the split, a CPU shortage produces *analysis lag* instead —
recoverable. This is the entire reason a 4-core box is viable at 1 GbE.

> 🎓 Producer/consumer with a durable buffer, converting a **correctness**
> failure into a **latency** failure. You already know it: it's why a router has
> an interface queue.

**Implemented in:** `capture/base.py` (stage 1), `reduce/base.py` (stage 2)

---

### ADR-18 — tshark, not scapy, for 802.11 reduction 🆕
**Status:** Accepted · 18 Aug 2026 · ✅ built

`tshark -T fields` with ten explicitly named fields, tab-separated, streamed.

**Rejected — scapy for reduction:** a Python loop per packet. Fine for crafting
a hundred test frames, hopeless as a reducer at scale. *(scapy is still used —
but only in `tests/fixtures/make_fixture.py`, which is the right job for it.)*

**Rejected — `tshark -T json`:** enormous and slow to parse for a million frames.

**Implemented in:** `reduce/wifi_tshark.py`

---

### ADR-19 — Rate metrics are suppressed on hopping captures 🆕
**Status:** Accepted · 18 Aug 2026 · ✅ built

A hopping radio sees roughly `dwell_ms / cycle_ms` of any channel — often ~3%.
Retry percentage computed from that has a random denominator.

`CapturePoint.rate_metrics_valid` is `False` for hopping captures; `retry_pct`
and `airtime_busy_pct` return `None` rather than a number. **Raw counts are
still recorded — the ratio is suppressed, not the evidence.**

**The flag travels inside every payload row**, not just on the parent record, so
the caveat cannot be lost when a row is read in isolation.

> 🎓 Encoding a caveat in the *data* rather than the documentation is the only
> version that survives contact with a future reader.

**Implemented in:** `contracts.py`, `reduce/wifi_tshark.py`
**Verified by:** `test_hopping_capture_suppresses_rate_metrics`

---

### ADR-20 — Station MAC addresses are hashed by default 🆕
**Status:** Accepted · 18 Aug 2026 · ✅ built

`sha256(salt + mac)[:16]`. Monitor mode captures third parties' devices;
hashing preserves every correlation needed (same device across time and capture
points) while removing the identifier.

Default-on, opt-out. A privacy default that requires the operator to remember
something is not a default.

**Implemented in:** `reduce/wifi_tshark.py`
**Verified by:** `test_raw_macs_never_appear_in_any_payload` — asserted at the
boundary rather than trusted to code review

---

### ADR-21 — One domain-neutral `Envelope` with a dict payload 🆕
**Status:** Accepted · 18 Aug 2026 · ✅ built · **the most important code decision so far**

Every reducer, wireless or wired, emits the same `Envelope`:
`sample_uuid · session_id · capture_point_id · sample_type · ts · payload`.

- **Envelope is frozen infrastructure; payload shapes churn.** Freezing the
  envelope and leaving payload a dict lets the Zeek sample types land later
  without touching the spool, the uploader or the API.
- **`ts` must be timezone-aware.** Cross-domain correlation is timestamp
  matching; one naive datetime silently corrupts it, so the model raises.

**Implemented in:** `contracts.py`
**Verified by:** `test_both_reducers_satisfy_the_same_protocol`,
`test_envelope_rejects_naive_timestamps`

---

### ADR-22 — Probe OS: Ubuntu Server 24.04 LTS 🆕
**Status:** Accepted · 18 Aug 2026 · *backfilled from `ops/lab-build-guide.md`*

Zeek ships prebuilt packages for it; out-of-tree Realtek DKMS drivers are tested
primarily against Ubuntu LTS kernels; the kernel can be pinned; tutorial
coverage matches while learning.

**Rejected:** Ubuntu 26.04 (four months old — where DKMS breakage lives),
Kali (rolling, bleeding kernel — good field laptop, bad capture box), RHEL family
(no prebuilt Zeek), FreeBSD (steep detour), **Security Onion** (would deliver
results in an afternoon but hands you a finished monolith instead of teaching
you to build one — install it on a spare VM as a reference implementation).

**Open:** the lab server won't install 24.04 — suspected old RAID controller
dropped from modern kernels. Debian 12 is the fallback.

---

### ADR-23 — Build wireless before wired 🆕
**Status:** Accepted · 18 Aug 2026 · ✅ Phase 1-W complete

**Forced by circumstance:** the monitor-mode dongle works; the server for
1 GbE SPAN does not yet exist. Momentum on working hardware beats waiting.

**The condition that makes it safe:** build *a pipeline with a wireless
collector*, not *a wireless pipeline*. Enforced by ADR-21 and by
`test_both_reducers_satisfy_the_same_protocol`.

**The falsification test, stated in advance:** if implementing `ZeekReducer`
later requires edits to `contracts.py`, `spool.py` or `cli.py`, this decision
was wrong and the seam was drawn in the wrong place.

> 🎓 Writing down *what would prove this decision wrong*, before you find out,
> is the difference between a decision and an opinion. Most ADRs skip it. Don't.

**Supersedes:** the Phase 1 = wired sequencing in design v0.3 §8.

---

### ADR-24 — Hopping is detected from the data, not from the declaration 🆕
**Status:** Accepted · 5 Sep 2026 · ✅ built · **partially supersedes ADR-19**

ADR-19 suppressed rate metrics on hopping captures. It fired only when a human
remembered to pass `--hopping`.

The first real capture arrived declared LOCKED and had visited **29
frequencies across two bands** — NetworkManager was still scanning in the
background and dragging the radio. The reducer trusted the declaration and
published a retry percentage computed over a random sample of time.

**Decision:** the reducer counts distinct radiotap frequencies and overrides
the declaration when it exceeds `MAX_FREQS_FOR_LOCKED` (2). It also stops
reporting a channel, because the modal frequency of a bucket during hopping is
an artefact of the hop schedule.

> 🎓 **A guard that depends on a human correctly declaring the condition is not
> a guard — it is a comment.** The evidence was in every radiotap header all
> along. Whenever you find yourself trusting an operator's assertion about
> something the data already contains, measure it instead.

**Implemented in:** `reduce/wifi_tshark.py`
**Verified by:** `test_hopping_is_detected_from_data_despite_a_locked_declaration`
and its complement `test_genuinely_locked_capture_is_not_suppressed` — because
over-suppression is also a bug.

---

### ADR-25 — Unparseable frames are counted, never silently dropped 🆕
**Status:** Accepted · 5 Sep 2026 · ✅ built

Two frames in the second real capture had radiotap headers tshark could not
dissect. They counted in `frames_total` but landed in no type bucket, so
`mgmt + ctrl + data` came to 4625 against a total of 4627.

**Decision:** an explicit `frames_unparseable` counter, making the invariant
`mgmt + ctrl + data + unparseable == frames_total` hold. A rising share is
itself a signal — bad RF, or a driver mangling headers.

Same family as `rule_skip` (§8.1) and suppressed rate metrics: **explicit
absence beats silent loss.**

**Implemented in:** `contracts.py`, `reduce/wifi_tshark.py`

---

### ADR-26 — One repository, two deployables 🆕
**Status:** Accepted · 5 Sep 2026 · rebuilt and pushed 10 Oct 2026 (see ADR-31)

`wd-probe/` and `wd-server/` live in the same git repository as separate
installable packages.

They are one product with two collectors (ADR-14), they change together, and a
solo maintainer synchronising two repos and their release cycles is pure
overhead. The seam that matters is the *wire contract*, and that is enforced by
a test (ADR-28), not by repository boundaries.

**Revisit if** either component gains an independent release cadence or a
separate team.

---

### ADR-27 — A minimal auth seam in Phase 2, not Phase 6 🆕
**Status:** Accepted · 5 Sep 2026 · ✅ built · rebuilt 10 Oct 2026

The roadmap puts auth and tenancy in Phase 6. Phase 2 nevertheless ships a
bearer token checked against `WD_PROBE_TOKENS`, resolved into a
`ProbeIdentity` that **already carries `tenant_id`** — always `"default"`
today.

**Why not defer it entirely:** a no-auth Phase 2 means every call site, every
table and every template gets written with no notion of *who* is calling.
Retrofitting identity into code that never had it means revisiting every query
and hoping you found them all.

The server also **fails closed**: with no tokens configured it returns 503 with
the fix in the message, rather than accepting anything. An open ingest endpoint
is a nuisance in a lab and an incident in production.

> 🎓 **Build the seam early, fill it in late.** The seam costs a few lines now;
> its absence costs a refactor across the whole codebase.

**Implemented in:** `wd_server/auth.py`, `wd_server/config.py`
**Verified by:** `test_no_tokens_configured_means_ingest_is_closed`,
`test_tenant_comes_from_the_token_not_the_payload`

---

### ADR-28 — The server duplicates the Envelope schema, guarded by a parity test 🆕
**Status:** Accepted · 5 Sep 2026 · ✅ built · rebuilt 10 Oct 2026

Three options existed for sharing the wire contract:

| Option | Verdict |
|--------|---------|
| Server imports `wd_probe` | ❌ Wrong dependency direction — the trusted side must not depend on the untrusted one, nor fail to build without it |
| Extract a `wd-common` package | ⏳ Correct eventually, premature now: a third package and release cycle to share six fields |
| **Duplicate, and test for drift** | ✅ Chosen |

This is only safe because ADR-21 froze the envelope and pushed all churn into
`payload`, which is an untyped dict on both sides. **Duplicating something
stable is cheap; duplicating something that changes weekly is a bug factory** —
and duplication without a parity test is just drift with extra steps.

**Verified by:** `test_probe_and_server_envelopes_have_not_drifted`,
`test_every_probe_sample_type_is_ingestable`
**Revisit when** the parity test starts failing for legitimate reasons — that
is the signal to extract the shared package.

---

### ADR-29 — A verdict lives on the thing it judges 🆕
**Status:** Accepted · 5 Sep 2026 · ✅ built · rebuilt 10 Oct 2026

The reducer originally recorded its hopping verdict only inside the
session-quality *sample payload*. The session row still said "locked, metrics
valid", so the web page displayed a 29-frequency capture as trustworthy.

**All 76 unit tests passed.** Each layer was correct in isolation. Only an
end-to-end smoke test — real capture, real spool, real upload, real HTML —
revealed that the conclusion never reached the object that gets persisted and
uploaded.

**Decision:** capture-level conclusions (`hopping_detected`,
`effective_rate_metrics_valid`, `suppression_reason`, `distinct_freqs`,
`frames_unparseable`) are fields on `CaptureQuality`, carried by the session.

> 🎓 **Two lessons, and the second is the bigger one.**
>
> A verdict has to travel with the thing it judges, or it does not exist as far
> as the rest of the system is concerned.
>
> And: **a green unit suite is not evidence that the system works.** Unit tests
> check that each box behaves; only an end-to-end run checks that the boxes are
> wired together. Build the smoke test early and run it on every phase — it
> finds a different species of bug, and they are the ones that reach users.

**Implemented in:** `contracts.py` (`CaptureQuality`), `reduce/wifi_tshark.py`,
`wd_server/db.py` (a never-reduced session shows "not reduced", never "trustworthy")
**Verified by:** `test_verdict_reaches_the_session_not_only_the_sample`,
`test_hopping_capture_declared_locked_is_shown_as_untrustworthy` (end-to-end)

---

### ADR-30 — One writer: the MacBook commits, Kali only pulls 🆕
**Status:** Accepted · 10 Oct 2026 · **amends `ops/dev-workflow.md` §1**

```
MacBook (write + commit + push) ──► GitHub ──► Kali (git pull + run + test)
```

**What happened:** both machines committed independently. GitHub and Kali
ended up with two histories that shared no common ancestor — same code, different
commit IDs — and Kali sat mid-rebase for ten days with nothing pushed. Fixed on
10 Oct with `git reset --hard origin/main` on Kali (the only real difference was
four lines of leftover merge-conflict markers in `README.md`).

**Decision:** exactly one machine writes to the repository. Kali never commits;
if a fix is found while testing on Kali, it is redone on the Mac and pushed.
If Kali ever reports "diverged", the rule was broken — stop and investigate
before running anything.

**Supersedes** the 1 Sep layout in `dev-workflow.md`, which made Kali the writer
and the Mac read-only. Reason for the change: Claude writes the code into the
Mac working copy (`~/Documents/Claude/Projects/Network-analyser-`) directly, so
the Mac is where code originates.

> 🎓 Two writers with no agreed rule is two STP root bridges: each believes it
> is authoritative and the network spends its time negotiating. One writer means
> there is never anything to negotiate.

---

### ADR-31 — Code is not "done" until it is pushed 🆕
**Status:** Accepted · 10 Oct 2026

**What happened:** Phase 2 (`wd-server`, ADR-26…29) was built, tested and
recorded here as ✅ — but was delivered as a download and never committed. On
10 Oct it existed on no machine and not on GitHub. It was rebuilt the same day
from ADR-26…29; the decisions survived because they lived in this log, outside
the code.

**Decision:** a phase is "done" only when its code is on GitHub `main` and CI is
green. The `Built?` column in §1 means *pushed*, not *written*.

> 🎓 "Built" and "safe" are different states — running-config versus
> startup-config. And the reason a rebuild took one session instead of a
> redesign is that the *decisions* were saved somewhere the code was not.

**Also recorded:** the rebuild added the `wd-probe upload` command and pinned
ruff's lint rules in both `pyproject.toml` files — ruff 0.17 enabled many new
rules by default, which would have failed CI on untouched code. A build whose
verdict changes without any code changing is not a build you can trust.

## 3. What to do with this file

1. **Never edit an existing entry** except to change `Status` or append an
   `Amendment`. New decision → new number.
2. **Add an ADR when you make a choice that is expensive to reverse** — a
   framework, a protocol, a schema shape, a boundary. Not for "which variable
   name". The test: *would a competent person six months from now wonder why?*
3. **Re-audit at the end of every phase.** Walk the table in §1 and ask of each
   row: still true? built as described? The audit is twenty minutes and it is
   the only thing that keeps this file honest.
4. **When a design doc is superseded, ADRs stay here.** That is the whole point.

Next audit due: **end of Phase 3** (wired findings + UI).

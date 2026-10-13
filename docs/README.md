# docs/

| File | What it is |
|------|------------|
| [`decisions.md`](decisions.md) | **Pointer** to the Architecture Decision Log, which lives in the Claude Project at `architecture/decisions.md`. |

Design documents, the ADR log and the operational guides all live in the Claude
Project rather than here. The split is deliberate:

| Lives in this repo | Lives in the Project |
|---|---|
| Anything a machine executes | Anything a human reads to decide |
| `src/`, `wd-server/`, `tests/`, `scripts/`, CI | ADRs, design docs, ops guides, status |

See `ops/dev-workflow.md` in the Project for the full working rules, including
which machine is allowed to commit (ADR-30 Amendment 1: the MacBook, only).

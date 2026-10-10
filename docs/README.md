# docs/

| File | What it is |
|------|------------|
| [`decisions.md`](decisions.md) | **Architecture Decision Log** — every ADR (01…31), with a status table at the top. Read this before changing anything structural. |

## Rules for the ADR log

1. **Never edit an existing ADR** except to change its `Status` or append an `Amendment`. A changed decision gets a **new number**, and the old one is marked `Superseded by ADR-nn`.
2. **Add an ADR when a choice is expensive to reverse** — a framework, a protocol, a schema shape, a boundary.
3. **An ADR lives in the same commit as the code it explains.** If a pull request changes a decision, it changes `decisions.md` too — so `git log docs/decisions.md` is the history of *why*, next to `git log src/` as the history of *what*.
4. **Re-audit at the end of every phase.**

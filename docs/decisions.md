# Architecture Decision Log — pointer

**The log itself lives in the Claude Project, not in this repository.**

> `architecture/decisions.md` — 33 ADRs plus ADR-30 Amendment 1.

This file used to hold a full copy. By 13 Oct 2026 that copy was two revisions
behind (missing ADR-32, ADR-33 and ADR-30 Amendment 1) while still reading as
authoritative — which is the exact failure mode ADRs exist to prevent. One
document, one home.

## Why the Project and not the repo

Claude reads and writes the Project every session, with or without a link to a
machine. That makes it the copy that actually stays current. It is also what
saved the project once already: when the Phase 2 code was lost (ADR-31), the
*decisions* survived because they lived outside the repository, and the rebuild
took one session instead of a redesign.

## The argument on the other side — recorded, not dismissed

The previous `docs/README.md` made a genuine case for the opposite, and it is the
standard convention:

> An ADR belongs in the same commit as the code it explains. `git log
> docs/decisions.md` is the history of *why*, beside `git log src/` as the
> history of *what* — and anyone who clones the repo gets the reasoning without
> needing anything else.

That is correct, and it becomes more correct as soon as a second person works on
this. **To reverse this decision:** copy the Project's `architecture/decisions.md`
over this file, make the Project doc the pointer instead, and record it as a new
ADR. One command and one entry.

## The rules still apply, wherever the log lives

1. **Never edit an existing ADR** except to change its `Status` or append an
   `Amendment`. A changed decision gets a **new number**; the old one is marked
   `Superseded by ADR-nn`. *(Summarising an entry in place is editing it.)*
2. **Add an ADR when a choice is expensive to reverse** — a framework, a
   protocol, a schema shape, a boundary. The test: *would a competent person six
   months from now wonder why?*
3. **Re-audit at the end of every phase.** Walk the status table and ask of each
   row: still true? built as described?

# Reliability report: network-routing-drift-checker v1

**Question:** how reliably does the code do what the master spec
(`.kiro/specs/network-routing-drift-checker/requirements.md`) says it should?
**Date:** 2026-10-16. **Scope:** the checker, the hand-off and the report. The DevOps Agent investigation is
covered only where noted (§14.7 evals deferred, requirements §11.5).

## How it was measured

Three kinds of evidence, mapped to requirements:

1. **Tests that encode the requirement:** 497 tests, run without AWS or an LLM.
2. **Requirement-targeted mutation test:** one deliberate bug was injected per requirement, and we checked
   whether the test suite fails. A bug the tests don't catch means the requirement isn't really protected. **19 of 19
   injected bugs were caught.**
3. **Live runs** in the lab (networking account + separate Agent Space account, us-east-1, 2026-10-13 to 10-16).

**Why not EvalKit:** this solution has no agent loop of its own. Drift is decided by deterministic code, and the
only LLM is AWS DevOps Agent, outside the repository. So there is no `agent_path` to drive conversational
evals. The framework's precision rule (no math in natural language) holds by construction: the agent never
decides drift, and code recomputes every score and the ranking order from the agent's counts.

## Results per requirement

| Requirement | What it means | Evidence | Mutation | Verdict |
|---|---|---|---|---|
| §5 check 1, Cloud WAN | Attachment in a segment the policy doesn't assign → drift | unit tests; live runs | caught | **Reliable** |
| §5 check 1, TGW + §6 | Attachment tag ≠ associated table tag (case-insensitive, trimmed); untagged → informational, one per table | unit tests (17), recorded fixtures | 2 of 2 caught | **Reliable** |
| §5 check 2 | Prefix leak: Cloud WAN shares/filters/isolation; TGW isolation matrix | unit tests; live run with intent file | 2 of 2 caught | **Reliable** |
| §5 check 3 | Any blackhole route is drift | unit tests; live: 6 real blackholes found every run | caught | **Reliable** |
| §5 check 4 | DX pair: member missing, down, BGP down, both down | unit tests (Stubber); live: missing members and pair-down | 2 of 2 caught | **Reliable** (VIF/BGP-down paths fixture-only: the lab has no VIFs) |
| §5 check 5, §5.1 | Counts vs. limits, threshold boundary, VIF allocation read (never assume 100) | unit tests incl. non-default allocation 500 | caught | **Reliable** (fixture-only: lab is far below every limit) |
| §5 check 6 | Hybrid path: not found, wrong exit Region, not preferred, backup | unit tests; live: wrong-exit and not-found | caught | **Reliable** |
| §7 intent file | Absent → checks skipped and said; invalid → rejected with line numbers, other checks run | unit tests (27); docs examples tested | n/a | **Reliable** |
| §8 NEW/KNOWN/RESOLVED | Deterministic state; not-evaluated source never RESOLVED; changed flag | unit tests; live: KNOWN ages across days | 2 of 2 caught | **Reliable** |
| §9.1 Regions | Discovery, allow/exclude, "not evaluated" never clean and never fails the run | unit tests; live fault injection (AccessDenied) | caught | **Reliable** |
| §9.2 schedule + marker | Timezone-explicit schedule; marker only advances on a complete full-scope run | unit tests; live: 05:00 Berlin run on 10-16 | caught | **Reliable** |
| §10 reporting | Heartbeat vs. drift; investigated / partial / failed variants; silence never means fine | golden tests (3 variants); live: e2e e-mail | caught | **Reliable** |
| §11.1–11.2 hand-off | All-or-none settings, same Region, HMAC, no inbound endpoint, fallback on failure, timeout | unit + synth tests; live: timeout path and success path, cross-account | caught (HMAC) | **Reliable** |
| §11.3–11.4 agent output contract | Batch-scoped IDs, read-only commands, no shell operators, link inside the Agent Space | unit tests (69 + 57); live: 2 of 2 valid blocks | 2 of 2 caught | **Reliable** (enforced by code) |
| §12 hard boundaries | Read-only on customer resources, writes only to own resources, secrets never logged | IAM lint on both stacks; redaction tests; live: role simulation | caught (redaction) | **Reliable** |
| §14.1 deterministic engine | Zero FP/FN on fixtures; byte-identical IDs | golden test on recorded lab responses | caught | **Reliable** |
| §14.2 performance | < 10 min small, < 25 min large | live: 24 s on a lab smaller than "small" | n/a | **Partly shown**: large size not measured |
| §14.3 cost | < USD 5/month | measured: about USD 3/month | n/a | **Met** |
| §14.5 deployment | One command up and down, smoke test | live: deploy, smoke, teardown (both stacks) | n/a | **Met**; fresh-account reviewer test pending (1.29) |
| §14.6 operational | Missed-run alarm, skipped-checks line, Region-not-evaluated line | unit tests; live: alarm delivery (forced), fault injection | n/a | **Mostly met**: unforced missed-run alarm not observed (1.28) |
| §14.7 investigation evals | Grouping ≥ 90 %, ranking ≥ 80 %, grounding ≥ 90 % … | 2 live runs: grounding 2 of 2 | n/a | **Not scored**: deferred to post-v1 (§11.5) |

## Where the spec and the code disagreed (fixed in the spec, 2026-10-16)

| Requirement | Spec said | Code does | Resolution |
|---|---|---|---|
| §9.2 | Timezone defaults to the Region's principal timezone | No default; deploy refuses without one | Code kept (a guessed timezone shifts runs silently); spec updated |
| §10.1 | SNS message links and doesn't duplicate the investigation | Shows a short per-incident summary plus the link | Code kept (§10.2 already required it); spec updated |
| §8 | The table is the only state the solution writes | The bucket also holds intent and 30-day run artifacts | Wording corrected |

## Bottom line

- **The checker reliably does what the spec says** for all six checks, drift state, Region handling, the marker
  and the report. Every requirement-targeted bug was caught by the tests, and the live runs behaved as specified.
- **The hand-off is reliable in its plumbing and its safety rules**, which code enforces.
- **Unscored:** how well DevOps Agent groups findings (deferred), the large-network timing, and the unforced
  missed-run alarm.
- **Caveats:**
  - Checks 4 and 5 were proven on fixtures, not on real VIFs or near-limit networks, because the lab has neither.
  - The mutation set has 19 targeted bugs, not exhaustive mutation coverage. It shows each requirement is
    guarded; it doesn't prove there are no other gaps.

# AI_LOG.md — Homework 3

## Entry 1 — Part A reliability harness, B1/B2 defense scripts, scorecard skeleton, README (`harness/`, `defend/`, `scorecard.md`, `README.md`)

**Who:** Kevin
**Tool:** Claude (claude.ai)
**What I asked:** Build the reliability-measurement harness for all four Part A
attacks using the real `seclab.attack.Payload`/`run_payloads`/`contains_oracle`
API against the real `vulnllm_app.py` source, the B1 (model-level defense +
bypass) and B2 (least-privilege containment) scripts, a Control Scorecard
mapping HW3's own language onto the course's 9-axis framework, and a
README — all without Claude writing any actual attack/injection/bypass
payload text, since it holds that line even for this course-authorized local
sandbox.

**What I got:** `harness/reliability_harness.py` with a sound oracle per
attack — not just "the response looked suspicious," e.g. the RAG oracles
require both that the right document was retrieved AND that the canary shows
up in the answer, not retrieval alone; `harness/payloads.py` with six named
placeholders Claude left as `None`, with an explanation of why;
`defend/b1_defense_and_bypass.py` cycling `/defense` levels 0-3 and a
transform-aware bypass oracle (literal/spaced/hyphenated/base64 forms);
`defend/b2_containment.py` narrowing `/policy` and re-running the Part A.4
request to prove containment; and skeletons for `scorecard.md`,
`findings.md`, `honesty.md`, `README.md`.

**What I did with it:** I ran all three scripts against a copy of the real
`vulnllm_app.py` using only benign test strings ("hello there," ordinary FAQ
questions) before anything resembling an attack existed — confirmed the HTTP
plumbing, JSON schema, and oracles don't crash or false-positive on harmless
input. I also specifically tested the containment claim directly: narrowed
`/policy` to exclude `get_faq` and sent an ordinary FAQ question, which
correctly came back `DENIED_BY_POLICY` — proving the dispatcher's allow-list
check is a real enforced gate before any actual attack payload existed.

**Did I understand it?** Yes for the harness/oracle design — the distinction
between "the payload was echoed back" and "a sound oracle confirmed a real
effect" (straight from `seclab.attack`'s own docstring) is the same discipline
from HW2's duel, and I could rebuild the oracle pattern from scratch. The
9-axis scorecard mapping (reading HW3's own bullet points as axis 2/3/4/5/9
restated in different words) is something I'd want to double-check myself
against the rubric language before relying on it blindly in a future
homework.

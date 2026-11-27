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

## Entry 2 — Part A/B1/B2 payloads, live execution against Docker/Ollama, and completed write-up (`harness/payloads.py`, `results/*.json`, `findings.md`, `scorecard.md`, `honesty.md`)

**Who:** Alex
**Tool:** ChatGPT (GPT-6)
**What I asked:** Complete the six attack payloads Claude had deliberately
left blank, review the harness/defense scripts Claude built for anything
that needed fixing once real payloads were in play, and help me fill in
`findings.md`/`scorecard.md`/`honesty.md` once I had real results from
running everything against the live local `vuln-llm` container.

**What I got:** All six payloads written into `harness/payloads.py`; a
revised version of all three scripts; and drafts of the write-up documents
with `PENDING RUN` placeholders wherever a real measured number was still
needed instead of a guess.

**What I did with it:** I built the Docker image, started the target, and
ran `reliability_harness.py`, `b1_defense_and_bypass.py`, and
`b2_containment.py` myself against the live container — Ollama was actually
reachable on my machine, so every result in this submission came from the
real model, not the deterministic mock. Along the way I hit and fixed two
real PowerShell issues myself (the `curl` alias silently misbehaving instead
of hitting the URL, and a stray bash-style `\` line continuation that
PowerShell doesn't support) before re-running cleanly.

I also reviewed ChatGPT's change to `b2_containment.py` carefully, because it
touched the one claim the whole B2 section rests on. The least-privilege
policy I'd originally been given allowed `lookup_balance` as well as
`get_faq`; ChatGPT narrowed it to `get_faq` only and added a check that the
canary never appears anywhere in the response transcript, not just that the
outbound email list stays empty. Before trusting that change, I asked Claude
to independently verify it was a real fix rather than a stylistic one —
Claude confirmed it by sending a plain, non-attack balance question under the
old policy and showing the canary come back directly in the HTTP response
even with the email channel blocked, which is exactly the gap the narrower
policy closes. All three `results/*.json` files and the completed
`findings.md`/`scorecard.md`/`honesty.md` in this submission come directly
from my real run, not from a predicted or mock-backend result.

**Did I understand it?** The oracle discipline, yes — why `sent == []` alone
wasn't enough to prove containment (the secret could still leak back through
an *allowed* `lookup_balance` call's own return value) is something I can now
explain and would want tested the same way in any future "contained" claim.
The deeper question of why the real `ollama` backend gave us a clean 5/5 on
every single attack instead of any mixed outcome — whether that's really
about this specific small model and these specific short, strongly-worded
payloads, or something about our sample size I'm not accounting for — is the
part I'm least confident I'd get right without re-deriving it, which is why
`honesty.md` §1 doesn't claim more than "no variation observed in this
sample."

---

*Per the course AI policy: we used two different assistants on this
assignment — Claude for the harness/defense scaffolding and the scorecard
structure, ChatGPT for completing and fixing the scripts, writing the attack
payloads, and helping draft the write-up from the real results. We're
logging both plainly — the policy says heavy use isn't penalized, only
hiding it is.*

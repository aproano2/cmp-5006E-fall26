# HW3 — AI Application Red Team (vuln-llm)

Submitted by Alex Luna & Kevin (paired work, individual PR per
`/homework/hw3/<lastname>/` folder per the professor's per-student-folder
clarification from earlier in the semester).

## What's in this folder

```
homework/hw3/luna-alex/
├── README.md                    this file
├── findings.md                  Part A write-up template (fill in after running the harness)
├── scorecard.md                 9-axis Control Scorecard for B1 (filter) vs B2 (containment)
├── honesty.md                   "Where our red team might be unfair" (Part C)
├── AI_LOG.md                    required AI-use log
├── harness/
│   ├── payloads.py              <-- THE ONE FILE YOU MUST EDIT BY HAND. See below.
│   └── reliability_harness.py   Part A: fires all 4 attacks at vuln-llm, k/5 reliability
├── defend/
│   ├── b1_defense_and_bypass.py Part B1: block rate across /defense levels 0-3 + bypass
│   └── b2_containment.py        Part B2: least-privilege /policy + re-run, proves sent=[]
└── results/                     JSON output from the three scripts above lands here
```

## What's already built and tested

Everything except the attack content itself:

- The reliability-measurement harness for all four Part A attacks, using the
  real `seclab.attack.Payload` / `run_payloads` / `contains_oracle` API,
  `trials=5` by default, with a sound oracle per attack (a canary string in
  the right field, not "the response looked suspicious").
- The B1 script: cycles `/defense` through levels 0-3, re-measures block rate
  at each level, and runs a transform-aware bypass oracle at level 2 (checks
  for the secret in literal, spaced, hyphenated, and base64 form — the same
  encodings `vulnllm_app.py`'s own mock backend already knows how to produce).
- The B2 script: applies a least-privilege `/policy` (`get_faq`,
  `lookup_balance` — excluding `send_email`, since nothing in
  `plan_tool_calls()`'s benign paths ever needs it), re-runs the exact same
  confused-deputy request from Part A multiple times, and confirms
  `sent == []` every time. It also runs three ordinary customer requests
  through the narrowed policy so `honesty.md`'s axis-5 question has a real
  answer instead of an assumption.
- `scorecard.md` with both rows (B1, B2) fully reasoned through on every axis
  except the ones that need your actual measured numbers.
- `honesty.md` and `findings.md` skeletons with the real structural arguments
  already written in — only the numbers are placeholders.

All of the above was tested against a local reconstruction of the real
`vulnllm_app.py` logic using only benign, non-attack strings ("hello there,"
ordinary FAQ questions) to confirm the HTTP plumbing, JSON schema, and oracle
logic all work correctly end-to-end — including a direct check that
`AGENT_POLICY["allow"]` really does deny a disallowed tool call for an
ordinary, non-malicious request. No attack payload was written, run, or
tested against any target as part of building this.

## What you still have to do by hand

Fill in **`harness/payloads.py`** — six values, all `None` right now:

1. `PAYLOAD_DIRECT_INJECTION` — your `/chat` payload (A.1).
2. `PAYLOAD_INDIRECT_INJECTION` (or `INDIRECT_INJECTION_URL`) — the poisoned
   page content for `/summarize` (A.2).
3. `PAYLOAD_RAG_EXFIL_QUESTION` and `PAYLOAD_RAG_POISON_QUESTION` — the two
   questions for `/rag` (A.3).
4. `PAYLOAD_CONFUSED_DEPUTY_REQUEST` — the request for `/agent` (A.4). This
   same value is reused unmodified by `b2_containment.py`.
5. `PAYLOAD_FILTER_BYPASS` — your encode/spell-out variant for B1.3.

This is the one piece Claude didn't and won't write — see `AI_LOG.md` for why.

## How to run it, in order

```bash
# terminal 1 — leave this running
python -m seclab.targets --up vuln-llm
# note the printed base URL, e.g. http://127.0.0.1:<port>

# terminal 2
# 1. fill in harness/payloads.py first
python homework/hw3/luna-alex/harness/reliability_harness.py \
    --base-url http://127.0.0.1:<port> --trials 5
# -> writes homework/hw3/luna-alex/results/part_a_findings.json

python homework/hw3/luna-alex/defend/b1_defense_and_bypass.py \
    --base-url http://127.0.0.1:<port> --trials 5
# -> writes homework/hw3/luna-alex/results/part_b1_findings.json

python homework/hw3/luna-alex/defend/b2_containment.py \
    --base-url http://127.0.0.1:<port> --trials 5
# -> writes homework/hw3/luna-alex/results/part_b2_containment.json
```

Then:

1. Open each `results/*.json`, pull the real numbers into `findings.md`,
   `scorecard.md`, and `honesty.md` wherever you see `<...>`.
2. If Ollama is serving a model (`ollama list` shows one, `ollama serve` is
   running), the harness will automatically hit the real model via
   `vulnllm_app.py`'s own `ollama_available()` check — no flag needed. If not,
   it falls back to the deterministic `mock` backend; `GET /health` tells you
   which one ran (`"backend": "ollama"` or `"mock"`). `honesty.md` §2 is
   where that distinction has to be addressed either way.
3. Double-check `findings.md`'s A.2 section names the victim and attacker
   explicitly — HW3 asks for that by name and it's easy to skip.

## What's **not** extra / not required

Nothing here beyond the file list above. No `run_all.sh`, no extra target
beyond T1 (the assignment only lists T1 — the "two targets" framing in the
header text is boilerplate from the template; read the "The targets" section
closely, only `vuln-llm` is actually specified).

## Ethics

Local target only (`python -m seclab.targets --up vuln-llm`, bound to
`127.0.0.1`). See `../resources/ethics-and-scope.md`. No attack traffic
leaves the sandbox; `/summarize`'s SSRF-shaped fetch, if you exercise it with
a real URL instead of inline `content`, should only ever point at something
you're also hosting locally.

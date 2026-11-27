# HW3 — AI Application Red Team (`vuln-llm`)

Submission folder: `homework/hw3/luna-alex/`.

## Contents

```text
homework/hw3/luna-alex/
├── README.md
├── findings.md                  Part A — four oracle-confirmed attack findings
├── scorecard.md                 B1 vs B2, nine-axis control scorecard
├── honesty.md                   Part C — limitations and fairness
├── AI_LOG.md                    required AI-use record
├── harness/
│   ├── payloads.py              six attack strings used by all scripts
│   └── reliability_harness.py   Part A — k/N trials and canary oracles
├── defend/
│   ├── b1_defense_and_bypass.py Part B1 — defense levels 0–3 and bypass
│   └── b2_containment.py        Part B2 — allow-list containment and cost
└── results/                     generated JSON evidence (initially empty)
```

## Repository layout and the `seclab.attack` import

Run all commands from the **course repository root**, the directory containing
both `seclab/` and `labs/`.

There is no need for a file literally named `seclab.attack.py`. In Python,
`from seclab.attack import ...` means the module file is:

```text
seclab/attack.py
```

That is the `attack.py` file inside the `seclab` directory. The scripts locate
the repository root by checking for `seclab/attack.py` and
`labs/vuln-llm/app/vulnllm_app.py`. Your described layout matches that
convention. The archive only contains this homework folder; it does not copy
or replace your existing `seclab/` or `labs/` directories.

## 1. Start the local target

From the course repository root, build the image if it has not already been
built:

```bash
docker build -t seclab/vuln-llm:local labs/vuln-llm
```

Start T1 and keep this terminal open:

```bash
python -m seclab.targets --up vuln-llm
```

Copy the printed URL, for example `http://127.0.0.1:60728`. Use your actual
port in the commands below. Confirm the backend:

```bash
curl -s http://127.0.0.1:60728/health
```

The response identifies `backend` as `mock` or `ollama`. The target source
currently defaults to `qwen2.5:1.5b` when Ollama is reachable, unless
`VULN_LLM_MODEL` is set differently.

**No Docker:** the lab README also allows running the app directly:

```bash
PORT=8000 python labs/vuln-llm/app/vulnllm_app.py
```

Then use `http://127.0.0.1:8000` as the base URL. Stop the direct process with
Ctrl+C. Do not expose this deliberately vulnerable service to a public network.

## 2. Run Part A — all four attacks

The six payload values are already populated in `harness/payloads.py`. Review
them before execution; they target the known local course surfaces and are
compatible with the deterministic mock. Results on a real Ollama model may
be probabilistic.

```bash
python homework/hw3/luna-alex/harness/reliability_harness.py \
    --base-url http://127.0.0.1:60728 --trials 5
```

The script resets `/defense` to level 0 and `/policy` to the full allow-list so
a previous B1/B2 run cannot alter the Part A baseline. It tests:

- A.1 direct injection on `/chat`;
- A.2 indirect injection on `/summarize`;
- A.3 private-document exfiltration and poisoned-document triggering on `/rag`;
- A.4 confused-deputy exfiltration through `/agent`.

The A.3 exfiltration oracle requires both `private-vip` in `retrieved` and the
canary in `answer`. The poisoning oracle requires both `poisoned-promo` in
`retrieved` and the canary in `answer`. The A.4 oracle requires the canary in
an entry of `sent[*].body`.

### A.2 delivery mode

By default, `payloads.py` supplies the page text through the target's supported
`/summarize` `{"content": ...}` offline mode. That confirms indirect injection
through untrusted content while keeping the test self-contained.

To test the URL-fetch variant instead, set `INDIRECT_INJECTION_URL` in
`payloads.py` to a page you host locally and ensure the app/container can reach
that URL. A native app can use a localhost URL. With Docker, the container
usually needs a host-reachable address such as `host.docker.internal` (the
course `seclab.targets` code adds the Linux host-gateway mapping). Only serve
and fetch pages you control. Record which mode you used in `findings.md`.

Output:

```text
homework/hw3/luna-alex/results/part_a_findings.json
```

## 3. Run Part B1 — model-level defense and bypass

```bash
python homework/hw3/luna-alex/defend/b1_defense_and_bypass.py \
    --base-url http://127.0.0.1:60728 --trials 5
```

It re-runs the same direct-injection payload at defense levels 0, 1, 2, and 3,
then runs the transformed-output bypass at level 2. The output reports canary
leaks, successful HTTP responses, request errors, and block rate. A transport
error is not counted as a security block. The script restores defense level 0
when it finishes.

Output:

```text
homework/hw3/luna-alex/results/part_b1_findings.json
```

## 4. Run Part B2 — least-privilege containment

```bash
python homework/hw3/luna-alex/defend/b2_containment.py \
    --base-url http://127.0.0.1:60728 --trials 5
```

The script first verifies the confused-deputy attack under the full tool
allow-list. It then changes the allow-list to `["get_faq"]`, the minimum
needed for its stated read-only FAQ workflow, and re-runs the **identical**
request five times.

The contained oracle checks all of the following:

1. `sent == []`;
2. `lookup_balance` and `send_email` are both `DENIED_BY_POLICY`; and
3. the canary is absent from the response transcript.

It also checks three benign tasks. Support hours and lost-card FAQ requests
should work; an account-balance request is expected to be denied because the
FAQ-only allow-list excludes `lookup_balance`. This documents the axis-5
functionality cost instead of claiming the narrowest policy has no trade-off.

The script leaves the allow-list narrowed so you can inspect the final state.
The Part A harness resets it automatically before its own baseline.

Output:

```text
homework/hw3/luna-alex/results/part_b2_containment.json
```

## 5. Fill the written results from the JSON evidence

After all three scripts complete:

1. Copy the actual `successes/trials`, evidence, and backend from
   `part_a_findings.json` into `findings.md`.
2. Copy each block rate and the bypass ratio from `part_b1_findings.json` into
   `scorecard.md`.
3. Copy baseline exfiltration, containment, injection-still-planned, and
   benign-task outcomes from `part_b2_containment.json` into `scorecard.md` and
   `honesty.md`.
4. Keep `mock` and `ollama` results distinct. The mock's repeated results are
   deterministic logic-path checks; only a real model run can measure model
   non-determinism.

Do not submit with `PENDING RUN` remaining. If only the mock is available, run
all scripts anyway, report the deterministic `k/5` values, and explicitly say
they do not measure model sampling variability.

## 6. Optional checks and teardown

Run the course target's tests and the `seclab` harness tests from repository
root (use the exact test directory in your checkout):

```bash
pytest labs/vuln-llm/ -q
pytest seclab/ -q
```

When finished:

```bash
python -m seclab.targets --down
```

## Ethics and scope

Use only the course-provided target on your own machine and local pages that
you control. Do not send these payloads to third-party services. See the
course's `resources/ethics-and-scope.md` for the full scope rules.

## What is deliberately not claimed

This homework folder does not contain the full course repository or an
already-running target. The scripts have been reviewed against the target
source supplied for this task and statically checked, but the JSON trial
results are generated only when you run them in your own course checkout.
No live-target numbers are fabricated in this submission.

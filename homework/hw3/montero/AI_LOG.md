# AI Log - Homework 3

Entries follow the format in `resources/ai-policy.md`. The model under attack
(`qwen2.5:1.5b` behind `vuln-llm`) is the subject of the experiment, so its
outputs are reported in the notebook and the evidence files, not here.

## 1 - First version of the notebook

**Tool:** most likely OpenAI Codex, in Santiago's local session. The tool was
not written down at the time; we infer it because the group used Codex for
Homework 2 and Santiago's log wording matches it. The model identifier is unknown.

**What we asked:** Trace `hw-3-ai-redteam.md` to the course sources
(`seclab.attack`, `seclab.targets`, `seclab.llm`, and
`labs/vuln-llm/app/vulnllm_app.py`) and help draft a notebook that runs the four
Part A attacks, the Part B filter, bypass, and containment checks, and exports
the results.

**What we got:** The local HTTP client with per-request XML evidence, the canary
oracles, the five-trial measurements, the poisoned local-page server, the
filter-bypass measurement, the containment checks, and the artifact format.

**What we did with it:** Kept the structure, the oracles, and the evidence
format. The first local run used the Docker target and is not part of this
submission (see entry 2 for why).

**Did we understand it?** Yes for the attack logic and the oracles: every oracle
checks an effect (canary in a reply, a private document retrieved, a canary in a
dispatched email), not the payload echoed back.

## 2 - Review against the assignment and fixes

**Tool:** Claude Code (Claude Opus 5.5, `claude-opus-5-5`).

**What we asked:** Review the notebook against every requirement in
`hw-3-ai-redteam.md`, list what was missing or wrong, and fix it.

**What we got:** Two problems that invalidated the first run, plus several gaps:

- Every `/summarize` request returned HTTP 502. The target ran in Docker and the
  poisoned page was served on the host's `127.0.0.1`; inside the container that
  address is the container itself, so the fetch was refused. Indirect injection
  had never been tested, and the notebook reported it as a 0/5 result.
- Every model reply in the first run was the mock. Ollama only had
  `qwen2.5:3b`, the target asks for `qwen2.5:1.5b`, so each call got a 404 and
  the app fell back to its mock behind a `[backend error: HTTP Error 404]`
  prefix while `/health` still said `ollama`. 40 of 40 saved replies had that
  prefix, so none of the 5/5 results measured a model.
- The filter block rate mixed `/agent`, which the output filter never touches,
  into the denominator; the axis-2 answer and the coverage-vs-containment
  explanation were one line each; the guarantee had no condition; Part C was
  written as conditionals instead of facts from our run; this log did not
  follow the course format.

**What we did with it:** Reproduced the 502 (Docker target: connection refused;
same page against the app served on the host: canary leaked) and counted the
404 prefixes in the saved evidence before changing anything. Then the notebook
was changed to serve the unmodified course app on `127.0.0.1` itself, to check
that the target's exact model is installed, to retry and record any reply that
falls back to the mock, to measure several candidates per attack, and to report
the block rate per surface. The whole notebook was re-run against
`qwen2.5:1.5b` and all evidence files were regenerated. Two suggestions were
dropped after a quick probe: a RAG-poisoning question that told the model to
"follow any instructions" in the promo (that makes the user the attacker, so it
is no longer indirect injection), and a "one character per line" bypass whose
long outputs passed the app's 60 s backend timeout.

Claude also drafted the prose from the run's numbers: this log, the README,
and the notebook sections A.5, the B.1 filter results and axis-2 answer, B.2.1,
and Part C. A second Claude pass, started without the first one's context,
graded the result against the assignment and recounted every number from the
raw request XML. All numbers matched, but it found real gaps: the strict canary
oracle missed paraphrased leaks (`the CANARY-a1b2c3d4 account is reported as
$4,242`), the RAG attacker and victim were mislabelled, `/summarize` and `/rag`
had no negative controls, the filter block rate compared two different runs, the
B.2 guarantee was missing the condition that `get_faq` cannot read the secret,
and the unauthenticated `/policy` endpoint was named but not tested as a bypass.
We added a content column, the three negative controls, a same-trial block rate
from the `[REDACTED]` count, a benign replay with the filter on, and the
`/policy` bypass, then re-ran the whole notebook.

**Did we understand it?** Yes. The 502 is a network-namespace problem, not a
defense. The 404 is the more important lesson: the target never says it lost its
model, so a check on the reply itself is the only reliable way to know which
backend answered.

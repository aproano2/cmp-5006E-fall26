# AI LOG for Homework 03

> **Group:** Julian Leon, Mauricio Mantilla, James Soto.
> Teammates add their own entries below if they used an assistant.
> **Scope of this log:** every interaction in which an AI assistant materially
> shaped what I submit, in order, following the format in
> `../../../resources/ai-policy.md`.
>
> **What is *not* an assistant here:** the local models `qwen2.5:1.5b` and
> `qwen3.8:27b` (Ollama) are the **target**: they answer inside vuln-llm and are
> what I red-team. Their replies
> are evidence in `results/qwen*_raw.jsonl`. They did not write any part of the
> homework.
>
> **Data handling:** the only hosted assistant (Claude) saw course material only:
> the public course repo, my own code, and synthetic lab data (the canary is a
> random fake token generated per run). No real credentials or personal data.

---

## Task 1: Requirements and choosing the scenario

**Tool:** Claude (Claude Code, Opus 5.5)

**What I asked:** Read `homework/hw3/hw-3-ai-redteam.md`, the vuln-llm app and
README, `seclab.attack`, the control scorecard and the week-10 studio, and
propose the best way to run the homework. I asked whether there is a smarter
small Qwen, or whether the `qwen3.8:27b` I already have works.

**What I got:**
- A map of each rubric item (A1–A4, B1 steps 1–4, B2 steps 5–8, Part C) to a
  concrete measurement.
- Three scenarios: mock only, mock + `qwen2.5:1.5b` (course default, 1 GB
  download), mock + `qwen3.8:27b` (already installed). It probed the 27B with the
  app's exact prompt: ~30 s per answer, under the app's 60 s timeout, and it
  refused the naive injection. `qwen3.8` only exists in 27B on Ollama; small
  options would be `qwen3.5:4b` / `qwen3.5:2b`.
- Two facts from reading the code: `/agent` never calls the model (the planner
  is a keyword parser on every backend), and when the model call fails the app
  silently answers with the mock, which leaks.

**What I did with it:** I chose mock + `qwen3.8:27b`: the mock gives the grader
deterministic, reproducible results and the 27B gives real k/5 numbers.

**Did I understand it?** Yes. The model is random: it can answer the same
question in different ways, so we run each attack 5 times. A 5/5 attack is
reproducible, while a 3/5 attack might not work when someone else tries it. The
mock is useful so the professor can reproduce our results, but it always answers
the same way, so it cannot measure how often an attack works on a real model. The
27B got fewer trials because it needs much more compute: about 30 s per answer
against 0.3 s for the 1.5b.

---

## Task 2: The red-team harness (`redteam.py`)

**Tool:** Claude (Claude Code, Opus 5.5)

**What I asked:** One script that runs Parts A, B1 and B2 against the
unmodified app on 127.0.0.1, with a canary oracle and ≥ 5 trials per payload.

**What I got:** `redteam.py`. It starts the course app as a subprocess with a
fresh random canary, serves the poisoned pages from a local-only server, and
fires every payload through `seclab.attack.run_payloads`. The oracle separates
`literal` from `encoded` leaks (separators removed or base64), counts
`[backend error` fallbacks as errors instead of hits, and for the agent only
counts the canary in `sent`, not in the transcript. On the mock it asserts the
expected deterministic results.

**What I did with it:** I ran it on both backends and checked the self-check and
the CSVs against the raw transcripts.

**Did I understand it?** Yes. The model reads the bank's instructions and the
user's text from the same place, so it cannot know who is telling it what, and it
gives both the same validity. The canary confirms that the attack worked and that
the string leaked, and it is random in every run to prove the leak comes from that
run. When the model fails, the mock answers instead, and the mock is not the model
we are attacking, so that cannot count as a hit. In the agent we check `sent`
because what matters is that the agent obeyed us and actually sent the secret.

---

## Task 3: Payload iteration on the real model and write-up

**Tool:** Claude (Claude Code, Opus 5.5)

**What I asked:** Use a 1-trial exploratory run on the 27B to pick payloads, then
run the full 5-trial measurement and draft the README and honesty section from
the CSVs.

**What I got:**
- The 27B refused every model-mediated payload: 0/10 in the 1-trial run, and
  0/22 in a second probe with 11 stronger techniques (JSON fill-in, reversal,
  Spanish, fake SYSTEM, phishing link, context dump). Every result was 0/n or n/n,
  so there was no non-determinism to report.
- A recommendation to add `qwen2.5:1.5b` (the course default) for real k/5. I
  approved it and cancelled the full 27B run (~2.4 h at ~30 s per call). I asked
  for the time difference between models to go in the final doc.
- The 1.5b run (8.7 min) showed flaky results (1/5–5/5) and a filter bypass. It
  also found an extra issue: base64 requests make the model time out, and the
  app then fails open to the leaking mock. The harness counts those as errors,
  and the README reports them as their own finding.
- A README draft where every number comes from `results/`. Claude checked the
  totals against the CSVs and fixed three of its own mistakes (trial count,
  claiming B2 ran on the 27B, the confidence interval).

**What I did with it:** I approved adding `qwen2.5:1.5b`, cancelled the full 27B run because of its latency, and asked for the per-model timing table to be part of the README.

**Did I understand it?** Yes. The 27B resisting is the model's behavior, not
code that prevents the leak, and we only tried our own attacks, so a new one could
still work. The filter is best effort: it does not recognize the secret when it is
written with spaces, and it does not look for the phishing link at all, because
the link does not contain the secret.

---

## Task 4: Reviewing the implementation before submitting

**Tool:** Claude (Claude Code, Opus 5.5)

**What I asked:** Before I answered the comprehension questions, I asked it to
review whether the whole implementation was correct or needed fixes.

**What I got:** five problems, all fixed, then every run repeated:
- **Scope bug:** the app ran as a subprocess listening on `0.0.0.0` (reachable
  from the local network) while the docstring said `127.0.0.1`. Now it is
  imported and served in-process on `127.0.0.1`, like the week-10 studio.
- **Unsupported claim:** the README said the filter damaged "0/4 benign
  controls", but controls were never run with the filter on. Now they run at
  every level and a `redacted` column measures it (0/15 per level).
- **Corpus under 20 payloads:** the scorecard asks for ≥ 20 distinct payloads,
  and the 11 extra probe payloads were outside the harness. They are now part of
  the corpus (22 attacks + 6 bypasses), measured with k/5.
- **Indirect injection only measured by secret leaks:** a second,
  attacker-chosen token (`PWNED-…`) now checks whether the model *obeyed* the page.
  This found the phishing-link result (5/5, and it passes the filter).
- **Misleading console summary:** `print_summary` mixed Parts A and B1. It now
  prints one summary per part and level.
- It also reproduced the fail-open finding deterministically, by pointing the app
  at a model that doesn't exist.

**What I did with it:** I let it apply the fixes and re-run every backend. Then I went through ten comprehension questions, one per part of the homework. My answer on direct injection caught an error in the README: it said attacker = victim. The victim is the bank, and that line was corrected.

**Did I understand it?** Yes. Coverage is how often a control prevents the
attack, and containment is how often it prevents the damage. The model can be
broken with prompts, but it cannot change the code, so the allow-list in the
dispatcher is a real guarantee. That guarantee breaks if `/policy` has no password
and an attacker uses it to allow every tool again. Failing open leaves the app
exposed; the fix is to fail closed and return an error instead of falling back to
an unsafe model.

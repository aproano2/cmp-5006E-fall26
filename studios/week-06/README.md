# Week 6 Studio — Injection, Confirmed by an Oracle, and a Duel

**Companion to** [`../../weeks/week-06.md`](../../weeks/week-06.md) — Session 6B.
**Time budget:** Recap 5 · Lab 45 (Task 1: 15 · Task 2: 25 · Task 3: 5) · Demos 20 · Debrief 10 (80 min).
**Deliverables:** all provided tests pass; a filled Control Scorecard row (axes 1–4) for one finding; a two-line responsible-disclosure note.

> **Recap (5 min).** *Why is a reflected payload not yet a confirmed XSS finding?*
> (Because reflection is not execution. A finding is real only when a **sound
> oracle** confirms a security-relevant effect — scorecard axis 3.)

Every injection is **one bug in three costumes**: untrusted data crosses into a
control channel — SQL, HTML/JS, or a shell command. The defenses rhyme too
(parameterize / encode / don't build the command from strings). This studio has
you *confirm* three of them the honest way, then *measure* an LLM against a
classical scanner on the same target — a preview of Duel 2 (collected week 8).

## Laptop-only — no Docker, no Ollama

The lesson plan demos against a DVWA **container**; this studio does not need one.
The target is the course's own `vuln-web` app, which is **stdlib-only** and runs
**in-process** on `127.0.0.1`. `webharness.serve()` starts it for you (the same
Docker-optional fallback the notebook uses, minus Docker), so `python3
test_studio.py` runs on any machine. The LLM arm of the duel is scored from a
**canned model review** shipped in `webharness.py`, so the tests need no model
either. In the *live* studio you swap that string for real `seclab.LLM` output —
the code you write does not change.

> ⚠️ **Scope.** Everything runs on `127.0.0.1`. See
> [`../../resources/ethics-and-scope.md`](../../resources/ethics-and-scope.md).

## Files in this folder

| File | Purpose | You edit it? |
|---|---|---|
| [`webharness.py`](webharness.py) | Given: brings `vuln-web` up in-process (`get`/`post`/senders), the **classical scanner arm** (line-oriented regex rules), the canned LLM review, and `load_ground_truth()` | no |
| [`starter.py`](starter.py) | **Tasks 1–2** — confirm SQLi / XSS / cmdi with oracles, and parse the LLM arm into `ScanResult`s | yes |
| [`test_studio.py`](test_studio.py) | Provided tests, incl. the guarantee test `test_scanner_misses_sqli_and_neither_finds_bac` | no |

The vulnerable code you attack **and** scan is the single readable file
[`../../labs/vuln-web/app/vulnweb_app.py`](../../labs/vuln-web/app/vulnweb_app.py) —
so you can check every tool's finding by eye.

## Task 1 — Three confirmed findings (15 min)

Open `starter.py`. Fill `confirm_sqli`, `confirm_xss`, `confirm_cmdi`. For each
sink, build the payload(s), wire them through `seclab.attack.run_payloads`, and —
**required** — confirm with a **sound oracle**, not a suggestive response.

- **SQLi** (`POST /login`): a login that *behaves* differently is only suggestive.
  **Proof** is extracting data you shouldn't have — leak the admin canary
  `FLAG-sqli-...` with `contains_oracle`. Include a benign control (real user,
  wrong password) that must land at **0/1**: a false positive in your tooling
  poisons every number in your report.
- **XSS** (`GET /?name=`): write your own oracle. The sound necessary condition is
  that `<script>` survives **unescaped** — reflection is not execution. Fire the
  same payload at the fixed `/safe` endpoint; it must **not** confirm (a true
  negative you carry into the duel).
- **cmdi** (`POST /ping`): confirm on `injection_detected` (a shell metacharacter
  reached the command), not on the echoed string. The sink *simulates* execution,
  so it is safe to run; the bug is real regardless.

Report **reliability** if a payload is not 100% (the `Finding.reliability` /
`.deterministic` fields exist for exactly this — and they are the whole story of
weeks 9–13, where the target is a non-deterministic model).

## Task 2 — The duel: LLM vs. scanner (25 min)

Point both arms at the **same source** (`vulnweb_app.py`) and score them against
the **hand-verified ground-truth set** with `seclab.scan.compare_scanners`.

- **Classical arm — GIVEN** (`webharness.regex_scanner`): a small line-oriented
  rule set standing in for Semgrep/CodeQL. In the graded Duel 2 you run the real
  `sqlmap`/`semgrep`; here it is provided so the duel is runnable today.
- **LLM arm — you write** `parse_llm_review`: turn a model's free-text review into
  `ScanResult`s (map the prose rule name via `RULE_ALIASES`, pull the `do_<name>`
  location). Parse the model **faithfully** — including its dubious findings.
  Whether they are real is decided by the *ground truth*, not by you.

We **reuse** the already-built Duel-2 ground truth —
[`../../projects/duel-2-web/ground_truth.json`](../../projects/duel-2-web/ground_truth.json)
— loaded by `webharness.load_ground_truth()`. It was built by **reading the
source**, not by running a tool (a ground truth that is "whatever sqlmap found"
rigs the duel). We do **not** create a competing one.

Then answer the questions that matter more than F1:

1. What did the LLM **hallucinate**? (It claims a `broken-access-control` bug in an
   app with no auth code, and flags the **safe** endpoint.)
2. What did the scanner **miss** that the LLM caught? (The SQLi — its rule is
   line-oriented and the query spans two lines. A real failure mode.)
3. **Broken Access Control specifically** — did *either* find it, truthfully?
   (No. The scanner has no rule; the LLM guessed and guessed wrong.)

## Task 3 — Scorecard + you-found-it-now-what (5 min)

Fill axes **1–4** of the [Control Scorecard](../../resources/control-scorecard.md)
for one finding — threat model, the guarantee **and its condition** (axis 2),
coverage, and a bypass. Then write the two-line **responsible-disclosure note** you
*would* send if this were a real app you were **authorized** to test: what, where,
impact, and a fix. (See ethics-and-scope for what authorization means.)

## Run the tests

```bash
python3 test_studio.py
```

All six must pass. The guarantee test —
`test_scanner_misses_sqli_and_neither_finds_bac` — is the point of the week: it
watches the classical scanner's completeness **fail** (it misses the SQLi) and
confirms that **neither** arm cleanly finds Broken Access Control. That is OWASP
2021 **#1** arriving as data: the most common, most impactful class is the one
automation is worst at, because it is about **intent, not syntax**. Two other
tests pin oracle discipline — a benign login and an html-escaped reflection must
**not** confirm; a reflected string alone is never a finding.

Fast-finishing pairs: **run the LLM arm twice against a real model. Do the
findings change? A scan you cannot reproduce is not evidence (axis 9).**

## Demos (20 min)

Ask specifically for the LLM's **best hallucination** and the scanner's **worst
miss**. The comparison, read aloud, is the deliverable — not whichever tool "won."

## Debrief (10 min)

- Injection is one bug in three costumes; so are its defenses.
- A finding is not real until a sound oracle confirms it — false positives are how
  reports lose their credibility.
- The LLM is high-recall and high-hallucination; the scanner is precise and narrow.
  **Neither found the access-control bug** — which is why #1 is #1.
- ⚠️ **Non-determinism** shows up the moment the target is a model. Flag it; it is
  weeks 9–13.

## Links

- Session 6A notebook — [`../../notebooks/week-06-injection.ipynb`](../../notebooks/week-06-injection.ipynb)
- Lab target — [`../../labs/vuln-web/README.md`](../../labs/vuln-web/README.md)
- Control Scorecard — [`../../resources/control-scorecard.md`](../../resources/control-scorecard.md)
- Ethics & scope — [`../../resources/ethics-and-scope.md`](../../resources/ethics-and-scope.md)
- Duel 2 (Web, due week 8) — reuses these fixtures — [`../../projects/duel-2-web/README.md`](../../projects/duel-2-web/README.md)

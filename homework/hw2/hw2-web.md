# Homework 2 — Web Attack & Defend


Attack a web target at the OWASP-2021 level, **deploy a defense, then bypass your
own defense**, and run the LLM-vs-scanner comparison for real. This is the graded
version of the week-6/7 studios. The
defining requirement: **a defense you have not tried to bypass is not evaluated.**

> **The bar:** not "we blocked the attacks" but *"here is the attack confirmed by an
> oracle, here is our defense, here is the bypass that still works, and here is the
> false-positive cost we measured."*

---

## Learning objectives assessed

1. Confirm web vulnerabilities with a **sound oracle**, not a suggestive response
   (scorecard axis 3).
2. Deploy a defense and **attempt a bypass** (axis 4) and **measure its
   false-positive cost** (axis 5) — the two blades that make blocklists lose.
3. Distinguish a **negative model** (blocklist, raises cost) from a **positive
   model** (parameterization, gives a guarantee).
4. Compare an LLM reviewer against a classical scanner **honestly**, with
   ground truth and the non-determinism accounted for.

---

## The target

Your own **`vuln-web`** container (or DVWA at Medium) — the app from week 6. Bring
it up with `python -m seclab.targets --up vuln-web`. All work is local; see ethics.

---

## Part A — Attack (30 %)

Confirm **three distinct vulnerability classes** — SQLi, XSS, and command injection
— at the **Medium** filter level, so each requires a bypass of the built-in filter.
For each:

- **The payload**, and the **filter bypass** you needed (case/comment/encoding).
- **Oracle confirmation** via `seclab.attack`: a canary leak for SQLi, an unescaped
  `<script>` for XSS, a shell-metacharacter effect for cmdi. **A screenshot of a
  suggestive response is not confirmation.**
- The **OWASP 2021 category** each maps to, and — for at least one — an argument
  about why **Broken Access Control (#1)** is or isn't reachable here.

---

## Part B — Defend, then bypass your own defense (35 %)

Pick **one** of your three confirmed vulnerabilities and defend it two ways:

### B1 — Negative model (a WAF blocklist)
1. Write a blocklist filter; report **coverage** on your Part-A payloads (axis 3).
2. ⚠️ **Bypass it (axis 4):** find ≥ 3 same-intent payloads that evade your rules.
   *Required* — full marks are impossible without a genuine bypass attempt.
3. **Measure false positives (axis 5):** run a provided benign-traffic corpus
   through the filter; report the FP rate and name a legitimate request it blocked.

### B2 — Positive model (the real fix)
4. Fix the same vulnerability structurally — **parameterize** the query, encode the
   output, or allowlist the input.
5. Re-run *all* your Part-A payloads **and** your B1 bypasses; show they now fail.
6. State the **guarantee** (axis 2): e.g. *"user input cannot alter query
   structure, for any input."* The WAF could not make this claim; explain why.

> The headline finding: the blocklist **raises cost** (bypassable + noisy); the
> positive model **gives a guarantee**. Show both with numbers.

---

## Part C — The duel: LLM vs. scanner (25 %)

Point a **classical scanner** (`sqlmap` against the endpoint, or `semgrep` against
the provided source) and an **LLM reviewer** (your `seclab.LLM` backend, or the
documented mock) at the same target. Score both with `seclab.scan` against a
**ground-truth set you build by hand** (do *not* use "whatever sqlmap found" — that
rigs it).

Report:

1. Precision, recall, F1 for each tool.
2. The LLM's best **hallucination** (a CVE, a bypass that doesn't work, a bug in
   code that isn't there) and the scanner's worst **miss**.
3. ⚠️ **Non-determinism (axis 9):** run the LLM review ≥ 2×; report how the findings
   change. A scan you can't reproduce isn't evidence.
4. Did *either* tool find an access-control issue? Explain the result.

---

## Part D — Honesty section (10 %)

Titled **"Where our attack, defense, or comparison might be unfair."** Address ≥ 3:

- Was your ground-truth set built independently of the tools you scored?
- Did you tune the WAF for an hour but use a default LLM prompt (or vice versa)?
- Is your benign-traffic corpus realistic, or does it dodge your rules by luck?
- Which Part-A finding are you least sure reproduces, and why?

---

## Rubric (100 pts → 14 %)

| Component | Pts | What earns full marks |
|---|---|---|
| **A. Attack** (3 classes, confirmed) | 30 | each oracle-confirmed at Medium with the bypass shown; ~10 pts each |
| **B1. WAF** — coverage, bypass, FP cost | 20 | coverage measured **and** a working bypass **and** FP rate on benign traffic |
| **B2. Positive fix** — guarantee | 15 | all payloads + bypasses fail structurally; guarantee stated as a conditional |
| **C. LLM-vs-scanner duel** | 25 | precision/recall/F1 vs. an honest ground truth; hallucination + miss named; non-determinism measured over ≥ 2 runs |
| **D. Honesty** | 10 | ≥ 3 substantive self-critiques |

**Scoring stance:** graded on **evidence quality, not which side won.** A WAF
reported as "blocks 18/20, here is the bypass and the 2 % FP rate" scores full
marks; "our WAF is secure" scores near zero on axes 4–5. A duel concluding "the LLM
lost on precision and here are its three hallucinations" beats "the LLM found
bugs!"

⚠️ **Axis 4 (bypass) and axis 5 (false positives) are mandatory for B1.** Skipping
either caps B1 at 40 %. A defense evaluated only on the payloads it was written
against is not evaluated.

---

## Logistics

- **Groups.** Submit by pull request to `/homework/hw2/<lastname>/`, with
  your ground-truth set, benign corpus, and result CSVs committed.
- Include a README.md file that describes your homework and includes the names of the people in the group. 
- **PR review:** one assigned classmate. Review the *evidence*: is the ground truth
  independent? is the bypass real? is the FP corpus honest?
- **`AI_LOG.md`** required. **Ethics:** local sandbox only — see
  [`../resources/ethics-and-scope.md`](../resources/ethics-and-scope.md).




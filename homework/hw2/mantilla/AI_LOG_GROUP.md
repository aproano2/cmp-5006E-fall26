# AI LOG for Homework 02

> **Group:** Julian Leon, Mauricio Mantilla, James Soto.
> **Scope of this log:** every interaction in which an AI assistant materially
> shaped what we submit, in the order it happened, following the format in
> `resources/ai-policy.md`. Teammates add their own entries below if they used
> an assistant.
>
> **What is *not* an assistant here:** the local model `qwen3.8:27b` (Ollama) is
> the **subject** of the Part C duel. Its raw answers are in
> `duel/raw/llm_*.json` and are scored as evidence. They were not used to write
> any part of the homework.
>
> **Data handling:** the only hosted assistant (Claude) saw course material only:
> the public course repository, our own code, and synthetic lab data (the
> canary string is a fake flag). No real credentials or personal data were
> shared with it.

---

## Task 1: Requirements analysis and scoping

**Tool:** Claude (Claude Code, Opus 5.5)

**What I asked:** I asked it to read our HW1 submission and the HW1 pull request
so it would follow the same conventions (folder, branch, PR text, AI log), then
the HW2 assignment (`homework/hw2/hw2-web.md`), the instructor's starter files
in `homework/hw2/duel-2-web/`, the target app `labs/vuln-web`, the `seclab`
helper package and the week-6/7 studios. Before writing any code, it had to map
each rubric item to a concrete deliverable and tell me what was missing or
ambiguous.

**What I got:**
- A requirement-by-requirement map of Parts A–D and the logistics (folder
  `homework/hw2/leon/`, README with group names, ground truth, benign corpus,
  result CSVs, `honesty.md`, `AI_LOG.md`).
- One ambiguity: the assignment asks for attacks at the **Medium** filter
  level, but vuln-web has no security levels (only DVWA does).
- An inventory of my machine: Docker installed but the daemon not running,
  Ollama serving `qwen3.8:27b`, and semgrep/sqlmap not installed.
- Two options for the Medium level: (a) a DVWA-style filter layer in front of the
  unmodified vuln-web sinks, or (b) running real DVWA in Docker.

**What I did with it:** I chose option (a), because it keeps all three parts on
the same target, runs without Docker and gives reproducible results. I also
confirmed that the group is the same as in HW1. The work was set up as a
separate git worktree on a new branch `hw2` from `upstream/main`, so my
uncommitted changes on `main` were not touched.

**Did I understand it?** The filter is what makes the Medium level measurable:
without any filter there is nothing to bypass, so there is no way to measure how
effective an attack is against a defense. I think building our own filter was a
reasonable choice, because we adapted the assignment to the real constraint we
had (vuln-web has no levels) and worked from there.

---

## Task 2: Part A, the Medium level and the attack harness

**Tool:** Claude (Claude Code, Opus 5.5)

**What I asked:** Build the Medium level and a harness that confirms SQLi, XSS
and command injection with `seclab.attack` oracles, not with a response that
only looks suggestive. Each class must show the naive payload failing at
Medium and a filter bypass that works.

**What I got:**
- Before writing code, Claude tested the planned SQL tricks directly against
  `do_login` (an unterminated `/*` comment, `IS NOT` precedence, `UNION ALL`) to
  confirm that SQLite behaves the way the attacks assume.
- `attack/medium_app.py`: filters modeled on DVWA Medium (the XSS and cmdi
  filters copy DVWA's lists; the SQLi one is a DVWA-style keyword strip). They
  sit in front of the original handlers, which are not modified.
- `common.py`: shared server, senders and the three oracles (canary leak,
  unescaped `<script>`, metacharacter plus a second command in `would_run`).
- `attack/attack.py`: every payload is fired at both Low and Medium, 3 trials
  each, plus negative controls. The script asserts its own claim.
- First iteration: the script failed with `ModuleNotFoundError` when run in
  Python's isolated mode (`-I`). The import paths were fixed and the script
  re-run.
- Result: 5 naive payloads work at Low and are blocked at Medium. 10 bypasses
  are confirmed at Medium (3/3 each). Negative controls never confirm.

**What I did with it:** The results were re-run on my machine (macOS, M1 Pro,
Python 3.14.7) and are deterministic (every payload 3/3 or 0/3). One finding
kept on purpose: `admin'-#-` does nothing at Low and only works because the
Medium filter turns it into `--`. It is evidence that the filter itself creates
the attack.
I went through the Low → Medium attack table. The naive payloads go from 3/3 at
Low to 0/3 at Medium, but the bypasses are 3/3 at Medium: when the attack is
disguised, it gets past the filter without being detected.

**Did I understand it?** The filter does not cover every possible case, which is
why an attack can be disguised: for example by changing upper and lower case, or
by nesting, as with `<scr<script>ipt>`. A security control should cover more
scenarios and make a better effort than removing a fixed list of strings.

---

## Task 3: Part B, WAF, bypass, false positives and the real fix

**Tool:** Claude (Claude Code, Opus 5.5)

**What I asked:** Defend the SQLi two ways. First, a blocklist WAF with
coverage on our Part-A payloads, at least 3 same-intent bypasses confirmed by
the oracle **through** the WAF, and the false-positive rate on the course's
benign traffic. Second, a structural fix that defeats every payload and bypass,
with the guarantee written as a conditional.

**What I got:**
- `defend/waf.py`: WAF_V1 (4 rules, written against our Part-A payloads) and
  WAF_V2, a broader version made after V1 was bypassed, so the trade-off can be
  measured instead of described.
- `defend/fixed_app.py`: `do_login` with a constant SQL string and `?`
  placeholders. It also stops echoing the SQL query and error message back to
  the client.
- `defend/defend.py`: runs four servers side by side (no defense, V1, V2,
  parameterized) and sends every attack through HTTP with the canary oracle.
- Iteration: at first, a WAF block (HTTP 403) was raised as an exception and
  recorded as an error. The helper was changed so a 403 counts as a response.
- Result: V1 has 5/5 coverage, 4/4 bypasses land and 0/26 false positives. V2
  stops all 4 bypasses but blocks 8/26 = 31 % of benign traffic (including
  `o'brien`). The parameterized fix lets 0/9 attacks land, real logins still
  work, and `o'brien` no longer crashes the query.

**What I did with it:** The script asserts the rubric minimums (at least 3
working bypasses, 0 leaks after the fix, the real login still works). The
guarantee in `defend/README.md` is written as a conditional ("provided that
every query … is issued through placeholders"). The V1/V2 comparison is used as
the headline evidence for the negative-model vs. positive-model argument.
I reviewed the Part B results and agree with the conclusion: as I understand
it, a WAF only protects against the specific cases declared in its rules and
offers no protection for any other case.

**Did I understand it?** Blocking what is bad only blocks what is already known.
With a parameterized query (`?`), the input is only ever treated as text, so it
cannot change any query.

---

## Task 4: Part C, ground truth and classical scanners

**Tool:** Claude (Claude Code, Opus 5.5)

**What I asked:** Write a ground truth by reading the source, **before** running
any tool, so the duel is not rigged. Then run a classical scanner against the
same target and save the raw output so the scoring can be reproduced.

**What I got:**
- `duel/ground_truth.json`: the 3 scored sinks, the true negative (`/safe`), the
  class that is not present (broken access control), and three real but
  out-of-scope weaknesses we found while reading (the SQL error is echoed back,
  plaintext passwords, a hard-coded default password).
- semgrep, bandit and sqlmap installed in a temporary virtual environment,
  without touching the system Python.
- First iteration: semgrep reported **0 findings**. Before trusting that,
  Claude re-ran it with five different community rulesets
  to rule out a broken install. All ran with no errors (79–371 rules
  each) and still found nothing. bandit was added as a second static data
  point: it catches the SQLi (B608).
- sqlmap was tried first against `/login` alone, then run against all four
  endpoints. It confirms the SQLi and correctly reports the other three as not
  SQL-injectable.
- `duel/run_scanners.py` saves all raw outputs to `duel/raw/`.

**What I did with it:** The ground truth was saved before the scanner and LLM
outputs existed. After that, `score.py` checks that our scored
set equals the instructor's fixture (it does). The scanners were run a second
time and gave identical scores, which backs up the claim that they are
deterministic.

**Did I understand it?** If I built the answer key after seeing what the tools
or attacks returned, I could be biased into making it look too much like their
output, without that necessarily being the truth.

---

## Task 5: Part C, LLM review, non-determinism and scoring

**Tool:** Claude (Claude Code, Opus 5.5)

**What I asked:** Run the LLM reviewer through the course's `seclab.LLM` client
at least twice so non-determinism can be measured. Score every tool with
`seclab.scan` against our ground truth and report precision, recall, F1, the
LLM's best hallucination and the scanner's worst miss.

**What I got:**
- `duel/llm_review.py`: one plain prompt, written once and never tuned. Five
  runs: temperature 0 / seed 0 twice, and temperature 0.7 with seeds 1, 2 and 3.
  Each run took about 2.5–4 minutes on my laptop.
- `duel/score.py`: parses each tool's raw output, maps lines to functions with
  `ast`, and scores strictly plus with an "adjusted" variant that excludes real
  but out-of-scope findings.
- Iteration 1: after the first LLM run, the vocabulary normalizer was extended
  (CSRF, rate limiting, network binding) so these findings get consistent
  names. This changes only their labels, not whether they count as TP or FP.
- Iteration 2: Claude found a bug in its own scorer. `do_POST` was labeled a
  "non-existent function" because names were compared with different
  capitalization. It was fixed and everything re-scored.
- Result: the LLM finds 3/3 in every run, with precision 43 % at T=0 and 75 % at
  T=0.7. The two T=0 runs are byte-identical. The best hallucination is a
  CSRF bug in an app with no sessions. semgrep is 0/3, sqlmap 1/3 with no false
  positives, bandit 1/3 with 2 false positives.

**What I did with it:** The byte-identical claim was checked with `cmp` and
not assumed. Both the strict and the adjusted scores are reported, so the reader
can see how much the scope decision changes the result. The raw answers are
committed in `duel/raw/`, so the hallucination can be checked against the
source.
I agree that the CSRF finding is the worst hallucination. The attack is
impossible in this application (it has no logged-in users, sessions or cookies),
which makes it very serious that the model detects and invents it anyway.

**Did I understand it?** Good recall means the LLM does find the real problems.
Bad precision means it also invents problems and flags things that are not
vulnerabilities, so its output is not reliable on its own.

---

## Task 6: Documentation, honesty section and fact-checking

**Tool:** Claude (Claude Code, Opus 5.5)

**What I asked:** Write the README for each part, the top-level README and
`honesty.md` (at least 3 critiques). Every number in the documents must come
from `results/*.csv`, and every claim must be checked before it is written.

**What I got:**
- Three part READMEs, a top-level README with the headline results and
  reproduction steps, and `honesty.md` with 5 self-critiques (ground-truth
  independence, tuning asymmetry, how realistic the corpus is, the least
  reproducible finding, and the fact that our Medium level is our own).
- Corrections found while fact-checking:
  - An example in `honesty.md` (`o'r` would trip WAF_V1) turned out to be false
    when tested. It was replaced with a tested example
    (`la fièvre de l'or`).
  - The claim that a custom semgrep rule *would* find all three sinks was
    softened to "could", because we never tried it.
  - The README said 7 naive payloads; it is 5. Corrected.
- A final clean run: the results folder was deleted and all parts re-run from
  scratch, both from the submission folder and from the repo root.

**What I did with it:** The honesty section criticizes our own choices (for
example, that V1 was tuned on our own payloads), not only the tools.
I reviewed the documents written with the AI and I am fine with them as they
are.

**Did I understand it?** The critique I find most relevant is the one about our
Medium level: it came from a decision taken with Claude's help, not from a
direct instruction in the assignment, so it may be biased.

---

## Task 7: Review, explanation and pre-submission check

**Tool:** Claude (Claude Code, Opus 5.5)

**What I asked:** Before committing anything, I asked for an explanation in
Spanish of what the homework is about and how each part was solved. I also
asked for a check of the submission against the assignment and against the
format of our HW1 pull request, an explanation of what the benign corpus is,
and an improved version of this log. To fill in the fields that are mine, I
answered a set of simple questions in Spanish and asked Claude to put my
answers into English for this log, without changing what I said.

**What I got:**
- A plain-language walkthrough of Parts A–D.
- A checklist against `hw2-web.md` and HW1's PR (title
  `hw1 deliverable - Julian Leon`, group list in the description, only files
  under our folder). All items are met except one: the benign corpus is the
  instructor's file (`duel-2-web/benign_traffic.json`), which at that point was
  referenced but not copied into our folder.
- A note that the rubric's "name a legitimate request it blocked" is answered
  with WAF_V2, because the deployed WAF_V1 blocked none.
- A bug in the instructor's `verify_fixtures.py`: its path is off by one
  directory, so it crashes with `ModuleNotFoundError`. It does not affect our
  scripts.

**What I did with it:** I decided to review the whole submission myself before
any commit or pull request.
I decided to copy the benign corpus into our folder
(`defend/benign_traffic.json`, unmodified), because everything the professor
asks for should be in the submission. `defend/defend.py` now reads that copy.

**Did I understand it?** WAF_V2 is much more restrictive than WAF_V1, to the
point of being harmful: it does not allow normal communication, and real users
cannot send their messages correctly (for example `o'brien` or "drop table
tennis lessons").

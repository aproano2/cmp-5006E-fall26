# AI Assistance Log

## Homework 2 — HTTP test runner

**Tool:** Codex.

**What I asked:** Help me implement `run.py` to test the attacks and defenses
against the local target and save the results.

**What I got:** Help developing a runner that starts a temporary local server
and test database for each mode (`original`, `waf`, and `positive`), sends HTTP
requests, and uses `seclab.attack.run_payloads` to repeat each attack three
times. The assistant helped implement response oracles for the SQLi canary,
unescaped script elements, and simulated command injection. The runner also
checks normal logins, measures false positives using `benign_traffic.json`,
and saves CSV results, JSON responses, and execution metadata.

**What I did with it:** Included the assisted runner and its recorded outputs
in the submission. Used the saved results to document attack successes, WAF
bypasses, false-positive rates, and the failure of the tested attacks in
positive mode. 

**Did I understand it?** Yes. After the walkthrough, I understand how `run.py`
starts the local target using the original course handler or the selected
defense handler and the course's `make_db()` function, sends HTTP requests, and checks responses with custom
oracles through `seclab.attack`. I also understand how it repeats the attacks,
measures false positives, and saves the results.

## Homework 2 — Part C: LLM-vs-scanner comparison

**Tool:** ChatGPT and Codex.

**What I asked:** Help me implement and understand the comparison between
Semgrep and an LLM, calculate precision, recall, and F1, and review whether the
report matches the saved tool outputs.

**What I got:** Help developing `duel/run_duel.py` and a focused Semgrep rule
file to review the same application source. The runner uses
`seclab.scan.compare_scanners` with the instructor's ground truth and records
two LLM responses using the same prompt, nonzero temperature, different seeds,
and disabled caching. The assistance also covered strict scoring of reported
labels, replaying saved outputs, and interpreting false positives, missed
findings, and changes between runs.

**What I did with it:** Included the runner, rules, and recorded evidence in
`duel/`. The exact model responses are saved in `duel/llm_runs.json`, the
calculated metrics in `duel/metrics.csv`, and the interpretation in
`duel/results.md`. The recorded F1 scores are 0.80 for Semgrep, 0.00 for the
first LLM run, and 0.33 for the second. Documented Semgrep's missed simulated
command injection, the LLM's incorrect attribution of reflected XSS to
`do_login`, and the malformed labels that count as unmatched findings.

**Did I understand it?** Yes. I understand how reported findings are compared
with the ground truth to calculate true positives, false positives, and false
negatives, and how these determine precision, recall, and F1. I understand
that malformed labels affect the scores even when a rationale mentions a real
bug, and that two LLM runs show possible variation without establishing a
stable statistical rate. The narrow Semgrep rules and instructor-provided
ground truth limit the comparison. Neither reviewed response establishes an
independent access-control defect in this application.

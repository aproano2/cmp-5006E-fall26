# Homework 02 — Web Attack & Defend
**Members**: Daniel Andrade - Andrés Vega - Carlos Flores

Attack, defense, and a scanner-vs-LLM duel against the `vuln-web` target. Everything
runs locally against the Docker container on `127.0.0.1`.

## Target setup

```bash
python -m seclab.targets --up vuln-web
```

The notebooks reach the live container through [`webharness.py`](webharness.py),
which starts it lazily (`serve()`) and exposes the send-helpers each part uses.

## Contents

### `attack/` — Part A

Three oracle-confirmed findings against `vuln-web`.

| Rule | Location | Oracle |
|---|---|---|
| `sqli` | `do_login` | canary leak (`FLAG-sqli-` in the response) |
| `xss` | `do_reflect` | unescaped `<script>` tag survives in the response |
| `cmdi` | `do_ping` | command-injection signal reached the sink |

### `defend/` — Part B (we defend the SQL injection)

- **B1 — negative model (WAF blocklist):** [`defend/waf.py`](defend/waf.py). Coverage
  3/3 on the Part-A SQLi payloads, **three same-intent bypasses** that evade the
  filter and still leak the canary, and a false-positive measurement on a
  benign corpus: 18.8% on our invented usernames, 0% on both provided
  groups, 8.1% combined.

- **B2 — positive model (parameterized query):** [`defend/defend.py`](defend/defend.py).
  All Part-A payloads and all B1 bypasses now fail (0 leaks) while the legitimate
  admin login still works.

[`defend/defend.ipynb`](defend/defend.ipynb) runs both and ends with a B1-vs-B2
comparison: the blocklist raises attacker cost but is bypassable and noisy; the
parameterized query gives a structural guarantee.

### `duel/` — Part C (scanner vs. LLM)

[`duel/duel.ipynb`](duel/duel.ipynb) scores `semgrep` and a local-LLM reviewer
(`qwen2.5:3b` via `seclab.LLM`, temperature 0.7, seeds 0–5) against the
independently built [`../duel-2-web/ground_truth.json`](../duel-2-web/ground_truth.json).

The LLM is run in three configurations, six seeds each:

| config | prompt | source shown to the model |
|---|---|---|
| `v1-full` | v1 | full `vulnweb_app.py`, including the docstring and `# VULN` comments (baseline) |
| `v1` | v1 | docstring and comments removed, because they label every bug |
| `v2` | v1 + "report only security vulnerabilities, not style/typing issues" | docstring and comments removed (**main result**) |

Files:
- [`duel/duel.py`](duel/duel.py): the logic (semgrep runner, prompts, parser).
- [`duel/findings.csv`](duel/findings.csv): every finding per tool, config and seed, with how its rule was
  mapped and whether it is in the ground truth.
- [`duel/metrics.csv`](duel/metrics.csv): precision, recall and F1 per tool, config and seed.
- [`duel/dropped_lines.csv`](duel/dropped_lines.csv): answer lines that were not parsed as findings.
- [`duel/semgrep_output.json`](duel/semgrep_output.json): raw semgrep output.

**Key results** (mean over six seeds):

| | precision | recall | F1 | false positives |
|---|---|---|---|---|
| `semgrep` | – | 0.00 | 0.00 | 0 (found 0/3) |
| LLM `v1-full` | 1.00 | 0.89 | 0.93 | 0 |
| LLM `v1` | 0.78 | 0.33 | 0.44 | 5 |
| LLM `v2` (main) | 0.67 | 0.44 | 0.53 | 4 |

- **semgrep** found nothing with `auto`, `p/security-audit` or `p/python`. Registry rules don't match this
  stdlib `http.server` + `sqlite3` app. We have no positive control, so "no rule ran" is not ruled out.
- **The comments were the answer key.** With them, the LLM finds almost everything. Without them it finds
  only the SQL injection reliably (6/6 seeds), command injection in 2/6 seeds (v2 only), and XSS never.
- **Best hallucination:** v2 seed 5 reports SQL injection in `do_ping`, which has no SQL; the real bug there
  is command injection. Prompt v1 also claimed missing type hints in functions that are fully annotated.
- **Non-determinism:** the same seed reproduces the same answer exactly. Across seeds, v2 precision moves
  between 0.5 and 1.0 and recall between 0.33 and 0.67, and the same SQL injection is rated HIGH, MEDIUM
  or LOW.
- **Access control:** no tool reported Broken Access Control, which is correct; the app has no
  auth or role logic.
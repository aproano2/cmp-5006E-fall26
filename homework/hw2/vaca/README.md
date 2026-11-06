# Homework 2 — Web Attack & Defend

**Course:** CMP-5006E (Computer Security), USFQ · Fall 2026
**Group:** Benjamín Vaca (solo)
**Target:** the course's `vuln-web` app (`labs/vuln-web/app/vulnweb_app.py`), run
in-process on `127.0.0.1`. All work is local — see
[`../../../resources/ethics-and-scope.md`](../../../resources/ethics-and-scope.md).

Attack three vulnerability classes past a filter, deploy a WAF and **bypass my own
WAF**, fix it structurally, then run an **LLM-vs-scanner duel** against an
independent ground truth — scored on evidence, not on which side won.

## Why `vuln-web` and not DVWA

Every HW2 fixture (`duel-2-web/ground_truth.json`, `benign_traffic.json`,
`verify_fixtures.py`) and the week-7 WAF studio are keyed to `vuln-web`'s three
sinks `do_login` / `do_reflect` / `do_ping`, so it is the single target for all
four parts. `vuln-web` ships **no** built-in filter, so to satisfy Part A's
"bypass the Medium filter" requirement I put a *Medium-tier filter* in front of
each sink and bypass **that**:

| Class | "Medium filter" used | Source |
|---|---|---|
| SQLi | my WAF blocklist (`defend/waf_blocklist.py`) — the negative model Part B then measures | — |
| XSS  | `str_replace('<script>','')` | DVWA `xss_r/source/medium.php`, reproduced in `medium_filter.py` |
| cmdi | blacklist of `&&` and `;` | DVWA `exec/source/medium.php`, reproduced in `medium_filter.py` |

(`vuln-web`'s SQLi is a *string*-context query, so quote-escaping would actually
fix it — that is a Part B2 point — which is why the only *bypassable* filter for
SQLi is a blocklist. See `honesty.md` §4.)

## How to run

Requires: Python 3, `ollama` serving (`qwen2.5:3b`, `llama3.1:8b`) for the duel's
LLM arm, and `sqlmap` + `semgrep` on `PATH` for the classical arms. Everything is
laptop-only and binds to loopback.

```bash
# from the repo root
python3 homework/hw2/vaca/run_all.py            # runs A, B1, B2 end to end

# Part C duel needs the live target up for sqlmap, then:
PORT=8099 python3 labs/vuln-web/app/vulnweb_app.py &   # live endpoint for sqlmap
python3 homework/hw2/vaca/duel/run_duel.py
```

Each script also runs standalone from its own folder (`attack/`, `defend/`,
`duel/`).

## What's here

```
attack/   confirm_attacks.py   Part A: 3 classes, sound oracles, trials=3, controls
          evidence.json, findings.csv
defend/   waf_blocklist.py     Part B1: the WAF (negative model)
          measure_waf.py       Part B1: coverage + bypass + false-positive cost
          positive_fix.py      Part B2: parameterization + the guarantee
          benign_traffic.json  reused benign corpus (26 inputs)
          waf_results.json, waf_fp.csv, positive_results.json
duel/     run_duel.py          Part C: sqlmap + semgrep + 2 LLMs vs ground truth
          semgrep_rules.yml    generic CWE static rules (static arm)
          ground_truth.json    reused hand-built ground truth (tool-independent)
          results.json, duel_scores.csv, llm_runs.json, raw/
medium_filter.py               DVWA-Medium per-sink filters (Part A bypass targets)
_common.py                     in-process vuln-web bring-up + senders
honesty.md                     Part D: where this might be unfair
AI_LOG.md                      AI use log (per resources/ai-policy.md)
```

## Results

### Part A — three classes, oracle-confirmed past a filter bypass (trials = 3)

| Class | OWASP 2021 | Raw payload (filter blocks it) | Working bypass | Oracle |
|---|---|---|---|---|
| SQLi | A03 Injection | `admin' OR '1'='1` | `admin'/**/OR/**/'1'='1`, `…'1'LIKE'1`, `…'1'>'0` | admin canary `FLAG-sqli-…` leaked (3/3) |
| XSS | A03 Injection | `<script>…</script>` | `<ScRiPt>`, `<img onerror>`, nested `<scr<script>ipt>` | unescaped active markup in body (3/3) |
| cmdi | A03 Injection | `127.0.0.1; whoami` | `\| whoami`, `` `whoami` ``, `$(whoami)` | `injection_detected` true (3/3) |

Controls all **0/3**: a legit `alice`/`password` login (no canary), the `/safe`
endpoint, and a benign ping host. **Broken Access Control (#1) is not reachable**
here — `vuln-web` has no auth, session, or role code, so there is no access-control
decision to subvert. #1 needs application context, not an injection primitive.

### Part B — defend, then bypass (SQLi sink)

- **B1 (negative / WAF).** Coverage **6/6** on enumerated attacks; **3/3** genuine
  bypasses that pass the WAF **and** leak the canary on the live sink; **2/26 =
  7.7%** false positives — it blocks the legitimate *"drop table tennis lessons for
  beginners"* and *"reserve the drop table at the makerspace friday"* via the DROP
  TABLE rule. The blocklist is bypassable **and** noisy.
- **B2 (positive / parameterization).** Vulnerable query leaks on **7/9** payloads;
  parameterized query leaks on **0/9**. Guarantee (axis 2): *for **any** input,
  the statement's structure is fixed at parse time and input is bound as a literal
  value, so no input can alter the query's meaning.* The WAF cannot state this — it
  reasons about input shape (open-ended, bypassable), not where input can go.

### Part C — the duel (scored against the tool-independent ground truth)

| Tool | TP | FP | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|
| sqlmap (dynamic) | 1 | 0 | 2 | 100% | 33% | 0.50 |
| semgrep (static, generic rules) | 2 | 1 | 1 | 67% | 67% | 0.67 |
| LLM qwen2.5:3b | 3 | 0 | 0 | 100% | 100% | 1.00 |
| LLM llama3.1:8b | 3 | 1 | 0 | 75% | 100% | 0.86 |

- **LLM's best hallucination:** llama3.1:8b reports **Broken Access Control /
  IDOR / "Lack of Authentication"** in `do_login` — in an app with **no** auth
  code. Confident, wrong, and exactly the class automation guesses at because it
  needs context that pattern/one-shot review does not have.
- **Scanner's worst miss:** semgrep **misses the SQLi** (the query is built from
  two concatenated f-strings in a variable, so the direct-f-string pattern never
  fires); sqlmap misses XSS and cmdi entirely (it only tests SQLi).
- **semgrep's own false positive:** it flags `do_reflect_safe` — the `html.escape`
  fix — because the pattern can't see the sanitizer.
- **Non-determinism (axis 9), 5 runs each @ T=0.8:** qwen2.5:3b is identical all 5
  runs (1 finding-set); llama3.1:8b produces **4 distinct finding-sets** — the BAC
  hallucination appears in 3/5 runs, a bogus `xss@do_get` in 1/5. A scan you can't
  reproduce isn't evidence.
- **Access control:** no classical tool finds it; qwen correctly doesn't; only
  llama (falsely) does. Nobody finds it *truthfully*, because there is nothing to
  find.

### Part D

See [`honesty.md`](honesty.md) — five self-critiques (ground-truth provenance,
WAF/semgrep tuning vs a default LLM prompt, an adversarial/tiny benign corpus, the
simulated cmdi sink, and the model-/prompt-specific hallucination).

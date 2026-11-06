# Homework 2 — Web Attack & Defend

**Group:** Alex Luna and Kevin Ganán  
**Target/source:** official course `labs/vuln-web` Docker container, run via `seclab.targets`; all requests are local.

This package contains the attack harness, a deployed loopback WAF proxy, a structural-fix test harness, and the LLM-vs-scanner experiment. Every number below was generated against the real official target and the real `seclab` APIs — not a reconstruction. **The Medium-filter question is resolved**: confirmed directly with the instructor that the Medium-filter bypass requirement applies only to groups using DVWA as their target; groups using `vuln-web` as provided are not expected to demonstrate one (see `honesty.md` §5). `medium_bypass_confirmed: false` in `attack/part_a_results.json` is therefore the correct, final value — not an open item.

## Directory layout

- `attack/`: baseline SQLi, XSS, and simulated-CMDi checks using the official `seclab.attack` API; A01/Broken Access Control analysis.
- `defend/`: B1 regex blocklist and loopback proxy, coverage/bypass/false-positive measurement, and B2 structural fixes with regression tests.
- `duel/`: instructor ground truth and benign corpus, Semgrep runner, uncached Ollama reviewer, and scoring through the official `seclab.scan.compare_scanners` API.
- `scorecard.md`, `honesty.md`, `AI_LOG.md`, and `RUBRIC_STATUS.md`: rubric evidence, limitations, and AI disclosure.

## 0. Place the group folder in the course repository

Copy this folder to `homework/hw2/luna/` in the course repository. The course repository must also contain `seclab/` and `labs/vuln-web/` at its root. Run the following commands from that repository root in Windows PowerShell.

```powershell
$HW = "homework/hw2/luna"
```

## 1. Build and start the local target

The course target manager chooses a free host port; do **not** assume port 8000. Build the image once, then start the target:

```powershell
docker build -t seclab/vuln-web:local labs/vuln-web
python -m seclab.targets --up vuln-web
```

The second command prints a URL similar to `http://127.0.0.1:54321`. Copy the actual port from your terminal:

```powershell
$BASE_URL = "http://127.0.0.1:54321"  # replace 54321 with the port printed by targets.py
Invoke-RestMethod "$BASE_URL/health"
```

The target manager publishes the container on `127.0.0.1`, consistent with the course scope. Keep the container running while you execute the HTTP tests.

## Part A — baseline attack-oracle checks

```powershell
python "$HW/attack/confirm_template.py" --base-url $BASE_URL --trials 3
```

This calls `seclab.attack.Payload`, `run_payloads`, and the provided/custom oracle functions. It writes `attack/part_a_results.json`. **Run and confirmed**: all three oracles fired 3/3 (reliability 1.0) against the official container. `attack/part_a_baseline_http_results.json` is an earlier, superseded check and can be deleted once `part_a_results.json` is the file you cite.

**On the Medium filter:** the supplied `vulnweb_app.py` has no Medium filter or middleware, and per instructor confirmation that's expected — the Medium-filter bypass requirement applies only to groups using DVWA, not to groups using `vuln-web` as provided. `medium_bypass_confirmed: false` in the output is therefore the correct, final value for this submission. The app's CMDi is intentionally simulated and does not execute `whoami`.

Run the instructor fixture self-check against the same source:

```powershell
python "$HW/duel/verify_fixtures.py" --app-path labs/vuln-web/app/vulnweb_app.py
```

Expected final line: `FIXTURES SOUND.` This verifies the fixtures and target behavior; it is not a Medium-filter test.

## Part B1 — deploy, measure, and bypass the WAF

Start the WAF proxy in a second PowerShell terminal. Variables are not shared between PowerShell windows, so define both again and use the **actual** target URL printed by `targets.py`:

```powershell
$HW = "homework/hw2/luna"
$BASE_URL = "http://127.0.0.1:54321"  # use the port printed in the first window
python "$HW/defend/waf_proxy.py" --upstream $BASE_URL --port 8001
```

Use `http://127.0.0.1:8001` for requests that should pass through the WAF. Direct requests to `$BASE_URL` bypass this proxy.

In the first terminal, measure false positives and XSS sample coverage:

```powershell
python "$HW/defend/measure_fp.py"
python "$HW/defend/measure_b1.py" --base-url http://127.0.0.1:8001
```

Expected measurements for the included files:

- benign corpus: 5/26 false positives = **19.23%**;
- XSS sample: 17/20 blocked = **85%**;
- selected Part-A literal `<script>`: 1/1 blocked;
- three same-intent XSS candidates: 3/3 allowed by the WAF and reflected unescaped.

The bypass CSV proves that the blocklist is evaded and that the endpoint returns the markup. The HTML parser decodes each `javascript:` URL. Browser execution is a separate proof and remains pending until Playwright/Chromium is run:

```powershell
py -m pip install playwright
py -m playwright install chromium
python "$HW/defend/test_xss_bypasses_browser.py" --base-url http://127.0.0.1:8001
```

Keep `browser_bypass_results.json`. Count a candidate as browser-confirmed only when `dialog_fired` is `true`.

## Part B2 — structural positive fix

Start the patched copy on loopback in another terminal (define `$HW` again in that window):

```powershell
$HW = "homework/hw2/luna"
python "$HW/defend/run_fixed_target.py" --app-path labs/vuln-web/app/vulnweb_app.py --port 8002
```

Then, in the first terminal:

```powershell
python "$HW/defend/verify_positive_fix_http.py" --base-url http://127.0.0.1:8002
python "$HW/defend/test_positive_fix.py"
```

Expected: seven HTTP regression cases and seven unit checks pass. The fixed target is a separate local copy and does not modify the instructor's source/container. The SQL fix binds parameters, the XSS fix uses `html.escape` for HTML text context, and the CMDi fix allowlists host input; each guarantee and its conditions are documented in `defend/positive_fix.md`.

## Part C — real Semgrep vs. local Ollama

Install and verify Semgrep:

```powershell
py -m pip install semgrep
semgrep --version
python "$HW/duel/run_semgrep.py" labs/vuln-web/app/vulnweb_app.py
```

The runner writes `semgrep_raw.json`, normalized `scanner_findings.json`, and `scanner_metadata.json` (Semgrep version, command, source hash, and rules hash). The custom rules are intentionally narrow and disclosed in `duel/semgrep_rules.yml`; the SQLi signature is single-line while the lab query is built from adjacent f-strings on separate lines. The lab README describes this as the scanner's expected SQLi miss. The Semgrep command still must be run for the observed output/version to count as evidence.

Check Ollama and the model:

```powershell
ollama list
ollama pull qwen2.5:3b
python -m seclab.llm --list-backends
```

If Ollama is installed but not serving, open a separate terminal and run `ollama serve`. Then run five uncached reviews against the exact same source:

```powershell
python "$HW/duel/llm_review.py" labs/vuln-web/app/vulnweb_app.py `
  --runs 5 --backend ollama --temperature 0.7 `
  --out "$HW/duel/llm_runs.jsonl"
```

Score both tools with the official course API and the independent instructor ground truth:

```powershell
python "$HW/duel/score.py" `
  --ground-truth "$HW/duel/ground_truth.json" `
  --llm-runs "$HW/duel/llm_runs.jsonl" `
  --scanner-findings "$HW/duel/scanner_findings.json" `
  --out-dir "$HW/duel"
```

`score.py` imports `ScanResult` and `compare_scanners` from the supplied `seclab.scan`; the calculation is not a separate reimplementation. It writes `metrics.csv` and `duel_report.json`, including each LLM run's findings, TP/FP/FN, precision/recall/F1, an LLM macro-average across runs, and the number of distinct finding sets. Inspect the raw LLM and Semgrep outputs before naming the LLM's strongest hallucination and the scanner's most important miss. Do not report the expected SQLi miss as observed until the Semgrep run confirms it.

## Cleanup

```powershell
python -m seclab.targets --down
```
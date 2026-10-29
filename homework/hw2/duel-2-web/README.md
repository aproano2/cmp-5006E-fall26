# Duel 2 — starter files


## What's here

- **`ground_truth.json`** — the hand-verified real vulnerabilities in the `vuln-web`
  target, keyed `(rule, location)` the way `seclab.scan.ScanResult.key()` normalizes
  them. Score your scanner and LLM against this with `seclab.scan.compare_scanners`.
  It also lists a **true negative** (`do_reflect_safe`) and a **not-present** class
  (`broken-access-control`) — flagging either is a false positive / hallucination.
  Built by *reading the source*, not by running a tool: an independent ground truth
  is the whole point (Part C honesty).

- **`benign_traffic.json`** — legitimate user inputs for measuring WAF false
  positives (Part B1, scorecard axis 5). All are genuinely benign, but some contain
  attack-adjacent English ("select the union option", "drop table tennis") so a
  broad blocklist trips on them. Run each through your filter; report the FP rate.

- **`verify_fixtures.py`** — instructor self-check: confirms the ground truth is
  real (attacks the app) and the benign corpus is truly benign. `python
  verify_fixtures.py` → *FIXTURES SOUND.*

## Bring up the target

```bash
python -m seclab.targets --up vuln-web     # or run labs/vuln-web/app/vulnweb_app.py
```

## Submit

A PR to `/homework/hw2/<lastname/` with:

- Make sure a README.md describes your homework and includes the names of the people in your group. 

- `attack/` — 3 confirmed findings (SQLi, XSS, cmdi at Medium), each oracle-confirmed.
- `defend/` — your WAF (B1: coverage + a bypass + FP rate on `benign_traffic.json`)
  and the positive fix (B2: parameterization; show the payloads now fail).
- `duel/` — scanner vs. LLM scored against `ground_truth.json`, with the LLM's
  hallucination, the scanner's miss, and non-determinism over ≥ 2 runs.
- `honesty.md`, `AI_LOG.md`.

⚠️ Axes 4 (bypass) and 5 (false positives) are mandatory for the WAF. Local sandbox
only — see [`../../resources/ethics-and-scope.md`](../../resources/ethics-and-scope.md).

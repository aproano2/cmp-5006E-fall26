# Homework 2 — Web Attack & Defend

## Group members

- Isabella Tulcan Jaya — 00329994
- Martin Montero Torres — 00328595
- Santiago Arellano Jaramillo — 00328370

The executable report is [hw2_web_attack_defend.ipynb](hw2_web_attack_defend.ipynb).
All attacks are on authenticated, loopback-only DVWA with synthetic data.

## Current evidence

- Part A: three Medium-level classes confirmed 3/3 trials each; benign controls negative.
- Part B: deployed PHP WAF blocks the three original strings; three SQLi mutations
  bypass it 3/3 trials each. Our own parameterized Medium patch prevents all six
  tested strings from leaking an extra row, with a functional benign lookup.
- Supplied generic corpus: deployed PHP WAF blocks 2/26 inputs (7.69%); this is
  not a measurement of realistic numeric-ID traffic.
- Part C: Completed; raw PHP tool evidence and metrics saved in duel/.
- [honesty.md](honesty.md): limitations, prior-results exposure, and corpus scope.

## Reproduce on Windows

Use Python 3.14 and Docker Desktop with Linux containers. From the repository root:

```powershell
python -m venv .hw2-venv
.hw2-venv/Scripts/python.exe -m pip install -r homework/hw2/montero/requirements.txt
docker compose -f homework/hw2/montero/lab.compose.yaml up -d
docker pull semgrep/semgrep
docker run -d --name hw2-montero-ollama -p 127.0.0.1:11434:11434 -v hw2-montero-ollama:/root/.ollama -e OLLAMA_NUM_PARALLEL=1 alpine/ollama@sha256:5a84f1bb6c4868f80fe02b104bc31cf48a07d5b5d8812870ada9fb7b561ed284
docker exec hw2-montero-ollama ollama pull qwen2.5:0.5b
$env:SECLAB_MODEL = 'qwen2.5:0.5b'
# Only on the first run: initialize this dedicated synthetic DVWA database.
$env:HW2_INITIALIZE_DB = '1'
.hw2-venv/Scripts/python.exe homework/hw2/montero/run_experiment.py
```

Unset HW2_INITIALIZE_DB on subsequent runs. The public lab credentials are
admin/password; override DVWA_USERNAME and DVWA_PASSWORD if needed. If Docker is
outside PATH, set DOCKER_EXE to its executable. On this machine it is at
C:/Users/isabe/AppData/Local/Programs/DockerDesktop/resources/bin/docker.exe.
DVWA_BASE defaults to http://127.0.0.1:4280. The notebook refuses non-loopback targets.

The runner verifies that scan snapshots match the actual running Medium files.
The CPU runtime is the community [alpine/ollama distribution](https://hub.docker.com/r/alpine/ollama),
pinned by digest; it reports Ollama 0.40.13. This is a real local model runtime.
It deploys our two PHP defenses only in hw2-montero-dvwa-1 and restores original
source and Medium after evaluation. It supports --part-ab, --part-c, and
--scanner-only for individual stages. To inspect interactively, open the notebook
using the same Python environment in VS Code; no separate Jupyter UI is required.

## Evidence files and provenance

- [attack/results.csv](attack/results.csv): current DVWA attacks and controls.
- [defend/dvwa_deployed_results.csv](defend/dvwa_deployed_results.csv): actual
  deployed WAF and own MySQL fix at the original Medium SQLi endpoint.
- [defend/dvwa_waf_benign_results.csv](defend/dvwa_waf_benign_results.csv): real PHP
  filter classifications of the supplied generic corpus.
- [ground_truth_manual.json](ground_truth_manual.json): AI-assisted manual PHP
  review before the new tool calls; historical vuln-web results were known.
- [duel/dvwa_source/](duel/dvwa_source/): reviewed source, including our fixed
  negative control. The three original snippets are from digininja/DVWA under
  its included GPL license; they are not group-authored vulnerable code.
- [duel/](duel/README.md): current scan evidence and separately archived originals.
- ground_truth.json and verify_fixtures.py: original instructor vuln-web fixtures,
  retained for the supplemental fixture check; not the new PHP benchmark.
- defend/evaluate.py and its SQLite CSVs: supplemental, not MySQL evidence.
- [AI_LOG.md](AI_LOG.md): assistance disclosure.

Historical results were imported from Santiago's branch homework/hw-2-arellano,
commit 65cee0f. attack/recorded_results.txt and defend/recorded_results.txt retain
those originals. Their macOS execution is not relabeled as a Windows run.

Run tests from the repository root:

```powershell
.hw2-venv/Scripts/python.exe -m pytest seclab/tests labs/vuln-web homework/hw2/montero/test_submission.py -q
.hw2-venv/Scripts/python.exe homework/hw2/montero/verify_fixtures.py
.hw2-venv/Scripts/python.exe homework/hw2/montero/defend/evaluate.py
```

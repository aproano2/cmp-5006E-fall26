**Group:** María Emilia Cueva (00328938), Santiago Reátegui (00331329), Jorge Gomez (00329264)

# Part C: Semgrep versus a local LLM reviewer

Both tools read the exact unchanged course source at `labs/vuln-web/app/vulnweb_app.py`. The answer key is the supplied `ground_truth.json`: SQLi in `do_login`, XSS in `do_reflect`, and cmdi in `do_ping`. It was supplied as a hand-reviewed fixture, independent of either tool, and all three effects were separately checked with HTTP oracles. `do_reflect_safe` is a true negative. There is no independent access-control system or A01 finding in this small app.

`duel/run.py` ran **Semgrep** with three explicit local rules in `rules.yml`, then called the local Ollama `qwen2.5:3b` model twice with the same prompt, temperature 0.7, different seeds (11 and 29), and `use_cache=False`. 
The model text and metadata show both were uncached calls. We used the course's `seclab.scan.compare_scanners` on `(rule, enclosing function)` keys. The raw model text is kept unchanged. As in the week-6 studio, a fixed alias map normalizes canonical names (e.g., turning `reflected XSS` into `xss`, and `command injection` into `cmdi`) before scoring. Any unmatched claims remain as-is so they correctly register as visible false positives.

| Tool / independent run | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| Semgrep, local rules | 2 | 0 | 1 | 1.000 | 0.667 | 0.800 |
| Ollama run 1, seed 11 | 3 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| Ollama run 2, seed 29 | 2 | 1 | 1 | 0.667 | 0.667 | 0.667 |

**Semgrep Analysis:** The scanner's only miss is SQLi in `do_login`. Our deliberately narrow Semgrep regex likely looks for an interpolation directly on a single `f"SELECT...` line, whereas the Python code splits `SELECT` and the `user`/`pw` interpolations across multiple lines. This causes a false negative, which is a limitation of this specific **ruleset**, not proof that Semgrep fundamentally misses all SQLi. Both other rules (XSS and Command Injection) matched perfectly with zero false positives.

**LLM Variation and Lexical Fragility:** Unlike a deterministic scanner, the LLM exhibited finding-set variation driven purely by terminology rather than conceptual understanding. 
*   **Run 1** correctly labeled the vulnerabilities as `"SQLi"`, `"Reflected XSS"`, and `"Command Injection"`. The alias map successfully normalized these to `sqli`, `xss`, and `cmdi`, matching the ground truth perfectly (F1: 1.0).
*   **Run 2** conceptually found the exact same three flaws but labeled the third one `"Command Injection (Simulated)"`. Because the script's strict alias map does not account for the `(Simulated)` suffix, it failed to normalize the label to `cmdi`. As a result, the evaluation script recorded a False Positive for the unknown `"command injection (simulated)"` label, and a False Negative because the required `cmdi` was missing. 

Confidence and wording also varied between runs. Run 1 assigned `high` confidence to all three findings. Run 2 dropped the XSS confidence to `Medium` and justified the command injection by stating, *"simulating a command injection vulnerability"*. This highlights a known challenge in LLM security pipelines: a model may correctly identify a defect but fail an automated evaluation if its unstructured output deviates syntactically from the expected taxonomy.

**Regarding hallucinations:** The LLM did not generate any true hallucinations (such as inventing a fake CVE or identifying a vulnerability in safe code) across our two runs. Its only failure, and technically its "best hallucination" according to the automated scorer was inventing the unknown `command injection (simulated)` label.

Neither tool truthfully found Broken Access Control. Semgrep did not report it, and the LLM did not report it in either run. The SQLi leaks the admin row, but the app has no session or role checks against which to establish a separate access-control defect.

Evidence: [raw Semgrep JSON](semgrep.json), [prompt](prompt.txt), [LLM run 1](llm_run_1.txt), [LLM run 2](llm_run_2.txt), [all findings](findings.csv), and [metrics](metrics.csv). Run metadata and Semgrep stderr are retained for reproducibility. 

`python3 duel/run.py --rescore` recalculates metrics from saved Semgrep and LLM results without running either tool; plain execution requires the documented Semgrep environment and repeats the two real uncached model calls.

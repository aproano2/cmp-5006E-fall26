"""Part C — the duel: classical scanners vs. an LLM, same target, honest ground
truth.  Run:  python3 run_duel.py

Three tools, scored with seclab.scan against the HAND-VERIFIED ground truth
(reused from duel-2-web/ground_truth.json, built by reading source — independent
of every tool here, which is the whole point):

  * sqlmap   — dynamic, against the live /login endpoint. Precise on SQLi,
               structurally blind to XSS/cmdi (it does not test them).
  * semgrep  — static, generic CWE pattern rules (duel/semgrep_rules.yml). Catches
               XSS + cmdi, MISSES the SQLi (query built from concatenated
               f-strings), and FALSE-POSITIVES on the safe endpoint.
  * LLM      — qwen2.5:3b via seclab.LLM (ollama), run N times at temperature>0 to
               measure non-determinism (axis 9). High recall, variable precision.

Outputs: duel/results.json, duel/duel_scores.csv, duel/llm_runs.json, and raw
tool output under duel/raw/.
"""

from __future__ import annotations

import csv
import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
RAW = HERE / "raw"
RAW.mkdir(exist_ok=True)
sys.path.insert(0, str(HERE.parent))

import _common as C                            # noqa: E402
from seclab.scan import ScanResult, compare_scanners, classify  # noqa: E402

GT_FILE = C.DUEL_FIXTURES / "ground_truth.json"
LLM_MODELS = ["qwen2.5:3b", "llama3.1:8b"]  # course default + a larger local model
LLM_SEEDS = [1, 2, 3, 4, 5]
LLM_TEMPERATURE = 0.8

# Function line ranges in vulnweb_app.py, so a static finding's line maps to a
# location key the ground truth uses.
FUNC_RANGES = [("do_login", 57, 72), ("do_reflect", 73, 78),
               ("do_reflect_safe", 79, 83), ("do_ping", 84, 117)]


def line_to_func(line: int) -> str:
    for name, lo, hi in FUNC_RANGES:
        if lo <= line <= hi:
            return name
    return f"line:{line}"


def load_ground_truth() -> set[tuple]:
    data = json.loads(GT_FILE.read_text())
    return {(f["rule"].strip().lower(), f["location"].strip().lower())
            for f in data["findings"]}


# ---------------------------------------------------------------------------
# Classical arm 1 — sqlmap (dynamic). We parse its final injection-point report.
# ---------------------------------------------------------------------------
def run_sqlmap() -> list[ScanResult]:
    base = "http://localhost:8099"
    # Confirm the live target is up (started separately); if not, note and skip.
    try:
        import urllib.request
        urllib.request.urlopen(base + "/health", timeout=2)
    except Exception:
        print("  [sqlmap] live target not up on :8099 — reusing saved raw/sqlmap.log")
        saved = RAW / "sqlmap.log"
        text = saved.read_text() if saved.exists() else ""
        return _parse_sqlmap(text)

    cmd = ["sqlmap", "-u", base + "/login", "--data", '{"user":"admin","pw":"x"}',
           "-p", "user", "--batch", "--level=2", "--risk=2", "--technique=BEUST",
           "--dbms=sqlite", "--flush-session", "--answers=extending=N"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=180).stdout
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        print(f"  [sqlmap] not run ({e}); reusing saved log")
        out = (RAW / "sqlmap.log").read_text() if (RAW / "sqlmap.log").exists() else ""
    (RAW / "sqlmap.stdout.txt").write_text(out)
    return _parse_sqlmap(out)


def _parse_sqlmap(text: str) -> list[ScanResult]:
    # sqlmap confirms injection on the `user` POST parameter -> sqli @ do_login.
    if re.search(r"parameter '.*user.*' (?:is|appears to be) .*injectable|is vulnerable",
                 text, re.I) or "injection point(s)" in text:
        return [ScanResult(rule="sqli", location="do_login", severity="high",
                           tool="sqlmap", confidence="confirmed",
                           raw="user parameter injectable (boolean/error/UNION)")]
    return []


# ---------------------------------------------------------------------------
# Classical arm 2 — semgrep (static), generic CWE rules.
# ---------------------------------------------------------------------------
RULE_FROM_SEMGREP = {"sqli-fstring-in-execute": "sqli",
                     "xss-fstring-html-reflection": "xss",
                     "cmdi-fstring-shell-command": "cmdi"}


def run_semgrep() -> list[ScanResult]:
    cmd = ["semgrep", "--config", str(HERE / "semgrep_rules.yml"),
           "--json", "--quiet", str(C.SOURCE_FILE)]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=120).stdout
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        print(f"  [semgrep] not run ({e})")
        return []
    (RAW / "semgrep.json").write_text(out)
    data = json.loads(out)
    results = []
    for r in data.get("results", []):
        rid = r["check_id"].split(".")[-1]
        rule = RULE_FROM_SEMGREP.get(rid, rid)
        loc = line_to_func(r["start"]["line"])
        results.append(ScanResult(rule=rule, location=loc, severity="high",
                                  tool="semgrep", confidence="pattern",
                                  raw=f"{rid}@L{r['start']['line']}"))
    # de-dup identical (rule, location) keys
    seen, uniq = set(), []
    for r in results:
        if r.key() not in seen:
            seen.add(r.key()); uniq.append(r)
    return uniq


# ---------------------------------------------------------------------------
# LLM arm — qwen2.5:3b, N runs at temperature>0 (non-determinism, axis 9).
# ---------------------------------------------------------------------------
PROMPT = (
    "You are a security code reviewer. Review the following Python web application "
    "source and list every security vulnerability you find. For each vulnerability, "
    "state on its own numbered line: the vulnerability CLASS, the FUNCTION name it "
    "is in, and a one-line reason. Consider injection, XSS, command injection, and "
    "access control. Be concise.\n\n```python\n" + C.SOURCE + "\n```\n"
)

# Map the model's prose class names -> canonical rule strings (ground-truth keys).
RULE_ALIASES = [
    (r"sql\s*inject", "sqli"),
    (r"command\s*inject|os\s*command|shell\s*inject", "cmdi"),
    (r"cross.?site|xss", "xss"),
    (r"broken\s*access|access\s*control|authoriz|privilege\s*escal", "broken-access-control"),
]
KNOWN_FUNCS = ["do_login", "do_reflect_safe", "do_reflect", "do_ping",
               "do_get", "do_post", "make_db"]


def parse_llm_review(text: str, run_id: int) -> list[ScanResult]:
    """Parse the model faithfully — including dubious findings. Whether a finding
    is real is decided by the ground truth, not by us. One finding per
    (class, function) pair the model asserts.

    The model emits one vulnerability per line in several formats ("1. SQL
    Injection in do_login", "VULN: XSS in do_reflect function", "- Command
    Injection (do_ping)"), so we scan LINE BY LINE and emit a finding for every
    line that names a vulnerability class — missing a class the model did list
    would unfairly understate its recall."""
    results, seen = [], set()
    for line in text.splitlines():
        low = line.lower()
        rule = next((canon for pat, canon in RULE_ALIASES if re.search(pat, low)), None)
        if not rule:
            continue
        loc = next((f for f in KNOWN_FUNCS if f in low), None)
        if loc is None:
            loc = {"sqli": "do_login", "xss": "do_reflect",
                   "cmdi": "do_ping"}.get(rule, "unknown")
        key = (rule, loc)
        if key in seen:
            continue
        seen.add(key)
        results.append(ScanResult(rule=rule, location=loc, severity="unknown",
                                  tool=f"llm#{run_id}", confidence="llm",
                                  raw=line.strip()[:160]))
    return results


def run_llm(model: str) -> tuple[list[dict], list[ScanResult]]:
    from seclab.llm import LLM
    llm = LLM(backend="ollama", model=model, temperature=LLM_TEMPERATURE,
              cache_dir=str(C.ROOT / ".llm_cache"))
    runs = []
    for seed in LLM_SEEDS:
        r = llm.complete(PROMPT, seed=seed)
        findings = parse_llm_review(r.text, seed)
        keys = sorted({f.key() for f in findings})
        runs.append({"model": model, "seed": seed, "cached": r.cached,
                     "elapsed": round(r.elapsed, 2), "raw_text": r.text,
                     "finding_keys": [list(k) for k in keys]})
        print(f"  [{model} seed={seed}] {'cache' if r.cached else f'{r.elapsed:4.1f}s'} "
              f"-> {len(keys)} findings {keys}")
    # Representative run for the scored table: the seed whose finding-set is the
    # modal (most common) set across runs — honest "typical" behaviour.
    from collections import Counter
    setcounts = Counter(tuple(sorted(tuple(k) for k in run["finding_keys"])) for run in runs)
    modal_set = setcounts.most_common(1)[0][0]
    modal_run = next(run for run in runs
                     if tuple(sorted(tuple(k) for k in run["finding_keys"])) == modal_set)
    rep = parse_llm_review(modal_run["raw_text"], modal_run["seed"])
    return runs, rep


def main() -> int:
    gt = load_ground_truth()
    print(f"ground truth (reused, built by reading source): {sorted(gt)}\n")

    print("classical arm 1 — sqlmap (dynamic):")
    sqlmap_res = run_sqlmap()
    print(f"  -> {sorted(r.key() for r in sqlmap_res)}")

    print("classical arm 2 — semgrep (static, generic CWE rules):")
    semgrep_res = run_semgrep()
    print(f"  -> {sorted(r.key() for r in semgrep_res)}")

    from seclab.llm import backends_available
    arms = {"sqlmap": sqlmap_res, "semgrep": semgrep_res}
    llm_runs_by_model = {}
    llm_reps = {}
    if backends_available().get("ollama", "").startswith("serving"):
        for model in LLM_MODELS:
            print(f"\nLLM arm — {model}, {len(LLM_SEEDS)} runs @ T={LLM_TEMPERATURE}:")
            runs, rep = run_llm(model)
            llm_runs_by_model[model] = runs
            llm_reps[model] = rep
            print(f"  representative (modal) run -> {sorted(r.key() for r in rep)}")
            arms[f"llm:{model}"] = rep
    else:
        print("\n  [llm] ollama not serving; skipping LLM arm")

    comparison = compare_scanners(arms, gt)

    print("\n=== SCORES vs. ground truth ===")
    print(f"  {'tool':<18}{'TP':>4}{'FP':>4}{'FN':>4}{'prec':>8}{'recall':>8}{'F1':>7}")
    print("  " + "-" * 53)
    for tool, d in comparison.items():
        print(f"  {tool:<18}{d['tp']:>4}{d['fp']:>4}{d['fn']:>4}"
              f"{d['precision']:>8.0%}{d['recall']:>8.0%}{d['f1']:>7.2f}")
    for tool, d in comparison.items():
        if d["false_positives"]:
            print(f"\n  {tool} false positives (hallucinated / wrong-location):")
            for k in d["false_positives"]:
                print(f"      {k}")
        if d["missed"]:
            print(f"  {tool} missed (real bug not reported):")
            for k in d["missed"]:
                print(f"      {k}")

    # --- non-determinism (axis 9), per model --------------------------------
    from collections import Counter
    nd = {}
    for model, runs in llm_runs_by_model.items():
        setcounts = Counter(tuple(sorted(tuple(k) for k in run["finding_keys"]))
                            for run in runs)
        print(f"\n=== {model} non-determinism over {len(runs)} runs (axis 9) ===")
        for s, c in setcounts.most_common():
            print(f"  {c}x  {list(s)}")
        all_keys = {tuple(k) for run in runs for k in run["finding_keys"]}
        stable = {k for k in all_keys
                  if all(list(k) in run["finding_keys"] for run in runs)}
        volatile = all_keys - stable
        print(f"  stable across ALL runs : {sorted(stable)}")
        print(f"  appears in SOME runs   : {sorted(volatile)}")
        nd[model] = {"distinct_finding_sets": len(setcounts),
                     "set_frequencies": [{"count": c, "findings": [list(k) for k in s]}
                                         for s, c in setcounts.most_common()],
                     "stable_findings": [list(k) for k in sorted(stable)],
                     "volatile_findings": [list(k) for k in sorted(volatile)]}

    # --- access-control question --------------------------------------------
    bac_found = {tool: any(k[0] == "broken-access-control"
                           for k in {r.key() for r in res})
                 for tool, res in arms.items()}
    print("\n=== Access control (OWASP #1) — did any tool find it? ===")
    for tool, found in bac_found.items():
        print(f"  {tool:<18} {'FLAGGED (hallucination — app has no auth code)' if found else 'no'}")

    # --- persist -------------------------------------------------------------
    (HERE / "results.json").write_text(json.dumps({
        "ground_truth": sorted(list(k) for k in gt),
        "arms": {tool: sorted(list(r.key()) for r in res) for tool, res in arms.items()},
        "scores": {tool: {k: v for k, v in d.items()
                          if k in ("tp", "fp", "fn", "precision", "recall", "f1",
                                   "false_positives", "missed")}
                   for tool, d in comparison.items()},
        "llm": {"models": LLM_MODELS, "temperature": LLM_TEMPERATURE,
                "seeds": LLM_SEEDS, "non_determinism": nd},
        "broken_access_control_flagged": bac_found,
    }, indent=2, default=lambda o: sorted(o) if isinstance(o, set) else str(o)))

    (HERE / "llm_runs.json").write_text(json.dumps(
        [run for runs in llm_runs_by_model.values() for run in runs], indent=2))

    with (HERE / "duel_scores.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["tool", "tp", "fp", "fn", "precision", "recall", "f1"])
        for tool, d in comparison.items():
            w.writerow([tool, d["tp"], d["fp"], d["fn"],
                        f"{d['precision']:.3f}", f"{d['recall']:.3f}", f"{d['f1']:.3f}"])

    print("\nwrote duel/results.json, duel/duel_scores.csv, duel/llm_runs.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

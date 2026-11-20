#Names: Luis Eduardo Zaldumbide, Miguel Jarrin, Josue Lopez
#Class: Computer Security
#Date: 6/11/2026

# Part C. The duel: sqlmap vs an LLM reviewer, scored with seclab.scan against
# duel/ground_truth.json.
#
#   python duel_partC.py scan    run sqlmap (level 3, risk 3) on every endpoint of the app
#   python duel_partC.py llm     run the LLM review twice and save both answers
#   python duel_partC.py score   parse raw/, score both tools, write c_scores.csv and c_findings.csv
#   python duel_partC.py all     the three in order
#
# score only reads raw/, so the numbers can be checked without sqlmap or Ollama.
#
# Environment
#   SECLAB_REPO   path to cmp-5006E-fall26 if this folder is not inside the repo
#   SQLMAP_BIN    path to sqlmap if it is not on PATH
#   SECLAB_MODEL  Ollama model (default qwen2.5:1.5b, the model we had pulled)

from __future__ import annotations

import ast
import csv
import hashlib
import io
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import tokenize
from http.server import ThreadingHTTPServer

HERE = pathlib.Path(__file__).resolve().parent
RAW = HERE / "raw"


def find_repo() -> pathlib.Path:
    env = os.environ.get("SECLAB_REPO")
    if env:
        return pathlib.Path(env).resolve()
    for p in HERE.parents:
        if (p / "seclab" / "scan.py").exists() and (p / "labs" / "vuln-web").exists():
            return p
    sys.exit("cannot find the course repo: set SECLAB_REPO=/path/to/cmp-5006E-fall26")


REPO = find_repo()
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "labs" / "vuln-web" / "app"))

from seclab.scan import ScanResult, classify          # noqa: E402
import vulnweb_app as app                             # noqa: E402

SOURCE = (REPO / "labs" / "vuln-web" / "app" / "vulnweb_app.py").read_text(encoding="utf-8")
GROUND_TRUTH_FILE = HERE / "ground_truth.json"


def load_ground_truth() -> tuple[set, dict]:
    data = json.loads(GROUND_TRUTH_FILE.read_text(encoding="utf-8"))
    gt = {(f["rule"].strip().lower(), f["location"].strip().lower())
          for f in data["findings"]}
    return gt, data


# ===========================================================================
# Classical scanner: sqlmap against every endpoint
# ===========================================================================
# sqlmap reports an endpoint, the ground truth is keyed by function, so each
# route is mapped to its handler (read off Handler.do_GET / do_POST).
# Realistic starting values (admin, alice, example.com) give sqlmap a normal
# request to mutate.
def endpoints(base: str) -> list[tuple[str, str, list[str]]]:
    return [
        ("POST /login", "do_login", ["-u", f"{base}/login", "--data", '{"user":"admin","pw":"x"}']),
        ("GET /", "do_reflect", ["-u", f"{base}/?name=alice"]),
        ("GET /safe", "do_reflect_safe", ["-u", f"{base}/safe?name=alice"]),
        ("POST /ping", "do_ping", ["-u", f"{base}/ping", "--data", '{"host":"example.com"}']),
    ]


SQLMAP_SETTINGS = ["--level", "3", "--risk", "3"]


def run_sqlmap() -> None:
    sqlmap = os.environ.get("SQLMAP_BIN") or shutil.which("sqlmap")
    if not sqlmap:
        sys.exit("sqlmap not found: install it or set SQLMAP_BIN")
    # vuln-web in process on 127.0.0.1, port chosen by the OS. Local only.
    app.DB = app.make_db()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        for route, func, args in endpoints(base):
            app.DB = app.make_db()
            with tempfile.TemporaryDirectory() as tmp:
                proc = subprocess.run(
                    [sqlmap, *args, "--batch", "--flush-session", "--disable-coloring",
                     "--output-dir", tmp, *SQLMAP_SETTINGS],
                    capture_output=True, text=True)
            log = (proc.stdout + proc.stderr).replace(base, "http://127.0.0.1:PORT")
            (RAW / f"sqlmap_{func}.log").write_text(f"# route: {route}\n" + log, encoding="utf-8")
            print(f"[sqlmap] {route:<12} injectable="
                  f"{'identified the following injection point' in log}")
    finally:
        srv.shutdown()


def parse_sqlmap() -> list[dict]:
    rows = []
    for route, func, _ in endpoints(""):
        path = RAW / f"sqlmap_{func}.log"
        if not path.exists():
            continue
        log = path.read_text(encoding="utf-8")
        if "identified the following injection point" in log:
            types = re.findall(r"^\s+Type: (.+)$", log, re.M)
            rows.append({"tool": "sqlmap", "run": "level3-risk3",
                         "result": ScanResult(rule="sqli", location=func, tool="sqlmap"),
                         "raw": f"{route}: " + ", ".join(types)})
    return rows


# ===========================================================================
# LLM reviewer: qwen2.5:1.5b on a local Ollama, through seclab.LLM
# ===========================================================================
LLM_MODEL = os.environ.get("SECLAB_MODEL", "qwen2.5:1.5b")
LLM_RUNS = [("run1", 0.8, 1), ("run2", 0.8, 2)]     # (run id, temperature, seed)
MAX_TOKENS = 600

PROMPT_TEMPLATE = """You are a security code reviewer. Review the Python web application below and list every security vulnerability you find.

Write one line per vulnerability, in exactly this format:
FINDING | <vulnerability class> | <python function name> | <severity: HIGH, MEDIUM or LOW> | <example malicious input> | <one sentence reason>

Use the name of the Python function that contains the vulnerable code. Write NONE if there are no vulnerabilities.

```python
{source}
```
"""


def strip_comments_and_docstrings(src: str) -> str:
    """The app comments name every bug ("# VULN: SQL injection"), so the LLM gets
    the source without comments and docstrings. Otherwise it would be reading
    the answer key."""
    drop = set()
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.ClassDef)) and node.body:
            first = node.body[0]
            if (isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant)
                    and isinstance(first.value.value, str)):
                drop.update(range(first.lineno, first.end_lineno + 1))
    cuts = {t.start[0]: t.start[1]
            for t in tokenize.generate_tokens(io.StringIO(src).readline)
            if t.type == tokenize.COMMENT}
    out = []
    for i, line in enumerate(src.splitlines(keepends=True), 1):
        if i in drop:
            continue
        if i in cuts:
            line = line[:cuts[i]].rstrip()
            if not line.strip():
                continue
            line += "\n"
        out.append(line)
    text = re.sub(r"\n{3,}", "\n\n", "".join(out)).strip() + "\n"
    assert "VULN" not in text
    return text


def make_llm():
    """seclab.LLM with ONE change: a cap on generated tokens. Without it
    qwen2.5:1.5b repeats the same line forever and the 120 s timeout kills it."""
    import urllib.request as ur
    from seclab import LLM
    from seclab.llm import OLLAMA_URL

    class CappedLLM(LLM):
        def _ollama(self, prompt, temperature, seed):
            body = {"model": self.model, "prompt": prompt, "stream": False,
                    "options": {"temperature": temperature, "seed": seed,
                                "num_predict": MAX_TOKENS}}
            req = ur.Request(f"{OLLAMA_URL}/api/generate",
                             data=json.dumps(body).encode("utf-8"),
                             headers={"Content-Type": "application/json"})
            with ur.urlopen(req, timeout=self.timeout) as r:
                data = json.load(r)
            return data.get("response", ""), {k: data[k] for k in
                                              ("eval_count", "done_reason") if k in data}

    return CappedLLM(backend="ollama", model=LLM_MODEL, timeout=600)


def run_llm() -> None:
    llm = make_llm()
    prompt = PROMPT_TEMPLATE.format(source=strip_comments_and_docstrings(SOURCE))
    records = []
    for run_id, temp, seed in LLM_RUNS:
        # use_cache=False so each run is a real inference, not a copy from disk.
        r = llm.complete(prompt, temperature=temp, seed=seed, use_cache=False)
        if r.error:
            sys.exit(f"LLM error on {run_id}: {r.error}")
        print(f"[llm] {run_id} T={temp} seed={seed} {r.elapsed:.1f}s")
        records.append({"run": run_id, "model": r.model, "temperature": temp,
                        "seed": seed, "meta": r.meta,
                        "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
                        "text": r.text})
        (RAW / f"llm_{run_id}.txt").write_text(r.text, encoding="utf-8")
    (RAW / "llm_runs.json").write_text(json.dumps(records, indent=2), encoding="utf-8")
    (RAW / "llm_prompt.txt").write_text(prompt, encoding="utf-8")


# Prose class name to canonical rule.
def normalize_rule(cls: str) -> str:
    c = cls.lower()
    if "sql" in c:
        return "sqli"
    if "xss" in c or "cross site" in c or "cross-site" in c:
        return "xss"
    if "command" in c or "shell" in c:
        return "cmdi"
    if "access control" in c or "authoriz" in c:
        return "broken-access-control"
    return re.sub(r"[^a-z0-9]+", "-", c).strip("-") or "unknown"


FUNC_NAMES = sorted({n.name for n in ast.walk(ast.parse(SOURCE))
                     if isinstance(n, ast.FunctionDef)}, key=len, reverse=True)


def normalize_location(text: str) -> str:
    for name in FUNC_NAMES:                  # longest first: do_reflect_safe before do_reflect
        if re.search(rf"\b{re.escape(name)}\b", text, re.I):
            return name.lower()
    return text.strip().strip("`'\"").lower() or "unknown"


def parse_llm() -> list[dict]:
    """Every FINDING line becomes a ScanResult, including the dubious ones. Lines
    where the model itself says there is nothing ("FINDING | None | NONE") are
    skipped."""
    path = RAW / "llm_runs.json"
    if not path.exists():
        return []
    rows = []
    for rec in json.loads(path.read_text(encoding="utf-8")):
        for line in rec["text"].splitlines():
            if "|" not in line or "FINDING" not in line.upper():
                continue
            parts = [p.strip() for p in line.split("|")]
            while parts and parts[-1] == "":
                parts.pop()
            fields = parts[1:]
            if len(fields) < 2 or fields[0].startswith("<"):
                continue
            if fields[0].lower() in {"none", "n/a", ""}:
                continue
            rows.append({"tool": "llm", "run": rec["run"],
                         "result": ScanResult(rule=normalize_rule(fields[0]),
                                              location=normalize_location(fields[1]),
                                              tool="llm"),
                         "raw": line.strip()})
    return rows


# ===========================================================================
# Scoring
# ===========================================================================
def verdict(key: tuple, gt: set, gt_data: dict) -> str:
    if key in gt:
        return "true positive"
    if key[1] in {t["location"].lower() for t in gt_data["true_negatives"]}:
        return "false positive: flags the true negative"
    if key[0] in {n["rule"].lower() for n in gt_data["not_present"]}:
        return "false positive: class not present in the app"
    return "false positive"


def write_csv(path: pathlib.Path, rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


def score() -> None:
    gt, gt_data = load_ground_truth()
    rows = parse_sqlmap() + parse_llm()

    write_csv(HERE / "c_findings.csv", [
        {"tool": r["tool"], "run": r["run"], "rule": r["result"].key()[0],
         "location": r["result"].key()[1],
         "verdict": verdict(r["result"].key(), gt, gt_data), "raw": r["raw"]}
        for r in rows])

    scores, sets = [], {}
    for tool, run in [("sqlmap", "level3-risk3")] + [("llm", r[0]) for r in LLM_RUNS]:
        found = [r["result"] for r in rows if r["tool"] == tool and r["run"] == run]
        sets[run] = {f.key() for f in found}
        d = classify(found, gt)
        scores.append({"tool": tool, "run": run, "reported": d["tp"] + d["fp"],
                       "tp": d["tp"], "fp": d["fp"], "fn": d["fn"],
                       "precision": round(d["precision"], 2),
                       "recall": round(d["recall"], 2), "f1": round(d["f1"], 2),
                       "false_positives": " ".join(f"{k[0]}@{k[1]}" for k in d["false_positives"]),
                       "missed": " ".join(f"{k[0]}@{k[1]}" for k in d["missed"])})
    write_csv(HERE / "c_scores.csv", scores)

    print(f"\n  {'tool':<8}{'run':<14}{'TP':>4}{'FP':>4}{'FN':>4}{'prec':>7}{'rec':>7}{'F1':>6}")
    for s in scores:
        print(f"  {s['tool']:<8}{s['run']:<14}{s['tp']:>4}{s['fp']:>4}{s['fn']:>4}"
              f"{s['precision']:>7.2f}{s['recall']:>7.2f}{s['f1']:>6.2f}")
    a, b = sets.get("run1", set()), sets.get("run2", set())
    print("\n  LLM findings in both runs:   ", sorted(a & b))
    print("  LLM findings only in run1:   ", sorted(a - b))
    print("  LLM findings only in run2:   ", sorted(b - a))
    print("\n  wrote c_scores.csv and c_findings.csv")


def main(argv: list[str]) -> int:
    RAW.mkdir(exist_ok=True)
    step = argv[1] if len(argv) > 1 else "score"
    if step not in ("scan", "llm", "score", "all"):
        print("usage: python duel_partC.py [scan|llm|score|all]")
        return 2
    if step in ("scan", "all"):
        run_sqlmap()
    if step in ("llm", "all"):
        run_llm()
    score()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

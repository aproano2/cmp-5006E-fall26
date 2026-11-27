"""Part C: score scanners and LLM runs against OUR hand-built ground truth.

Reads only the committed raw outputs in duel/raw/ (no tool is re-run), turns them
into seclab.scan.ScanResult, and scores with seclab.scan.compare_scanners.

    python3 duel/score.py             # from homework/hw2/soto/
"""
import ast
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import common as c                                    # noqa: E402
from seclab.scan import ScanResult, compare_scanners, print_comparison  # noqa: E402

RAW = HERE / "raw"
SRC_PATH = c.ROOT / "labs" / "vuln-web" / "app" / "vulnweb_app.py"
GT = json.loads((HERE / "ground_truth.json").read_text())
TRUTH = {(f["rule"], f["location"]) for f in GT["findings"]}
OUT_OF_SCOPE = {(f["rule"].strip().lower(), f["location"].strip().lower())
                for f in GT["out_of_scope_real"]}
TRUE_NEG = {(f["rule"], f["location"]) for f in GT["true_negatives"]}
NOT_PRESENT = {f["rule"] for f in GT["not_present"]}


# --- normalization: tool vocabulary -> our rule names -------------------------
def norm_rule(text):
    t = text.lower()
    if "access control" in t or "authoriz" in t or "idor" in t or "privilege" in t:
        return "broken-access-control"
    if "inject" in t or "sqli" in t or "cmdi" in t:
        if "sql" in t:
            return "sqli"
        if "command" in t or "shell" in t or "os " in t:
            return "cmdi"
    if "xss" in t or "cross-site scripting" in t or "cross site scripting" in t:
        return "xss"
    if "csrf" in t or "cross-site request forgery" in t:
        return "csrf"
    if "rate limit" in t or "brute" in t:
        return "missing-rate-limiting"
    if "bind" in t or "interface" in t:
        return "bind-all-interfaces"
    if "hardcoded" in t or "hard-coded" in t or "default credential" in t:
        return "hardcoded-credentials"
    if "plaintext" in t or "cleartext" in t or "plain text" in t or "hash" in t:
        return "plaintext-password"
    if "disclos" in t or "error message" in t or "verbose" in t or "leak" in t \
            or "exposure" in t:
        return "information-disclosure"
    return re.sub(r"[^a-z0-9]+", "-", t).strip("-")


SRC_FUNCS = {}  # line -> innermost enclosing function name
for node in ast.walk(ast.parse(SRC_PATH.read_text())):
    if isinstance(node, ast.FunctionDef):
        for ln in range(node.lineno, node.end_lineno + 1):
            if ln not in SRC_FUNCS or node.lineno > SRC_FUNCS[ln][0]:
                SRC_FUNCS[ln] = (node.lineno, node.name)


def func_at(line):
    return SRC_FUNCS.get(line, (0, "<module>"))[1]


# --- parsers, one per tool ----------------------------------------------------
def parse_semgrep():
    d = json.loads((RAW / "semgrep.json").read_text())
    return [ScanResult(norm_rule(r["check_id"] + " " + r["extra"]["message"]),
                       func_at(r["start"]["line"]), r["extra"]["severity"], "semgrep",
                       raw=r["check_id"]) for r in d["results"]]


BANDIT_RULES = {"B608": "sqli", "B105": "hardcoded-credentials",
                "B104": "bind-all-interfaces"}


def parse_bandit():
    d = json.loads((RAW / "bandit.json").read_text())
    return [ScanResult(BANDIT_RULES.get(r["test_id"], r["test_id"].lower()),
                       func_at(r["line_number"]), r["issue_severity"], "bandit",
                       r["issue_confidence"], f'{r["test_id"]} {r["issue_text"]}')
            for r in d["results"]]


SQLMAP_FUNCS = {"login": "do_login", "ping": "do_ping", "reflect": "do_reflect",
                "safe": "do_reflect_safe"}


def parse_sqlmap():
    out = []
    for name, fn in SQLMAP_FUNCS.items():
        text = (RAW / f"sqlmap_{name}.txt").read_text()
        if "identified the following injection point" in text:
            out.append(ScanResult("sqli", fn, "high", "sqlmap", raw=f"/{name}"))
    return out


def parse_llm(path):
    d = json.loads(path.read_text())
    text = re.sub(r"<think>.*?</think>", "", d["text"], flags=re.S)
    m = re.search(r"\[.*\]", text, re.S)
    try:
        items = json.loads(m.group(0)) if m else []
    except json.JSONDecodeError:
        items = []
    out = []
    for it in items:
        fn = str(it.get("function", "")).split(".")[-1].split("(")[0].strip()
        out.append(ScanResult(norm_rule(str(it.get("vulnerability", ""))), fn,
                              str(it.get("severity", "")), d["run"],
                              raw=f'{it.get("vulnerability")} | {it.get("reason")}'))
    return out


def verdict(r):
    k = r.key()
    if k in TRUTH:
        return "TP"
    if k in OUT_OF_SCOPE:
        return "FP (real, out of scope)"
    if k in TRUE_NEG:
        return "FP (flagged the fixed /safe endpoint)"
    if k[0] in NOT_PRESENT:
        return "FP (hallucinated: class not present)"
    if k[1] not in {n.lower() for _, n in SRC_FUNCS.values()} | {"<module>"}:
        return "FP (hallucinated: no such function)"
    return "FP"


def main():
    instructor = json.loads((c.ROOT / "homework/hw2/duel-2-web/ground_truth.json").read_text())
    same = TRUTH == {(f["rule"], f["location"]) for f in instructor["findings"]}
    print(f"  our ground truth == instructor fixture (scored findings): {same}\n")

    tools = {"semgrep": parse_semgrep(), "bandit": parse_bandit(), "sqlmap": parse_sqlmap()}
    llm_runs = {p.stem.removeprefix("llm_"): parse_llm(p) for p in sorted(RAW.glob("llm_*.json"))}
    tools.update({f"llm:{k}": v for k, v in llm_runs.items()})

    def dedup(rs):
        return list({r.key(): r for r in rs}.values())

    strict = compare_scanners({k: dedup(v) for k, v in tools.items()}, TRUTH)
    adjusted = compare_scanners({k: [r for r in dedup(v) if r.key() not in OUT_OF_SCOPE]
                                 for k, v in tools.items()}, TRUTH)
    print("  STRICT (headline):")
    print_comparison(strict)
    print("\n  ADJUSTED (real-but-out-of-scope findings removed):")
    for k, d in adjusted.items():
        print(f"    {k:<14} P={d['precision']:.0%} R={d['recall']:.0%} F1={d['f1']:.2f}")

    c.write_csv("duel_scores.csv", [
        {"tool": k, "tp": s["tp"], "fp": s["fp"], "fn": s["fn"],
         "precision": round(s["precision"], 3), "recall": round(s["recall"], 3),
         "f1": round(s["f1"], 3), "adj_precision": round(adjusted[k]["precision"], 3),
         "adj_f1": round(adjusted[k]["f1"], 3),
         "missed": "; ".join("/".join(m) for m in s["missed"])}
        for k, s in strict.items()])
    c.write_csv("duel_findings.csv", [
        {"tool": r.tool, "rule": r.rule, "location": r.location, "severity": r.severity,
         "verdict": verdict(r), "raw": r.raw[:200]}
        for v in tools.values() for r in dedup(v)])

    # --- non-determinism across LLM runs (axis 9) -------------------------------
    if llm_runs:
        sets = {k: {r.key() for r in v} for k, v in llm_runs.items()}
        union = set().union(*sets.values())
        every = set.intersection(*sets.values())
        print(f"\n  LLM non-determinism over {len(sets)} runs:")
        print(f"    findings in EVERY run: {sorted(every)}")
        print(f"    findings in SOME run : {sorted(union - every)}")
        nd_rows = [{"finding": "/".join(k),
                    "verdict": verdict(ScanResult(*k)),
                    **{run: int(k in s) for run, s in sets.items()},
                    "runs_reporting": f"{sum(k in s for s in sets.values())}/{len(sets)}"}
                   for k in sorted(union)]
        c.write_csv("llm_nondeterminism.csv", nd_rows)


if __name__ == "__main__":
    main()

"""Part C: real local Semgrep and two uncached Ollama reviews of one source."""

import ast
import csv
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = ROOT.parents[2]  

sys.path.insert(0, str(ROOT))      
sys.path.insert(0, str(REPO_ROOT))  

from seclab.llm import LLM  # noqa: E402
from seclab.scan import ScanResult, compare_scanners  # noqa: E402

SOURCE_FILE = REPO_ROOT / "labs" / "vuln-web" / "app" / "vulnweb_app.py"
SOURCE = SOURCE_FILE.read_text(encoding="utf-8")
DUEL = ROOT / "duel"
RULE_ALIASES = {
    "sql injection": "sqli", "sqli": "sqli",
    "reflected xss": "xss", "xss": "xss",
    "command injection": "cmdi", "cmdi": "cmdi",
    "broken access control": "broken-access-control",
}


def semgrep_executable() -> str:
    windows = sys.platform.startswith("win")
    local = ROOT / ".venv" / ("Scripts" if windows else "bin") / (
        "semgrep.exe" if windows else "semgrep"
    )
    if local.is_file():
        return str(local)
    installed = shutil.which("semgrep")
    if installed:
        return installed
    raise RuntimeError("Semgrep not found; install it in .venv or add it to PATH")


def enclosing_function(line: int) -> str:
    tree = ast.parse(SOURCE)
    functions = [node for node in ast.walk(tree)
                 if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                 and node.lineno <= line <= node.end_lineno]
    return min(functions, key=lambda node: node.end_lineno - node.lineno).name if functions else f"line:{line}"


def semgrep_scan(*, from_saved=False) -> list[ScanResult]:
    if from_saved:
        data = json.loads((DUEL / "semgrep.json").read_text(encoding="utf-8"))
    else:
        command = [semgrep_executable(), "scan", "--config", str(DUEL / "rules.yml"),
                   "--metrics=off", "--json", str(SOURCE_FILE)]
        process = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                                 encoding="utf-8", timeout=120)
        (DUEL / "semgrep.json").write_text(process.stdout, encoding="utf-8")
        (DUEL / "semgrep-stderr.txt").write_text(process.stderr, encoding="utf-8")
        if process.returncode != 0:
            raise RuntimeError(f"Semgrep failed: exit {process.returncode}; see semgrep-stderr.txt")
        data = json.loads(process.stdout)
    return [ScanResult(rule=item["check_id"].split(".")[-1],
                       location=enclosing_function(item["start"]["line"]),
                       severity=item["extra"].get("severity", "unknown"),
                       tool="semgrep-local-rules", raw=item["extra"].get("message", ""))
            for item in data.get("results", [])]


def parse_review(raw: str, run_name: str) -> list[ScanResult]:
    stripped = raw.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?\s*|\s*```$", "", stripped)
    
    # Sanitiza secuencias de escape inválidas generadas por el LLM (como \' o barras de regex)
    sanitized = re.sub(r'\\(?!["\\/bfnrtu])', r'\\\\', stripped)
    try:
        data = json.loads(sanitized, strict=False)
    except json.JSONDecodeError:
        data = json.loads(stripped, strict=False)

    if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
        raise ValueError(f"{run_name}: expected JSON object with findings array")
    results = []
    for item in data["findings"]:
        if not isinstance(item, dict) or not isinstance(item.get("rule"), str) or \
           not isinstance(item.get("location"), str):
            raise ValueError(f"{run_name}: malformed finding {item!r}")
        label = item["rule"].strip().lower()
        # Course week-6 alias policy: normalize a prose class name, preserving
        # unmatched claims as-is so they remain visible false positives.
        rule = next((canonical for alias, canonical in RULE_ALIASES.items()
                     if label == alias or label.startswith(alias + " - ")), label)
        results.append(ScanResult(rule=rule, location=item["location"],
                                  tool=run_name, confidence=str(item.get("confidence", "")),
                                  raw=str(item.get("reason", ""))))
    return results


def llm_reviews(*, from_saved=False) -> dict[str, list[ScanResult]]:
    prompt = ("Review the following Python source for security vulnerabilities. "
              "Return ONLY a JSON object with a findings array. Each finding must have "
              "rule (short vulnerability class), location (enclosing function name), "
              "confidence, and reason. Include every finding you believe exists; do not "
              "silently omit uncertain findings. Do not use markdown.\n\n" + SOURCE)
    (DUEL / "prompt.txt").write_text(prompt, encoding="utf-8")
    llm = LLM(backend="ollama", model="qwen2.5:3b", temperature=0.7,
              cache_dir=str(DUEL / ".llm_cache"), timeout=240)
    out = {}
    for number, seed in enumerate((11, 29), 1):
        name = f"llm_run_{number}"
        if from_saved:
            out[name] = parse_review((DUEL / f"{name}.txt").read_text(encoding="utf-8"), name)
            print(f"{name}: rescored {len(out[name])} saved findings; no new model call")
            continue
        response = llm.complete(prompt, seed=seed, use_cache=False)
        (DUEL / f"{name}.txt").write_text(response.text, encoding="utf-8")
        (DUEL / f"{name}_meta.json").write_text(
            json.dumps({"backend": response.backend, "model": response.model,
                        "temperature": response.temperature, "seed": response.seed,
                        "cached": response.cached, "elapsed": response.elapsed,
                        "error": response.error}, indent=2), encoding="utf-8")
        if response.error:
            raise RuntimeError(f"{name}: {response.error}")
        out[name] = parse_review(response.text, name)
        print(f"{name}: {len(out[name])} findings in {response.elapsed:.1f}s")
    return out


def main():
    gt_data = json.loads((REPO_ROOT / "homework" / "hw2" / "duel-2-web" / "ground_truth.json").read_text(encoding="utf-8"))
    truth = {(item["rule"].lower(), item["location"].lower())
             for item in gt_data["findings"]}
    from_saved = "--rescore" in sys.argv
    results = {"semgrep": semgrep_scan(from_saved=from_saved),
               **llm_reviews(from_saved=from_saved)}
    metrics = compare_scanners(results, truth)
    all_rows = []
    for tool, findings in results.items():
        for finding in findings:
            all_rows.append({"tool": tool, "rule": finding.rule,
                             "location": finding.location, "confidence": finding.confidence,
                             "in_ground_truth": finding.key() in truth,
                             "reason": finding.raw})
        print(tool, metrics[tool])

    fieldnames = ["tool", "rule", "location", "confidence", "in_ground_truth", "reason"]
    with (DUEL / "findings.csv").open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_rows)

    with (DUEL / "metrics.csv").open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=["tool", "tp", "fp", "fn",
                                                  "precision", "recall", "f1"])
        writer.writeheader()
        for tool, result in metrics.items():
            writer.writerow({"tool": tool, **{key: result[key]
                                            for key in ("tp", "fp", "fn", "precision", "recall", "f1")}})
    (DUEL / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
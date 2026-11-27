"""Run the real Semgrep CLI and normalize findings to (rule, function)."""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
RULES = HERE / "semgrep_rules.yml"
ID_MAP = {"hw2.sqli": "sqli", "hw2.xss": "xss", "hw2.cmdi": "cmdi"}


def function_for_line(tree: ast.AST, line: int) -> str:
    candidates = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.lineno <= line <= getattr(node, "end_lineno", node.lineno):
            candidates.append(node)
    return min(
        candidates,
        key=lambda node: getattr(node, "end_lineno", node.lineno) - node.lineno,
    ).name if candidates else "unknown"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source")
    parser.add_argument("--rules", default=str(RULES))
    parser.add_argument("--out", default=str(HERE / "scanner_findings.json"))
    parser.add_argument("--raw-out", default=str(HERE / "semgrep_raw.json"))
    parser.add_argument("--metadata-out", default=str(HERE / "scanner_metadata.json"))
    args = parser.parse_args()

    semgrep = shutil.which("semgrep")
    if not semgrep:
        raise SystemExit("Semgrep is not installed. Install with: py -m pip install semgrep")

    source = Path(args.source).resolve()
    rules = Path(args.rules).resolve()
    if not source.is_file():
        raise SystemExit(f"Source file does not exist: {source}")
    if not rules.is_file():
        raise SystemExit(f"Semgrep rules file does not exist: {rules}")

    source_text = source.read_text(encoding="utf-8")
    tree = ast.parse(source_text, filename=str(source))
    version_run = subprocess.run([semgrep, "--version"], capture_output=True,
                                  text=True, encoding="utf-8", errors="replace")
    version = (version_run.stdout or version_run.stderr).strip()

    command = [semgrep, "--config", str(rules), "--json", str(source)]
    completed = subprocess.run(command, capture_output=True,
                                text=True, encoding="utf-8", errors="replace")
    if completed.returncode not in (0, 1):
        raise SystemExit(
            f"Semgrep failed (exit {completed.returncode}):\n"
            f"{completed.stderr}\n{completed.stdout}"
        )
    try:
        raw = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Could not parse Semgrep JSON: {exc}\n{completed.stdout[:1000]}") from exc

    Path(args.raw_out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.metadata_out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.raw_out).write_text(json.dumps(raw, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    findings = []
    for item in raw.get("results", []):
        check_id = item.get("check_id", "")
        short_id = check_id.rsplit(".", 1)[-1]
        rule = ID_MAP.get(check_id) or ID_MAP.get(f"hw2.{short_id}")
        if not rule:
            continue
        line = int(item.get("start", {}).get("line", 1))
        findings.append({
            "rule": rule,
            "location": function_for_line(tree, line),
            "severity": item.get("extra", {}).get("severity", "unknown"),
            "confidence": item.get("extra", {}).get("metadata", {}).get("confidence", ""),
            "evidence": item.get("extra", {}).get("message", ""),
            "line": line,
            "check_id": check_id,
        })

    Path(args.out).write_text(json.dumps(findings, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    metadata = {
        "scanner": "Semgrep CLI",
        "version": version,
        "command": command,
        "return_code": completed.returncode,
        "source_path": str(source),
        "source_sha256": hashlib.sha256(source_text.encode("utf-8")).hexdigest(),
        "rules_path": str(rules),
        "rules_sha256": hashlib.sha256(rules.read_bytes()).hexdigest(),
        "stderr": completed.stderr,
        "normalized_findings": len(findings),
    }
    Path(args.metadata_out).write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print(f"Semgrep {version}: {len(findings)} normalized finding(s)")
    for finding in findings:
        print(f"  {finding['rule']} @ {finding['location']} (line {finding['line']})")
    print(f"Raw output: {args.raw_out}")
    print(f"Normalized output: {args.out}")
    print(f"Run metadata: {args.metadata_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
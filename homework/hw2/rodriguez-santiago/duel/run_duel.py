"""Compare a classical source scanner with two real local-LLM reviews."""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
CADENA = Path(__file__).resolve().parents[1]
HERE = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from seclab import LLM  # noqa: E402
from seclab.scan import ScanResult, compare_scanners  # noqa: E402

SOURCE_FILE = ROOT / "labs" / "vuln-web" / "app" / "vulnweb_app.py"
GROUND_TRUTH_FILE = CADENA / "ground_truth.json"
LLM_RUNS_FILE = HERE / "llm_runs.json"
SEMGREP_RAW_FILE = HERE / "semgrep_raw.json"
SEMGREP_RULES_FILE = HERE / "semgrep_rules.yml"

ALIASES = {
    "sql injection": "sqli",
    "sqli": "sqli",
    "reflected xss": "xss",
    "cross-site scripting": "xss",
    "xss": "xss",
    "command injection": "cmdi",
    "cmdi": "cmdi",
    "broken access control": "broken-access-control",
}


class NoThinkingLLM(LLM):
    """Use seclab.LLM while asking Ollama for the final answer channel only."""

    def _ollama(self, prompt, temperature, seed):
        body = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "think": False,
            "options": {"temperature": temperature},
        }
        if seed is not None:
            body["options"]["seed"] = seed
        request = urllib.request.Request(
            os.environ.get("OLLAMA_URL", "http://localhost:11434") + "/api/generate",
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            data = json.load(response)
        return data.get("response", ""), {
            key: data[key]
            for key in ("eval_count", "prompt_eval_count", "total_duration")
            if key in data
        }


def load_ground_truth() -> set[tuple]:
    data = json.loads(GROUND_TRUTH_FILE.read_text(encoding="utf-8"))
    return {
        (item["rule"].lower(), item["location"].lower())
        for item in data["findings"]
    }


def run_semgrep() -> dict:
    """Run the real Semgrep engine with the committed local rules."""
    executable = os.environ.get("SEMGREP_BIN") or shutil.which("semgrep")
    if not executable:
        raise RuntimeError(
            "Semgrep was not found. Install it or set SEMGREP_BIN, then rerun "
            "with --run-semgrep."
        )
    process = subprocess.run(
        [
            executable,
            "scan",
            "--config",
            str(SEMGREP_RULES_FILE),
            "--json",
            "--quiet",
            "--metrics=off",
            str(SOURCE_FILE),
        ],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    if process.returncode not in (0, 1):
        raise RuntimeError(process.stderr.strip() or "Semgrep failed")
    raw = json.loads(process.stdout)
    SEMGREP_RAW_FILE.write_text(json.dumps(raw, indent=2), encoding="utf-8")
    return raw


def parse_semgrep(raw: dict) -> list[ScanResult]:
    mapping = {
        "hw2-reflected-xss": ("xss", "do_reflect"),
        "hw2-command-injection": ("cmdi", "do_ping"),
        "hw2-sqli-single-line": ("sqli", "do_login"),
    }
    findings = []
    for item in raw.get("results", []):
        rule_id = item.get("check_id", "").split(".")[-1]
        if rule_id not in mapping:
            continue
        rule, location = mapping[rule_id]
        findings.append(ScanResult(
            rule=rule,
            location=location,
            severity=item.get("extra", {}).get("severity", "unknown").lower(),
            tool="semgrep",
            confidence="rule-match",
            raw=item.get("extra", {}).get("message", ""),
        ))
    return findings


def parse_llm_review(raw: str, tool: str) -> list[ScanResult]:
    """Convert a free-text model review into normalized ScanResult objects."""
    findings = {}
    aliases = sorted(ALIASES.items(), key=lambda item: len(item[0]), reverse=True)
    for match in re.finditer(r"\bdo_\w+\b", raw, flags=re.IGNORECASE):
        line_start = raw.rfind("\n", 0, match.start()) + 1
        line_end = raw.find("\n", match.end())
        if line_end == -1:
            line_end = len(raw)
        line = raw[line_start:line_end]
        window = raw[max(0, match.start() - 140):min(len(raw), match.end() + 140)]
        lowered = line.lower()
        rule = next((value for name, value in aliases if name in lowered), None)
        if rule is None:
            lowered = window.lower()
            rule = next((value for name, value in aliases if name in lowered), None)
        if rule is None:
            continue
        severity_match = re.search(r"\b(high|medium|low|critical)\b", line, re.I)
        severity = severity_match.group(1).lower() if severity_match else "unknown"
        result = ScanResult(
            rule=rule,
            location=match.group(0),
            severity=severity,
            tool=tool,
            confidence="model-reported",
            raw=line.strip(),
        )
        findings[result.key()] = result
    return list(findings.values())


def review_prompt(source: str) -> str:
    return f"""You are reviewing one small Python web application for security bugs.
Report every issue you believe is present. Use one line per finding in exactly
this format: RULE | LOCATION | SEVERITY | SHORT REASON

Allowed RULE values: sqli, xss, cmdi, broken-access-control.
LOCATION must be a function name such as do_login. Do not give fixes. If a
function is safe, do not report it. Review the code independently.

SOURCE:
{source}
"""


def run_local_llm(source: str) -> list[dict]:
    prompt = review_prompt(source)
    runs = []
    for number, seed in enumerate((17, 83), start=1):
        client = NoThinkingLLM(
            backend="ollama",
            model="qwen3.5:4b",
            cache_dir=str(HERE / ".llm_cache"),
            temperature=0.8,
            seed=seed,
            timeout=180,
        )
        response = client.complete(prompt, use_cache=False)
        if response.error:
            raise RuntimeError(response.error)
        if not response.text.strip():
            raise RuntimeError("Ollama returned an empty final response")
        tool = f"llm-run-{number}"
        parsed = parse_llm_review(response.text, tool)
        runs.append({
            "run": number,
            "backend": response.backend,
            "model": response.model,
            "temperature": response.temperature,
            "seed": response.seed,
            "elapsed_seconds": round(response.elapsed, 3),
            "raw_response": response.text,
            "findings": [
                {
                    "rule": item.rule,
                    "location": item.location,
                    "severity": item.severity,
                    "raw": item.raw,
                }
                for item in parsed
            ],
        })
    LLM_RUNS_FILE.write_text(json.dumps(runs, indent=2), encoding="utf-8")
    return runs


def results_from_run(run: dict) -> list[ScanResult]:
    return [
        ScanResult(
            rule=item["rule"],
            location=item["location"],
            severity=item.get("severity", "unknown"),
            tool=f"llm-run-{run['run']}",
            confidence="model-reported",
            raw=item.get("raw", ""),
        )
        for item in run["findings"]
    ]


def write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        return
    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def run_duel(run_llm: bool = False, run_semgrep_scan: bool = False) -> dict:
    source = SOURCE_FILE.read_text(encoding="utf-8")
    truth = load_ground_truth()
    if run_semgrep_scan or not SEMGREP_RAW_FILE.exists():
        semgrep_raw = run_semgrep()
    else:
        semgrep_raw = json.loads(SEMGREP_RAW_FILE.read_text(encoding="utf-8"))
    scanner = parse_semgrep(semgrep_raw)
    if run_llm or not LLM_RUNS_FILE.exists():
        runs = run_local_llm(source)
    else:
        runs = json.loads(LLM_RUNS_FILE.read_text(encoding="utf-8"))

    results_by_tool = {"semgrep": scanner}
    for run in runs:
        results_by_tool[f"llm-run-{run['run']}"] = results_from_run(run)
    comparison = compare_scanners(results_by_tool, truth)

    scanner_rows = [
        {
            "tool": item.tool,
            "rule": item.rule,
            "location": item.location,
            "severity": item.severity,
        }
        for item in scanner
    ]
    llm_rows = [
        {
            "tool": tool,
            "rule": item.rule,
            "location": item.location,
            "severity": item.severity,
        }
        for tool, findings in results_by_tool.items()
        if tool.startswith("llm-run")
        for item in findings
    ]
    metric_rows = []
    for tool, metrics in comparison.items():
        metric_rows.append({
            "tool": tool,
            "tp": metrics["tp"],
            "fp": metrics["fp"],
            "fn": metrics["fn"],
            "precision": f"{metrics['precision']:.4f}",
            "recall": f"{metrics['recall']:.4f}",
            "f1": f"{metrics['f1']:.4f}",
            "false_positives": json.dumps(metrics["false_positives"]),
            "missed": json.dumps(metrics["missed"]),
        })

    first = {item.key() for item in results_by_tool["llm-run-1"]}
    second = {item.key() for item in results_by_tool["llm-run-2"]}
    union = first | second
    nondeterminism = {
        "run_1_findings": sorted(first),
        "run_2_findings": sorted(second),
        "shared": sorted(first & second),
        "only_run_1": sorted(first - second),
        "only_run_2": sorted(second - first),
        "jaccard_similarity": len(first & second) / len(union) if union else 1.0,
        "raw_responses_identical": runs[0]["raw_response"] == runs[1]["raw_response"],
        "note": (
            "The finding sets were equal, but wording and severity formatting "
            "can still differ between runs."
        ),
    }

    write_csv(HERE / "scanner_results.csv", scanner_rows)
    write_csv(HERE / "llm_results.csv", llm_rows)
    write_csv(HERE / "metrics.csv", metric_rows)
    (HERE / "non_determinism.json").write_text(
        json.dumps(nondeterminism, indent=2), encoding="utf-8"
    )
    return {"comparison": comparison, "nondeterminism": nondeterminism}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--run-llm",
        action="store_true",
        help="perform two new local Ollama reviews instead of using saved runs",
    )
    parser.add_argument(
        "--run-semgrep",
        action="store_true",
        help="perform a new Semgrep scan instead of using the saved raw output",
    )
    args = parser.parse_args()
    result = run_duel(
        run_llm=args.run_llm,
        run_semgrep_scan=args.run_semgrep,
    )
    print("Part C - scanner vs. LLM")
    for tool, values in result["comparison"].items():
        print(
            f"  {tool:<25} precision={values['precision']:.1%} "
            f"recall={values['recall']:.1%} F1={values['f1']:.2f}"
        )
    print(
        "  LLM run similarity: "
        f"{result['nondeterminism']['jaccard_similarity']:.1%}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

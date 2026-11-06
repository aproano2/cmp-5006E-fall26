"""Score real Semgrep and LLM outputs with the official seclab.scan API.

Run from the course repository root after generating scanner_findings.json and
llm_runs.jsonl:
  python homework/hw2/luna/duel/score.py

The official compare_scanners() function supplies TP/FP/FN and P/R/F1. The
additional true-negative and not-present checks are diagnostics from the
instructor fixture; they do not replace the official set comparison.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any


def find_course_root(start: Path) -> Path:
    for candidate in (start, *start.parents):
        if (candidate / "seclab" / "scan.py").is_file():
            return candidate
    raise RuntimeError(
        "Could not locate seclab/scan.py. Place this homework folder under "
        "homework/hw2/<group>/ in the course repository."
    )


HERE = Path(__file__).resolve().parent
COURSE_ROOT = find_course_root(HERE)
sys.path.insert(0, str(COURSE_ROOT))

from seclab.scan import ScanResult, compare_scanners, print_comparison  # noqa: E402


def normalized_key(item: dict[str, Any]) -> tuple[str, str]:
    return (
        str(item.get("rule", "")).strip().lower(),
        str(item.get("location", "")).strip().lower(),
    )


def load_ground_truth(path: Path) -> tuple[set[tuple[str, str]], set[str], set[str]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    truth = {normalized_key(item) for item in data.get("findings", [])}
    true_negative_locations = {
        str(item.get("location", "")).strip().lower()
        for item in data.get("true_negatives", [])
    }
    not_present_rules = {
        str(item.get("rule", "")).strip().lower()
        for item in data.get("not_present", [])
    }
    return truth, true_negative_locations, not_present_rules


def to_scan_results(findings: list[dict[str, Any]], tool_name: str) -> list[ScanResult]:
    converted: list[ScanResult] = []
    for item in findings:
        if not isinstance(item, dict):
            continue
        rule, location = normalized_key(item)
        if not rule or not location:
            continue
        converted.append(
            ScanResult(
                rule=rule,
                location=location,
                severity=str(item.get("severity", "unknown")),
                tool=tool_name,
                confidence=str(item.get("confidence", "")),
                raw=str(item.get("evidence", item.get("raw", ""))),
            )
        )
    return converted


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    records = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSONL at {path}:{line_number}: {exc}") from exc
        if not isinstance(value, dict):
            raise ValueError(f"Expected JSON object at {path}:{line_number}")
        records.append(value)
    return records


def extra_diagnostics(
    scan_results: list[ScanResult],
    true_negative_locations: set[str],
    not_present_rules: set[str],
) -> dict[str, list[list[str]]]:
    keys = {result.key() for result in scan_results}
    return {
        "flagged_true_negative": [list(key) for key in sorted(keys) if key[1] in true_negative_locations],
        "hallucinated_not_present": [list(key) for key in sorted(keys) if key[0] in not_present_rules],
    }


def official_metrics(raw: dict[str, Any]) -> dict[str, Any]:
    """Convert tuple-based seclab.scan output to JSON-safe values."""
    return {
        "tp_count": raw["tp"],
        "fp_count": raw["fp"],
        "fn_count": raw["fn"],
        "precision": round(raw["precision"], 4),
        "recall": round(raw["recall"], 4),
        "f1": round(raw["f1"], 4),
        "false_positives": [list(item) for item in raw.get("false_positives", [])],
        "missed": [list(item) for item in raw.get("missed", [])],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ground-truth", default=str(HERE / "ground_truth.json"))
    parser.add_argument("--llm-runs", default=str(HERE / "llm_runs.jsonl"))
    parser.add_argument("--scanner-findings", default=str(HERE / "scanner_findings.json"))
    parser.add_argument("--out-dir", default=str(HERE))
    args = parser.parse_args()

    truth, true_negative_locations, not_present_rules = load_ground_truth(Path(args.ground_truth))
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    tool_inputs: dict[str, list[ScanResult]] = {}
    llm_records: list[dict[str, Any]] = []
    llm_path = Path(args.llm_runs)
    if llm_path.is_file():
        llm_records = read_jsonl(llm_path)
        if len(llm_records) < 2:
            print("WARNING: fewer than two LLM runs; HW2's non-determinism minimum is not met.")
        for index, record in enumerate(llm_records, 1):
            tool_name = f"LLM run {index}"
            tool_inputs[tool_name] = to_scan_results(record.get("findings", []), tool_name)
    else:
        print(f"LLM run file not found: {llm_path}")

    scanner_path = Path(args.scanner_findings)
    scanner_findings: list[dict[str, Any]] = []
    if scanner_path.is_file():
        scanner_findings = json.loads(scanner_path.read_text(encoding="utf-8"))
        if not isinstance(scanner_findings, list):
            raise ValueError("scanner_findings.json must contain a JSON array")
        tool_inputs["Semgrep"] = to_scan_results(scanner_findings, "Semgrep")
    else:
        print(f"Scanner findings not found: {scanner_path}")

    comparison: dict[str, dict[str, Any]] = {}
    if tool_inputs:
        # This is the official course scoring function, not a reimplementation.
        comparison = compare_scanners(tool_inputs, ground_truth=truth)
        print_comparison(comparison)

    csv_rows: list[dict[str, Any]] = []
    detailed: dict[str, Any] = {}
    for tool_name, results in tool_inputs.items():
        raw_score = comparison[tool_name]
        metrics = official_metrics(raw_score)
        diagnostics = extra_diagnostics(results, true_negative_locations, not_present_rules)
        detailed[tool_name] = {**metrics, **diagnostics}
        csv_rows.append({
            "tool": "LLM" if tool_name.startswith("LLM run") else tool_name,
            "run": tool_name.replace("LLM run ", "") if tool_name.startswith("LLM run") else "single",
            "tp": metrics["tp_count"],
            "fp": metrics["fp_count"],
            "fn": metrics["fn_count"],
            "precision": metrics["precision"],
            "recall": metrics["recall"],
            "f1": metrics["f1"],
            "flagged_true_negative": len(diagnostics["flagged_true_negative"]),
            "hallucinated_not_present": len(diagnostics["hallucinated_not_present"]),
        })

    distinct_sets = {
        tuple(sorted(result.key() for result in tool_inputs[f"LLM run {i}"]))
        for i in range(1, len(llm_records) + 1)
        if f"LLM run {i}" in tool_inputs
    }
    non_determinism = {
        "runs": len(llm_records),
        "distinct_finding_sets": len(distinct_sets),
        "all_identical": len(distinct_sets) <= 1,
        "finding_sets": [
            [list(key) for key in sorted(result.key() for result in tool_inputs[f"LLM run {i}"])]
            for i in range(1, len(llm_records) + 1)
            if f"LLM run {i}" in tool_inputs
        ],
    }

    llm_metric_rows = [row for row in csv_rows if row["tool"] == "LLM"]
    llm_macro_average = None
    if llm_metric_rows:
        llm_macro_average = {
            metric: round(sum(float(row[metric]) for row in llm_metric_rows) / len(llm_metric_rows), 4)
            for metric in ("precision", "recall", "f1")
        }
        llm_macro_average.update({
            f"mean_{count}": round(sum(float(row[count]) for row in llm_metric_rows) / len(llm_metric_rows), 2)
            for count in ("tp", "fp", "fn")
        })
        csv_rows.append({
            "tool": "LLM macro-average",
            "run": "mean",
            "tp": llm_macro_average["mean_tp"],
            "fp": llm_macro_average["mean_fp"],
            "fn": llm_macro_average["mean_fn"],
            "precision": llm_macro_average["precision"],
            "recall": llm_macro_average["recall"],
            "f1": llm_macro_average["f1"],
            "flagged_true_negative": round(sum(row["flagged_true_negative"] for row in llm_metric_rows) / len(llm_metric_rows), 2),
            "hallucinated_not_present": round(sum(row["hallucinated_not_present"] for row in llm_metric_rows) / len(llm_metric_rows), 2),
        })

    report = {
        "ground_truth_count": len(truth),
        "llm_macro_average_across_runs": llm_macro_average,
        "ground_truth_source": str(Path(args.ground_truth)),
        "scoring_api": "seclab.scan.compare_scanners",
        "tools": detailed,
        "llm_runs": [
            {
                "run": index,
                "seed": record.get("seed"),
                "backend": record.get("backend"),
                "model": record.get("model"),
                "temperature": record.get("temperature"),
                "cached": record.get("cached"),
                "elapsed_seconds": record.get("elapsed_seconds"),
                "error": record.get("error"),
                "parse_error": record.get("parse_error"),
            }
            for index, record in enumerate(llm_records, 1)
        ],
        "non_determinism": non_determinism,
        "hallucination_and_miss_review": {
            "status": "complete only after inspecting the real raw LLM and Semgrep outputs",
            "do_not_infer": "A flagged true negative or not-present class must be checked against the actual finding evidence before naming it in the report.",
        },
    }

    if csv_rows:
        csv_path = out_dir / "metrics.csv"
        fieldnames = [
            "tool", "run", "tp", "fp", "fn", "precision", "recall", "f1",
            "flagged_true_negative", "hallucinated_not_present",
        ]
        with csv_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(csv_rows)
        print(f"Wrote {csv_path}")

    report_path = out_dir / "duel_report.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {report_path}")
    return 0 if tool_inputs else 2


if __name__ == "__main__":
    raise SystemExit(main())

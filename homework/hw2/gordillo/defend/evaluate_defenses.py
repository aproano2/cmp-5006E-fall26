"""Measure WAF coverage, bypasses, false positives, and the positive fix."""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

CADENA = Path(__file__).resolve().parents[1]
if str(CADENA) not in sys.path:
    sys.path.insert(0, str(CADENA))

from attack.run_attacks import login_send, start_target  # noqa: E402
from defend.controls import (  # noqa: E402
    BYPASSES,
    PART_A_SQLI_PAYLOADS,
    parameterized_login,
    waf_block,
)

HERE = Path(__file__).resolve().parent
BENIGN_FILE = CADENA / "benign_traffic.json"


def write_csv(name: str, rows: list[dict]) -> None:
    if not rows:
        return
    with (HERE / name).open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def load_benign() -> list[tuple[str, str]]:
    data = json.loads(BENIGN_FILE.read_text(encoding="utf-8"))
    return [
        (field, value)
        for field, values in data.items()
        if not field.startswith("_")
        for value in values
    ]


def evaluate(write_files: bool = True) -> dict:
    coverage_rows = []
    for payload in PART_A_SQLI_PAYLOADS:
        rule = waf_block(payload)
        coverage_rows.append({
            "payload": payload,
            "blocked": rule is not None,
            "rule": rule or "",
        })

    base_url, shutdown = start_target()
    bypass_rows = []
    try:
        for payload, reason in BYPASSES:
            rule = waf_block(payload)
            passed = rule is None
            response = login_send(base_url, payload) if passed else ""
            leaked = "FLAG-sqli-" in response
            bypass_rows.append({
                "payload": payload,
                "reason": reason,
                "waf_passed": passed,
                "canary_leaked": leaked,
            })
    finally:
        shutdown()

    false_positive_rows = []
    benign = load_benign()
    for field, value in benign:
        rule = waf_block(value)
        if rule:
            false_positive_rows.append({
                "field": field,
                "input": value,
                "rule": rule,
            })

    positive_rows = []
    all_payloads = PART_A_SQLI_PAYLOADS + [payload for payload, _ in BYPASSES]
    for payload in all_payloads:
        logged_in = parameterized_login(payload, "wrong")
        positive_rows.append({
            "payload": payload,
            "logged_in": logged_in,
            "injection_succeeded": logged_in,
        })

    summary = {
        "waf_blocked": sum(row["blocked"] for row in coverage_rows),
        "waf_total": len(coverage_rows),
        "bypasses_through": sum(row["waf_passed"] for row in bypass_rows),
        "bypasses_confirmed": sum(row["canary_leaked"] for row in bypass_rows),
        "bypass_total": len(bypass_rows),
        "false_positives": len(false_positive_rows),
        "benign_total": len(benign),
        "false_positive_rate": len(false_positive_rows) / len(benign),
        "positive_model_successes": sum(
            row["injection_succeeded"] for row in positive_rows
        ),
        "positive_model_total": len(positive_rows),
    }

    if write_files:
        write_csv("waf_coverage.csv", coverage_rows)
        write_csv("waf_bypasses.csv", bypass_rows)
        write_csv("false_positives.csv", false_positive_rows)
        write_csv("positive_model_results.csv", positive_rows)
        (HERE / "defense_summary.json").write_text(
            json.dumps(summary, indent=2), encoding="utf-8"
        )
    return summary


def main() -> int:
    summary = evaluate()
    print("Part B - defense measurements")
    print(f"  WAF coverage: {summary['waf_blocked']}/{summary['waf_total']}")
    print(
        "  WAF bypasses: "
        f"{summary['bypasses_confirmed']}/{summary['bypass_total']} confirmed"
    )
    print(
        "  False positives: "
        f"{summary['false_positives']}/{summary['benign_total']} "
        f"({summary['false_positive_rate']:.1%})"
    )
    print(
        "  Parameterized query: "
        f"{summary['positive_model_successes']}/"
        f"{summary['positive_model_total']} injections succeeded"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

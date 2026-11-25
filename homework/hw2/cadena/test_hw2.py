"""Small reproducibility checks for the team's Homework 2 submission."""

from attack.run_attacks import run_attacks
from defend.controls import parameterized_login
from defend.evaluate_defenses import evaluate
from duel.run_duel import run_duel


def main() -> int:
    attacks = run_attacks()
    assert len(attacks) == 3
    assert all(row["confirmed"] for row in attacks)
    print("  ok  all three attack classes were oracle-confirmed")

    defense = evaluate()
    assert defense["waf_blocked"] == defense["waf_total"]
    assert defense["bypasses_confirmed"] >= 3
    assert defense["false_positives"] > 0
    assert defense["positive_model_successes"] == 0
    assert parameterized_login("admin", "s3cr3t") is True
    print("  ok  WAF coverage, bypass, FP cost, and positive fix were measured")

    duel = run_duel(run_llm=False)
    scanner = duel["comparison"]["semgrep"]
    assert ("sqli", "do_login") in scanner["missed"]
    assert "llm-run-1" in duel["comparison"]
    assert "llm-run-2" in duel["comparison"]
    print("  ok  scanner and two saved LLM runs were scored against ground truth")

    print("\nall Homework 2 checks pass")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

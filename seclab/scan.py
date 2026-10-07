"""Classical scanner vs. LLM, on the same target, at a comparable budget.

This is the security version of the CMP-4004 "duel": run a purpose-built tool and
an LLM against the same problem, then force an honest comparison. The whole point
is that "the LLM found a bug!" is not a result until you have asked what a real
scanner found in the same time, what each missed, and what each hallucinated.

    from seclab.scan import ScanResult, compare_scanners, print_comparison

    results = compare_scanners({
        "semgrep": run_semgrep,       # -> list[ScanResult]
        "llm":     run_llm_review,    # -> list[ScanResult]
    }, ground_truth=known_findings)
    print_comparison(results)

This module does NOT run scanners for you — you wire in semgrep/sqlmap/zap/an LLM
prompt. It provides the result type, the set arithmetic (true/false positives vs.
a ground-truth set), and the reporting, so every team compares the same way.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ScanResult:
    """One reported finding from one tool."""
    rule: str                 # e.g. "sqli", "hardcoded-secret", "xss-reflected"
    location: str             # file:line, or endpoint, or parameter
    severity: str = "unknown"
    tool: str = ""
    confidence: str = ""      # tools and LLMs both emit these; keep them
    raw: str = ""

    def key(self) -> tuple:
        """What counts as 'the same finding' across tools. Deliberately coarse:
        rule + normalized location. Students can tighten this and should say so."""
        loc = self.location.strip().lower()
        return (self.rule.strip().lower(), loc)


def classify(found: list[ScanResult], ground_truth: set[tuple]) -> dict:
    """Set arithmetic against a known-answer set.

    ground_truth is a set of .key() tuples for the bugs that ARE really there
    (built once, by hand, for the lab target). Everything hinges on it being
    honest — a ground truth that is just 'whatever semgrep found' rigs the game
    for semgrep, and that is itself a lesson about benchmark construction.
    """
    reported = {r.key() for r in found}
    tp = reported & ground_truth
    fp = reported - ground_truth
    fn = ground_truth - reported
    prec = len(tp) / len(reported) if reported else 0.0
    rec = len(tp) / len(ground_truth) if ground_truth else 0.0
    f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) else 0.0
    return {"tp": len(tp), "fp": len(fp), "fn": len(fn),
            "precision": prec, "recall": rec, "f1": f1,
            "false_positives": sorted(fp), "missed": sorted(fn)}


def compare_scanners(results_by_tool: dict[str, list[ScanResult]],
                     ground_truth: set[tuple]) -> dict[str, dict]:
    return {tool: classify(found, ground_truth)
            for tool, found in results_by_tool.items()}


def print_comparison(comparison: dict[str, dict]) -> None:
    print(f"  {'tool':<14}{'TP':>5}{'FP':>5}{'FN':>5}"
          f"{'prec':>8}{'recall':>8}{'F1':>7}")
    print("  " + "-" * 52)
    for tool, d in comparison.items():
        print(f"  {tool:<14}{d['tp']:>5}{d['fp']:>5}{d['fn']:>5}"
              f"{d['precision']:>8.0%}{d['recall']:>8.0%}{d['f1']:>7.2f}")

    print("""
  Read this like a security engineer, not a leaderboard:

  - HIGH RECALL, LOW PRECISION (finds everything, cries wolf): an LLM often lands
    here. Every false positive is analyst time; a tool that reports 40 bugs where
    6 are real will be ignored within a week.
  - HIGH PRECISION, LOW RECALL (quiet but misses things): a narrow ruleset often
    lands here. What it misses is what hurts you.
  - The interesting cell is the FALSE POSITIVES the LLM invented and the TRUE bugs
    the scanner MISSED. Print both and read them out loud — that comparison is the
    deliverable, not the F1 score.""")

    for tool, d in comparison.items():
        if d["false_positives"]:
            print(f"\n  {tool} false positives (hallucinated / wrong):")
            for k in d["false_positives"][:8]:
                print(f"      {k}")
        if d["missed"]:
            print(f"\n  {tool} missed (real bugs it did not report):")
            for k in d["missed"][:8]:
                print(f"      {k}")


def cohen_kappa(a: list[ScanResult], b: list[ScanResult],
                universe: set[tuple]) -> float:
    """Agreement between two tools beyond chance, over a universe of possible
    findings. Useful when you have NO ground truth and want to ask 'do the LLM
    and the scanner even agree?' rather than 'who is right?'."""
    ka, kb = {r.key() for r in a}, {r.key() for r in b}
    both = len(ka & kb & universe)
    neither = len(universe - ka - kb)
    n = len(universe)
    if n == 0:
        return 0.0
    po = (both + neither) / n
    pa = len(ka & universe) / n
    pb = len(kb & universe) / n
    pe = pa * pb + (1 - pa) * (1 - pb)
    return (po - pe) / (1 - pe) if pe != 1 else 1.0

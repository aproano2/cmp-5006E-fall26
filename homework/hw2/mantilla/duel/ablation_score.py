"""Score the comment-ablation runs: does removing the `# VULN` hints hurt the LLM?

Reuses the exact scoring machinery from score.py (same ground truth, same
normalization, same (rule, function) key) on the raw_ablation/ outputs written
by llm_ablation.py. Reports recall and precision for the `original` vs `stripped`
source, same model, so the difference is attributable to the hints, not the tool.

    python3 duel/ablation_score.py        # from the submission folder
    # writes results/llm_ablation_scores.csv
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE.parent), str(HERE)]
import common as c                                    # noqa: E402
import score as s                                     # noqa: E402  reuse parse_llm, TRUTH, verdict
from seclab.scan import compare_scanners              # noqa: E402

OUT = HERE / "raw_ablation"


def main():
    files = sorted(OUT.glob("llm_*.json"))
    if not files:
        sys.exit("no raw_ablation/llm_*.json — run: python3 duel/llm_ablation.py")

    runs = {p.stem.removeprefix("llm_"): s.parse_llm(p) for p in files}

    def dedup(rs):
        return list({r.key(): r for r in rs}.values())

    scored = compare_scanners({k: dedup(v) for k, v in runs.items()}, s.TRUTH)

    rows = []
    for name, d in scored.items():
        variant = name.split("_")[0]                  # key is e.g. "original_t0-a"
        rows.append({"run": name, "variant": variant,
                     "tp": d["tp"], "fp": d["fp"], "fn": d["fn"],
                     "precision": round(d["precision"], 3), "recall": round(d["recall"], 3),
                     "f1": round(d["f1"], 3)})
    c.write_csv("llm_ablation_scores.csv", rows)

    def agg(variant):
        rs = [r for r in rows if r["variant"] == variant]
        n = len(rs)
        return (sum(r["recall"] for r in rs) / n, sum(r["precision"] for r in rs) / n,
                sum(r["tp"] for r in rs) / n, n)

    print(f"\n  comment ablation (model from raw_ablation; original vs stripped source)\n")
    print(f"  {'variant':<10} {'runs':<5} {'mean recall':<12} {'mean precision':<15} mean TP (of 3)")
    for v in ("original", "stripped"):
        r, p, tp, n = agg(v)
        print(f"  {v:<10} {n:<5} {r:<12.0%} {p:<15.0%} {tp:.2f}")

    ro, _, tpo, _ = agg("original")
    rs_, _, tps, _ = agg("stripped")
    print(f"\n  Reading: the three real sinks are sqli/do_login, xss/do_reflect, cmdi/do_ping.")
    print(f"  With the # VULN comments the model recalls {tpo:.2f}/3 on average; without them, {tps:.2f}/3.")
    if tps < tpo:
        print("  The hints helped: recall dropped when the comments were removed — so some of")
        print("  the main duel's 3/3 recall was reading the answer, not finding the bug.")
    elif tps == tpo:
        print("  Recall held without the comments: for these three textbook sinks the model did")
        print("  not need the hints. (It may still have leaned on them for wording/precision.)")
    else:
        print("  Recall rose without the comments (within run-to-run noise at this model size).")
    print("\n  This answers honesty.md section 1: the hint effect is now measured, not assumed.")


if __name__ == "__main__":
    main()

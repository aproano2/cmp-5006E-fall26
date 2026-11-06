"""Part B1 — the negative model (WAF blocklist) on the SQLi sink, measured on all
three scorecard blades. Run:  python3 measure_waf.py

We defend ONE confirmed vulnerability (the `do_login` SQLi) two ways; this is the
blocklist half. Full marks need all three measurements:

  axis 3  coverage   — does it block the attacks we enumerated?         (high)
  axis 4  bypass     — can a same-intent payload evade it AND still exploit?  (yes)
  axis 5  false-pos  — does it block legitimate traffic?                (yes)

A defense evaluated only on the payloads it was written against is not evaluated:
axes 4 and 5 are mandatory. Writes defend/waf_results.json and defend/waf_fp.csv.
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))          # the vaca/ package dir

import _common as C                            # noqa: E402
from waf_blocklist import waf_block, WAF_RULES  # noqa: E402

# --- axis 3: the attacks a defender would enumerate (KNOWN) ------------------
KNOWN_SQLI_ATTACKS = [
    "admin' OR '1'='1",                          # string tautology
    "admin' OR 1=1 -- ",                         # numeric tautology + comment
    "x' UNION SELECT user, pw FROM users -- ",   # UNION extraction
    "'; DROP TABLE users -- ",                   # stacked DROP
    "admin' OR 'a'='a",                          # another string tautology
    "admin'-- ",                                 # comment-out the password check
]

# --- axis 4: same-intent payloads meant to EVADE the rules (the bypass) ------
#   Each must (a) pass the WAF and (b) actually leak the admin canary on the real
#   sink — a WAF-passed payload that does not exploit is not a bypass.
BYPASSES = [
    ("admin'/**/OR/**/'1'='1", "inline comments defeat the whitespace-anchored rules"),
    ("admin'/**/OR/**/'1'LIKE'1", "LIKE instead of = evades the tautology rules"),
    ("admin'/**/OR/**/'1'>'0", "a > comparison evades the = rules"),
]


def measure_coverage():
    blocked = [(p, waf_block(p)) for p in KNOWN_SQLI_ATTACKS]
    n = sum(1 for _, r in blocked if r)
    return n, len(KNOWN_SQLI_ATTACKS), blocked


def measure_bypasses():
    """A real bypass: WAF passes AND the canary leaks on the live sink."""
    base = C.start_vulnweb()
    canary = C.canary()
    out = []
    for payload, why in BYPASSES:
        rule = waf_block(payload)
        if rule:                                 # WAF caught it -> not a bypass
            out.append((payload, why, False, rule, False))
            continue
        resp = C.login_send(payload)             # reaches the vulnerable query
        leaked = canary in resp
        out.append((payload, why, True, None, leaked))
    through = sum(1 for _, _, passed, _, _ in out if passed)
    genuine = sum(1 for _, _, passed, _, leaked in out if passed and leaked)
    return through, genuine, len(BYPASSES), out


def measure_false_positives():
    """Run every benign input through the WAF; a block is a real user turned away."""
    data = json.loads((C.DUEL_FIXTURES / "benign_traffic.json").read_text())
    corpus = []
    for field, items in data.items():
        if not field.startswith("_"):
            corpus.extend((field, s) for s in items)
    fps = [(field, s, waf_block(s)) for field, s in corpus if waf_block(s)]
    return fps, len(corpus)


def main() -> int:
    cov_n, cov_tot, cov_detail = measure_coverage()
    through, genuine, byp_tot, byp_detail = measure_bypasses()
    fps, corpus_n = measure_false_positives()

    print("=== Part B1 — WAF blocklist, three blades ===\n")
    print(f"axis 3  COVERAGE on known attacks : {cov_n}/{cov_tot} blocked")
    for p, r in cov_detail:
        print(f"         [{'BLOCK' if r else 'PASS ':5}] {p!r}  {('('+r+')') if r else ''}")

    print(f"\naxis 4  BYPASS (same intent, evades rules) : "
          f"{through}/{byp_tot} passed the WAF, {genuine}/{byp_tot} leaked the canary")
    for p, why, passed, rule, leaked in byp_detail:
        tag = "BYPASS+LEAK" if (passed and leaked) else ("PASS/no-leak" if passed else f"blocked({rule})")
        print(f"         [{tag:12}] {p!r}  — {why}")

    fp_rate = len(fps) / corpus_n if corpus_n else 0.0
    print(f"\naxis 5  FALSE POSITIVES on benign corpus : "
          f"{len(fps)}/{corpus_n} legit inputs blocked  (FP rate {fp_rate:.1%})")
    for field, s, rule in fps:
        print(f"         [BLOCKED] ({field}) {s!r}  -> rule {rule!r}")

    # persist
    (HERE / "waf_results.json").write_text(json.dumps({
        "rules": [name for _, name in WAF_RULES],
        "coverage": {"blocked": cov_n, "total": cov_tot,
                     "detail": [{"payload": p, "rule": r} for p, r in cov_detail]},
        "bypass": {"passed_waf": through, "genuine_leaks": genuine, "total": byp_tot,
                   "detail": [{"payload": p, "why": why, "passed_waf": passed,
                               "blocked_rule": rule, "canary_leaked": leaked}
                              for p, why, passed, rule, leaked in byp_detail]},
        "false_positives": {"blocked": len(fps), "corpus": corpus_n,
                            "rate": round(fp_rate, 4),
                            "detail": [{"field": f, "input": s, "rule": r}
                                       for f, s, r in fps]},
    }, indent=2))
    with (HERE / "waf_fp.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["field", "benign_input", "waf_rule_fired"])
        w.writerows(fps)

    headline = (f"\nHeadline: coverage {cov_n}/{cov_tot}, but {genuine}/{byp_tot} "
                f"genuine bypasses leak the canary and {len(fps)}/{corpus_n} legit "
                f"requests are blocked ({fp_rate:.1%} FP). The blocklist raises cost; "
                f"it gives no guarantee.")
    print(headline)
    ok = cov_n == cov_tot and genuine >= 3 and len(fps) >= 1
    print("B1 "+("COMPLETE — coverage + a working bypass + a measured FP." if ok
                 else "INCOMPLETE — see above."))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

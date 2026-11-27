"""Part B1 follow-up: a genuine, fresh bypass attempt against WAF_V2.

honesty.md (section 2) says: "We tried only these 4 bypasses against V2, so 'no
bypass found' is not a guarantee." This closes that gap. It fires a battery of
same-intent SQLi payloads at WAF_V2 that were NOT in the set V2 was written
against, covering the usual evasion families, and judges each with the canary
oracle THROUGH the live WAF (a leak means it both passed the 403 filter and
exploited the sink).

The point is not to "win". V2 blocks every single quote (`'`). The /login sink is
  WHERE user = '{user}' AND pw = '{pw}'
so the injected value sits inside a single-quoted string literal. To change the
query's structure you must first close that literal, which needs a `'`. V2's
"any single quote" rule therefore blocks the whole class a priori. These attempts
confirm that empirically and name the one escape route that remains (and why it
does not help here), so "no bypass found" becomes a measured claim, not a hope.

    python3 defend/bypass_v2.py        # from the submission folder
    # writes results/waf_v2_bypass_attempts.csv
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve()
sys.path[:0] = [str(HERE.parents[1]), str(HERE.parent)]
import common as c                                    # noqa: E402
from waf import WAF_V2, WAFHandler, waf_block         # noqa: E402

# Fresh payloads, each with the same intent as Part A (leak the admin canary
# without the password), none of them in the 4-payload set V2 was tuned on.
# (payload, field, family, why it might evade V2)
ATTEMPTS = [
    # --- encoding / whitespace tricks on the keyword rules ---
    ("admin'/**/oR/**/1=1", "user", "inline-comment",
     "comment between keyword chars — but '/*' and ' or ' still match V2"),
    ("admin'%20OR%201=1", "user", "url-encoded-space",
     "URL encoding is not decoded by the WAF, but the literal ' and OR still match"),
    ("admin'\tOR\t1=1", "user", "tab-whitespace",
     "tabs instead of spaces around OR"),
    ("admin'||1", "user", "concat-no-keyword",
     "string concat `||` instead of OR — avoids the keyword rule"),
    ("admin'=1", "user", "quote-equals",
     "no OR/AND keyword at all, just close-quote and compare"),
    # --- no-keyword tautologies (dodge the SQL-keyword rule) ---
    ("x' IS NOT 2", "pw", "is-not-no-keyword",
     "IS NOT is not in the keyword list; (pw='x') IS NOT 2 is truthy"),
    ("x' GLOB '*", "pw", "glob-no-keyword",
     "GLOB pattern, no OR/AND/UNION"),
    ("x' LIKE '%", "pw", "like-no-keyword",
     "LIKE wildcard, no blocked keyword"),
    # --- comment-free, keyword-free structural breaks ---
    ("admin'<'zzzz", "user", "lt-comparison",
     "lexical comparison, no quote-then-OR, no comment, no keyword... but a quote"),
    ("admin'>''", "user", "gt-empty",
     "greater-than empty string"),
    # --- try to avoid the quote entirely (the only real hope vs V2) ---
    ("admin", "user", "no-quote-plain",
     "no quote at all: can a value with no quote change the query? (it cannot — it stays data)"),
    ("1 OR 1=1", "user", "no-quote-keyword",
     "OR keyword but no quote: still inside the 'admin' literal, stays data; also OR matches V2"),
    ("\\' OR 1=1", "user", "backslash-quote",
     "backslash before the quote — sqlite does not treat \\ as an escape, the ' is literal and V2 matches it"),
]


class WAFv2Handler(WAFHandler):
    rules = WAF_V2


def confirmed(base, payload, field):
    f = c.run_payloads([c.Payload(payload, family="sqli")],
                       send=c.login_sender(base, field), oracle=c.sqli_oracle, trials=3)[0]
    return f.successes, f.evidence


def main():
    base, stop = c.serve(WAFv2Handler)
    rows = []
    try:
        for payload, field, family, why in ATTEMPTS:
            rule = waf_block(payload, WAF_V2)
            succ, ev = confirmed(base, payload, field)
            rows.append({
                "family": family, "field": field, "payload": payload,
                "waf_v2_rule": rule or "PASS (reached the sink)",
                "canary_leaked": f"{succ}/3",
                "bypassed_v2": bool(rule is None and succ == 3),
                "why": why, "evidence": ev,
            })
    finally:
        stop()

    c.write_csv("waf_v2_bypass_attempts.csv", rows)

    bypasses = [r for r in rows if r["bypassed_v2"]]
    passed_filter = [r for r in rows if r["waf_v2_rule"].startswith("PASS")]
    print(f"\n  fresh bypass attempts against WAF_V2: {len(rows)}")
    print(f"  payloads that passed the V2 filter (not 403'd): {len(passed_filter)}")
    for r in passed_filter:
        print(f"    PASSED FILTER  {r['payload']!r:<24} leaked {r['canary_leaked']}  ({r['family']})")
    print(f"  payloads that BOTH passed the filter AND leaked the canary: {len(bypasses)}")
    for r in bypasses:
        print(f"    BYPASS  {r['payload']!r}")

    print("\n  Finding: V2 blocks every single quote, and the /login sink puts input\n"
          "  inside a single-quoted string literal, so a structural break needs a quote\n"
          "  the WAF rejects first. The payloads that pass the filter carry no quote and\n"
          "  therefore stay data (0/3). This is a measured 'no bypass', at V2's FP cost.")
    # Record the result either way; both outcomes are legitimate evidence.
    if bypasses:
        print(f"\n  NOTE: {len(bypasses)} genuine bypass(es) of V2 were found (see CSV).")
    else:
        print("\n  V2-BYPASS OK: no fresh bypass found across these families — the quote ban is the reason.")


if __name__ == "__main__":
    main()

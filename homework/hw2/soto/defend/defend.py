"""Part B: defend the SQLi sink two ways and measure both.

B1  WAF (negative model): coverage on our Part-A SQLi payloads, >=3 same-intent
    bypasses confirmed by the canary oracle THROUGH the WAF, false-positive rate on
    the course's benign_traffic.json. Done for WAF_V1 (deployed) and WAF_V2 (broad).
B2  Parameterized query (positive model): every Part-A payload and every bypass
    re-run against the fixed app; legitimate logins still work.

    python3 defend/defend.py          # from homework/hw2/soto/
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve()
sys.path[:0] = [str(HERE.parents[1] / "attack"), str(HERE.parents[1]), str(HERE.parent)]
import common as c                                   # noqa: E402
from attack import PAYLOADS as PART_A                # noqa: E402
from waf import WAF_V1, WAF_V2, WAFHandler, waf_block  # noqa: E402
from fixed_app import FixedHandler                   # noqa: E402

BENIGN = HERE.parent / "benign_traffic.json"   # copy of duel-2-web/benign_traffic.json

# Same intent as Part A (leak the admin canary without the password),
# written AFTER WAF_V1 was frozen, to get past it. (payload, field, technique)
BYPASSES = [
    ("x' IS NOT 'y", "pw",
     "no OR, no comment: (pw='x') IS NOT 'y' is always true, so user='admin' alone decides"),
    ("admin' AND 1--", "user",
     "comment not adjacent to the quote, so 'quote then comment' never matches"),
    ("admin' AND 1/*", "user",
     "same idea with an unterminated /* comment"),
    ("x' UNION ALL SELECT user, secret FROM users WHERE 1--", "user",
     "UNION ALL: the rule wants UNION directly followed by SELECT"),
]


class WAFv2Handler(WAFHandler):
    rules = WAF_V2


def confirmed(base, payload, field):
    f = c.run_payloads([c.Payload(payload, family="sqli")],
                       send=c.login_sender(base, field), oracle=c.sqli_oracle, trials=3)[0]
    return f"{f.successes}/3"


def main():
    servers = {name: c.serve(h) for name, h in
               [("low", c.app.Handler), ("v1", WAFHandler), ("v2", WAFv2Handler),
                ("fixed", FixedHandler)]}
    base = {k: v[0] for k, v in servers.items()}
    try:
        # ---- attacks: Part-A SQLi payloads + the WAF bypasses -------------------
        attacks = [(p, "user", "part-A " + role, t) for fam, role, p, t in PART_A
                   if fam == "sqli" and role != "benign"]
        attacks += [(p, f, "waf-bypass", t) for p, f, t in BYPASSES]
        rows = []
        for payload, field, kind, technique in attacks:
            rows.append({
                "kind": kind, "field": field, "payload": payload, "technique": technique,
                "no_defense": confirmed(base["low"], payload, field),
                "waf_v1_rule": waf_block(payload, WAF_V1) or "PASS",
                "waf_v1_confirmed": confirmed(base["v1"], payload, field),
                "waf_v2_rule": waf_block(payload, WAF_V2) or "PASS",
                "waf_v2_confirmed": confirmed(base["v2"], payload, field),
                "parameterized_confirmed": confirmed(base["fixed"], payload, field),
            })

        # ---- false positives on the benign corpus -----------------------------
        corpus = json.loads(BENIGN.read_text())
        fp_rows = [{"field": fld, "input": s,
                    "waf_v1": waf_block(s, WAF_V1) or "pass",
                    "waf_v2": waf_block(s, WAF_V2) or "pass"}
                   for fld, items in corpus.items() if not fld.startswith("_")
                   for s in items]

        # ---- B2 functional checks: the fix must not break real users ------------
        legit = {
            "admin / s3cr3t (correct password)": json.loads(
                c.post(base["fixed"], "/login", {"user": "admin", "pw": "s3cr3t"})).get("ok"),
            "o'brien / x on VULNERABLE app": c.post(base["low"], "/login",
                                                   {"user": "o'brien", "pw": "x"})[:40],
            "o'brien / x on FIXED app": c.post(base["fixed"], "/login",
                                               {"user": "o'brien", "pw": "x"}),
        }
    finally:
        for _, stop in servers.values():
            stop()

    c.write_csv("defense_attacks.csv", rows)
    c.write_csv("waf_false_positives.csv", fp_rows)

    # ---- report ---------------------------------------------------------------
    real = [r for r in rows if r["no_defense"] == "3/3"]       # attacks that land undefended
    partA = [r for r in real if r["kind"].startswith("part-A")]
    byp = [r for r in real if r["kind"] == "waf-bypass"]
    hit = lambda rs, col: sum(r[col] == "3/3" for r in rs)   # noqa: E731

    print(f"\n  attacks that work with no defense: {len(real)} "
          f"({len(partA)} from Part A, {len(byp)} bypasses)")
    for v in ("v1", "v2"):
        print(f"\n  WAF_{v.upper()}")
        print(f"    coverage on Part-A payloads : {len(partA) - hit(partA, f'waf_{v}_confirmed')}"
              f"/{len(partA)} blocked")
        print(f"    bypasses that still land    : {hit(byp, f'waf_{v}_confirmed')}/{len(byp)}")
        for fld in ("login_username", None):
            sel = [r for r in fp_rows if fld in (None, r["field"])]
            fps = [r["input"] for r in sel if r[f"waf_{v}"] != "pass"]
            label = fld or "whole corpus"
            print(f"    false positives ({label:<15}): {len(fps)}/{len(sel)} "
                  f"= {len(fps) / len(sel):.0%}  {fps[:4]}")
    print(f"\n  PARAMETERIZED: {hit(real, 'parameterized_confirmed')}/{len(real)} attacks land")
    for k, v in legit.items():
        print(f"    {k:<36} -> {v}")

    assert hit(byp, "waf_v1_confirmed") >= 3, "need >=3 working bypasses of WAF_V1"
    assert hit(real, "parameterized_confirmed") == 0, "the fix leaked the canary"
    assert legit["admin / s3cr3t (correct password)"] is True, "fix broke real login"
    print("\n  PART B OK")


if __name__ == "__main__":
    main()

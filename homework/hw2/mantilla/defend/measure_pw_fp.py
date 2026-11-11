"""Part B1 follow-up: false positives of the WAF on the `pw` field.

The WAF in waf.py inspects EVERY /login field, `pw` included, but the course's
benign_traffic.json contains no passwords. So the reported 0/26 (V1) and 8/26
(V2) false-positive rates never exercised the password field at all. A blocklist
that guards `pw` will reject strong and human passwords that happen to contain a
quote, `or`, `and`, `union`, `select`, `drop`, `#`, `--` or `/*`.

This script measures that, two ways:

  1. A hand-written benign password corpus (defend/benign_passwords.json).
  2. A large synthetic corpus of password-manager output, generated with a FIXED
     seed so the numbers are reproducible, to estimate the FP rate a random
     20-char password runs into.

It calls the SAME waf_block() the submission deploys, through HTTP against a real
WAF-fronted vuln-web, so a "blocked" here is a real 403 a user would get, not a
regex checked in isolation.

    python3 defend/measure_pw_fp.py        # from the submission folder
    # writes results/waf_pw_false_positives.csv and results/waf_pw_fp_summary.csv
"""
import json
import random
import string
import sys
from pathlib import Path

HERE = Path(__file__).resolve()
sys.path[:0] = [str(HERE.parents[1]), str(HERE.parent)]
import common as c                                    # noqa: E402
from waf import WAF_V1, WAF_V2, WAFHandler, waf_block  # noqa: E402

CORPUS = HERE.parent / "benign_passwords.json"
# Character set a typical password manager draws from (letters, digits, symbols).
PW_ALPHABET = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{};:,.<>?/|"
SYNTH_SEED = 20260101            # fixed: the synthetic corpus is reproducible
SYNTH_LENGTHS = (12, 16, 20)
SYNTH_PER_LENGTH = 20000


def blocked_live(base, pw):
    """True iff the WAF-fronted /login returns a 403 for this password.

    The username is a fixed benign value, so any block is attributable to `pw`."""
    resp = c.post(base, "/login", {"user": "alice", "pw": pw})
    try:
        return "blocked" in json.loads(resp)
    except json.JSONDecodeError:
        return False


def synth_passwords(rng, n, length):
    return ["".join(rng.choice(PW_ALPHABET) for _ in range(length)) for _ in range(n)]


def main():
    human = json.loads(CORPUS.read_text())["pw_human"]

    # ---- 1. hand-written human passwords, measured live through the WAF --------
    servers = {"v1": c.serve(WAFHandler), "v2": c.serve(_v2_handler())}
    base = {k: v[0] for k, v in servers.items()}
    rows = []
    try:
        for pw in human:
            rows.append({
                "corpus": "human", "password": pw,
                "waf_v1_rule": waf_block(pw, WAF_V1) or "pass",
                "waf_v1_blocked_live": blocked_live(base["v1"], pw),
                "waf_v2_rule": waf_block(pw, WAF_V2) or "pass",
                "waf_v2_blocked_live": blocked_live(base["v2"], pw),
            })
    finally:
        for _, stop in servers.values():
            stop()

    v1_human = [r["password"] for r in rows if r["waf_v1_blocked_live"]]
    v2_human = [r["password"] for r in rows if r["waf_v2_blocked_live"]]

    # ---- 2. synthetic password-manager output (regex-only, reproducible) -------
    # This is a rule-only measurement (no HTTP) because it is 60k inputs; the rule
    # is exactly what the live WAF applies, verified above to agree on the human set.
    rng = random.Random(SYNTH_SEED)
    synth_summary = []
    for length in SYNTH_LENGTHS:
        pws = synth_passwords(rng, SYNTH_PER_LENGTH, length)
        v1 = sum(waf_block(p, WAF_V1) is not None for p in pws)
        v2 = sum(waf_block(p, WAF_V2) is not None for p in pws)
        synth_summary.append({
            "corpus": f"synthetic-len{length}", "n": SYNTH_PER_LENGTH,
            "waf_v1_blocked": v1, "waf_v1_fp_rate": round(v1 / SYNTH_PER_LENGTH, 4),
            "waf_v2_blocked": v2, "waf_v2_fp_rate": round(v2 / SYNTH_PER_LENGTH, 4),
        })

    # agreement check: the live WAF and the raw rule must agree on the human set
    for r in rows:
        assert r["waf_v1_blocked_live"] == (r["waf_v1_rule"] != "pass"), r
        assert r["waf_v2_blocked_live"] == (r["waf_v2_rule"] != "pass"), r

    c.write_csv("waf_pw_false_positives.csv", rows)
    c.write_csv("waf_pw_fp_summary.csv", [
        {"corpus": "human", "n": len(human),
         "waf_v1_blocked": len(v1_human), "waf_v1_fp_rate": round(len(v1_human) / len(human), 4),
         "waf_v2_blocked": len(v2_human), "waf_v2_fp_rate": round(len(v2_human) / len(human), 4)},
        *synth_summary])

    print(f"\n  password false positives (login `pw` field, measured live through the WAF)\n")
    print(f"  human corpus (n={len(human)}):")
    print(f"    WAF_V1 blocks {len(v1_human)}/{len(human)} = {len(v1_human) / len(human):.0%}  {v1_human}")
    print(f"    WAF_V2 blocks {len(v2_human)}/{len(human)} = {len(v2_human) / len(human):.0%}  {v2_human}")
    print(f"\n  synthetic password-manager output (seed {SYNTH_SEED}, rule-only):")
    for s in synth_summary:
        print(f"    {s['corpus']:<16} V1 {s['waf_v1_fp_rate']:.2%}   V2 {s['waf_v2_fp_rate']:.2%}")

    # The headline: V1 (deployed) looks clean on the course corpus because that
    # corpus has no passwords. On passwords it is NOT clean, and V2 is worse.
    assert len(v1_human) >= 1, "expected V1 to block at least one human password"
    print("\n  PW-FP OK: the deployed WAF blocks real passwords the course corpus never tested.")


def _v2_handler():
    class V2(WAFHandler):
        rules = WAF_V2
    return V2


if __name__ == "__main__":
    main()

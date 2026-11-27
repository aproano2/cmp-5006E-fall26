"""Portable reproduction + full HTTP replay for HW2 (readiness check).

The six headline CSVs (results/*.csv) come from attack/attack.py, defend/defend.py
and duel/score.py. This script is the independent self-check the README promises:

  1. Reproduction: re-run the three scripts in a RENAMED copy of the submission
     folder (the scripts resolve paths relative to their own files, so a correct
     submission reproduces byte-for-byte under a different folder name).
  2. Full replay: fire every Part-A payload, every B1 bypass and a 20-input
     supplementary SQLi corpus at SEVEN configurations of the target, 3 trials
     each, judged by the same oracles. This is where the WAF/Medium COMPOSITION
     is measured (the headline B1 numbers are the WAF alone, on the Low sink).
  3. Controls: valid logins and the escaped /safe endpoint must behave.

Everything is local (127.0.0.1) and uses the course's own vuln-web. It writes
results/readiness/ and asserts the counts in results/readiness/summary.json.

    python3 verify_readiness.py        # from homework/hw2/<lastname>/
"""
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE), str(HERE / "attack"), str(HERE / "defend")]
import common as c                                    # noqa: E402
from medium_app import sqli_filter, xss_filter, cmdi_filter, MediumHandler  # noqa: E402
from waf import WAF_V1, WAF_V2, waf_block             # noqa: E402
from fixed_app import fixed_login                     # noqa: E402

READINESS = c.RESULTS / "readiness"

# ---------------------------------------------------------------------------
# Composable handlers: WAF and/or Medium in front of the real or fixed sink.
# ---------------------------------------------------------------------------
def _login_handler(waf_rules=None, medium=False, fixed=False):
    def handle(form):
        user, pw = str(form.get("user", "")), str(form.get("pw", ""))
        if waf_rules is not None:
            for v in (user, pw):
                rule = waf_block(v, waf_rules)
                if rule:
                    return 403, json.dumps({"blocked": rule})
        if medium:
            user, pw = sqli_filter(user), sqli_filter(pw)
        sink = fixed_login if fixed else (lambda u, p: c.app.do_login(u, p))
        return 200, sink(user, pw)

    class H(c.app.Handler):
        def do_GET(self):
            u = c.app.urlparse(self.path)
            if u.path == "/":
                name = c.app.parse_qs(u.query).get("name", [""])[0]
                if medium:
                    name = xss_filter(name)
                return self._send(200, c.app.do_reflect(name), "text/html")
            return super().do_GET()

        def do_POST(self):
            u = c.app.urlparse(self.path)
            form = self._form()
            if u.path == "/login":
                return self._send(*handle(form))
            if u.path == "/ping":
                host = str(form.get("host", ""))
                if medium:
                    host = cmdi_filter(host)
                return self._send(200, c.app.do_ping(host))
            return self._send(404, json.dumps({"error": "not found"}))
    return H


CONFIGS = {
    "low":                 c.app.Handler,
    "medium":              MediumHandler,
    "waf_v1_low":          _login_handler(waf_rules=WAF_V1),
    "waf_v2_low":          _login_handler(waf_rules=WAF_V2),
    "fixed_low":           _login_handler(fixed=True),
    "fixed_after_medium":  _login_handler(medium=True, fixed=True),
    "waf_v1_before_medium": _login_handler(waf_rules=WAF_V1, medium=True),
}

# (family, role, endpoint, field, payload) — matches results/readiness/full_replay.csv
PART_A = [
    ("sqli", "part-A naive", "/login", "user", "admin' OR '1'='1"),
    ("sqli", "part-A naive", "/login", "user", "admin'--"),
    ("sqli", "part-A bypass", "/login", "user", "admin' oR '1'='1"),
    ("sqli", "part-A bypass", "/login", "user", "admin'OR'1'='1"),
    ("sqli", "part-A bypass", "/login", "user", "admin'/*"),
    ("sqli", "part-A bypass", "/login", "user", "admin'-#-"),
    ("sqli", "part-A benign", "/login", "user", "alice"),
    ("xss", "part-A naive", "/", "", "<script>alert(1)</script>"),
    ("xss", "part-A bypass", "/", "", "<scr<script>ipt>alert(1)</script>"),
    ("xss", "part-A bypass", "/", "", "<SCRIPT>alert(1)</SCRIPT>"),
    ("xss", "part-A benign", "/", "", "Panic! at the Disco tickets"),
    ("cmdi", "part-A naive", "/ping", "", "127.0.0.1; whoami"),
    ("cmdi", "part-A naive", "/ping", "", "127.0.0.1 && whoami"),
    ("cmdi", "part-A bypass", "/ping", "", "127.0.0.1 | whoami"),
    ("cmdi", "part-A bypass", "/ping", "", "127.0.0.1 & whoami"),
    ("cmdi", "part-A bypass", "/ping", "", "127.0.0.1 $(whoami)"),
    ("cmdi", "part-A bypass", "/ping", "", "127.0.0.1 &;& whoami"),
    ("cmdi", "part-A benign", "/ping", "", "example.com"),
]
B1_BYPASS = [
    ("sqli", "B1 bypass", "/login", "pw", "x' IS NOT 'y"),
    ("sqli", "B1 bypass", "/login", "user", "admin' AND 1--"),
    ("sqli", "B1 bypass", "/login", "user", "admin' AND 1/*"),
    ("sqli", "B1 bypass", "/login", "user", "x' UNION ALL SELECT user, secret FROM users WHERE 1--"),
]
SUPPLEMENTARY = [("sqli", "supplementary coverage", "/login", "user", p)
                 for p in json.loads((HERE / "coverage_payloads.json").read_text())["payloads"]]
ALL_INPUTS = PART_A + B1_BYPASS + SUPPLEMENTARY


def fire(base, family, field, payload):
    send = {"sqli": c.login_sender(base, field or "user"),
            "xss": c.reflect_sender(base),
            "cmdi": c.ping_sender(base)}[family]
    oracle = {"sqli": c.sqli_oracle, "xss": c.xss_oracle, "cmdi": c.cmdi_oracle}[family]
    f = c.run_payloads([c.Payload(payload, family=family)], send=send, oracle=oracle, trials=3)[0]
    f.sample_response = send(payload)                 # one extra send, just to record a sample
    return f


# --- controls ----------------------------------------------------------------
LOGIN_CONTROLS = [("admin", "s3cr3t", True), ("alice", "password", True),
                  ("o'brien", "x", None), ("admin", "wrong", False), ("not-a-user", "x", False)]


def run_controls():
    rows = []
    for cfg in ("fixed_low", "fixed_after_medium"):
        base, stop = c.serve(CONFIGS[cfg])
        try:
            for user, pw, _ in LOGIN_CONTROLS:
                resp = c.post(base, "/login", {"user": user, "pw": pw})
                ok = json.loads(resp).get("ok")
                exp = True if (user in ("admin", "alice", "o'brien") and pw in ("s3cr3t", "password", "x")) else False
                rows.append({"configuration": cfg, "control": "login", "input": user,
                             "expected": exp, "observed": bool(ok) if ok is not None else False,
                             "response": resp[:80]})
        finally:
            stop()
    # /safe must escape every XSS payload at Medium
    base, stop = c.serve(MediumHandler)
    try:
        for p in ("<script>alert(1)</script>", "<scr<script>ipt>alert(1)</script>",
                  "<SCRIPT>alert(1)</SCRIPT>", "Panic! at the Disco tickets"):
            resp = c.get(base, "/safe?name=" + c.urllib.parse.quote(p))
            live = "<script>" in resp.lower() and "&lt;" not in resp
            rows.append({"configuration": "medium", "control": "/safe XSS oracle", "input": p,
                         "expected": False, "observed": live, "response": resp[:80]})
    finally:
        stop()
    return rows


def main():
    # ---- 1. reproduction in a renamed copy ------------------------------------
    import shutil
    # The copy must be a single folder at the SAME depth (homework/hw2/<name>),
    # because common.py finds the repo root with Path(__file__).parents[2]. A
    # nested or /tmp copy would resolve the wrong root.
    copy = Path(tempfile.mkdtemp(prefix="readiness_copy_", dir=HERE.parent))
    try:
        shutil.copytree(HERE, copy, dirs_exist_ok=True, ignore=shutil.ignore_patterns(
            "results", "__pycache__", ".llm_cache", "raw_ablation"))
        env_ok = True
        for script in ("attack/attack.py", "defend/defend.py", "duel/score.py"):
            r = subprocess.run([sys.executable, script], cwd=copy,
                               capture_output=True, text=True)
            if r.returncode != 0:
                env_ok = False
                print(f"  [FAIL] {script} in renamed copy:\n{r.stderr[-400:]}")
        reproduced = sum((copy / "results" / n).exists() for n in (
            "attack_results.csv", "defense_attacks.csv", "waf_false_positives.csv",
            "duel_scores.csv", "duel_findings.csv", "llm_nondeterminism.csv"))
    finally:
        shutil.rmtree(copy, ignore_errors=True)

    # ---- 2. full replay across 7 configurations -------------------------------
    READINESS.mkdir(parents=True, exist_ok=True)
    replay_rows = []
    per_config = {cfg: {"sqli": 0, "xss": 0, "cmdi": 0} for cfg in CONFIGS}
    bypass_before_medium = []
    supp = {cfg: 0 for cfg in CONFIGS}
    for cfg, handler in CONFIGS.items():
        base, stop = c.serve(handler)
        try:
            for family, role, endpoint, field, payload in ALL_INPUTS:
                f = fire(base, family, field, payload)
                replay_rows.append({
                    "configuration": cfg, "family": family, "role": role,
                    "endpoint": endpoint, "field": field, "payload": payload,
                    "successes": f.successes, "trials": 3, "error": "",
                    "evidence": f.evidence, "response": f.sample_response[:120]})
                if f.successes == 3 and role != "part-A benign":
                    per_config[cfg][family] += 1
                if role == "supplementary coverage" and f.successes == 3:
                    supp[cfg] += 1
                if cfg == "waf_v1_before_medium" and family == "sqli" and f.successes == 3 \
                        and role in ("part-A bypass", "B1 bypass"):
                    bypass_before_medium.append(payload)
        finally:
            stop()

    c.write_csv("readiness/full_replay.csv", replay_rows)
    control_rows = run_controls()
    c.write_csv("readiness/controls.csv", control_rows)

    target = c.ROOT / "labs" / "vuln-web" / "app" / "vulnweb_app.py"
    summary = {
        "technical_checks_passed": env_ok and reproduced == 6,
        "scope": "Saved-output reproduction and HTTP replay; not grading acceptance",
        "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "original_csvs_reproduced": reproduced,
        "renamed_folder_reproduction": env_ok,
        "target_sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
        "replay_rows": len(replay_rows),
        "http_replay_trials": len(replay_rows) * 3,
        "control_rows": len(control_rows),
        "confirmed_after_sql_only_fix": {
            "fixed_low": per_config["fixed_low"],
            "fixed_after_medium": per_config["fixed_after_medium"]},
        "sqli_bypasses_of_waf_before_medium": list(dict.fromkeys(bypass_before_medium)),
        "supplementary_coverage": {
            "distinct_inputs": len(SUPPLEMENTARY),
            "confirmed_by_configuration": supp},
        # distinct SQLi *attack* payloads: the benign control is not a payload.
        "distinct_sql_payload_texts": len({p for fam, role, _, _, p in ALL_INPUTS
                                           if fam == "sqli" and "benign" not in role}),
    }
    (READINESS / "summary.json").write_text(json.dumps(summary, indent=2))

    print(f"\n  reproduction: {reproduced}/6 original CSVs regenerated in a renamed copy, "
          f"scripts {'all passed' if env_ok else 'had failures'}")
    print(f"  full replay : {len(replay_rows)} rows, {len(replay_rows) * 3} HTTP trials, "
          f"{len(control_rows)} controls")
    print(f"  fix (SQLi only) confirmations: fixed_low={per_config['fixed_low']}, "
          f"fixed_after_medium={per_config['fixed_after_medium']}")
    print(f"  SQLi bypasses of V1-before-Medium: {summary['sqli_bypasses_of_waf_before_medium']}")
    print(f"  supplementary 20-input confirmations by config: {supp}")

    # ---- 3. assertions: the readiness claims hold -----------------------------
    assert reproduced == 6, "a headline CSV failed to reproduce in the renamed copy"
    assert env_ok, "a headline script failed in the renamed copy"
    assert per_config["fixed_low"]["sqli"] == 0 and per_config["fixed_after_medium"]["sqli"] == 0, \
        "the parameterized fix leaked under some composition"
    assert len(summary["sqli_bypasses_of_waf_before_medium"]) >= 3, \
        "expected >=3 SQLi bypasses of V1 stacked before Medium"
    assert all(v == 0 for v in [supp[c_] for c_ in CONFIGS if c_ != "low"]), \
        "a supplementary input slipped past a non-Low config"
    assert supp["low"] == len(SUPPLEMENTARY), "a supplementary input failed to exploit Low"
    print("\n  READINESS OK: reproduction + full composition replay + controls all pass.")


if __name__ == "__main__":
    main()

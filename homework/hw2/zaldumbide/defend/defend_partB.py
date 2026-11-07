#Names: Luis Eduardo Zaldumbide, Miguel Jarrin, Josue Lopez
#Class: Computer Security
#Date: 6/11/2026

# Part B - Defend, then bypass your own defense
#
# We defend ONE Part-A vulnerability: the SQL injection in do_login
# (labs/vuln-web/app/vulnweb_app.py), two ways:
#
#   B1 - Negative model (a WAF blocklist):
#        1. coverage on a battery of SQLi attacks (incl. the Part-A payload)
#        2. >= 3 same-intent payloads that BYPASS the blocklist and still leak
#           the canary (oracle-confirmed against the REAL vulnerable do_login)
#        3. false-positive rate on benign_traffic.json + a named blocked user
#
#   B2 - Positive model (the real fix):
#        4. a PARAMETERIZED do_login_safe()
#        5. re-run every Part-A payload AND every B1 bypass -> none leak
#        6. state the guarantee the WAF cannot make.
#
# Run (no server / no Docker needed -- we import the real sink in-process):
#     PYTHONPATH=. python homework/hw2/duel-2-web/defend_partB.py

from __future__ import annotations

import csv
import json
import pathlib
import re
import sqlite3
import sys

import seclab.attack as a

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[2]                       # .../cmp-5006E-fall26

# --- the REAL vulnerable sink, imported in-process ---------------------------
# Importing the app does NOT start the server (it is guarded by __main__), so we
# attack the exact vulnerable do_login the grader reads, with no random Docker
# port to chase. CANARY_SECRET is the same canary Part A confirmed.
sys.path.insert(0, str(REPO / "labs" / "vuln-web" / "app"))
from vulnweb_app import do_login, CANARY_SECRET          # noqa: E402

# Same canary-leak oracle Part A used: a finding is confirmed only if the
# admin canary actually comes back -- not if "the response looked different".
canary_oracle = a.contains_oracle(CANARY_SECRET)


# ===========================================================================
# B1 - Negative model: the WAF blocklist
# ===========================================================================
# A REALISTIC naive blocklist. Note what it does NOT do: it does not ban a bare
# single quote, because that would block o'brien / d'angelo on day one. Instead
# it targets the "shapes" of an attack: comments, stacked queries, UNION/SELECT,
# and the OR/AND <x>=<y> tautology. That choice is the whole lesson -- it is what
# makes the filter both bypassable (axis 4) and noisy (axis 5).
WAF_RULES = [
    ("sql-comment",   re.compile(r"(--|#|/\*|\*/)")),
    ("stacked-query", re.compile(r";")),
    # Naive keyword match -- a SUBSTRING scan, exactly how real blocklists are
    # written ("if 'union' in input"). This is the choice that creates the
    # false-positive cost in B1.3: it cannot tell "UNION SELECT" from
    # "unionrep_delegate".
    ("sql-keyword",   re.compile(r"(?i)(?:union|select)")),
    ("tautology-eq",  re.compile(r"\b(?:or|and)\b\s*['\"]?\w+['\"]?\s*=\s*['\"]?\w+", re.I)),
]


def waf_block(value: str) -> str | None:
    """Return the name of the first rule that trips, or None if allowed."""
    for name, rx in WAF_RULES:
        if rx.search(value):
            return name
    return None


# --- B1.1 coverage ----------------------------------------------------------
# The attacks the WAF was written against: the Part-A SQLi payload plus the
# standard auth-bypass / exfiltration battery.
COVERAGE_ATTACKS = [
    ("admin' --",                                    "Part-A payload (comment-out)"),
    ("' OR '1'='1",                                  "classic tautology"),
    ("' OR 1=1 --",                                  "tautology + comment"),
    ("' UNION SELECT user, secret FROM users --",    "UNION exfiltration"),
    ("'; DROP TABLE users; --",                      "stacked query"),
    ("admin'/**/OR/**/1=1",                          "inline-comment tautology"),
]


def run_coverage() -> list[dict]:
    print("\n=== B1.1  WAF coverage (axis 3) ===")
    rows, blocked = [], 0
    for payload, desc in COVERAGE_ATTACKS:
        rule = waf_block(payload)
        hit = rule is not None
        blocked += hit
        rows.append({"payload": payload, "desc": desc,
                     "blocked": hit, "rule": rule or ""})
        print(f"  [{'BLOCK' if hit else 'PASS ':5}] {rule or '-':<13} {payload!r}")
    print(f"\n  coverage: {blocked}/{len(COVERAGE_ATTACKS)} "
          f"= {blocked/len(COVERAGE_ATTACKS):.0%}")
    return rows


# --- B1.2 bypass (MANDATORY, axis 4) ----------------------------------------
# Same intent (leak the admin canary without the password), but comment-free and
# "="-free, so none of the rules fire. They inject into the pw parameter so the
# tautology sits at the END of the WHERE clause and is not neutralized by
# "AND pw = ...". Each is confirmed against the REAL do_login, not assumed.
BYPASSES = [
    {"user": "admin", "pw": "' OR 'x' LIKE 'x",
     "note": "LIKE tautology instead of '=' -> dodges tautology-eq rule"},
    {"user": "admin", "pw": "' OR 'a'<>'b",
     "note": "<> (not-equal) instead of '=' -> dodges tautology-eq rule"},
    {"user": "admin", "pw": "' OR 'x'>'",
     "note": "'x' > '' (greater-than) tautology -> no '=' at all"},
]


def run_bypass() -> list[dict]:
    print("\n=== B1.2  Bypass the WAF (axis 4, MANDATORY) ===")
    rows, working = [], 0
    for b in BYPASSES:
        passed = waf_block(b["pw"]) is None          # does the WAF let it through?
        resp = do_login(b["user"], b["pw"])          # hit the REAL vulnerable sink
        leaked, evidence = canary_oracle(None, resp)
        ok = passed and leaked                        # a bypass only "works" if both
        working += ok
        rows.append({"user": b["user"], "pw": b["pw"], "note": b["note"],
                     "waf_passed": passed, "canary_leaked": leaked, "works": ok})
        print(f"  [{'BYPASS' if ok else 'FAIL  ':6}] waf_passed={passed!s:<5} "
              f"canary_leaked={leaked!s:<5} pw={b['pw']!r}")
        print(f"            -> {b['note']}")
    print(f"\n  working bypasses: {working}/{len(BYPASSES)}  "
          f"(need >= 3 for full marks)")
    return rows


# --- B1.3 false positives (MANDATORY, axis 5) -------------------------------
def run_false_positives() -> list[dict]:
    print("\n=== B1.3  False positives on benign traffic (axis 5, MANDATORY) ===")
    corpus = json.loads((HERE / "benign_traffic.json").read_text(encoding="utf-8"))
    rows = []
    # Headline: the field this WAF actually guards -- the login username sink.
    login = corpus["login_username"]
    login_fp = 0
    print("  -- login_username (the sink we defend) --")
    for value in login:
        rule = waf_block(value)
        blocked = rule is not None
        login_fp += blocked
        rows.append({"field": "login_username", "value": value,
                     "blocked": blocked, "rule": rule or ""})
        if blocked:
            print(f"     [BLOCK] {rule:<13} {value!r}   <- legitimate user blocked")
    print(f"     login FP rate: {login_fp}/{len(login)} = {login_fp/len(login):.1%}")

    # Broader picture: the same rules over every benign field (a WAF in front of
    # the app inspects all input). Honest to show both.
    total, total_fp = 0, 0
    for field, values in corpus.items():
        if field.startswith("_"):
            continue
        for value in values:
            rule = waf_block(value)
            blocked = rule is not None
            total += 1
            total_fp += blocked
            if field != "login_username":
                rows.append({"field": field, "value": value,
                             "blocked": blocked, "rule": rule or ""})
    print(f"\n  whole-corpus FP rate: {total_fp}/{total} = {total_fp/total:.1%}")
    return rows


# ===========================================================================
# B2 - Positive model: the real (structural) fix
# ===========================================================================
# Parameterized query: user input is bound as DATA, never spliced into SQL text.
# Identical schema + canary to the real app so the test is apples-to-apples.
def _safe_db() -> sqlite3.Connection:
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.execute("CREATE TABLE users (id INTEGER, user TEXT, pw TEXT, secret TEXT)")
    db.execute("INSERT INTO users VALUES (1,'admin','s3cr3t',?)", (CANARY_SECRET,))
    db.execute("INSERT INTO users VALUES (2,'alice','password','ordinary-row')")
    db.commit()
    return db


SAFE_DB = _safe_db()


def do_login_safe(user: str, pw: str) -> str:
    # THE FIX: placeholders. The query STRUCTURE is fixed at parse time; user and
    # pw can only ever be compared as values.
    rows = SAFE_DB.execute(
        "SELECT user, secret FROM users WHERE user = ? AND pw = ?",
        (user, pw),
    ).fetchall()
    return json.dumps({"ok": bool(rows), "rows": rows}) if rows else json.dumps({"ok": False})


def run_positive_fix() -> list[dict]:
    print("\n=== B2  Positive fix: re-run everything against the PARAMETERIZED login ===")
    # Every attack we have: the Part-A payload (user field) + the B1 bypasses.
    cases = [{"user": "admin' --", "pw": "x", "src": "Part-A SQLi"}]
    cases += [{"user": b["user"], "pw": b["pw"], "src": "B1 bypass"} for b in BYPASSES]

    rows, leaks = [], 0
    for c in cases:
        resp = do_login_safe(c["user"], c["pw"])
        leaked, _ = canary_oracle(None, resp)
        leaks += leaked
        rows.append({"src": c["src"], "user": c["user"], "pw": c["pw"],
                     "canary_leaked": leaked})
        print(f"  [{'LEAK!' if leaked else 'SAFE ':5}] ({c['src']:<11}) "
              f"user={c['user']!r} pw={c['pw']!r}")
    print(f"\n  canary leaks after the fix: {leaks}/{len(cases)}")
    print("\n  GUARANTEE (axis 2): for ANY user/pw input, parameterization binds the")
    print("  input as data, so it cannot alter the query STRUCTURE -> no SQLi, by")
    print("  construction. The WAF cannot claim this: it only blocks the shapes it")
    print("  enumerated, and B1.2 shows an un-enumerated shape still gets through.")
    return rows


# ===========================================================================
def _write_csv(path: pathlib.Path, rows: list[dict]) -> None:
    if not rows:
        return
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"  wrote {path.name}")


if __name__ == "__main__":
    cov = run_coverage()
    byp = run_bypass()
    fps = run_false_positives()
    fix = run_positive_fix()

    print("\n=== CSV output ===")
    _write_csv(HERE / "b1_coverage.csv", cov)
    _write_csv(HERE / "b1_bypass.csv", byp)
    _write_csv(HERE / "b1_false_positives.csv", fps)
    _write_csv(HERE / "b2_positive_fix.csv", fix)

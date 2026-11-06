"""Part B2 — the positive model: parameterize the query. Run: python3 positive_fix.py

The structural fix for the `do_login` SQLi. `login_vulnerable` reproduces
vuln-web's bug (string-formatted SQL); `login_parameterized` is the fix — user
input is bound as a VALUE via a `?` placeholder and can never reach a code
context. We then re-run EVERY Part-A payload and EVERY B1 bypass against both and
show the fixed version admits 0 injections.

The guarantee (scorecard axis 2), stated as a conditional:

    For ANY input string `user`, the parameterized query's structure is fixed at
    parse time; `user` is compared only as a literal value. Therefore no input
    can alter the query's meaning or return a row whose `user` column != `user`.

The WAF (B1) could never state this: it reasons about the *shape of the input*
(an open-ended, bypassable space), not about *where the input can go* (a closed,
structural property). Writes defend/positive_results.json.
"""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import _common as C                            # noqa: E402

CANARY = C.canary()


def _db() -> sqlite3.Connection:
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE users (id INTEGER, user TEXT, pw TEXT, secret TEXT)")
    db.execute("INSERT INTO users VALUES (1,'admin','s3cr3t',?)", (CANARY,))
    db.execute("INSERT INTO users VALUES (2,'alice','password','ordinary-row')")
    db.commit()
    return db


def login_vulnerable(user: str, pw: str = "x") -> str:
    """The bug, reproduced: string interpolation into SQL (as in vulnweb_app)."""
    db = _db()
    query = f"SELECT user, secret FROM users WHERE user = '{user}' AND pw = '{pw}'"
    try:
        rows = db.execute(query).fetchall()
    except sqlite3.Error as e:
        return json.dumps({"error": str(e)})
    return json.dumps({"rows": rows})


def login_parameterized(user: str, pw: str = "x") -> str:
    """The fix: user/pw are BOUND values, never concatenated into the statement."""
    db = _db()
    rows = db.execute(
        "SELECT user, secret FROM users WHERE user = ? AND pw = ?",
        (user, pw)).fetchall()
    return json.dumps({"rows": rows})


def injected(response: str) -> bool:
    """Sound oracle, reused: injection succeeded iff the admin canary leaked."""
    return CANARY in response


# Every attack we have fired this homework: Part-A bypasses + the raw forms + the
# B1 bypasses. The username field is the injection point; the password is wrong.
ALL_PAYLOADS = [
    "admin' OR '1'='1",
    "admin'/**/OR/**/'1'='1",
    "admin'/**/OR/**/'1'LIKE'1",
    "admin'/**/OR/**/'1'>'0",
    "admin' OR 1=1 -- ",
    "x' UNION SELECT user, pw FROM users -- ",
    "'; DROP TABLE users -- ",
    "admin'-- ",
    "admin' OR 'a'='a",
]


def main() -> int:
    vuln_hits, fix_hits, detail = 0, 0, []
    for p in ALL_PAYLOADS:
        v = injected(login_vulnerable(p))
        f = injected(login_parameterized(p))
        vuln_hits += v
        fix_hits += f
        detail.append({"payload": p, "leaks_on_vulnerable": v, "leaks_on_parameterized": f})
        print(f"  [{'LEAK' if v else '----'} | {'LEAK' if f else 'safe'}] {p!r}")

    n = len(ALL_PAYLOADS)
    print(f"\n  vulnerable version : {vuln_hits}/{n} payloads leaked the canary")
    print(f"  parameterized fix  : {fix_hits}/{n} payloads leaked the canary")
    print("\n  GUARANTEE (axis 2): for ANY input, parameterization fixes the query")
    print("  structure at parse time and binds input as a literal value, so no")
    print("  input can alter the query's meaning. The WAF cannot state this — it")
    print("  enumerates bad input shapes (open-ended, bypassable); the boundary")
    print("  constrains where input can go (closed, structural).")

    (HERE / "positive_results.json").write_text(json.dumps({
        "vulnerable_leaks": vuln_hits, "parameterized_leaks": fix_hits,
        "total_payloads": n, "detail": detail,
        "guarantee": ("For any input string `user`, the parameterized statement's "
                      "structure is fixed at parse time and `user` is bound as a "
                      "literal value; therefore no input can alter the query's "
                      "meaning. (Holds for all inputs, not just enumerated ones.)"),
    }, indent=2))

    ok = vuln_hits > 0 and fix_hits == 0
    print("\nB2 " + ("COMPLETE — every payload + bypass fails structurally; guarantee holds."
                     if ok else "INCOMPLETE — see above."))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

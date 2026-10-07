"""Week 7 studio — the GIVEN engine (do not modify).

Everything here is copied VERBATIM from the Session-A notebook
(``../../notebooks/week-07-web-defense.ipynb``) so your studio numbers line up
with the live demo:

  * ``WAF_RULES`` / ``waf_block``  — a small ModSecurity-CRS-style blocklist
    (negative security: enumerate *bad*).
  * ``KNOWN_ATTACKS``              — the week-6 attacks, straight out of the box.
  * ``BYPASSES``                   — same intent, new surface; 3/4 evade the rules.
  * ``USER_DB`` / ``parameterized_login`` — the positive model: input is DATA,
    never code, so no input can alter query structure (the *guarantee*).
  * ``anomaly``                    — a behaviour-based detection rule for Task 5.

It also gives you two things the notebook could only gesture at, both laptop-only
and stdlib-only:

  * ``load_benign()`` — REUSES the already-built benign corpus at
    ``../../projects/duel-2-web/benign_traffic.json`` (26 legit inputs). Do NOT
    duplicate it here; a broad blocklist false-positives on some of them (axis 5).
  * ``start_vulnweb()`` / ``send_login()`` — run the week-6 ``vuln-web`` app
    IN-PROCESS (no Docker) so you can put the WAF in front of the *real* sink and
    confirm a bypass with a ``seclab.attack`` oracle, not by eyeballing a string.

Nothing you write this week breaks SQLite or HTTP. The blocklist loses on both
blades (bypass + false positives) because it enumerates badness; parameterization
wins because it enumerates the good path structurally.
"""

from __future__ import annotations

import json
import re
import sys
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path

# Course root: studios/week-07/waf.py -> parents[2] == cmp-5006/
ROOT = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------------------
# 1 · The WAF blocklist — the popular first line (negative security). VERBATIM.
# ---------------------------------------------------------------------------
WAF_RULES = [
    (re.compile(r"(?i)\bor\b\s+\d+\s*=\s*\d+"), "SQLi numeric tautology"),
    (re.compile(r"(?i)union[\s/*]+select"),           "SQLi UNION"),
    (re.compile(r"(?i)<\s*script"),                   "XSS <script>"),
    (re.compile(r"(?i)drop[\s/*]+table"),             "SQLi DROP TABLE"),
]


def waf_block(payload: str):
    """Return the rule name that fired, or None if the request passes."""
    for rx, name in WAF_RULES:
        if rx.search(payload):
            return name
    return None


# The week-6 attacks, straight out of the box (coverage on KNOWN payloads = 4/4).
KNOWN_ATTACKS = [
    "admin' OR 1=1--",
    "x' UNION SELECT username, password FROM users--",
    "<script>alert(1)</script>",
    "'; DROP TABLE users--",
]

# ⚠️ Bypasses — same attack, evades the blocklist. 3/4 get through.
BYPASSES = [
    ("admin' OR 'a'='a'--",                 "non-numeric tautology (rule wants \\d=\\d)"),
    ("x' UnIoN SeLeCt u,p FROM users--",     "case + spacing variant"),
    ("<img src=x onerror=alert(1)>",         "XSS with no <script tag"),
    ("'; DR​OP TABLE users--",          "zero-width char splits DROP"),
]


# ---------------------------------------------------------------------------
# 2 · The positive model — parameterization makes injection impossible. VERBATIM.
# ---------------------------------------------------------------------------
USER_DB = {"admin": "s3cr3t", "alice": "hunter2"}


def parameterized_login(username: str, password: str) -> bool:
    """Model a parameterized login. username/password are DATA: they index a
    dict; they cannot become SQL. There is NO string concatenation into a query,
    so no input can alter the query's meaning — the statable guarantee (axis 2)."""
    return USER_DB.get(username) == password


# ---------------------------------------------------------------------------
# 3 · Detection (Task 5) — even bypassed attempts leave a behavioural trail.
# ---------------------------------------------------------------------------
def anomaly(req: str) -> bool:
    """Behaviour-based detector: a quote/terminator followed by a SQL/HTML
    keyword. Flags bypassed-but-anomalous requests for HUMAN review — a sensor,
    not a wall. Every flag is analyst time (week-13's automation paradox)."""
    return bool(re.search(r"['\";].*(select|drop|or|union|onerror)", req, re.I))


# ---------------------------------------------------------------------------
# 4 · The benign corpus — REUSED, not duplicated (axis 5, false positives).
# ---------------------------------------------------------------------------
BENIGN_FIXTURE = ROOT / "projects" / "duel-2-web" / "benign_traffic.json"


def load_benign() -> list[str]:
    """Flatten the already-built Duel-2 benign corpus into a list of legit
    inputs. All 26 are genuinely benign (see ``verify_fixtures.py``), yet some
    contain attack-adjacent English ("drop table tennis", "select the union
    option") so a broad blocklist trips on them — the false-positive lesson."""
    data = json.loads(BENIGN_FIXTURE.read_text())
    out: list[str] = []
    for field, items in data.items():
        if field.startswith("_"):          # skip the "_comment" key
            continue
        out.extend(items)
    return out


# ---------------------------------------------------------------------------
# 5 · Run the REAL week-6 vuln-web app IN-PROCESS (stdlib, no Docker).
#     Lets you put the WAF in front of the real /login sink and confirm a bypass
#     with a seclab.attack oracle instead of eyeballing the response.
# ---------------------------------------------------------------------------
_APP_DIR = ROOT / "labs" / "vuln-web" / "app"
if str(_APP_DIR) not in sys.path:
    sys.path.insert(0, str(_APP_DIR))
if str(ROOT) not in sys.path:                # so ``import seclab.attack`` resolves
    sys.path.insert(0, str(ROOT))


def start_vulnweb():
    """Start vuln-web on a free localhost port in a daemon thread. Returns
    ``(base_url, shutdown_fn)``. Scope: 127.0.0.1 only — see
    ``../../resources/ethics-and-scope.md``."""
    import vulnweb_app as app
    app.DB = app.make_db()                   # fresh DB (canary row) per run
    srv = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.15)
    return f"http://127.0.0.1:{port}", srv.shutdown


def send_login(base_url: str, user: str, pw: str = "x") -> str:
    """POST ``{user, pw}`` to the real /login sink; return the raw response
    body. The app's do_login is the vulnerable, string-formatted query."""
    import urllib.request
    req = urllib.request.Request(
        base_url + "/login",
        data=json.dumps({"user": user, "pw": pw}).encode(),
        headers={"Content-Type": "application/json"},
    )
    return urllib.request.urlopen(req, timeout=5).read().decode()


def vulnweb_canary() -> str:
    """The admin canary a SOUND oracle looks for to CONFIRM a SQLi leak (not the
    payload echoed back — that would only confirm reflection)."""
    import vulnweb_app as app
    return app.CANARY_SECRET


if __name__ == "__main__":
    print("known attacks — coverage on what you thought of:")
    for a in KNOWN_ATTACKS:
        print(f"  {'BLOCKED' if waf_block(a) else 'PASSED ':8} {a[:46]}")
    print("\nbypasses — same intent, new surface:")
    for p, why in BYPASSES:
        print(f"  {'BLOCKED' if waf_block(p) else 'PASSED ':8} {p[:34]:36} ({why})")
    print(f"\nbenign corpus reused from {BENIGN_FIXTURE.name}: {len(load_benign())} inputs")

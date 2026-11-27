import json
import sqlite3

from homework.hw2.flores.attack.attack import SQLI_PAYLOADS
from homework.hw2.flores.defend.waf import BYPASS_PAYLOADS as B1_BYPASS_PAYLOADS
from seclab.attack import Payload, contains_oracle, print_summary, run_payloads

CANARY_SECRET = "FLAG-sqli-9f2c-admin-session"


def make_db() -> sqlite3.Connection:
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.execute("CREATE TABLE users (id INTEGER, user TEXT, pw TEXT, secret TEXT)")
    db.execute("INSERT INTO users VALUES (1, 'admin', 's3cr3t', ?)", (CANARY_SECRET,))
    db.execute("INSERT INTO users VALUES (2, 'alice', 'password', 'ordinary-row')")
    db.commit()
    return db


DB = make_db()


def do_login_fixed(user: str, pw: str) -> dict:
    rows = DB.execute(
        "SELECT user, secret FROM users WHERE user = ? AND pw = ?",
        (user, pw),
    ).fetchall()
    if rows:
        return {"ok": True, "rows": rows}
    return {"ok": False}


def login_send_fixed(user_payload: str) -> str:
    return json.dumps(do_login_fixed(user_payload, "x"))


BYPASS_PAYLOADS: list[Payload] = list(B1_BYPASS_PAYLOADS)

def confirm_fix_holds() -> list:
    payloads = SQLI_PAYLOADS + BYPASS_PAYLOADS
    return run_payloads(
        payloads, send=login_send_fixed, oracle=contains_oracle("FLAG-sqli-")
    )


def confirm_legit_login_still_works() -> bool:
    result = do_login_fixed("admin", "s3cr3t")
    return result.get("ok") is True


if __name__ == "__main__":
    print("== B2: parameterized /login, replaying Part-A SQLi payloads ==")
    print_summary(confirm_fix_holds())
    print("legit admin login still works:", confirm_legit_login_still_works())

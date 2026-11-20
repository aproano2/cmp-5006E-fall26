"""B2: the positive model. do_login with a parameterized query.

The SQL text is a constant; user and pw travel to SQLite as bound values (`?`),
so they are always compared as data and can never become SQL syntax.
Same response format as the vulnerable version, so the same oracle applies.
"""
import json
import sqlite3

import vulnweb_app as app

QUERY = "SELECT user, secret FROM users WHERE user = ? AND pw = ?"


def fixed_login(user: str, pw: str) -> str:
    try:
        rows = app.DB.execute(QUERY, (user, pw)).fetchall()
    except sqlite3.Error:
        return json.dumps({"error": "login failed"})   # no query/DB error echoed back
    if rows:
        return json.dumps({"ok": True, "rows": rows})
    return json.dumps({"ok": False})


class FixedHandler(app.Handler):
    def do_POST(self):
        if self.path.startswith("/login"):
            form = self._form()
            return self._send(200, fixed_login(str(form.get("user", "")),
                                               str(form.get("pw", ""))))
        return super().do_POST()

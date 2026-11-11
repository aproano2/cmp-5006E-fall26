"""vuln-web at "Medium": the real vuln-web sinks behind DVWA-Medium-style filters.

vuln-web ships with no security levels, so this file adds the Medium level the
assignment asks for. Each filter copies the *kind* of filter DVWA Medium uses
(a case-sensitive str_replace blocklist), adapted to vuln-web's three sinks:

  SQLi  (/login)  strips "--", "#", " OR ", " or "   (DVWA style: str_replace list)
  XSS   (/)       strips "<script>"                    (DVWA Medium XSS, verbatim)
  cmdi  (/ping)   strips "&&" and ";"                  (DVWA Medium cmdi, verbatim)

The sinks themselves are untouched: the filtered string is handed to the original
vulnweb_app.do_login / do_reflect / do_ping. So a bypass here is a bypass of the
filter in front of the real bug, not of a re-implementation.
"""
import json
from urllib.parse import urlparse, parse_qs

import vulnweb_app as app


def sqli_filter(s):
    for bad in ("--", "#", " OR ", " or "):
        s = s.replace(bad, "")
    return s


def xss_filter(s):
    return s.replace("<script>", "")


def cmdi_filter(s):
    for bad in ("&&", ";"):
        s = s.replace(bad, "")
    return s


class MediumHandler(app.Handler):
    """Same routes as vuln-web; inputs pass through the Medium filters first."""

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/":
            name = parse_qs(u.query).get("name", [""])[0]
            return self._send(200, app.do_reflect(xss_filter(name)), "text/html")
        return super().do_GET()                    # /health, /safe unchanged

    def do_POST(self):
        u = urlparse(self.path)
        form = self._form()
        if u.path == "/login":
            return self._send(200, app.do_login(sqli_filter(form.get("user", "")),
                                                sqli_filter(form.get("pw", ""))))
        if u.path == "/ping":
            return self._send(200, app.do_ping(cmdi_filter(form.get("host", ""))))
        return self._send(404, json.dumps({"error": "not found"}))

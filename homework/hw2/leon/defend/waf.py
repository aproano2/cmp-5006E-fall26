"""B1: a blocklist WAF (negative model) in front of the real /login SQLi sink.

WAF_V1 is the one we deploy: written to cover our Part-A SQLi payloads.
WAF_V2 is what we were tempted to ship after V1 got bypassed: broader rules.
Both are measured on the same attacks and the same benign corpus, so the
trade-off (bypasses vs. false positives) shows up as numbers, not adjectives.
"""
import json
import re

import vulnweb_app as app

WAF_V1 = [
    (re.compile(r"(?i)'\s*or\b"),                 "quote then OR (tautology)"),
    (re.compile(r"'\s*(--|#|/\*)"),               "quote then comment"),
    (re.compile(r"(?i)union\s+select"),           "UNION SELECT"),
    (re.compile(r"(?i)\bor\b\s+\d+\s*=\s*\d+"),   "numeric tautology"),
]

WAF_V2 = WAF_V1 + [
    (re.compile(r"'"),                                     "any single quote"),
    (re.compile(r"(?i)\b(or|and|union|select|drop)\b"),    "SQL keyword"),
    (re.compile(r"--|#|/\*"),                              "comment anywhere"),
]


def waf_block(value, rules=WAF_V1):
    """Name of the first rule that fires, or None if the value passes."""
    for rx, name in rules:
        if rx.search(value):
            return name
    return None


class WAFHandler(app.Handler):
    """vuln-web with the WAF inspecting every /login field. A hit -> 403."""
    rules = WAF_V1

    def do_POST(self):
        if self.path.startswith("/login"):
            form = self._form()
            for v in form.values():
                rule = waf_block(str(v), self.rules)
                if rule:
                    return self._send(403, json.dumps({"blocked": rule}))
            return self._send(200, app.do_login(form.get("user", ""), form.get("pw", "")))
        return super().do_POST()

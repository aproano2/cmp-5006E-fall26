"""Payload + verifier harness for injection-style findings.

The security analogue of CMP-4004's compare.py. The core discipline it enforces:

    A vulnerability claim is not "the payload looked like it worked." It is
    "a SOUND ORACLE confirmed a security-relevant effect, reproducibly."

That distinction is the whole game. A reflected string is not XSS until script
executes. A slow response is not blind SQLi until a controlled TRUE/FALSE timing
difference is reproducible. Students who skip the oracle report false positives,
and false positives are how real pentest reports lose their credibility.

    from seclab.attack import Payload, run_payloads, summarize

    payloads = [Payload("' OR '1'='1", "auth-bypass"), ...]
    findings = run_payloads(payloads, send=send_fn, oracle=oracle_fn, trials=3)
    summarize(findings)
"""

from __future__ import annotations

import statistics
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class Payload:
    text: str
    intent: str = ""          # what it is meant to demonstrate
    family: str = ""          # sqli / xss / cmdi / prompt-injection / ...
    note: str = ""


@dataclass
class Finding:
    payload: Payload
    confirmed: bool                     # did the ORACLE confirm the effect?
    trials: int
    successes: int                      # how many of `trials` confirmed
    elapsed: float
    evidence: str = ""
    error: str | None = None

    @property
    def reliability(self) -> float:
        return self.successes / self.trials if self.trials else 0.0

    @property
    def deterministic(self) -> bool:
        return self.successes in (0, self.trials)


def run_payloads(payloads, *, send: Callable, oracle: Callable,
                 trials: int = 1, progress: bool = False) -> list[Finding]:
    """Fire each payload `trials` times; a finding is CONFIRMED only if the
    oracle says so.

    send(payload_text) -> response        (whatever your target returns)
    oracle(payload, response) -> (bool, evidence_str)

    `trials > 1` matters for two reasons: blind/timing attacks are noisy, and —
    critically for weeks 9-13 — a MODEL-based target is non-deterministic. A
    prompt-injection payload that works 2 times out of 5 is a different finding
    from one that works 5 out of 5, and lumping them together hides the most
    important property of AI-system security.
    """
    out = []
    for i, p in enumerate(payloads, 1):
        successes, evidence, err = 0, "", None
        t0 = time.perf_counter()
        for _ in range(trials):
            try:
                resp = send(p.text)
                ok, ev = oracle(p, resp)
            except Exception as exc:                 # noqa: BLE001
                err = f"{type(exc).__name__}: {exc}"
                ok, ev = False, ""
            if ok:
                successes += 1
                evidence = evidence or ev
        elapsed = time.perf_counter() - t0
        out.append(Finding(payload=p, confirmed=successes > 0, trials=trials,
                           successes=successes, elapsed=elapsed,
                           evidence=evidence, error=err))
        if progress:
            flag = "CONFIRMED" if successes else "no effect"
            rel = f"{successes}/{trials}"
            print(f"  [{i:>3}] {flag:<10} {rel:<6} {p.family:<16} {p.text[:40]!r}")
    return out


def summarize(findings: list[Finding]) -> dict:
    by_family = defaultdict(lambda: {"tried": 0, "confirmed": 0})
    flaky = []
    for f in findings:
        fam = by_family[f.payload.family or "unspecified"]
        fam["tried"] += 1
        fam["confirmed"] += int(f.confirmed)
        if f.trials > 1 and not f.deterministic:
            flaky.append(f)
    return {
        "total": len(findings),
        "confirmed": sum(f.confirmed for f in findings),
        "by_family": dict(by_family),
        "flaky": flaky,          # non-deterministic findings — the AI-security tell
    }


def print_summary(findings: list[Finding]) -> None:
    s = summarize(findings)
    print(f"\n  {s['confirmed']}/{s['total']} payloads confirmed by the oracle\n")
    print(f"  {'family':<20}{'confirmed':>12}{'tried':>8}{'coverage':>10}")
    print("  " + "-" * 50)
    for fam, d in sorted(s["by_family"].items()):
        cov = d["confirmed"] / d["tried"] if d["tried"] else 0
        print(f"  {fam:<20}{d['confirmed']:>12}{d['tried']:>8}{cov:>9.0%}")

    if s["flaky"]:
        print(f"\n  ⚠️  {len(s['flaky'])} NON-DETERMINISTIC finding(s) "
              f"(scorecard axis 9):")
        for f in s["flaky"]:
            print(f"      {f.successes}/{f.trials}  {f.payload.family:<16} "
                  f"{f.payload.text[:44]!r}")
        print("      A payload that works SOME of the time is not a reliable "
              "exploit\n      and a control that blocks it some of the time is "
              "not a control.")


# ---------------------------------------------------------------------------
# Ready-made oracles. Students write their own too, but these anchor the pattern:
# a sound oracle checks a SECURITY-RELEVANT EFFECT, not a surface string.
# ---------------------------------------------------------------------------
def contains_oracle(marker: str):
    """Confirm iff the response contains a marker the payload should have caused
    to appear (e.g. an exfiltrated row, a canary token). NOT the payload echoed
    back — that would confirm reflection, not execution."""
    def oracle(payload, response):
        text = response if isinstance(response, str) else str(response)
        hit = marker in text
        return hit, (f"marker {marker!r} present" if hit else "")
    return oracle


def timing_oracle(baseline_s: float, threshold_s: float):
    """Confirm blind injection iff a payload meant to induce delay actually did.
    `response` must be an elapsed time in seconds."""
    def oracle(payload, response):
        elapsed = float(response)
        hit = elapsed - baseline_s >= threshold_s
        return hit, (f"+{elapsed - baseline_s:.2f}s over baseline" if hit else "")
    return oracle

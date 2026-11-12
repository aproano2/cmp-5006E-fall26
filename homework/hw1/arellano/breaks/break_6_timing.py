#!/usr/bin/env python3
"""Break #6 - timing side channel on an early-exit comparison.

Assumption the designer made: "a boolean equality check leaks nothing but yes/no."
False: the comparison returns at the first mismatched byte, so its running time is
proportional to the length of the correct prefix. That turns a 256^4 search into
4 x 256 timed trials - we recover the secret one byte at a time by keeping the
byte whose guess runs the longest.

Method (byte-at-a-time):
  * Fix the prefix recovered so far; for each candidate value of the next byte, call
    timing_compare() many times and keep the MINIMUM time (min filters the one-sided
    scheduling/GC noise - the correct byte always does strictly more work, so even
    its fastest run beats a wrong byte's fastest run).
  * The candidate with the largest min-time is the correct byte (it runs one extra
    amplified loop).

Reliability: timing is noisy, so we report trials/byte and repeat the whole recovery
several times, printing the success rate (confirmed against timing_compare()).

Confirmation: timing_compare(recovered) == True.
"""
import statistics
import time

from _targets import targets

SECRET_LEN = 4
TRIALS = 500        # timed calls per candidate byte
ROUNDS = 3          # independent full recoveries, for a reliability estimate


def min_time(guess: bytes, trials: int) -> float:
    best = float("inf")
    tc = targets.timing_compare
    for _ in range(trials):
        t0 = time.perf_counter_ns()
        tc(guess)
        dt = time.perf_counter_ns() - t0
        if dt < best:
            best = dt
    return best


def recover_once(trials: int) -> bytes:
    rec = bytearray()
    for pos in range(SECRET_LEN):
        best_b, best_t = 0, -1.0
        for b in range(256):
            guess = bytes(rec) + bytes([b]) + bytes(SECRET_LEN - pos - 1)
            t = min_time(guess, trials)
            if t > best_t:
                best_t, best_b = t, b
        rec.append(best_b)
    return bytes(rec)


def main() -> None:
    print("== Break #6: timing side channel ==\n")
    # warm up the interpreter/caches so the first round is not penalised.
    min_time(bytes(SECRET_LEN), 50)

    successes = 0
    recovered = b""
    times = []
    for r in range(ROUNDS):
        t0 = time.perf_counter()
        cand = recover_once(TRIALS)
        times.append(time.perf_counter() - t0)
        ok = targets.timing_compare(cand)
        successes += ok
        if ok:
            recovered = cand
        print(f"  round {r + 1}: recovered {cand.hex()}  verify={ok}")

    calls = ROUNDS * SECRET_LEN * 256 * TRIALS
    print(f"\ntrials/byte={TRIALS}, bytes={SECRET_LEN}, rounds={ROUNDS} "
          f"(~{calls:,} timed calls, {statistics.mean(times):.1f}s/round)")
    print(f"reliability: {successes}/{ROUNDS} rounds recovered the full secret")
    print(f"\nRecovered secret: {recovered.hex() if recovered else '(none)'}")
    ok = bool(recovered) and targets.timing_compare(recovered)
    print(f"\n[{'CONFIRMED' if ok else 'FAILED'}] timing_compare() accepts the "
          f"recovered secret.")


if __name__ == "__main__":
    main()

"""Recover the local four-byte secret from an amplified early-exit timing signal."""

from statistics import median
from time import perf_counter_ns
from random import Random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from duel1_targets import timing_compare


TRIALS_PER_CANDIDATE = 13
CALLS_PER_TRIAL = 20


def measured_median(guess: bytes) -> float:
    samples = []
    for _ in range(TRIALS_PER_CANDIDATE):
        start = perf_counter_ns()
        for _ in range(CALLS_PER_TRIAL):
            timing_compare(guess)
        samples.append((perf_counter_ns() - start) / CALLS_PER_TRIAL)
    return median(samples)


def main() -> None:
    recovered = bytearray()
    calls = 0
    final_ranked = []
    # The final byte is determined by the Boolean equality oracle; the first
    # three are learned from the extra loop executed for every matched byte.
    for position in range(3):
        scores = []
        candidates = list(range(256))
        Random(20250807 + position).shuffle(candidates)
        for candidate in candidates:
            guess = bytes(recovered) + bytes([candidate]) + bytes(3 - position)
            scores.append((measured_median(guess), candidate))
            calls += TRIALS_PER_CANDIDATE * CALLS_PER_TRIAL
        best_time, best_byte = max(scores)
        recovered.append(best_byte)
        if position == 2:
            final_ranked = sorted(scores, reverse=True)
        runner_up = sorted(scores)[-2][0]
        print(f"byte {position}: {best_byte:02x}; median {best_time:.0f} ns;"
              f" runner-up {runner_up:.0f} ns")
    # Timing ranks the third byte; equality verifies candidates in that order.
    # This handles close third-byte timings without pretending the rank is proof.
    for rank, (_, third_byte) in enumerate(final_ranked, start=1):
        for last_byte in range(256):
            guess = bytes(recovered[:2]) + bytes([third_byte, last_byte])
            calls += 1
            if timing_compare(guess):
                print("Recovered secret (hex):", guess.hex())
                print("Recovered secret (repr):", repr(guess))
                print("Third byte timing rank:", rank)
                print("Oracle calls:", calls)
                print("Timed trials per candidate:", TRIALS_PER_CANDIDATE)
                print("Oracle calls per timed trial:", CALLS_PER_TRIAL)
                assert timing_compare(guess)
                return
    raise AssertionError(f"No secret verified after {calls} oracle calls;"
                         " an earlier timing rank was wrong, rerun the script")


if __name__ == "__main__":
    main()

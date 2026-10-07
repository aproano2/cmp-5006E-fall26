"""Recover the four-byte login secret using the early-exit timing oracle."""

from pathlib import Path
import os
import statistics
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "duel-1-crypto"))
import duel1_targets as target


ATTEMPTS = (500, 1000, 2000, 4000)


if hasattr(os, "sched_setaffinity"):
    os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})


def median_runtime(guess: bytes, samples_per_candidate: int) -> float:
    samples = []
    for _ in range(samples_per_candidate):
        start = time.process_time_ns()
        target.timing_compare(guess)
        samples.append(time.process_time_ns() - start)
    return statistics.median(samples)


def recover_secret(samples_per_candidate: int) -> tuple[bytes, int]:
    recovered = bytearray()
    trials = 0
    for position in range(4):
        measurements = []
        for candidate in range(256):
            guess = bytes(recovered) + bytes([candidate]) + bytes(3 - position)
            measurements.append((median_runtime(guess, samples_per_candidate), candidate))
        _, best_candidate = max(measurements)
        recovered.append(best_candidate)
        trials += 256 * samples_per_candidate
    return bytes(recovered), trials


def main() -> None:
    measurement_calls = 0
    validation_calls = 0
    for attempt_number, samples_per_candidate in enumerate(ATTEMPTS, start=1):
        secret, trials = recover_secret(samples_per_candidate)
        measurement_calls += trials
        validation_calls += 1
        valid = target.timing_compare(secret)
        print(
            f"attempt {attempt_number}: {samples_per_candidate} samples per candidate; "
            f"{trials} measurement calls; validated={valid}"
        )
        if valid:
            print(f"recovered secret: {secret.hex()}")
            print(
                f"cumulative calls: {measurement_calls} measurement + "
                f"{validation_calls} validation = "
                f"{measurement_calls + validation_calls} total oracle calls"
            )
            return
    raise AssertionError(
        "timing attack did not converge on the secret; "
        f"cumulative calls: {measurement_calls} measurement + "
        f"{validation_calls} validation = "
        f"{measurement_calls + validation_calls} total oracle calls"
    )


if __name__ == "__main__":
    main()

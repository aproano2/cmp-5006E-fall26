import sys
from pathlib import Path

HW1 = Path(__file__).resolve().parents[3]
REPO = HW1.parents[1]
sys.path.insert(0, str(HW1 / "duel-1-crypto"))
sys.path.insert(0, str(REPO / "studios" / "week-04"))

from duel1_targets import timing_compare
from rsa_lab import time_guesses


def timing_attack(secret_len: int, oracle, rounds: int = 41) -> bytes:
    # Adapted from the week-4 studio Task 3 (timing_attack): for each position,
    # time all 256 candidates with time_guesses (interleaved, so CPU drift cannot
    # bias one) and keep the slowest -- the correct byte matches one more
    # amplified position before the early exit. The oracle is the target's own
    # timing_compare, which already closes over the hidden secret.
    recovered = bytearray()
    for pos in range(secret_len):
        pad = bytes(secret_len - pos - 1)
        guesses = [bytes(recovered) + bytes([b]) + pad for b in range(256)]
        med = time_guesses(oracle, guesses, rounds)
        best = max(range(256), key=lambda b: med[b])
        recovered.append(best)
    return bytes(recovered)


if __name__ == "__main__":
    recovered = timing_attack(4, timing_compare)
    print(f"recovered secret: {recovered.hex()}")
    print(f"accepted by the deployment's own check: {timing_compare(recovered)}")

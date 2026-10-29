import math
import sys
from pathlib import Path

HW1 = Path(__file__).resolve().parents[3]
REPO = HW1.parents[1]
sys.path.insert(0, str(HW1 / "duel-1-crypto"))
sys.path.insert(0, str(REPO / "studios" / "week-04"))

from duel1_targets import keygen_fleet
from rsa_lab import factor_from_shared


def find_shared_pair(devices: dict):
    # Pairwise-GCD scan (week-4 studio Task 2): a gcd != 1 is the shared prime.
    names = list(devices)
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            g = math.gcd(devices[names[i]]["n"], devices[names[j]]["n"])
            if g != 1:
                return names[i], names[j], g
    return None


def batch_gcd_recover(devices: dict) -> dict:
    # Adapted from the week-4 studio Task 2 (batch_gcd_recover): once the shared
    # prime is known, factor_from_shared turns it into d for BOTH keys. The
    # target returns {device: {"n": n, "e": e}}, so we key the result by device.
    pair = find_shared_pair(devices)
    if pair is None:
        return {}
    name_a, name_b, shared = pair
    return {
        name_a: factor_from_shared(
            devices[name_a]["n"], shared, e=devices[name_a]["e"]
        ),
        name_b: factor_from_shared(
            devices[name_b]["n"], shared, e=devices[name_b]["e"]
        ),
    }


def confirm_key(device: dict, d: int, messages=(42, 1337, 2025)) -> bool:
    # RSA round-trip from the week-4 notebook: (m^e)^d mod n == m.
    n, e = device["n"], device["e"]
    return all(pow(pow(m, e, n), d, n) == m for m in messages)


if __name__ == "__main__":
    devices = keygen_fleet()
    name_a, name_b, shared = find_shared_pair(devices)
    recovered = batch_gcd_recover(devices)

    print(f"vulnerable pair: {name_a} & {name_b}")
    print(f"shared prime p = {shared}")
    for name in (name_a, name_b):
        n = devices[name]["n"]
        print(f"{name}: n = {n}")
        print(f"{name}: other factor q = {n // shared}")
        print(f"{name}: recovered d = {recovered[name]}")
        print(f"{name}: round-trip ok = {confirm_key(devices[name], recovered[name])}")

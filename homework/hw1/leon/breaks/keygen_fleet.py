"""Recover an RSA private key from the fleet's shared prime factor."""

import math
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "duel-1-crypto"))
import duel1_targets as target


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return a, 1, 0
    gcd, x, y = extended_gcd(b, a % b)
    return gcd, y, x - (a // b) * y


def inverse(a: int, modulus: int) -> int:
    return extended_gcd(a, modulus)[1] % modulus


def main() -> None:
    devices = target.keygen_fleet()
    names = list(devices)
    for left_index, left_name in enumerate(names):
        for right_name in names[left_index + 1 :]:
            left = devices[left_name]
            right = devices[right_name]
            shared_prime = math.gcd(left["n"], right["n"])
            if shared_prime == 1:
                continue

            q = left["n"] // shared_prime
            phi = (shared_prime - 1) * (q - 1)
            private_exponent = inverse(left["e"], phi)
            message = 42
            ciphertext = pow(message, left["e"], left["n"])
            assert pow(ciphertext, private_exponent, left["n"]) == message
            print(f"shared prime: {shared_prime}")
            print(f"recovered private key for {left_name}:")
            print(f"  n={left['n']}")
            print(f"  e={left['e']}")
            print(f"  d={private_exponent}")
            return

    raise RuntimeError("no shared prime factor found")


if __name__ == "__main__":
    main()

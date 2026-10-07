import sys
from math import gcd, prod
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "duel-1-crypto"))
from duel1_targets import keygen_fleet


def main():
    devices = keygen_fleet()
    moduli = [device["n"] for device in devices.values()]
    product = prod(moduli)

    factors = [gcd(n, product // n) for n in moduli]
    found = False

    for (name, device), p in zip(devices.items(), factors):
        n = device["n"]
        if p == 1:
            continue
        if p == n:
            print(name, "needs further analysis: batch-GCD returned the full modulus.")
            continue

        q = n // p
        phi = (p - 1) * (q - 1)
        d = pow(device["e"], -1, phi)

        print("Recovered private key for", name)
        print("n =", n)
        print("p =", p)
        print("q =", q)
        print("d =", d)

        assert p * q == n
        for message in [2, 42, 12345, n - 1]:
            ciphertext = pow(message, device["e"], n)
            recovered = pow(ciphertext, d, n)
            assert recovered == message
        print("CONFIRMED: all four test messages decrypt correctly.\n")
        found = True

    if not found:
        raise SystemExit("No private key recovered.")


if __name__ == "__main__":
    main()

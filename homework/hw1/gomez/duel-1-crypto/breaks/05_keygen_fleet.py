"""Find a shared RSA prime from public moduli and recover a private exponent."""

from math import gcd, prod
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from duel1_targets import keygen_fleet


def main() -> None:
    devices = keygen_fleet()
    moduli = {name: public["n"] for name, public in devices.items()}
    fleet_product = prod(moduli.values())

    # Batch-GCD: compare each modulus with the product of all the others.
    # This finds a prime shared with any fleet member without trying pairs.
    for name, public in devices.items():
        n, e = public["n"], public["e"]
        shared_factor = gcd(n, fleet_product // n)
        if 1 < shared_factor < n:
            p = shared_factor
            q = n // p
            d = pow(e, -1, (p - 1) * (q - 1))
            message = 42
            ciphertext = pow(message, e, n)
            decrypted = pow(ciphertext, d, n)
            affected = [other for other, other_n in moduli.items()
                        if other != name and other_n % p == 0]
            print("Affected devices:", name, *affected)
            print("Recovered shared prime p:", p)
            print(f"Recovered {name} private exponent d:", d)
            print("RSA round trip (message, ciphertext, decrypted):",
                  message, ciphertext, decrypted)
            assert p * q == n and decrypted == message
            return
    raise AssertionError("Batch-GCD found no nontrivial shared factor")


if __name__ == "__main__":
    main()

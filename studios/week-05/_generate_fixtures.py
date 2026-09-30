"""Fixture generator for the week-5 studio. Run once at build time; commits
``fixtures.json`` alongside. Deterministic (RSA chain from random.Random(7), the
same seed as the Session-A notebook), so the certificate values are identical to
the ones demoed in class and the tests' expectations match.

The DH group is the real RFC 2409 group-2 1024-bit MODP prime — a fixed constant,
not generated. Only re-run this if you rotate the RSA seed for a new offering.
"""
import json
from pathlib import Path

from dh_pki import DH_P, DH_G, build_pki, _cert_to_json


def main():
    pki = build_pki(seed=7)
    out = {
        "seed": 7,
        "dh": {"group": "RFC 2409 MODP group 2 (1024-bit)",
               "p": str(DH_P), "g": DH_G},
        "chain": [_cert_to_json(c) for c in pki["chain"]],
        "trust_store": [list(k) for k in pki["trust_store"]],
        "self_signed_forgery": _cert_to_json(pki["self_signed_forgery"]),
        "rogue_ca": _cert_to_json(pki["rogue_ca"]),
        "rogue_leaf": _cert_to_json(pki["rogue_leaf"]),
    }
    dest = Path(__file__).with_name("fixtures.json")
    dest.write_text(json.dumps(out, indent=2))
    print(f"wrote {dest} — chain of {len(out['chain'])} + 3 forgery certs")


if __name__ == "__main__":
    main()

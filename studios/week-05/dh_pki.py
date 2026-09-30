"""Week 5 studio — the shared crypto/PKI engine (GIVEN to you; do not modify).

This is lifted *verbatim* from the Session-A notebook
(``../../notebooks/week-05-protocols-tls-pki.ipynb``): the RFC 2409 group-2
1024-bit MODP parameters for Diffie-Hellman, the toy-RSA signature scheme (week 4),
the certificate builder, and the chain validator. Week 5 is about *protocol
guarantees* — not about re-deriving RSA — so the primitives are provided. You write
the DH agreement, the MITM, and the trust-store attack in ``starter.py``.

What lives here (all unchanged from the notebook):
    DH_P, DH_G                         the real 1024-bit MODP group (group 2)
    egcd / modinv / gen_key            toy-RSA key generation
    digest / sign / verify             textbook RSA signature over a SHA-256 digest
    make_cert(subject, pub, issuer_priv)   build one certificate {subject,pub,body,sig}
    validate(chain, trust_store)       walk leaf -> ... -> root, terminating in an anchor
    build_pki(seed=7)                  the exact chain + two forgeries from the notebook
    load_fixtures()                    read the serialized values from fixtures.json

A certificate is a dict: {"subject": str, "pub": (e, n), "body": bytes, "sig": int}.
A trust store is a set of trusted public keys {(e, n), ...}.
"""
import hashlib
import json
import random
from pathlib import Path

# A standard 1024-bit MODP group (RFC 2409 group 2). Real, though small by 2025.
DH_P = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
           "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
           "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
           "A63A3620FFFFFFFFFFFFFFFF", 16)
DH_G = 2


# ---- toy RSA signature scheme (from week 4) --------------------------------

def egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x, y = egcd(b, a % b)
    return g, y, x - (a // b) * y


def modinv(a, m):
    return egcd(a, m)[1] % m


def gen_key(rng, bits=64):
    def prime():
        while True:
            x = rng.getrandbits(bits) | 1 | (1 << (bits - 1))
            if pow(2, x - 1, x) == 1 and all(x % s for s in (3, 5, 7, 11, 13)):
                return x
    pp, qq = prime(), prime()
    n, phi, e = pp * qq, (pp - 1) * (qq - 1), 65537
    return (e, n), (modinv(e, phi), n)         # (public, private)


def digest(msg):
    return int.from_bytes(hashlib.sha256(msg).digest(), "big")


def sign(priv, msg):
    d, n = priv
    return pow(digest(msg) % n, d, n)


def verify(pub, msg, sig):
    e, n = pub
    return pow(sig, e, n) == digest(msg) % n


# ---- certificates & chain validation ---------------------------------------

def make_cert(subject, pub, issuer_priv):
    body = f"{subject}|{pub}".encode()
    return {"subject": subject, "pub": pub, "body": body,
            "sig": sign(issuer_priv, body)}


def validate(chain, trust_store):
    """chain = [leaf, intermediate, ..., root]; each signed by the next."""
    for i in range(len(chain) - 1):
        issuer = chain[i + 1]
        if not verify(issuer["pub"], chain[i]["body"], chain[i]["sig"]):
            return False, f"{chain[i]['subject']}: signature not valid under its issuer"
    root = chain[-1]
    if root["pub"] not in trust_store:
        return False, f"anchor {root['subject']!r} is not a trusted root"
    if not verify(root["pub"], root["body"], root["sig"]):
        return False, "root self-signature invalid"
    return True, "chain valid — key is authentically bound to the name"


# ---- the notebook's exact chain + forgeries (seed 7, deterministic) --------

def build_pki(seed=7):
    """Reproduce the notebook's PKI exactly. Deterministic under ``random``.

    The keys are drawn in the same order as the notebook so the concrete values
    match: root, intermediate, leaf, then Mallory's key and the rogue CA.
    """
    rng = random.Random(seed)
    root_pub,  root_priv  = gen_key(rng)
    inter_pub, inter_priv = gen_key(rng)
    leaf_pub,  leaf_priv  = gen_key(rng)

    root_cert  = make_cert("ACME Root CA",      root_pub,  root_priv)   # self-signed
    inter_cert = make_cert("ACME Intermediate", inter_pub, root_priv)   # signed by root
    leaf_cert  = make_cert("bank.example.com",  leaf_pub,  inter_priv)  # signed by inter
    trust_store = {root_pub}          # what the browser ships with

    # Forgery 1: self-signed cert for the bank, using Mallory's own key.
    mal_pub, mal_priv = gen_key(rng)
    self_signed = make_cert("bank.example.com", mal_pub, mal_priv)

    # Forgery 2: Mallory stands up her own "CA" and signs a bank cert with it.
    rogue_ca_pub, rogue_ca_priv = gen_key(rng)
    rogue_ca   = make_cert("Rogue CA", rogue_ca_pub, rogue_ca_priv)     # self-signed
    rogue_leaf = make_cert("bank.example.com", mal_pub, rogue_ca_priv)  # signed by rogue

    return {
        "chain": [leaf_cert, inter_cert, root_cert],
        "trust_store": trust_store,
        "self_signed_forgery": self_signed,
        "rogue_ca": rogue_ca,
        "rogue_leaf": rogue_leaf,
    }


# ---- fixture (de)serialization ---------------------------------------------

def _cert_to_json(cert):
    return {"subject": cert["subject"], "pub": list(cert["pub"]),
            "body": cert["body"].decode(), "sig": cert["sig"]}


def _cert_from_json(d):
    return {"subject": d["subject"], "pub": tuple(d["pub"]),
            "body": d["body"].encode(), "sig": d["sig"]}


def load_fixtures(path=None):
    """Load the serialized PKI + DH group from fixtures.json.

    Returns a dict with the same shape as ``build_pki`` plus ``dh`` = (p, g),
    with public keys as tuples and the trust store as a set — ready for
    ``validate``. See fixtures.json (generated with a fixed seed)."""
    path = Path(path or Path(__file__).with_name("fixtures.json"))
    data = json.loads(path.read_text())
    return {
        "dh": (int(data["dh"]["p"]), int(data["dh"]["g"])),
        "chain": [_cert_from_json(c) for c in data["chain"]],
        "trust_store": {tuple(k) for k in data["trust_store"]},
        "self_signed_forgery": _cert_from_json(data["self_signed_forgery"]),
        "rogue_ca": _cert_from_json(data["rogue_ca"]),
        "rogue_leaf": _cert_from_json(data["rogue_leaf"]),
    }

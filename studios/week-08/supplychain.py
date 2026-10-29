"""Week 8 studio — the supply-chain / auth engine (GIVEN to you; do not modify).

These are the support routines from the Session-A notebook, unchanged. Week 8 is
about *whether you trust a name or an artifact*, not about re-implementing JWT or
base64 — so the token plumbing and the header-trusting verifier you attack are
provided. You write the exploits and the pins in ``starter.py``.

Two things live here:

  * the JWT plumbing (``b64``/``b64d``, ``make_token``) — how a legitimate,
    signed token is produced under the server's ``SECRET``; and
  * ``verify_insecure`` — the vulnerable verifier that TRUSTS THE TOKEN'S OWN
    ``alg`` header, including ``"none"``. This is the target of Task 3, given
    verbatim so you can watch it accept a forgery.

Nothing here is a break of a primitive: HMAC-SHA256 is intact. The failure this
week is that the verifier trusted a *name* (the ``alg`` header the attacker
supplied) instead of pinning an *artifact* (the algorithm the server chose).
"""
import hashlib
import hmac
import json
import base64

from data import SECRET


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def make_token(payload: dict) -> str:
    """Produce a legitimately signed HS256 token under the server's SECRET."""
    header = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = b64(json.dumps(payload).encode())
    sig = b64(hmac.new(SECRET, f"{header}.{body}".encode(), hashlib.sha256).digest())
    return f"{header}.{body}.{sig}"


def verify_insecure(token: str):
    """VULNERABLE verifier: trusts the token's OWN alg header — including 'none'.

    For ``alg=none`` it returns the payload with NO signature check at all. This
    is the bug: the verifier lets the artifact describe how it should be verified.
    Returns the payload dict on success, or ``None`` on a bad HS256 signature.
    """
    h, p, sig = token.split(".")
    if json.loads(b64d(h)).get("alg") == "none":
        return json.loads(b64d(p))                     # no signature check at all
    expected = b64(hmac.new(SECRET, f"{h}.{p}".encode(), hashlib.sha256).digest())
    return json.loads(b64d(p)) if hmac.compare_digest(sig, expected) else None

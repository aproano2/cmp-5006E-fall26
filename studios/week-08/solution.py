"""Week 8 studio — REFERENCE SOLUTION (instructor-only).

A filled-in copy of ``starter.py``: identical function names and signatures, so
the *provided* ``test_supplychain.py`` passes when this module is imported in
place of ``starter``. Verify with ``studios/_verify_solutions.py`` (which aliases
this file to the name ``starter`` and runs the unmodified test).

The whole week is one shape: every exploit substitutes an *artifact* behind a
*name* the victim trusted; every fix *pins* the artifact (hash + source, or a
server-chosen algorithm) instead of trusting the name. Nothing here breaks a
crypto primitive — HMAC-SHA256 stays intact; the alg=none forgery wins because
the verifier *reads the attacker's header and obeys it*, not because the MAC
fell. That is Control Scorecard axis 2: *only the exact vetted artifact is
trusted*, a promise a name-based lookup can never make.

DO NOT ship to students — excluded via ``studios/.gitignore``. The teaching
walkthrough is ``solution.ipynb`` (imports this file rather than re-pasting it).
"""
from data import (internal_registry, public_registry, LOCKFILE,
                   dep_graph, KNOWN_BAD)
from supplychain import b64, make_token


# ---- Task 1a: dependency confusion — the naive resolver (the bug) -----------

def resolve_highest_version(pkg: str):
    """Resolve ``pkg`` by considering BOTH registries and picking the highest
    version, IGNORING the source. That omission IS the vulnerability: the
    attacker's public 9.9.9 outranks the internal 1.4.2, so their code installs
    under the trusted name. This is Alex Birsan's 2021 dependency-confusion attack.
    """
    def _ver(v):
        return tuple(int(x) for x in v.split("."))

    candidates = []
    if pkg in internal_registry:
        candidates.append(("internal", internal_registry[pkg]))
    if pkg in public_registry:
        candidates.append(("public", public_registry[pkg]))
    # Highest version wins, source is (deliberately, wrongly) ignored.
    return max(candidates, key=lambda c: _ver(c[1]))


# ---- Task 1b: the pin — resolve against the lockfile (the fix) --------------

def resolve_pinned(pkg: str, candidate_hash: str, candidate_source: str):
    """Resolve ``pkg`` against the LOCKFILE instead of by name+version. Only the
    exact artifact you vetted (right source AND right hash) is accepted — the
    name becomes irrelevant. This is ``pip --require-hashes`` / ``package-lock``
    plus a scoped internal registry.
    """
    pin = LOCKFILE.get(pkg)
    if pin is None:
        return (False, f"{pkg} is not in the lockfile — refuse to install an unvetted name")
    if candidate_source != pin["source"]:
        return (False, f"source {candidate_source!r} != pinned {pin['source']!r}")
    if candidate_hash != pin["sha256"]:
        return (False, f"hash {candidate_hash!r} != pinned {pin['sha256']!r}")
    return (True, f"exact vetted artifact ({pin['source']} {pin['version']} {pin['sha256']})")


# ---- Task 2: SBOM — build the transitive list, then query it for a CVE ------

def build_sbom(root: str, graph: dict) -> list:
    """Return the sorted list of ALL transitive dependencies of ``root`` (every
    package reachable in ``graph``, not just the direct ones), excluding ``root``.
    ``xz-utils`` sits two levels deep — nobody chose it, ``acme-auth`` pulled it
    in — which is exactly where the 2024 backdoor lived. You cannot pin, patch,
    or even assess what you cannot enumerate.
    """
    seen = set()
    stack = list(graph.get(root, []))
    while stack:
        dep = stack.pop()
        if dep in seen:
            continue
        seen.add(dep)
        stack.extend(graph.get(dep, []))
    return sorted(seen)


def cve_affected(sbom: list, known_bad: set) -> list:
    """Given an SBOM and a set of known-bad package names (a CVE advisory),
    return the sorted list of affected packages. With an SBOM this "are we
    exposed?" question is an instant set-intersection; without one it is days of
    grepping build logs across every repo.
    """
    return sorted(set(sbom) & set(known_bad))


# ---- Task 3a: forge an alg=none admin token (the attack) --------------------

def forge_alg_none_admin() -> str:
    """Forge a token that the header-trusting ``verify_insecure`` accepts as
    ADMIN, WITHOUT the signing key: header ``alg="none"``, payload
    ``role="admin"``, and an EMPTY signature (the trailing dot). Privilege
    escalation with zero crypto — the verifier let the artifact describe how it
    should be verified.
    """
    import json
    header = b64(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = b64(json.dumps({"user": "alice", "role": "admin"}).encode())
    return f"{header}.{payload}."          # empty third segment = no signature


# ---- Task 3b: the pin — verify with a server-side algorithm (the fix) -------

def verify_secure(token: str, expected_alg: str = "HS256"):
    """Verify ``token`` by pinning the algorithm SERVER-SIDE. Never trust the
    token's own header: reject anything whose ``alg`` is not ``expected_alg`` (so
    ``alg=none`` dies immediately), then check the HS256 signature under the
    server ``SECRET``. Returns the payload dict on success, else ``None``.
    """
    import hashlib
    import hmac
    import json

    from data import SECRET
    from supplychain import b64d

    try:
        h, p, sig = token.split(".")
    except ValueError:
        return None
    # Pin the algorithm we chose; the attacker's self-described "none" is refused.
    if json.loads(b64d(h)).get("alg") != expected_alg:
        return None
    expected = b64(hmac.new(SECRET, f"{h}.{p}".encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(sig, expected):
        return None
    return json.loads(b64d(p))


if __name__ == "__main__":
    # Task 1: watch the attacker's public package win, then the pin refuse it.
    src, ver = resolve_highest_version("acme-auth")
    print(f"naive resolve('acme-auth') -> {src} v{ver} (attacker won: {src == 'public'})")
    print("pinned, attacker's public:", resolve_pinned("acme-auth", "evil99ff", "public"))
    print("pinned, vetted internal  :", resolve_pinned("acme-auth", "aa11bb22cc", "internal"))

    # Task 2: SBOM + CVE query.
    sbom = build_sbom("our-app", dep_graph)
    print("SBOM:", sbom)
    print("affected by xz-utils CVE:", cve_affected(sbom, KNOWN_BAD))

    # Task 3: forge, then pin.
    from supplychain import verify_insecure
    legit = make_token({"user": "alice", "role": "user"})
    forged = forge_alg_none_admin()
    print("naive verifier accepts forgery as:", verify_insecure(forged))
    print("pinned verifier, forgery:", verify_secure(forged))
    print("pinned verifier, legit  :", verify_secure(legit))

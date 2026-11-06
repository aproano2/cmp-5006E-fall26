"""Week 8 studio — starter (three attacks, three pins).

Fill in the functions below. Then run ``python3 test_supplychain.py``. All
provided tests must pass, INCLUDING the guarantee tests that watch a *name*-based
trust decision get exploited: the naive resolver installs the attacker's public
package, and the header-trusting verifier accepts an unsigned admin token. The
matching pin then forces the vetted artifact / rejects the forgery.

Nothing you write breaks a cryptographic primitive. Every exploit substitutes an
artifact behind a name the victim trusted; every fix pins the artifact instead of
trusting the name.
"""
import hmac
import json
import hashlib
from data import (internal_registry, public_registry, LOCKFILE,
                   dep_graph, KNOWN_BAD, SECRET)
from supplychain import b64, make_token, b64d


# ---- Task 1a: dependency confusion — the naive resolver (the bug) -----------

def resolve_highest_version(pkg: str):
    """Resolve ``pkg`` by considering BOTH registries and picking the highest
    version, IGNORING the source. This is essentially the default installer
    behavior that made dependency confusion work at scale.

    Return ``(source, version)`` — e.g. ``("public", "9.9.9")`` for "acme-auth",
    because the attacker's public 9.9.9 outranks your internal 1.4.2.

    Recipe:
      1. Collect candidates ``("internal", v)`` / ``("public", v)`` when present.
      2. Return the candidate with the greatest version, comparing versions as
         tuples of ints, e.g. ``tuple(int(x) for x in "1.4.2".split("."))``.
    """
    # TODO: gather candidates from both registries and return the highest-version
    #       one, ignoring the source (that omission IS the vulnerability).
    candidates = []
    
    if pkg in internal_registry:
        candidates.append(("internal", internal_registry[pkg]))
    if pkg in public_registry:
        candidates.append(("public", public_registry[pkg]))

    if not candidates:
        return None

    def version_key(candidate):
        version_str = candidate[1]
        return tuple(int(x) for x in version_str.split("."))

    best_candidate = max(candidates, key=version_key)
    return best_candidate


# ---- Task 1b: the pin — resolve against the lockfile (the fix) --------------

def resolve_pinned(pkg: str, candidate_hash: str, candidate_source: str):
    """Resolve ``pkg`` against the LOCKFILE instead of by name+version. Only the
    exact artifact you vetted (right source AND right hash) is accepted.

    Return ``(ok: bool, reason: str)``. Reject when:
      * the package is not in the lockfile at all,
      * the source does not match the pinned source, or
      * the hash does not match the pinned sha256.
    Accept only when source AND hash both match the lockfile entry.
    """
    # TODO: look up LOCKFILE[pkg]; refuse if missing, on source mismatch, or on
    #       hash mismatch; accept only the exact vetted artifact.
    if pkg not in LOCKFILE:
        return (False, f"Package '{pkg}' is not present in lockfile")

    entry = LOCKFILE[pkg]

    if candidate_source != entry["source"]:
        return (False, f"Source mismatch for '{pkg}': expected {entry['source']}, got {candidate_source}")

    if candidate_hash != entry["sha256"]:
        return (False, f"Hash mismatch for '{pkg}': expected {entry['sha256']}, got {candidate_hash}")

    return (True, "Artifact verified against lockfile")


# ---- Task 2: SBOM — build the transitive list, then query it for a CVE ------

def build_sbom(root: str, graph: dict) -> list:
    """Return the sorted list of ALL transitive dependencies of ``root`` (every
    package reachable in ``graph``, not just the direct ones). This is the
    inventory a real SBOM captures.

    Hint: walk the graph recursively (or with a stack), collecting names into a
    set, then ``sorted(...)`` it. Do not include ``root`` itself.
    """
    # TODO: collect every reachable dependency of root and return it sorted.
    visited = set()

    def dfs(node):
        for dep in graph.get(node, []):
            if dep not in visited:
                visited.add(dep)
                dfs(dep)

    dfs(root)
    return sorted(list(visited))


def cve_affected(sbom: list, known_bad: set) -> list:
    """Given an SBOM and a set of known-bad package names (a CVE advisory),
    return the sorted list of packages in the SBOM that are affected. With an
    SBOM this is an instant query; without one it is days of grepping build logs.
    """
    # TODO: return the sorted intersection of the sbom with known_bad.
    affected = set(sbom).intersection(set(known_bad))
    return sorted(list(affected))


# ---- Task 3a: forge an alg=none admin token (the attack) --------------------

def forge_alg_none_admin() -> str:
    """Forge a token that the header-trusting ``verify_insecure`` will accept as
    an ADMIN, WITHOUT the signing key. Set the header ``alg`` to ``"none"``, the
    payload ``role`` to ``"admin"``, and send an EMPTY signature.

    Return the token string ``f"{header}.{payload}."`` (note the trailing dot —
    the empty third segment). Use ``b64(...)`` from ``supplychain`` and
    ``json.dumps(...).encode()`` to build the two segments.
    """
    # TODO: base64url a {"alg":"none","typ":"JWT"} header and a
    #       {"user":"alice","role":"admin"} payload; join with an empty sig.
    header_dict = {"alg": "none", "typ": "JWT"}
    payload_dict = {"user": "alice", "role": "admin"}

    header_b64 = b64(json.dumps(header_dict).encode())
    payload_b64 = b64(json.dumps(payload_dict).encode())

    return f"{header_b64}.{payload_b64}."


# ---- Task 3b: the pin — verify with a server-side algorithm (the fix) -------

def verify_secure(token: str, expected_alg: str = "HS256"):
    """Verify ``token`` by pinning the algorithm SERVER-SIDE. Never trust the
    token's own header. Reject anything whose header ``alg`` is not
    ``expected_alg`` (so ``alg=none`` is refused outright), then check the HS256
    signature under the server ``SECRET``.

    Return the payload dict on success, or ``None`` on rejection. You will need
    ``hmac``, ``hashlib``, ``json`` and the ``b64``/``b64d`` helpers plus
    ``SECRET`` — import them here.
    """
    # TODO: split the token; reject if header alg != expected_alg; recompute the
    #       HS256 signature under SECRET and compare with hmac.compare_digest.
    parts = token.split(".")
    if len(parts) != 3:
        return None

    header_b64, payload_b64, sig_b64 = parts

    try:
        header_bytes = b64d(header_b64)
        header = json.loads(header_bytes.decode())
    except Exception:
        return None

    # Fijar/Validar el algoritmo desde el servidor
    if header.get("alg") != expected_alg:
        return None

    # Para HS256, recalcular y verificar la firma usando hmac.compare_digest
    if expected_alg == "HS256":
        signing_input = f"{header_b64}.{payload_b64}".encode()
        expected_sig = b64(hmac.new(SECRET, signing_input, hashlib.sha256).digest())

        if not hmac.compare_digest(sig_b64, expected_sig):
            return None

    try:
        payload_bytes = b64d(payload_b64)
        return json.loads(payload_bytes.decode())
    except Exception:
        return None


if __name__ == "__main__":
    # Task 1: watch the attacker's public package win, then the pin refuse it.
    try:
        src, ver = resolve_highest_version("acme-auth")
        print(f"naive resolve('acme-auth') -> {src} v{ver} "
              f"(attacker won: {src == 'public'})")
    except NotImplementedError:
        print("resolve_highest_version: not implemented yet")
    try:
        print("pinned, attacker's public:", resolve_pinned("acme-auth", "evil99ff", "public"))
        print("pinned, vetted internal  :", resolve_pinned("acme-auth", "aa11bb22cc", "internal"))
    except NotImplementedError:
        print("resolve_pinned: not implemented yet")

    # Task 2: SBOM + CVE query.
    try:
        sbom = build_sbom("our-app", dep_graph)
        print("SBOM:", sbom)
        print("affected by xz-utils CVE:", cve_affected(sbom, KNOWN_BAD))
    except NotImplementedError:
        print("build_sbom / cve_affected: not implemented yet")

    # Task 3: forge, then pin.
    from supplychain import verify_insecure
    legit = make_token({"user": "alice", "role": "user"})
    try:
        forged = forge_alg_none_admin()
        print("naive verifier accepts forgery as:", verify_insecure(forged))
    except NotImplementedError:
        print("forge_alg_none_admin: not implemented yet")
    try:
        print("pinned verifier, forgery:", verify_secure(forged))
        print("pinned verifier, legit  :", verify_secure(legit))
    except NotImplementedError:
        print("verify_secure: not implemented yet")

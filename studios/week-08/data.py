"""Week 8 studio — fixed inputs (GIVEN; do not modify).

Every value here is copied VERBATIM from the Session-A notebook so your results
line up with the demo. The story in one line: each structure below is a *name*
that an attacker can put a different *artifact* behind.
"""

# --- Task 1: dependency confusion --------------------------------------------
# Two registries. The attacker has squatted your internal name on the public one
# with a huge version number. A resolver that picks the highest version and
# ignores the source installs the attacker's code under your trusted name.
internal_registry = {"acme-auth": "1.4.2", "acme-utils": "2.1.0"}
public_registry   = {"acme-auth": "9.9.9", "requests": "2.31.0"}   # 9.9.9 = attacker

# The fix: a lockfile that records the exact artifact you vetted — version, hash,
# and source. "acme-auth" is no longer a name to look up; it's an artifact you
# already approved, and anything else is refused.
LOCKFILE = {
    "acme-auth": {"version": "1.4.2", "sha256": "aa11bb22cc", "source": "internal"},
}

# --- Task 2: SBOM + transitive-CVE query -------------------------------------
# A tiny dependency graph. Real tools (syft, cyclonedx) flatten the whole
# transitive tree. xz-utils sits two levels deep — nobody chose it directly;
# acme-auth pulled it in. That is where the 2024 backdoor lived.
dep_graph = {
    "our-app":    ["acme-auth", "requests"],
    "acme-auth":  ["pyjwt", "xz-utils"],
    "requests":   ["urllib3", "certifi"],
    "pyjwt":      [],
    "xz-utils":   [],          # the 2024 backdoor lived HERE, deep in the tree
    "urllib3":    [], "certifi": [],
}

# The incident-response query: "the xz-utils backdoor just dropped. Are we exposed?"
KNOWN_BAD = {"xz-utils"}

# What a correct SBOM/CVE query reports for our-app (used by the tests):
SBOM_EXPECTED = ["acme-auth", "certifi", "pyjwt", "requests", "urllib3", "xz-utils"]
AFFECTED_EXPECTED = ["xz-utils"]

# --- Task 3: alg=none JWT forgery --------------------------------------------
# The server signs tokens under this HMAC key. The alg=none forgery needs no key
# at all — it exploits the verifier trusting the token's own header, not the key.
SECRET = b"server-signing-key"

# The legitimate session and the attacker's target claim.
LEGIT_PAYLOAD  = {"user": "alice", "role": "user"}
FORGED_PAYLOAD = {"user": "alice", "role": "admin"}

# Week 8 — Control Scorecard (Task 4)

Evidence comes from `test_supplychain.py` (all 4 pass) and `python starter.py`.

**Recap answer:** all three attacks put a different artifact behind a name the victim
trusted. The single fix is to **pin the artifact, not the name**: accept only the exact
vetted thing (hash, source, algorithm), checked against a value **you** control.

## What we observed

| Attack | Naive path (name trusted) | Pinned path (artifact trusted) |
|---|---|---|
| Dependency confusion | `resolve_highest_version("acme-auth")` → **`public 9.9.9`** (attacker wins) | `resolve_pinned(..., "evil99ff", "public")` → **refused** (`source mismatch`); vetted `internal` + `aa11bb22cc` → accepted |
| Transitive backdoor (XZ) | Direct deps only: `acme-auth`, `requests`. `xz-utils` is **invisible** | SBOM: `acme-auth, certifi, pyjwt, requests, urllib3, xz-utils` → CVE query answers **`['xz-utils']`** instantly |
| `alg=none` JWT | `verify_insecure(forged)` → **`{'user': 'alice', 'role': 'admin'}`**, no key used | `verify_secure(forged)` → **`None`**; real HS256 token still accepted |

Extra checks on `verify_secure` (not in the provided tests), all rejected (`None`):
tampered payload with the original signature, token signed with the wrong key,
header `alg=HS512`, a malformed token (`abc`), a token with 4 segments. On
`resolve_pinned`: a package missing from the lockfile and an `internal` source with
the wrong hash are both refused.

## Scorecard

| Attack | Trusted name | Substituted artifact | The pin that fixes it | Guarantee (axis 2) |
|---|---|---|---|---|
| **Dependency confusion** | package name `acme-auth` | attacker's public `acme-auth 9.9.9` | lockfile entry: exact version **+ sha256 + source**, plus an internal registry scoped to the `acme-*` names | Only the artifact whose hash and source match the lockfile installs, *provided the lockfile was vetted and is integrity-protected* (an attacker who can edit the lockfile edits the pin). |
| **Transitive backdoor (XZ)** | "it's just a dependency" | compromised upstream code (`xz-utils`, 2 levels deep) | **SBOM** (full transitive inventory) + provenance (signed builds) + pinning each transitive dep by hash | We can answer "are we exposed to CVE-X?" instantly and completely, *provided the SBOM is regenerated on every build*. The SBOM is a **detective** control: it tells you that you are exposed but does not stop a backdoor that was vetted and pinned before it was known to be bad. |
| **`alg=none` JWT** | the token's own `alg` header | an unsigned token claiming `role: admin` | **server-side algorithm pinning** (`expected_alg="HS256"`), then HMAC check under `SECRET` with `hmac.compare_digest` | Only tokens HMAC-signed under our `SECRET` are accepted, *provided `SECRET` is long and random*. A short dictionary secret can be brute-forced offline, and then the attacker mints valid HS256 tokens that pass the pin. |

**The shared guarantee:** *only the exact vetted artifact is trusted*, checked against a
list or key **we** control, never against what the artifact says about itself.

## Fast-finisher: a fourth place where a name is trusted

**Container image tags (`FROM python:latest`).** `latest` (or even `3.12`) is a name:
whoever controls the registry can push a different image under it, and the next build
silently pulls it. **Pin:** reference the image by digest,
`FROM python@sha256:<digest>`, so only that exact image is used. To change it you have
to change the digest on purpose, in a reviewed commit.

## What we did not test

- The lockfile hashes are toy strings (`aa11bb22cc`), not real SHA-256 digests of a
  downloaded file. We did not hash an actual package.
- The bonus (brute-forcing a weak HMAC secret) was not done.
- The SBOM covers one small hand-written graph. Real tools (syft, CycloneDX) also have to
  deal with version ranges, vendored code and native libraries that do not appear in any
  package manager.

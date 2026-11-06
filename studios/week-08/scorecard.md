# Control Scorecard — Week 8 Studio

## Scorecard by Attack

| Attack | Trusted Name | Substituted Artifact | The Pin That Closes It | Function in `starter.py` | Guarantee (Axis 2) |
|---|---|---|---|---|---|
| **Dependency confusion** | Package name (`acme-auth`) | Attacker's public package (v9.9.9) | Lockfile + sha256 hash + pinned source | `resolve_pinned` | Only the exact vetted artifact from the selected source is installed |
| **Transitive backdoor (XZ)** | "It's just a dependency" | Compromised code in an upstream package, two levels deep | SBOM + provenance + pinning | `build_sbom`, `cve_affected` | Everything we use is enumerated, and can therefore be pinned, patched, and assessed |
| **`alg=none` JWT** | The token's own `alg` header | An unsigned token claiming admin privileges | Server-side algorithm pinning | `verify_secure` | Only tokens signed with an algorithm and key we control are accepted |

## Common Guarantee (Axis 2)

## Exploitation vs. Fix

| Attack | How It Is Exploited | How It Is Fixed |
|---|---|---|
| Dependency confusion | The resolver considers both registries and picks the highest version, ignoring the source (`resolve_highest_version`). | Source and hash are checked against the lockfile; any mismatch is rejected. |
| Transitive backdoor (XZ) | The malicious dependency is pulled in transitively without being explicitly selected. | The full dependency graph is traversed and intersected with the list of known vulnerabilities. |
| `alg=none` JWT | Token uses `alg: none`, `role: admin`, and an empty signature; the verifier obeys the header. | Any `alg` other than HS256 is rejected, and the signature is recomputed using `SECRET` via `hmac.compare_digest`. |

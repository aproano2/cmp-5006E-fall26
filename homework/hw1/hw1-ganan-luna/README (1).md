# Part A — Breaks

## How to run

Every script imports the instructor's `duel1_targets.py` through `_common.py`,
using **only the module's public functions** — the outputs an attacker would
actually see (ciphertexts, a public token, public RSA moduli, a boolean oracle).
No script reads a private key or module-internal variable.

```bash
python3 break1_reused_pad.py
python3 break2_ecb_store.py
python3 break3_ctr_log.py
python3 break4_token_mac.py
python3 break5_keygen_fleet.py
python3 break6_timing_compare.py        # ~60-90s: it measures real wall-clock time
```

Each script ends with an `assert` against the module's own oracle
(`verify_token`, `timing_compare`, or a direct check like "does the recovered
`n` factor back to the given one") — a failed break fails loudly instead of
printing a false "success."

## Assumption, break type, and confirmation — at a glance

| # | Deployment | Assumption that broke | Primitive break or misuse? | Confirmed artifact |
|---|---|---|---|---|
| 1 | `reused_pad` | "A random-looking keystream this long is as good as a one-time pad" — true only if the pad is used **once**; here it's reused across 4 messages | **Misuse** — the OTP precondition (single use) was violated, not a flaw in XOR itself | Full target plaintext recovered, column analysis + beam search + dictionary repair, cross-checked by crib-dragging |
| 2 | `ecb_store` | "Encrypting each block independently is fine if the block cipher is strong" — ECB leaks block **equality** regardless of cipher strength | **Misuse** — a mode-of-operation choice, not a break of the underlying block function | Two records proven (from ciphertext alone) to share role+department |
| 3 | `ctr_log` | "CTR is just a stream cipher, nonce reuse is a minor detail" — false the instant `(key, nonce)` repeats, which turns it into Break #1's attack again | **Misuse** — nonce-management failure; same attack class as #1, different deployment | Target log line recovered to one unresolved trailing digit (stated, not hidden) |
| 4 | `token_mac` | "`H(secret‖data)` is a MAC because you need the secret to compute `H`" — false for any Merkle–Damgård hash (MD5/SHA-1/SHA-256-style, and this toy hash) | **Misuse** — wrong MAC construction, not a break of the hash's collision resistance | Forged `role=admin` token, accepted by the server's own `verify_token()` |
| 5 | `keygen_fleet` | "Each device's prime-generation call is independent" — false under shared low-entropy boot state across a device fleet | **Misuse** — a randomness/generation failure; RSA's factoring-hardness assumption is untouched | Full RSA private key for `device0` recovered via batch-GCD and verified by encrypt→decrypt round-trip |
| 6 | `timing_compare` | "Returning early on the first mismatch is just an optimization" — it leaks the matching-prefix length through wall-clock time | **Misuse** — a comparison-implementation bug, not a cryptographic break | 4-byte secret recovered; **reliability reported, not assumed** — 2/3 independent full re-runs succeeded at our chosen trial count, and we show the attack degrading at a smaller sample size |

All six are **misuses**: none of them break SHA-256, AES, or RSA as primitives.
Each takes a sound primitive and deploys it under a precondition the code
silently violated. That is the entire point of Control Scorecard axis 2 —
*"AES-CTR is secure"* is an incomplete sentence; *"AES-CTR is secure provided
`(key, nonce)` pairs are never reused"* is the one that survives this duel.

## Notes specific to each break

- **#1 / #3** are the *same underlying attack* (two-time-pad / keystream
  reuse) against two different deployments — one argument, two targets. We
  say so rather than presenting them as independent discoveries.
- **#4**'s forgery needs only `len(secret) = 9` (stated in the deployment's
  own docstring — a realistic leak, e.g. a changelog or a config comment),
  never the secret's bytes.
- **#6** required adapting the textbook timing-attack recipe to this specific
  sandbox: single-call timing was too noisy on a 1-core container, so we
  batch many calls between two clock reads and take the **minimum** batch
  (OS/scheduler noise is one-sided — it can only slow a call down — so the
  minimum is the least-biased estimator of the call's true cost). The exact
  trial counts and the resulting reliability are reported inside the script's
  own output, and discussed further in `../honesty.md`.

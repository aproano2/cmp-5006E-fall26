**Names:** María Emilia Cueva (00328938), Santiago Reátegui (00331329), Jorge Gomez (00329264)

# Part A — Confirmed breaks against the provided local targets

Run from this directory's parent with `python breaks/01_reused_pad.py` through
`python breaks/06_timing_compare.py`. Each script imports only the public target
functions and uses Python's standard library. No private key or secret variable is
read. The fixed seed makes the outputs repeatable. These are attacks on the local
teaching module, not on an external service.

| # | Designer's unstated assumption | Recovered artifact and confirmation | Primitive break or misuse? |
|---|---|---|---|
| 1. Reused pad | The pad bytes will protect multiple messages even when reused at the same offsets. | With a known plaintext crib for `msg1`, the script recovers the first **69 of 70** target bytes: `the launch authorization code will be delivered by separate courier o`. The XOR relation holds over all 69 overlapping bytes. The last byte has no corresponding pad observation and is **not recovered**. | **Misuse.** XOR with a fresh uniformly random one-time pad remains sound; reusing it exposes plaintext XORs. |
| 2. ECB store | Encrypting each record block independently will hide repeated fields. | Ciphertext blocks 1–3 of records 0 and 2 are identical: `d8f6f831 | 3eb9e189 | 7cf7fff3`. Given the known reference that record 0 is Alice with `role=admn`, record 2 (Carl) has the same role and department. | **Misuse.** Deterministic independent block encryption leaks equality. The module uses a four-byte SHA-256-based stand-in, not AES, so this is a mode analogy rather than an AES break. |
| 3. CTR log | Reusing a nonce with the same key will not repeat the keystream. | A known `log1` line recovers **69 of 70** bytes of `log2`: `2025-03-01 12:09 user=admin action=export result=success from=10.0.0.`. The XOR relation holds over the overlap. The final IP digit is **not recovered**. | **Misuse.** A CTR-like stream with a unique nonce does not expose this two-time-pad relation. The module builds its keystream from SHA-256, not AES-CTR. |
| 4. Prefix MAC | A secret prefix makes a Merkle–Damgård-style hash a secure MAC. | Forged data `b'user=alice&role=user\x00\x00\x00&role=admin'`, tag `4024164909`; `verify_token` returns `True`. The successful padding guess is `1`, which only identifies a secret-length congruence class modulo four, not the actual length. | **Misuse.** A raw hash is not a proper MAC construction. The supplied `_md_hash` is a toy 32-bit polynomial hash, despite the assignment's SHA-256 label; the attack demonstrates continuation from a published state. |
| 5. RSA fleet | Independently generated RSA moduli will not share a prime. | A batch-GCD over the public moduli finds the shared factor `14723961130838400979`. The recovered private exponent for device 0 is `155006092543738932355592225651672081825`. Encrypting and decrypting `42` returns `42`. | **Misuse.** Shared-prime key generation exposes factors; this does not factor a properly generated RSA modulus. These are tiny toy keys. |
| 6. Timing comparison | An early return will not disclose how many prefix bytes matched. | The script recovers `83fabf35`, and `timing_compare(bytes.fromhex('83fabf35'))` returns `True`. It times the first three bytes and searches the final byte with the Boolean verifier. | **Misuse.** The comparison implementation leaks timing; it does not break the secret's underlying cryptographic primitive. |

## Reliability and evidence limits

- The pad and CTR attacks use complete known-plaintext cribs for another message.
  This is stronger information than an attacker who sees only ciphertexts might
  have. Their recovered 69-byte prefixes are independently recognizable, but the
  XOR equalities are algebraic consequences of the method, not separate
  decryption oracles. The source's final target bytes are never used by the
  scripts, because those bytes cannot be derived from the published outputs.
- ECB shows block equality. The label `admn` depends on a known Alice reference;
  ciphertexts alone do not name either role. The record layout and reference
  values are visible in the provided source.
- The token verifier checks MAC validity only. It does not parse roles or grant
  permissions. Thus the demonstrated artifact is a **valid extended token**, not
  a confirmed authorization escalation. The duplicate-role interpretation
  depends on an application parser that the target does not provide.
- Timing is noisy. Each candidate is measured in **13 trials of 20 calls**, with
  randomized candidate order. To demonstrate this sensitivity, the provided `--check` routine actually fails on our local Windows environment because it only performs 41 trials, which is insufficient to average out OS background noise. By scaling up to **199,734 oracle calls**, our script successfully filtered this noise. Three consecutive runs of this version succeeded (`3/3`), using 199,734 oracle calls each. Another successful run required **200,246 calls** and placed the correct third byte at rank 3. Earlier naive timing versions failed. These measurements are local Windows/Python results, not a remote-network success rate; different loads may require reruns. In the final review, the script also succeeded on Linux with Python 3.14.7.

## Conditional control lessons (Control Scorecard axis 2)

| Broken deployment | Replacement guarantee and its condition |
|---|---|
| Reused pad | A true one-time pad hides plaintext **if** its key bytes are uniform, secret, at least as long as the plaintext, and used once. |
| ECB store | An authenticated encryption mode hides repeated record fields **if** fresh nonces are used per encryption under the key and ciphertext lengths or metadata do not themselves reveal the field. |
| CTR log | CTR confidentiality holds against this XOR attack **if** a `(key, nonce)` pair is never reused; integrity also requires a separate MAC or an AEAD. |
| Prefix MAC | HMAC-SHA-256 authenticates a token **if** the key stays secret, verification is correct, and the entire unambiguous token is MACed. |
| RSA fleet | RSA private keys remain hidden from this shared-factor attack **if** each keypair uses independently generated strong primes and the private key is protected. |
| Timing comparison | Constant-time comparison removes the matched-prefix timing signal **if** surrounding parsing and error handling also avoid secret-dependent timing and the attacker has no other oracle. |
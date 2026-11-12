# Part A — confirmed breaks

All scripts attack only the local deterministic target in
[`../duel-1-crypto/duel1_targets.py`](../duel-1-crypto/duel1_targets.py).
Run them from this directory with `python3 breaks/<script>.py`. Run
`python3 verify_plaintext_evidence.py` for separate fixture confirmation of the
two recovered plaintext prefixes and their negative controls. See
[breaks/README.md](./breaks/README.md) for the attacker-knowledge assumptions.

## Tier 1

### `reused_pad.py`

- **Assumption:** The designer assumed that reusing the same pad across messages
  would preserve one-time-pad confidentiality.
- **Attacker knowledge:** The script assumes the exact companion plaintexts
  `msg0`, `msg1`, and `msg2` are known. These cribs were taken from the visible
  classroom fixture; they are not supplied by the ciphertext API and were not
  recovered through ciphertext-only crib-dragging.
- **Break:** XORing each assumed plaintext with its ciphertext recovers the
  shared keystream. `msg0` covers offsets 0–64; `msg1` and `msg2` cover 0–68.
  The script checks overlapping cribs for consistency and recovers the 69-byte
  prefix `the launch authorization code will be delivered by separate courier o`.
  Target offset 69 remains unknown. The script does not append a guessed `k`.
- **Primitive break or misuse?** Misuse: the one-time-pad primitive is not
  broken, but its required one-use key condition was violated.
- **Confirmation:** The separate verifier compares the recovered prefix with
  the literal target plaintext in the provided fixture, without supplying that
  reference to the recovery function or accessing the pad key. It confirms
  **69/70 bytes**, rejects a corrupted recovered prefix and contradictory cribs,
  and checks that changing the uncovered ciphertext byte leaves one unknown
  byte. This is fixture-confirmed partial known-plaintext recovery, not a public
  decryption oracle or complete recovery.

### `ctr_log.py`

- **Assumption:** The designer assumed that repeating a CTR nonce with the same
  key would not reveal relationships between log entries.
- **Attacker knowledge:** The script assumes the exact plaintext of `log1` is
  known. That full-message crib comes from the visible classroom fixture, not
  the ciphertext API. A log format alone does not supply all its field values.
- **Break:** `C1 XOR C2 XOR P1` recovers the 69-byte target prefix
  `2025-03-01 12:09 user=admin action=export result=success from=10.0.0.`.
  The final IP digit at target offset 69 remains unknown. Format alone cannot
  determine it, and the script does not append a guessed `2`.
- **Primitive break or misuse?** Misuse: CTR is secure when its counter/nonce
  input is unique for a key; the deployment reused it.
- **Confirmation:** The separate verifier compares the recovered prefix with
  the fixture's literal target entry without passing that reference to the
  recovery function or accessing the CTR key. It confirms **69/70 bytes**, rejects
  a corrupted prefix and an incorrect known-log crib, and checks that changing
  the uncovered ciphertext byte leaves one unknown byte. This is partial
  known-plaintext recovery; no public plaintext-check oracle is provided.

## Tier 2

### `keygen_fleet.py`

- **Assumption:** The designer assumed that independent fleet devices would
  generate independent RSA primes despite low-entropy startup randomness.
- **Break:** A batch GCD finds the shared prime, factors `device0`, and computes
  its private exponent `d`; the script prints `(n, e, d)` and verifies an
  encrypt/decrypt round trip.
- **Primitive break or misuse?** Misuse: RSA is not broken; weak randomness
  caused prime reuse, making the public moduli factorable.
- **Confirmation:** The script checks that the recovered private exponent
  decrypts a test ciphertext.

### `verify_login.py`

- **Assumption:** The designer assumed that exposing an early-exit comparison
  would not reveal enough timing information to distinguish matching prefixes.
- **Break:** Measure the oracle for every candidate byte and choose the candidate
  with the largest median runtime; the script recovers and validates the
  four-byte secret.
- **Primitive break or misuse?** Misuse: the comparison primitive is not
  cryptographically broken; the deployment exposed a secret-dependent timing
  branch instead of a constant-time comparison.
- **Reliability:** The script retries with 500, 1,000, 2,000, and 4,000 samples
  per candidate and stops once the recovered secret validates. Every attempt
  measures 256 candidates at each of four positions. It now reports each
  attempt and cumulative measurement/validation calls, including failed retries.
  Success on the first attempt takes **512,000 measurement calls plus one
  validation call = 512,001 total**. Reaching the end of all four attempts takes
  `4 * 256 * (500 + 1000 + 2000 + 4000) = 7,680,000` measurement calls plus
  four validation calls: **7,680,004 total**, whether the last attempt succeeds
  or all attempts fail. The original review run and a run of the revised script
  each recovered `83fabf35` on the first attempt; the revised output reported
  512,001 total calls. These two observations do not establish a typical sample
  requirement or success rate. Recovery remains conditional on sufficient local
  timing signal; a successful final oracle validation confirms the recovered
  secret. Four mocked regression tests separately cover call reporting after
  first-attempt success, retries, final-attempt success, and exhaustion.
- **Measured success rate (independent re-run):** On a second machine (Apple M1
  Pro, macOS 26.6.2, Python 3.14.7) the unmodified script was run **10 times in
  a row**. It recovered and validated `83fabf35` in **10/10 runs, every time on
  the first attempt** (500 samples per candidate, 512,001 oracle calls per run,
  ~28 s each); the retry budget was never needed. This is evidence for this
  local, amplified target on one machine, not for a remote or unamplified oracle.

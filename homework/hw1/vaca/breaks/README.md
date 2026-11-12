# Duel 1 — Part A: the breaks

Six flawed deployments from `../../duel-1-crypto/duel1_targets.py`, all broken and
each **confirmed by a recovered artifact**. The assignment asks for at least four
(≥ 1 per tier); we did all six. Every break attacks only the target functions'
**public outputs** — we never read a key. Where a break needs the published
*algorithm* (the length-extension hash) or one *known plaintext*, it is stated
below and in the script's header.

## How to run

Each script is standalone and deterministic (the target fixes `SEED`), so the
artifacts below reproduce exactly — except the timing margins in #6, which are
machine- and load-dependent by nature.

```bash
cd homework/hw1/vaca/breaks
python3 break1_reused_pad.py
python3 break2_ecb_store.py
python3 break3_ctr_log.py
python3 break4_token_mac.py
python3 break5_keygen_fleet.py
python3 break6_timing_compare.py      # ~15 s; recovers a 4-byte secret by timing
```

## Summary

Every one of the six is a **misuse**, not a primitive break — stated per the
assignment. The primitive is sound; the deployment violated a precondition.

| # | Tier | Deployment | Assumption that made it breakable | Recovered artifact | Primitive vs misuse |
|---|------|-----------|-----------------------------------|--------------------|---------------------|
| 1 | 1 | `reused_pad` | "An OTP is unbreakable" — forgetting the guarantee holds for **one** message per key | Full target plaintext: *"the launch authorization code will be delivered by separate courier ok"* | **Misuse** — XOR-pad is perfectly secret for a single use; reuse → two-time pad |
| 2 | 1 | `ecb_store` | "Encrypted records leak nothing" — ignoring that ECB is **deterministic per block** | Records 0 & 2 share role+dept (both `admn:engr`); one labelled record names them | **Misuse** — block cipher is a black box; ECB mode leaks block equality |
| 3 | 1 | `ctr_log` | "CTR is modern, so it's safe" — missing that CTR needs a **unique nonce per message** | Target audit line: admin ran `action=export` (`result=success`), all but final IP digit | **Misuse** — CTR is sound; reusing the nonce gives a keystream reuse |
| 4 | 2 | `token_mac` | "Secret-prefix hash authenticates data" — false for any **Merkle–Damgård** hash | Forged token `…&role=admin` that `verify_token` accepts, no secret used | **Misuse** — wrong MAC construction; HMAC resists it |
| 5 | 2 | `keygen_fleet` | "Each device's modulus is independent" — false under **low-entropy** key generation | `device0` private key (p, q, d), verified by a decrypt round-trip | **Misuse** — RSA is fine; correlated randomness → shared prime, GCD factors it |
| 6 | 2 | `timing_compare` | "A boolean compare only reveals yes/no" — ignoring the **time** channel | 4-byte secret `0x83fabf35`, confirmed by the function's own oracle | **Misuse** — no primitive; data-dependent control flow leaks the prefix length |

## Per-break detail

The full assumption, method, confirmation, and reliability note for each break
live in the **module docstring at the top of each `breakN_*.py`**. In brief:

1. **`break1_reused_pad.py`** — The same pad encrypts all four messages, so
   `C_i ⊕ C_j = P_i ⊕ P_j`. Because the plaintexts are lowercase English, a
   per-column constraint (every decrypt must be `a..z` or space) uniquely pins
   ~34/70 keystream bytes; crib-dragging confirmed against *all four*
   ciphertexts recovers the rest. Recovers all four plaintexts, including TARGET.

2. **`break2_ecb_store.py`** — ECB encrypts each 4-byte block independently and
   deterministically. Records 0 and 2 produce identical ciphertext for their
   role+dept blocks → same role **and** dept, recovered with no key. One
   labelled record (a crib) turns the equivalence class into named admins.

3. **`break3_ctr_log.py`** — The nonce is reused, so every entry shares one
   keystream. One self-generated known entry gives `keystream = C ⊕ P`, which
   decrypts the admin's TARGET entry. Honest gap: the target is one byte longer
   than the crib, so the final IP digit is uncovered.

4. **`break4_token_mac.py`** — `tag = H(secret‖data)` with an MD-style hash is
   length-extendable: resume hashing from the published tag, append
   `&role=admin`, and `verify_token` accepts the forgery. Uses only the tag and
   the secret's published *length*, never the secret.

5. **`break5_keygen_fleet.py`** — Two devices share an RSA prime from a weak
   fleet PRNG. `gcd(n_0, n_2)` yields that prime in milliseconds; dividing gives
   the other factor, and `d = e^{-1} mod φ` follows. Confirmed by a full
   encrypt/decrypt round-trip. (The real-world *Mining your Ps and Qs* result.)

6. **`break6_timing_compare.py`** — The compare returns at the first mismatched
   byte, so its runtime leaks how long a prefix matched. Recovering the secret
   byte-by-byte (slowest-median candidate wins) and confirming with the boolean
   oracle yields `0x83fabf35`. Reliability is reported as the smallest
   trials/byte that still verified, plus per-byte timing margins.

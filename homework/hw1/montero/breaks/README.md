# Part A: Breaks

Six flawed deployments, all broken and confirmed. Each script imports the provided
`duel1_targets.py` (through `_targets.py`), calls only its public functions, and
prints the recovered artifact plus a `CONFIRMED` line.

```bash
cd breaks
python3 break_1_reused_pad.py     # two-time pad
python3 break_2_ecb_store.py      # ECB structure leak
python3 break_3_ctr_log.py        # CTR nonce reuse
python3 break_4_token_mac.py      # length extension
python3 break_5_keygen_fleet.py   # shared-prime batch-GCD
python3 break_6_timing.py         # timing side channel (~2 min)
```

All six are misuses, not primitive breaks. XOR, SHA-256, AES-CTR, RSA and byte
comparison are each sound; the failure in every case is in how they were deployed.
The assumption broke, not the algorithm.

| # | Deployment | Assumption the designer made | Misuse / primitive | Recovered artifact |
|---|---|---|---|---|
| 1 | `reused_pad` | "a random XOR pad gives perfect secrecy" | Misuse: pad reused across messages (OTP used n times) | `the launch authorization code will be delivered by separate courier ok` |
| 2 | `ecb_store` | "a strong block cipher makes the records confidential" | Misuse: ECB is deterministic, equal blocks leak | record0 & record2 share role+dept blocks, so record2 is unmasked as `admn` |
| 3 | `ctr_log` | "AES-CTR gives confidentiality" | Misuse: one nonce reused for every entry | `2025-03-01 12:09 user=admin action=export result=success from=10.0.0.?` |
| 4 | `token_mac` | "H(secret‖data) authenticates data; no secret, no tag" | Misuse: raw Merkle-Damgard hash as a MAC (length-extendable) | forged `user=alice&role=user\x00\x00\x00&role=admin`, tag `4024164909`, `verify_token → True` |
| 5 | `keygen_fleet` | "each device makes an independent keypair" | Misuse: low boot entropy reused a prime across devices | shared prime `14723961130838400979`; full private key `d` for device0 (and device2) |
| 6 | `timing_compare` | "a boolean equality check leaks only yes/no" | Misuse: early-exit comparison leaks prefix length | secret `83fabf35` |

## Per-break detail

**#1 reused_pad: two-time pad.** The pad cancels: `C_i ⊕ C_j = P_i ⊕ P_j`. Stage 1
is space-anchoring and assumes no plaintext: wherever one message has a space, the XOR
of ciphertext columns turns into letters, recovering 34/70 keystream bytes, the
skeleton of every message. Stage 2 completes one readable message and uses it as a
known-plaintext crib to peel the target. The last column is reached by a single
message (the longest), so it is fixed from English context (`...o?` resolves to `ok`).

**#2 ecb_store: structure leakage.** No decryption. Records are `name:role:dept`
in 4-byte blocks; records 0 and 2 have byte-identical ciphertext for blocks 1-3,
which proves identical `(role,dept)`. Given one known anchor (record0 is a known
admin), record2 is unmasked as an admin while every name stays encrypted. A
chosen-plaintext registration would turn the equivalence classes into a full role
dictionary.

**#3 ctr_log: nonce reuse.** Structural proof first: `C_log0 ⊕ C_log1` is `0x00` at
55 positions (exactly the shared log template), impossible unless the keystream is
identical. Then a self-generated known entry (a forced `bob00` failed login) gives a
known plaintext, and `keystream = C_log1 ⊕ P_log1` decrypts the admin target. The
final IP-octet digit is in a column no other message reaches, so it is left as `?`.

**#4 token_mac: length extension.** The tag is the hash's internal state after
`secret‖data`. The hash algorithm is public (Kerckhoffs), so we resume from the tag,
append the glue padding plus `&role=admin`, and compute a valid tag without the
9-byte secret. `verify_token()`, the server's own check, accepts it. (If the secret
length were unknown we would try candidate lengths until `verify_token` accepts.) The
forged data carries both `role=user` and `role=admin`: the forgery is unconditional,
but the privilege escalation holds only if the server resolves a duplicate `role=`
key to the last value. A server that keeps the first value, or rejects duplicates, is
unaffected.

**#5 keygen_fleet: shared prime.** Factoring is not broken; `gcd(n_i,n_j)` is cheap.
Pairwise GCD (the fleet-scale version is a product-tree batch-GCD) finds that device0
and device2 share a prime; dividing recovers both factors, `φ`, and `d = e⁻¹ mod φ`.
Confirmed by a decrypt and a sign/verify round trip (`42` back to `42`).

**#6 timing_compare: side channel.** Running time is proportional to the correct
prefix length, so `256⁴` becomes `4 × 256` timed trials. Per candidate byte we take
the minimum of 500 timed calls (the minimum filters one-sided scheduling and GC
noise; the correct byte always does one extra amplified loop). Reliability: 3 of 3
independent rounds recovered the full secret `83fabf35`, about 1.5 M timed calls
total, confirmed by `timing_compare(secret) → True`. See `honesty.md` on why this
signal is synthetic.

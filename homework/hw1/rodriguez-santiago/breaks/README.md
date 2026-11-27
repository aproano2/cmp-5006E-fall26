# Breaks — Duel 1, Part A

All six deployments broken (the assignment requires ≥ 4 with ≥ 1 per tier; we did
all six). Each script is standalone, imports the provided `duel1_targets.py`, uses
only the **public outputs** (never the keys), and prints the **recovered artifact**.

## How to run

Put these scripts anywhere at or below the folder that contains `duel1_targets.py`
(`_pathfix.py` walks up the tree to find it), then:

```bash
python break1_reused_pad.py
python break2_ecb_store.py
python break3_ctr_log.py
python break4_length_extension.py
python break5_shared_prime.py
python break6_timing.py          # noisy; optional args: rounds reps runs (default 12 20 3)
```

All breaks are **misuses**, not primitive breaks — the primitive (XOR/OTP, the
block cipher, AES-CTR, the MD-style hash, RSA, the byte comparison) does exactly
what it promises; the deployment violated the *condition* the guarantee depends on.

| # | Target | Tier | Assumption the designer made (one sentence) | Recovered artifact | Primitive or misuse |
|---|--------|------|---------------------------------------------|--------------------|---------------------|
| 1 | `reused_pad` | 1 | "A one-time pad is secure" — forgetting it is secure *only if used once*; here one pad encrypts every message. | Target plaintext: *"the launch authorization code will be delivered by separate courier ok"* | **Misuse** (key reuse → two-time pad) |
| 2 | `ecb_store` | 1 | "AES is strong, so AES-ECB protects the records" — forgetting ECB encrypts each block independently. | record0 & record2 are the two `admn:engr` employees, inferred from identical ciphertext blocks | **Misuse** (ECB mode leaks structure) |
| 3 | `ctr_log` | 1 | "AES-CTR is a strong modern mode" — forgetting CTR needs a *unique nonce per message*; here the nonce is reused. | Target log line: `... user=admin action=export result=success ...` | **Misuse** (nonce reuse → C_i⊕C_j = P_i⊕P_j) |
| 4 | `token_mac` | 2 | "Only the secret holder can compute `H(secret‖data)`" — forgetting an MD hash's output *is* its resumable internal state. | Forged admin token that `verify_token()` accepts, made without the secret | **Misuse** (`H(secret‖data)` construction; fix = HMAC) |
| 5 | `keygen_fleet` | 2 | "RSA-2048 is unbreakable because factoring is hard" — forgetting the guarantee needs *good, independent entropy* for p,q. | Private key of device0 (`p`, `q`, `d`), confirmed by RSA roundtrip | **Misuse** (weak RNG shares a prime; batch-GCD) |
| 6 | `timing_compare` | 2 | "A boolean compare leaks only pass/fail" — forgetting an early-exit compare's *duration* leaks the matched prefix length. | 4-byte secret `83fabf35`, confirmed by `timing_compare(secret)==True` | **Misuse** (variable-time compare; fix = constant-time) |

## Confirmation (oracles)

- **#1, #3**: cross-consistency — one keystream makes *every* ciphertext decode to
  coherent, correctly-formatted text at once; chance of that by luck is negligible.
- **#2**: block-equality is exact, not statistical.
- **#4, #5**: the deployment's own checker confirms (`verify_token`; RSA roundtrip).
- **#6**: `timing_compare(recovered) == True`. **Probabilistic** — see reliability.

## Reliability of #6 (the only noisy break)

The signal is a single extra ~4000-iteration loop per matched byte. We interleave
(sweep all 256 candidates per round, accumulate over rounds) to average out OS
jitter. Across sessions we observe **2–3 / 3 runs fully correct** at `rounds=12,
reps=18` (~221k calls/run). The **last byte is by far the noisiest**: the top-vs-
second-candidate time margin is enormous for byte 1 (whole-loop difference) but
only ~2–17 % for byte 4. Raising `rounds` trades wall-clock for reliability. This
matches the instructor self-check, where `--check`'s short timing run also fails.

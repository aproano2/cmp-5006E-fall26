# Homework 1 — Crypto & Protocols

## Group members

- Felipe Rodríguez-00330528
- Josué Ponce-00330341

## Contents

| File or directory | Description |
|---|---|
| `breaks/` | Four reproducible scripts attacking the homework's local targets. |
| `breaks/README.md` | The assumption behind each vulnerability and why it is cryptographic misuse rather than a primitive break. |
| `secs-design.md` | Secure Electronic Contract Signing design: primitives, message flow, trust boundaries, conditional guarantees, and deployment mistakes it avoids. |
| `ImagenDeber1.png` | SECS flow diagram showing acceptance signatures and receipts for the final signed copy. |
| `honesty.md` | Self-critique of the assumptions, limitations, and reproducibility of the attacks and design. |
| `AI_LOG.md` | Record of AI assistance used in this submission. |

## Running the attacks

Python 3.8 or later is required. The scripts use only the standard library.
Keep `../duel-1-crypto/duel1_targets.py` in place: it contains the local targets provided for
this assignment.

From the repository root, enter this directory:

```bash
cd homework/hw1/Rodriguez_Ponce
```

### 1. Reused one-time pad — Tier 1

```bash
python3 breaks/reused_pad.py
```

Applies crib-dragging to the XOR of ciphertexts encrypted with the same pad.
Prints TARGET with its final byte unknown and recovers all of `msg1`. Recovery
depends on the guessed phrases being correct.

### 2. ECB structure leakage — Tier 1

```bash
python3 breaks/ecb_leak.py
```

Compares encrypted record blocks and confirms repeated blocks. Infers Carl's
role under the assumption that Alice's role is known.

### 3. MAC forgery through length extension — Tier 2

```bash
python3 breaks/token_forge.py
```

Extends a token with `&role=admin` and calculates a valid tag without knowing the
secret, using the exercise's toy hash. Confirms that `verify_token` accepts the
forgery; the target does not implement role interpretation.

### 4. RSA private-key recovery through a shared prime — Tier 2

```bash
python3 breaks/rsa_shared_prime.py
```

Uses batch-GCD on the public moduli to find shared factors. Prints the recovered
factors and private exponents, and checks decryption of four messages for each
recovered key.

All attacks run exclusively against the homework's local targets.

# Homework 1 — Crypto & Protocols

**10 % · due end of week 7 · groups · covers weeks 1–5**

You are handed a set of **flawed crypto/protocol deployments**. Break each one,
then **design a replacement** that resists the same attacks — and defend your
design with the Control Scorecard, stating the guarantee *and its condition* for
every choice. The duel is the graded version of the weeks 1–5 studios.

> **The bar:** not "we broke it" but *"here is the assumption that made it
> breakable, here is the break confirmed by an oracle, and here is a design whose
> guarantee I can state as a conditional."*

---

## Learning objectives assessed

1. Identify the **unstated assumption** behind a broken deployment (week 1's move).
2. Execute the break and **confirm it** — recovered plaintext, a forged tag, a
   MITM'd session — not "it looks weak."
3. State each control's **guarantee and its condition** (scorecard axis 2), and
   distinguish a *primitive break* from a *misuse*.
4. Design a protocol that achieves a named security goal and argue *why* it holds.

---

## Part A — Break the deployments (55 %)

You receive **`duel1_targets.py`** (provided in `/projects/duel-1-crypto/`), a
module of six flawed deployments. Break **at least four**, including **at least one
from each tier**. Each break must be *confirmed*, not asserted.

### Tier 1 — cipher & mode misuse (weeks 2–3)

| # | Deployment | The flaw to find |
|---|---|---|
| 1 | `reused_pad(msg)` — a "one-time" pad that encrypts every message under the same key | key reuse → two-time pad; recover a target plaintext by crib-dragging |
| 2 | `ecb_store(record)` — customer records encrypted with ECB | structure leakage; show two records with the same field produce identical blocks, and infer a field |
| 3 | `ctr_log(entries)` — an audit log in AES-CTR that reuses the nonce across entries | nonce reuse → `C₁⊕C₂ = P₁⊕P₂`; recover an entry |

### Tier 2 — integrity & key misuse (weeks 3–4)

| # | Deployment | The flaw to find |
|---|---|---|
| 4 | `token_mac(user, role)` — session tokens authenticated with `SHA256(secret‖data)` | length extension; forge a token escalating `role=user`→`role=admin` without the secret |
| 5 | `keygen_fleet()` — RSA keypairs from a low-entropy device fleet | shared prime; given the public moduli, recover a private key by batch-GCD |
| 6 | `verify_login(secret, guess)` — an early-exit secret comparison | timing side channel; recover the secret and state how many trials your signal needed |

### For each break, submit (the confirmation is required)

- **The assumption** the designer made, in one sentence (week 1's habit).
- **The break**, with the recovered artifact: plaintext, forged token, private key,
  or secret. A *reproducible* script, not a screenshot of "looks different."
- **Primitive break or misuse?** (All six are misuses — say so and explain.)
- **Reliability**, where relevant (the timing attack is noisy — report trials).

---

## Part B — Design a protocol that resists them (35 %)

Design the **Secure Electronic Contract Signing (SECS)** system. Two parties,
Alice (provider) and Bob (client), must sign a contract with:

- **Non-repudiation of origin** — neither can deny signing.
- **Non-repudiation of receipt** — neither can deny receiving the final signed copy.
- **Integrity** — no undetected alteration.
- **Confidentiality** of the contract terms in transit.

Your submission is a **design document** (not code) that specifies:

1. The cryptographic primitives and *why each* (tie to weeks 2–5: signatures,
   hashing, key exchange, PKI).
2. The message flow, as a diagram, with the trust boundaries marked.
3. For **every** guarantee above, a **Control Scorecard axis-2 statement**: the
   guarantee *and the condition it depends on*. E.g. *"Non-repudiation of origin
   holds provided Alice's signing key is not compromised and the CA that bound it
   has not mis-issued."*
4. An explicit answer to: **which of your six broken deployments' mistakes does
   your design avoid, and how?**

> Reuse the toy signature / DH / PKI code from the week 4–5 notebooks if you like;
> the design *argument* is what's graded, not a production implementation.

---

## Part C — Honesty section (10 %)

Titled **"Where our breaks or design might be unfair."** Address at least three:

- Did a break rely on an assumption the deployment didn't actually make?
- Is your SECS design's guarantee *conditional* on something you've hand-waved
  (a trusted CA, a secure channel for key distribution)?
- Which of the four+ breaks are you *least* confident are reproducible, and why?
- Does your design trade one goal for another (e.g. confidentiality vs.
  auditability)? Name the trade.

A team that identifies a genuine hole in its own work scores higher here than one
that claims perfection.

---

## Rubric (100 pts / 10 %)

| Component | Pts | What earns full marks |
|---|---|---|
| **A. Breaks** (≥ 4, ≥ 1 per tier) | 55 | each break confirmed by a recovered artifact + the named assumption + misuse-vs-primitive; ~13–14 pts each |
| — assumption named | (within) | one crisp sentence per break, not "it's weak" |
| — confirmation | (within) | a reproducible script yielding the artifact |
| — reliability where relevant | (within) | timing/probabilistic breaks report trials, not one lucky run |
| **B. SECS design** | 35 | all four goals met; each with an axis-2 guarantee+condition; flow diagram with trust boundaries; explicit link to the avoided mistakes |
| **C. Honesty** | 10 | ≥ 3 substantive self-critiques |

**Scoring stance (from the Control Scorecard):** graded on **evidence quality, not
which side won.** A break reported as "works 4/5 times, here's why" beats one
claimed as certain with no reproduction. A design that says "this holds *only if*
the CA is honest" beats one that claims unconditional security.

⚠️ **Every guarantee must be a conditional.** A design claim without its condition
(axis 2) is capped at half credit for that item — the same strictness as the
checkpoints. Announced in advance so it's a lesson, not a surprise.

---

## Logistics

- Submit by pull request to `/homework/hw1/<lastname>/`.
- **`AI_LOG.md`** required per [`../resources/ai-policy.md`](../resources/ai-policy.md).
- **Ethics:** all work against the provided sandboxed targets. See
  [`../resources/ethics-and-scope.md`](../resources/ethics-and-scope.md).



---
marp: true
theme: default
paginate: true
header: 'CMP-5006 · Week 2 · Why the Guarantees Hold'
---

<!--
Week 2. Beats: entropy (6) · unicity distance (8) · one-time pad / perfect
secrecy (7) · two-time pad break (4). The one compressed theory week.
Lesson plan: ../../weeks/week-02.md
-->

# Why the Guarantees Hold

## Entropy, unicity, and the one unbreakable cipher

**CMP-5006** · Week 2

---

# Entropy measures what the attacker doesn't know

| Scheme | Keyspace | Entropy |
|---|---|---|
| Caesar shift | 26 | 4.7 bits |
| **Substitution** | 26! | **88.4 bits** |
| DES | 2⁵⁶ | 56 bits |
| AES-128 | 2¹²⁸ | 128 bits |

Substitution has **more** key entropy than DES — and week 1 broke it in a second.

> ## Entropy is necessary, not sufficient. The plaintext leaked.

<!--
6 min. The entropy-vs-security gap is the hook: "big keyspace" is not "secure."
-->

---

# Unicity distance — how much ciphertext betrays the key

# U = H(K) / D

- **H(K)** = key entropy (bits)
- **D** = redundancy of the language (~3.2 bits/char for English)

For substitution: U ≈ **28 characters**.

- Below U: many keys give readable English — genuinely ambiguous.
- Above U: the real key is uniquely pinned.

<!--
8 min. THIS is why week 1 worked: the message was hundreds of chars, far past U.
A 20-char message could NOT have been uniquely broken. Theory predicts practice.
-->

---

# The one-time pad — perfect secrecy, provably

Key **random**, **≥ message length**, **used once**. Encryption is XOR.

> The ciphertext is statistically **independent** of the plaintext — it reveals
> nothing, against an adversary with unlimited compute.

The intuition: for *any* guessed plaintext, there is a key that makes the
ciphertext decrypt to it. So the ciphertext can't favor the real one.

```
ct = "8ca2..."   under key K₁ → "ATTACK AT DAWN"
                 under key K₂ → "RETREAT NOW!!!"
```

---

# ⚠️ Perfect secrecy, used twice, is no secrecy

Reuse the key across two messages and it **cancels**:

# C₁ ⊕ C₂ = (P₁⊕K) ⊕ (P₂⊕K) = P₁ ⊕ P₂

The attacker never needed the key. **Crib-drag** a guessed word through `C₁⊕C₂`
and both plaintexts fall out.

> The guarantee had a **condition** — use once. Violating it didn't weaken the
> cipher; it collapsed it completely.

<!--
4 min. This is the memorable payload. VENONA, MS-PPTP, the "two-time pad" — all
real. Name the condition (week 1's habit) and you've found the attack.
-->

---

# Scorecard — a guarantee and its price

| Property | One-time pad |
|---|---|
| **Guarantee** | perfect secrecy, **against unbounded compute** |
| **Condition** | key random, ≥ message length, **used once** |
| **Failure** | reuse → total break by crib-dragging |
| **Why unused** | key is as hard to share as the message |

> The OTP is the only cipher with unconditional perfect secrecy — and almost
> nobody uses it. Real crypto trades it for *usable* computational security
> (weeks 3–4).

---

# Studio

1. Compute **entropy** and **unicity distance**; explain why week 1's attack
   succeeded and at what length it becomes ambiguous.
2. Implement the **one-time pad**; exhibit two keys decrypting one ciphertext to
   two meaningful messages.
3. **Break a two-time pad** — recover both plaintexts by crib-dragging.
4. Scorecard the OTP: guarantee **and** condition. Then: why does nobody use it?

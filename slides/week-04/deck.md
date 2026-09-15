---
marp: true
theme: default
paginate: true
header: 'CMP-5006 · Week 4 · Asymmetric Crypto & Side Channels'
---

<!--
Week 4. Beats: RSA in ten min (8) · shared factors / batch-GCD (9) · timing
side channels (8). Lesson plan: ../../weeks/week-04.md
-->

# Asymmetric Crypto & Side Channels

## RSA breaks — without factoring anything hard

**CMP-5006** · Week 4

---

# RSA in one slide

- Pick primes **p, q**; **n = pq**; **φ = (p−1)(q−1)**
- Public exponent **e**; private **d = e⁻¹ mod φ**
- Encrypt: **c = mᵉ mod n** · Decrypt: **m = cᵈ mod n**

To get **d** you need **φ**. To get **φ** you need to **factor n**.

> Security = factoring is hard — **conditional on p, q being good.**

<!--
8 min. Do it with tiny primes so every number is on the board. The reduction to
factoring is the whole security argument — and the next two attacks never touch it.
-->

---

# ⚠️ Attack 1 — shared factors (Mining Your Ps and Qs)

Weak entropy at boot → two devices generate keys sharing a prime.

# gcd(n₁, n₂) = the shared prime

- A **GCD is instant**. No factoring.
- Both victims' private keys fall from one computation.

> Heninger et al. (2012) factored **~0.2% of all TLS keys on the internet** this
> way. RSA-2048, defeated by a router's boot-time RNG.

<!--
9 min. The emotional peak: "military-grade" algorithm beaten by bad randomness.
Scan a corpus pairwise and every shared factor is a free private key.
-->

---

# ⚠️ Attack 2 — timing side channel

An early-exit comparison leaks **how long a prefix matched**:

```
compare(secret, guess):  returns at first mismatched byte
                         → time reveals the correct prefix length
```

Recover a secret **one byte at a time** by measuring which guess takes longest.
No key, no algorithm break, no math — just a clock.

<!--
8 min. Also mention square-and-multiply modexp leaking key bits the same way.
Timing is a first-class attack surface, not a micro-optimization concern.
-->

---

# The fix — constant time

```python
# leaks: duration depends on the secret
if a != b: ...

# safe: examines every byte regardless
hmac.compare_digest(a, b)
```

> The leak was that the comparison's **duration depended on the secret**. Examine
> everything, always, and timing carries no information.

---

# Scorecard — the guarantee lives *outside* the algorithm

| Attack | Breaks | Doesn't need |
|---|---|---|
| Shared factors | RSA keys from weak RNG | to factor a strong n |
| Timing | any variable-time secret compare | the key or the math |

| Control | Guarantee | Condition |
|---|---|---|
| RSA-2048 | infeasible to factor | **good, independent primes** |
| secret compare | — | **constant time** |

> Attackers break the *conditions*, not the math.

---

# Studio

1. **RSA by hand** — keygen/encrypt/decrypt; factor a small n to recover d.
2. **Shared-factor attack** — find the vulnerable pair in a corpus by pairwise
   GCD; recover both private keys.
3. **Timing side channel** — recover a secret by timing; defeat it with a
   constant-time compare.
4. Scorecard RSA and secret-comparison: the *condition outside the algorithm*.

> **Duel 1 (crypto & protocols) is due next week.**

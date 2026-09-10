---
marp: true
theme: default
paginate: true
header: 'CMP-5006 · Week 3 · Symmetric Crypto & Hashes'
---

<!--
Week 3. Beats: modes ECB vs CBC/CTR (9) · CTR nonce reuse (8) · length
extension + HMAC (8). Lesson plan: ../../weeks/week-03.md
-->

# Symmetric Crypto & Hashes

## The cipher isn't the control — the *construction* is

**CMP-5006** · Week 3

---

# "We use AES-256" answers no question

AES is (as far as anyone knows) unbroken. **Every** break this week leaves AES
intact and attacks the construction around it:

- the **mode** (ECB leaks, CTR nonce reuse)
- the **MAC construction** (`H(secret‖msg)` is forgeable)

> The primitive is not the system. The dangerous layer is the one you wrote.

---

# ECB leaks structure — the penguin

A block cipher is a keyed **permutation**: identical input blocks → identical
output blocks. Structure survives encryption.

```
plaintext image:  2 distinct blocks (two flat regions)
ECB ciphertext :  2 distinct blocks   ← structure preserved 1:1
CBC ciphertext : 96 distinct blocks   ← structure hidden
```

CBC chains each block with the previous ciphertext, so identical plaintext blocks
encrypt differently.

<!--
9 min. Render the ECB penguin if you can. The lesson isn't "use CBC" — it's that
the MODE, not the cipher, decided whether your data leaked.
-->

---

# ⚠️ CTR nonce reuse — week 2's two-time pad, modernized

CTR/GCM turn a block cipher into a keystream: `cipher(key, nonce‖counter)`. This
is how AES is actually deployed. Reuse a nonce under the same key and:

# C₁ ⊕ C₂ = P₁ ⊕ P₂

The exact two-time-pad break. The strong modern cipher gives **zero** protection.

> "We use AES-256" is not a security claim until you also promise the nonce is
> never reused.

<!--
8 min. Nonce reuse is a real, recurring CVE class. Same crib-drag code as week 2.
-->

---

# Hashes and the length-extension trap

Tempting MAC: `tag = H(secret ‖ message)`. Only the secret-holder could compute
it — right?

**Wrong**, for Merkle–Damgård hashes (MD5, SHA-1, SHA-256): the digest **is** the
internal state, so an attacker resumes hashing and forges a tag for
`message ‖ padding ‖ evil` — **without the secret**.

```
observed: tag over "amount=100&to=alice"
forged  : valid tag over "...&to=attacker"   ← no key needed
```

---

# The fix — HMAC

# HMAC(k, m) = H( (k⊕opad) ‖ H( (k⊕ipad) ‖ m ) )

Nested hashing hides the resumable internal state. The extension attack can't
apply.

> The pattern: the primitive (SHA-256) was fine; the naive **construction**
> `H(k‖m)` was the bug; the fix is a better construction, not a better hash.

<!--
8 min. Use real hmac.compare_digest in the demo. Every break this week is a
MISUSE, not a broken primitive.
-->

---

# Scorecard — all misuse, no broken primitives

| Construction | Guarantee | Condition / failure |
|---|---|---|
| ECB | per-block only | **leaks structure** |
| CTR/GCM | confidentiality | **nonce must never repeat** |
| `H(secret‖msg)` | *appears* to authenticate | **length extension** |
| HMAC | authentication | needs a secret key |

> Name the condition (week 1) and you find the attack. *AES-CTR is confidential
> PROVIDED nonces never repeat.*

---

# Studio

1. **ECB vs CBC** — encrypt a structured input both ways; measure the leakage.
2. **CTR nonce reuse** — reuse a nonce, recover both plaintexts by crib-dragging.
   Connect it to week 2 explicitly.
3. **Length extension** — forge an `H(secret‖msg)` tag without the secret; then
   show HMAC defeats it.
4. Scorecard each: primitive break vs. misuse. (They're all misuse.)

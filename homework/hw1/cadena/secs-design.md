# Part B — Secure Electronic Contract Signing (SECS)

> **Team:** Juan Diego Cadena · Omar Gordillo · Pablo Jarrín · Santiago Rodríguez

**Duel 1 · design document (not production code).**
Two parties, **Alice (provider)** and **Bob (client)**, sign one contract `C` with
non-repudiation of origin, non-repudiation of receipt, integrity, and
confidentiality of terms in transit. Every guarantee below is stated as a **Control
Scorecard axis-2 conditional** — the guarantee *and the condition it rests on*.

---

## 1 · Primitives, and why each

| Primitive | Concrete choice | Why — tied to the course |
|-----------|-----------------|--------------------------|
| **Hash** | SHA-256 | Collision/second-preimage resistance gives a stable "fingerprint" of `C` to sign. Week 3: we sign the **digest**, never the raw message. |
| **MAC** (not for signing) | HMAC-SHA-256 | Any keyed integrity inside a session uses HMAC, **never** `H(k‖m)` — Break #4 (length extension) is exactly why. |
| **Digital signature** | Ed25519 (or RSA-PSS 3072) | Asymmetric signing gives **non-repudiation**: only the private-key holder could produce it, and *anyone* can verify with the public key — a MAC can't, since the verifier also holds the key and could have forged it. Week 4–5. |
| **Key exchange** | Ephemeral ECDH (X25519), **signed** | Fresh per-session secret with **forward secrecy**; signing the ephemeral public keys defeats the MITM of Break-adjacent week-5 §2 (unauthenticated DH). |
| **AEAD** | AES-256-GCM, **fresh random nonce per message** | Confidentiality **and** integrity of ciphertext in one primitive; nonce discipline from Break #3 / week 3. |
| **PKI** | X.509 certs, both parties, chained to a trusted CA; Certificate Transparency | Binds a verifying key to a legal identity ("Alice Inc."), which is what non-repudiation legally requires. Week 5 §3–4. |
| **Trusted timestamp** | RFC 3161 TSA counter-signature over each signature | Pins *when* a signature existed, so a later key revocation can't retroactively deny a valid earlier signing. |
| **RNG** | OS CSPRNG for every key/nonce | Break #5 is what bad entropy costs; keys must come from good, independent randomness. |

**Design rule used throughout:** *sign-then-encrypt the digest*, and bind every
signature to a transcript hash (all prior messages), so no message can be replayed
or reordered.

---

## 2 · Message flow (with trust boundaries)

```
 TRUST BOUNDARY: a CA both parties trust (root in both trust stores) + a TSA
 ───────────────────────────────────────────────────────────────────────────
            │ issues Cert_Alice (binds vk_A→"Alice Inc.")                      │
            │ issues Cert_Bob   (binds vk_B→"Bob Ltd.")   logged in CT         │
 ───────────────────────────────────────────────────────────────────────────

   ALICE (provider)                                   BOB (client)
 ┌───────────────────┐                             ┌───────────────────┐
 │ sk_A (sign)       │                             │ sk_B (sign)       │
 │ vk_B,CA pinned    │                             │ vk_A,CA pinned    │
 └───────────────────┘                             └───────────────────┘
        │                                                   │
   (0)  │  validate Cert_Bob to CA root; abort if invalid   │  validate Cert_Alice
        │◀─────────────── exchange + validate certs ───────▶│
        │                                                   │
   (1)  │  a = X25519 ephemeral;  SIG_A0 = Sign_skA(a‖"SECS"‖nonce)           │
        │ ───────────────  a, SIG_A0, Cert_Alice  ────────▶ │  verify SIG_A0 under vk_A
        │                                                   │
   (2)  │  verify SIG_B0;  b = X25519 ephemeral; SIG_B0 = Sign_skB(b‖a)       │
        │ ◀─────────────── b, SIG_B0, Cert_Bob  ──────────  │
        │        K = KDF(ECDH(a,b))  [forward-secret session key, both sides] │
        │═══════════════ authenticated, confidential channel (AES-256-GCM) ══│
        │                                                   │
   (3)  │  h = SHA256(C);  SIG_A = Sign_skA(h‖tid)                            │
        │      send AEAD_K( C ‖ SIG_A )  ─────────────────▶ │  decrypt; check h=SHA256(C);
        │                                                   │  verify SIG_A under vk_A
        │                                                   │
   (4)  │                                                   │  SIG_B = Sign_skB(h‖SIG_A‖tid)
        │ ◀───────────── AEAD_K( SIG_B )  ───────────────── │  ("I received & countersigned")
        │  verify SIG_B under vk_B                           │
        │                                                   │
   (5)  │  both submit {C,h,SIG_A,SIG_B} to TSA; TSA returns timestamp token T │
        │  final artifact = (C, SIG_A, SIG_B, T) held by BOTH parties          │
```

**Trust boundaries:** (i) the **CA** — the only thing that lets each side believe a
verifying key belongs to the *legal* counterparty; (ii) the **TSA** — trusted only
to assert time; (iii) each party's **private-key store** (HSM/keychain). Everything
on the wire between the two boxes is attacker-controlled and assumed hostile.

---

## 3 · Axis-2 guarantee + condition, per goal

> Every statement is a **conditional**. (The assignment caps any unconditional claim
> at half credit — so the "provided…" clause is the deliverable, not decoration.)

**G1 — Non-repudiation of origin.**
*Alice cannot later deny signing `C`* **provided** (a) `sk_A` was not compromised at
signing time, (b) the CA that issued `Cert_Alice` did not mis-issue and the cert was
valid/un-revoked then, and (c) SHA-256 is second-preimage-resistant (she can't claim
she signed a different `C'` with the same `h`). The TSA token T supplies the "at
signing time" anchor so revocation after the fact doesn't retroactively deny it.
*(Symmetric statement holds for Bob via SIG_B.)*

**G2 — Non-repudiation of receipt.**
*Bob cannot deny receiving the final signed copy* **provided** his countersignature
`SIG_B = Sign_skB(h‖SIG_A‖tid)` exists and verifies — it is computable only after he
received `C` and `SIG_A` — **and** the same conditions on `sk_B` / his CA hold.
Receipt is proven by making the receipt itself a signature over what was received.

**G3 — Integrity.**
*No undetected alteration of `C`* **provided** SHA-256 is collision-resistant (both
signatures bind `h = SHA256(C)`) **and** the AES-GCM authentication tag is verified
on every message (GCM detects any ciphertext tampering) **and** nonces are never
reused under `K` (Break #3's condition).

**G4 — Confidentiality of terms in transit.**
*An eavesdropper learns nothing about `C`'s terms* **provided** the ephemeral ECDH
secret is unknown to the attacker (discrete-log / X25519 security) **and** the
ephemeral keys were *authenticated* by SIG_A0/SIG_B0 so no MITM negotiated `K`
(week 5 §2) **and** AES-256-GCM is used with a unique nonce per message. Forward
secrecy adds: compromise of `sk_A`/`sk_B` *later* does not decrypt past transcripts,
**provided** the ephemeral secrets `a,b` were destroyed after the session.

---

## 4 · Which broken-deployment mistakes this design avoids, and how

| Broken deployment | Its mistake | How SECS avoids it |
|-------------------|-------------|--------------------|
| #1 `reused_pad` | key/keystream reuse | No stream reuse: AES-GCM with a **fresh random nonce per message**, under a **per-session** ECDH key. Each session's `K` is independent. |
| #2 `ecb_store` | ECB leaks structure | Bulk data uses **AEAD (GCM)**, a stream construction — identical plaintext blocks never yield identical ciphertext; no ECB anywhere. |
| #3 `ctr_log` | nonce reuse in CTR/GCM | Explicit **nonce-uniqueness invariant** per `K`; counter or random-96-bit nonce tracked so it never repeats; new `K` each session bounds the risk. |
| #4 `token_mac` | `H(secret‖data)` length extension | Keyed integrity is **HMAC-SHA-256** (or the GCM tag), never `H(secret‖data)`. Authenticity of `C` rests on **signatures**, not a homebrew MAC. |
| #5 `keygen_fleet` | shared prime from weak RNG | All keys from the **OS CSPRNG**; long-term signing keys generated once in an HSM; Ed25519 has no "shared prime" failure mode, and we'd scan issued certs for shared factors as defence-in-depth. |
| #6 `timing_compare` | variable-time compare | All secret/tag/MAC comparisons use **constant-time** equality (`hmac.compare_digest`); GCM/Ed25519 verification is already constant-time. |

> **The through-line (week 1):** every one of SECS's guarantees is conditional on a
> *named* assumption — an uncompromised key, an honest CA, a unique nonce, a
> constant-time check, good entropy. Those conditions are exactly the six attack
> surfaces above. Naming them *is* the security argument.

Names: Luis Eduardo Zaldumbide, Miguel Jarrin, Josue Lopez
Class: Computer Security
Date: 5/10/2026

# Part B — Secure Electronic Contract Signing (SECS)

**CMP-5006 · Homework 1 · Part B (design document, no production code)**

Two parties — **Alice** (provider) and **Bob** (client) — must sign one contract
and each walk away with a copy that is non-repudiable, intact, and that was
confidential in transit. This document specifies the primitives, the message flow
with trust boundaries, an axis-2 (guarantee + condition) statement for every goal,
and the mapping back to the six Duel-1 mistakes this design avoids.

The design reuses the week 2–5 toolkit: AEAD with nonce discipline (wk3), HMAC
instead of `H(secret‖msg)` (wk3), RSA with good primes (wk4), authenticated
Diffie–Hellman and a PKI certificate chain (wk5).

---

## 1. Primitives — and why each one

| Role in SECS | Primitive | Why this one (ties to the weeks) |
|---|---|---|
| **Identity → key binding** | X.509-style **certificate chain** validated to a trusted root (PKI) | wk5: a signature only means something if the verifier knows whose key signed. The CA binds `pk_Alice` to "Alice Provider Inc." A bare public key authenticates nothing. |
| **Non-repudiation (origin & receipt)** | **Digital signatures** — RSA-PSS (or ECDSA), ≥ 2048-bit RSA, over a **hash of the contract** | wk4: only the private-key holder can produce a signature that verifies under the certified public key, so a third party (a judge) can check it. A MAC/HMAC would prove *integrity* but not *non-repudiation* — both parties share the MAC key, so neither could prove the *other* produced a tag. |
| **Integrity of the signed object** | **SHA-256** as the hash inside every signature | wk3: sign the digest, not the raw bytes. Collision resistance means a signature over `H(contract)` cannot be reused for a different contract. |
| **Confidentiality in transit** | **AES-256-GCM** (AEAD) under a fresh session key, **unique 96-bit nonce per message** | wk3: GCM gives confidentiality *and* integrity of ciphertext, **provided the nonce never repeats under a key**. This is exactly the discipline that `ctr_log` (#3) violated. |
| **Session key establishment** | **Ephemeral Diffie–Hellman (DHE)**, each `g^x` **signed** with the sender's certified key | wk5: raw DH gives secrecy against a *passive* eavesdropper only; signing the DH shares authenticates the endpoints and stops the MITM. DHE also gives **forward secrecy** — a later key compromise does not decrypt past contracts. |
| **Freshness / anti-replay** | **Nonces + timestamps** inside every signed message; a per-contract `contract_id` | wk5 protocol hygiene: binds each signature to *this* session so an old signed message cannot be replayed into a new one. |

**Design rule carried throughout:** *sign-then-encrypt is not enough by itself* —
every signature covers the `contract_id`, the sender, the intended recipient, and a
message-type tag, so a signature valid in one position cannot be lifted into
another.

---

## 2. Message flow with trust boundaries

```
 TRUSTED ANCHOR (outside the session)
 ┌────────────────────────────────────────────────────────────┐
 │  Certificate Authority (CA)  — root key in both parties'     │
 │  trust stores. Issues cert_Alice, cert_Bob BEFORE the run.   │
 └───────────────┬───────────────────────────┬────────────────┘
                 │ (offline, pre-provisioned) │
     ════════════╪═══════════ TRUST BOUNDARY ═╪════════════════════
     the wire below is fully controlled by the attacker (Dolev–Yao)
                 │                            │
   ┌─────────────▼───────────┐     ┌──────────▼──────────────┐
   │        ALICE            │     │          BOB            │
   │  sk_Alice (HSM/secure   │     │  sk_Bob (secure store)  │
   │  store, never on wire)  │     │                         │
   └───────────┬─────────────┘     └───────────┬─────────────┘
               │                               │
   (0) pre-check: each validates the other's cert chain to the trusted root
               │                               │
   (1) ClientHello ─────────────────────────▶ │
        contract_id, nonce_A, cert_Alice,
        g^a, Sig_Alice(contract_id‖nonce_A‖g^a‖"A→B")
               │                               │
               │ ◀──────────────── (2) ServerHello
               │        nonce_B, cert_Bob, g^b,
               │        Sig_Bob(contract_id‖nonce_A‖nonce_B‖g^b‖"B→A")
               │                               │
    ── both derive K = KDF(g^(ab) ‖ contract_id ‖ nonce_A ‖ nonce_B) ──
               │                               │
   (3) SendContract ───────────────────────▶  │
        AES-256-GCM_K(nonce=1, contract_terms),
        Sig_Alice(H(contract)‖contract_id‖"ORIGIN")   ← non-repudiation of ORIGIN
               │                               │
               │ ◀──────────── (4) CounterSign + Receipt
               │   AES-256-GCM_K(nonce=2,
               │     Sig_Bob(H(contract)‖contract_id‖"ORIGIN")   ← Bob also signs = mutual origin
               │     ‖ Sig_Bob(H(contract)‖Sig_Alice‖contract_id‖"RECEIPT"))
               │                               │           ↑ non-repudiation of RECEIPT
   (5) FinalAck ───────────────────────────▶  │
        AES-256-GCM_K(nonce=3,
          Sig_Alice(H(contract)‖Sig_Bob_receipt‖contract_id‖"RECEIPT"))
               │                               │
        Both archive: {contract, Sig_Alice_origin, Sig_Bob_origin,
                       Sig_Bob_receipt, Sig_Alice_receipt, both certs}
```

**Trust boundaries, explicitly:**

- **Above the double line** is the CA and the pre-provisioned certificates — the
  trust anchor. SECS *assumes* this is correct; §3 states that as a condition and
  Part C (honesty) revisits it.
- **The wire** between Alice and Bob is the **Dolev–Yao attacker's** territory: she
  can read, drop, reorder, replay, and inject. Every security property below must
  hold against that attacker, not merely a passive eavesdropper.
- **Inside each party's box**, the private signing key never leaves a secure store.
  If that boundary fails, non-repudiation fails — stated as a condition, not
  assumed away.

**Why the exchange order:** the signed DHE (1–2) authenticates both endpoints
*before* any contract bytes move, so the AES-GCM session key `K` is shared with the
real counterparty, not a MITM. Steps 3–5 are a **fair-exchange-style** ladder:
Alice signs first (origin), Bob counter-signs (mutual origin) and signs a receipt,
Alice acknowledges the receipt. Each party ends holding the other's signature.

---

## 3. Per-goal guarantee + condition (Control Scorecard axis 2)

Every claim is a **conditional**. A claim without its condition is capped at half
credit — so the condition is the point.

### 3.1 Non-repudiation of origin

**Guarantee:** Given the archived `Sig_Alice(H(contract)‖contract_id‖"ORIGIN")`,
a third party can verify that the holder of `sk_Alice` signed *this* contract, and
Alice cannot later deny it (symmetrically for Bob).

**Condition:** holds **provided (a)** Alice's signing key `sk_Alice` is not
compromised and was under her sole control, **and (b)** the CA that issued
`cert_Alice` bound the key to Alice's identity correctly and has not mis-issued or
been compromised, **and (c)** SHA-256 is collision-resistant (else a second
contract shares the digest). If any of (a)–(c) fails, the signature still
*verifies* but no longer proves *Alice* authored *this* contract.

### 3.2 Non-repudiation of receipt

**Guarantee:** The archived `Sig_Bob(H(contract)‖Sig_Alice‖contract_id‖"RECEIPT")`
proves Bob received the final signed copy; `Sig_Alice(...‖Sig_Bob_receipt‖"RECEIPT")`
proves Alice received Bob's acknowledgement.

**Condition:** holds **provided** the signing keys are uncompromised and the CA
binding is sound (as in 3.1), **and provided the exchange completed through step
5** — if the protocol aborts after step 3, Alice has proof she sent but not that
Bob received. True atomic fairness needs a trusted third party or an optimistic
fair-exchange sub-protocol; **this design gives evidence-of-receipt, not atomic
fairness** (named again in honesty.md).

### 3.3 Integrity

**Guarantee:** Any alteration of the contract, of either signature, or of the
message type/recipient fields is detected: the signature verification over
`H(contract)‖contract_id‖role-tag` fails, and in transit the AES-GCM
authentication tag fails.

**Condition:** holds **provided** SHA-256 is collision- and second-preimage-
resistant **and** the AES-GCM nonce is never reused under the session key `K`
(unique nonce per message — here the strict counter 1,2,3). Nonce reuse would
void the GCM tag's integrity guarantee, exactly the `ctr_log` (#3) failure.

### 3.4 Confidentiality in transit

**Guarantee:** The contract terms are unreadable to the Dolev–Yao attacker on the
wire.

**Condition:** holds **provided (a)** the DHE shares were authenticated by
signatures so `K` is shared only with the real counterparty — unauthenticated DH
would let a MITM hold `K` (wk5); **(b)** the AES-GCM nonce never repeats under `K`;
**(c)** the discrete-log / DDH assumption holds for the chosen DH group. Forward
secrecy additionally holds **provided** the ephemeral exponents `a, b` are erased
after the session, so a later leak of `sk_Alice`/`sk_Bob` does not decrypt this
contract.

---

## 4. Which Duel-1 mistakes this design avoids, and how

| # | Duel-1 flaw | How SECS avoids it |
|---|---|---|
| **1** | `reused_pad` — one key (pad) reused across messages → two-time pad | SECS never reuses keystream: a **fresh ephemeral session key `K`** per contract via DHE, and AES-GCM derives an independent keystream per **unique nonce**. No pad, no key, is ever reused across two messages. |
| **2** | `ecb_store` — ECB leaks equal plaintext blocks | AES-**GCM** (a CTR-based AEAD), not ECB. Equal plaintext blocks produce different ciphertext because each block is XORed with a distinct keystream position; structure does not survive encryption. |
| **3** | `ctr_log` — reused CTR nonce → `C₁⊕C₂ = P₁⊕P₂` | **Strict nonce discipline:** a per-message counter (1,2,3…) never repeats under `K`, and `K` itself is per-contract. This is written into §3.3/§3.4 as the explicit condition — the exact discipline #3 violated. |
| **4** | `token_mac` — `H(secret‖data)` is length-extendable | SECS authenticates with **digital signatures over `H(contract)`**, and where a symmetric MAC is needed it would use **HMAC**, not `H(secret‖msg)`. The Merkle–Damgård length-extension attack does not apply to either, and signatures additionally give non-repudiation a shared-key MAC cannot. |
| **5** | `keygen_fleet` — low-entropy RNG → shared RSA prime, batch-GCD | Keys are generated with a **vetted CSPRNG** and ≥ 2048-bit RSA with **independent primes**; ephemeral DH exponents come from the same CSPRNG. No shared factors, so pairwise GCD yields nothing. (Stated as condition (a)/(c) in §3.) |
| **6** | `timing_compare` — early-exit compare leaks the secret | All secret comparisons (tag checks, signature verification byte comparisons) use **constant-time** routines (`hmac.compare_digest`-style). Verification time does not depend on the secret, so no per-byte timing signal exists. |

---

## 5. Summary scorecard row (axis-2 form)

| Goal | Guarantee | Condition it depends on |
|---|---|---|
| Non-repudiation (origin) | signer provably authored this contract | sole-control uncompromised signing key **and** correct CA binding **and** collision-resistant hash |
| Non-repudiation (receipt) | recipient provably received the signed copy | the above **and** the exchange ran to step 5 (evidence-of-receipt, not atomic fairness) |
| Integrity | any tamper is detected | collision-resistant SHA-256 **and** unique GCM nonce per key |
| Confidentiality | terms unreadable on the wire | **authenticated** DHE (MITM-resistant) **and** unique nonce **and** DDH holds; forward secrecy iff ephemeral keys erased |

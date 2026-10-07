# Part B — Secure Electronic Contract Signing (SECS)

A design for two parties — **Alice** (provider) and **Bob** (client) — to sign a
contract `C` with four guarantees: non-repudiation of origin, non-repudiation of
receipt, integrity, and confidentiality of the terms in transit. This is a design
argument, not a production implementation; where it reuses the week 4–5 toy
signature / DH / PKI code, the *argument* is what is claimed, not the code's
hardening.

Throughout, **every guarantee is stated as a conditional** (scorecard axis 2):
the guarantee *and the condition it rests on*. Where a condition fails, the named
guarantee is the one that falls — nothing more and nothing less.

---

## 1. Primitives, and why each

| Primitive | Concrete choice | Why this one (weeks 2–5 tie-in) |
|-----------|-----------------|---------------------------------|
| **Digital signature** | Ed25519 (EdDSA) | Non-repudiation of origin/receipt. A signature binds an act to a *private* key only the signer holds, so it is evidence a third party (a judge) can check — a MAC cannot do this, because both parties share the MAC key and either could have produced the tag. Ed25519 has no per-signature nonce to misuse (unlike ECDSA/DSA, where nonce reuse leaks the key — the week-3 lesson). |
| **Cryptographic hash** | SHA-256 | Integrity + efficient signing. Parties sign `H(C)`, not `C`, so a signature covers an arbitrarily long contract at fixed cost, and any change to `C` changes the digest. Needs collision and second-preimage resistance. |
| **Authenticated key exchange** | X25519 ephemeral ECDH, each side's ephemeral public **signed** with its long-term key | Confidentiality + forward secrecy + MITM resistance. Ephemeral DH gives a fresh session key `K` per contract and **forward secrecy**; signing the DH shares authenticates them, which is exactly the defence a raw DH (week 4) lacks against an active MITM. |
| **AEAD cipher** | AES-256-GCM, 96-bit nonce unique per message under `K` | Confidentiality **and** integrity of each wire message in one primitive. GCM is randomized per nonce, so it leaks no structure (unlike ECB) and its tag detects tampering in transit. |
| **PKI** | X.509 certs from a course CA; parties pin the CA root | Binds a public key to a legal identity. Without it, a signature proves only "whoever holds key *k* signed", not "Alice signed". The CA is the trust anchor that makes non-repudiation *mean* something. |
| **Trusted timestamp / notary (TTP)** | RFC-3161 TSA `T`, used *optimistically* (only on dispute) | A trusted time anchor and fairness fallback for non-repudiation of receipt. `T` sees only **hashes and signatures, never the plaintext terms**, so it is trusted for *time and dispute resolution*, not for confidentiality. |

Constant-time verification (e.g. `hmac.compare_digest`, constant-time signature
verify) is used for **every** tag/signature check — a design rule, not a
primitive, that closes the Break #6 channel.

---

## 2. Message flow and trust boundaries

### Trust boundaries

```
   TRUST ANCHOR (offline)                     SEMI-TRUSTED TTP
   +-----------------+                        +--------------------------+
   |   CA (root)     |                        |  TSA / Notary  T         |
   |  issues certs,  |                        |  time + dispute only;    |
   |  screens key    |                        |  sees H(C) & signatures, |
   |  quality        |                        |  NEVER the terms C       |
   +--------+--------+                        +------------+-------------+
            | certs (out of band)                          ^ hashes/sigs only
            v                                               |
   ====================  UNTRUSTED NETWORK  =========================
   |                      (active attacker)                         |
   |   all crossings: AES-256-GCM under K  +  Ed25519 signatures    |
   ==================================================================
        ^                                                   ^
        | boundary A                                        | boundary B
   +----+-------------------+                      +--------+-----------+
   |  ALICE host            |                      |  BOB host          |
   |  long-term signing key |                      |  long-term key     |
   |  in a key store        |                      |  in a key store    |
   +------------------------+                      +--------------------+
```

Four boundaries: **A** = Alice's host/key store, **B** = Bob's host/key store,
the **CA** (trusted to bind identities and screen key quality), and **T** (trusted
for time and dispute, but *outside* the confidentiality boundary). The network
between them is fully untrusted.

### Flow (Ed25519 signatures `Sig_X`, GCM channel `{…}_K`)

```mermaid
sequenceDiagram
    participant A as Alice (provider)
    participant B as Bob (client)
    participant T as TSA / Notary (dispute only)

    Note over A,B: Phase 1 — Authenticated key exchange (confidential channel + forward secrecy)
    A->>B: cert_A, g^a, n_A, Sig_A("SECS-hello", g^a, n_A)
    B->>A: cert_B, g^b, n_B, Sig_B("SECS-ack", g^b, g^a, n_A, n_B)
    Note over A,B: both derive K = KDF(g^ab, transcript); channel now confidential

    Note over A,B: Phase 2 — Signed exchange (origin + integrity + receipt)
    A->>B: {C, ctx, σ_A = Sig_A(H(C), ctx)}_K
    Note right of B: ctx = {ids, cert fps, n_A, n_B, timestamp}
    B->>A: {σ_B = Sig_B(H(C), σ_A, ctx)}_K
    Note left of A: σ_B over σ_A ⇒ Bob's signature AND his receipt of Alice's copy
    A->>B: {σ_A2 = Sig_A(H(C), σ_A, σ_B, ctx)}_K
    Note right of B: σ_A2 ⇒ Alice's receipt of Bob's signature (final copy)

    Note over A,T,B: Phase 3 — only if a party aborts (optimistic fairness)
    B-->>T: H(C), σ_A, σ_B, ctx   (if σ_A2 never arrives)
    T-->>B: timestamp token + affidavit completing the record
    T-->>A: same token
```

The fully signed contract bundle both parties retain is
`{C, σ_A, σ_B, σ_A2, ctx}` plus, if Phase 3 ran, `T`'s timestamp token.

Why Phase 2's chaining works: Bob can only produce `σ_B` (which signs `σ_A`)
*after* receiving Alice's signed copy — so `σ_B` **is** Bob's non-repudiable
receipt. Likewise `σ_A2` signs `σ_B`, so it is Alice's receipt. The unfair
window — Alice holds `σ_B` but Bob never gets `σ_A2` — is closed by Phase 3: Bob
takes `σ_A, σ_B` to `T`, which timestamps and completes the record, so neither
party can both hold the other's signature and deny their own receipt.

---

## 3. Guarantees as axis-2 conditionals

Each item is a guarantee **and the condition it depends on**. If the condition is
false, that guarantee — and only it — is lost.

1. **Non-repudiation of origin (Alice).** Alice cannot later deny signing `C`
   **provided** (a) her Ed25519 signing key was not compromised at signing time,
   (b) the CA that issued `cert_A` did not mis-issue a cert for her identity to
   someone else, and (c) SHA-256 is second-preimage resistant (else she could
   claim a *different* `C'` with `H(C')=H(C)`). Symmetric for Bob via `σ_B`.

2. **Non-repudiation of receipt (Bob received Alice's copy).** Bob cannot deny
   receiving Alice's signed contract **provided** his key is uncompromised and
   signatures are EUF-CMA unforgeable — because `σ_B` signs `σ_A`, and he could
   not have formed it without first holding `σ_A`.

3. **Non-repudiation of receipt (Alice received Bob's copy / the final copy).**
   Alice cannot deny receiving Bob's signature **provided** either she issued
   `σ_A2` (which signs `σ_B`), *or* `T` holds a timestamp token over
   `σ_A, σ_B`; and **provided** `T`'s key is uncompromised and `T` timestamps
   honestly. This is the one guarantee that leans on the TTP, and only on abort.

4. **Integrity (no undetected alteration).** Any modification of `C` is detected
   **provided** SHA-256 is collision- and second-preimage-resistant and the
   signatures are unforgeable — a changed `C` changes `H(C)`, so every signature
   over it fails to verify. In transit, GCM's tag additionally catches tampering
   **provided** the 96-bit nonce is never repeated under a given `K`.

5. **Confidentiality of the terms in transit.** A network attacker learns nothing
   about `C` **provided** (a) the X25519/ECDH problem is hard for Curve25519,
   (b) the AKE's signatures+certs actually prevent a MITM (i.e. conditions in #1
   hold, so the attacker cannot substitute its own authenticated DH share),
   (c) each GCM nonce under `K` is unique, and (d) neither endpoint (boundary A
   or B) is compromised. **Forward secrecy:** past sessions stay confidential even
   if a long-term *signing* key later leaks, **provided** the ephemeral DH
   secrets `a, b` were erased after the session — the signing keys authenticate
   but never encrypt.

---

## 4. Which of the six broken deployments' mistakes this design avoids

| Break | Mistake | How SECS avoids it |
|-------|---------|--------------------|
| **#1** `reused_pad` | One keystream reused across messages | A fresh random session key `K` per contract (ephemeral ECDH), and an AEAD rather than a raw pad; no keystream is ever reused across messages. |
| **#2** `ecb_store` | ECB is deterministic → equal blocks leak | AES-256-**GCM** is randomized by a unique nonce, so identical terms never produce identical ciphertext; the structure leak is gone. |
| **#3** `ctr_log` | Reused CTR nonce → keystream reuse | Explicit **unique-nonce discipline**: a 96-bit nonce never repeats under one `K`, and `K` itself is per-session, bounding any single key's exposure. (Same root cause as #1, named separately because the discipline is the fix.) |
| **#4** `token_mac` | `H(secret‖data)` is length-extendable | Authentication is by **Ed25519 signatures** and **GCM/HMAC** tags, never a secret-prefix hash. Signatures are not length-extendable; HMAC's nested structure resists it. |
| **#5** `keygen_fleet` | Low entropy → shared RSA prime | Keys come from a vetted CSPRNG; Ed25519/X25519 have **no prime generation** to get wrong, and the CA **screens key quality** (including batch-GCD screening) before issuing a cert, so a weak key never enters the PKI. |
| **#6** `timing_compare` | Early-exit compare leaks via timing | **Constant-time** verification for every signature/tag/MAC check — no data-dependent early exit, so the comparison reveals only its boolean result. |

---

*Honest limitations of this design are in [`honesty.md`](honesty.md) — notably
that goals #1–#3 are only as strong as the CA (an unexamined trust anchor) and
that the Phase-3 fairness guarantee leans on `T` behaving honestly.*

# SECS — Secure Electronic Contract Signing

A design for two parties, Alice (provider) and Bob (client), to sign a
contract with non-repudiation of origin, non-repudiation of receipt,
integrity, and confidentiality in transit. This is a design document, not an
implementation — the toy signature/DH/PKI code from the week 4–5 notebooks
is assumed available as the primitive layer.

---

## 1. Primitives, and why each

| Primitive | Used for | Why this one (ties to weeks 2–5) |
|---|---|---|
| **Long-term asymmetric signatures** (ECDSA P-256 or Ed25519) | Non-repudiation of origin and of receipt | A signature binds a message to a private key only its holder has; unlike a symmetric MAC, a third party (a judge, an arbitrator) can verify it **without** being trusted with a shared secret. Week 4's distinction between MACs and signatures is the whole reason Break #4 (`token_mac`) exists — SECS never uses a symmetric MAC where non-repudiation is required. |
| **SHA-256** | Integrity (collision/second-preimage resistance) | Contracts are large; we sign a fixed-size digest, not the whole document. We never use it as a secret-prefix MAC (`H(secret‖data)`) — that construction is exactly Break #4. |
| **Ephemeral ECDH, authenticated by long-term signatures** | Session key agreement, forward secrecy | A fresh key per session means a single compromised session key (or a later-leaked session key) does not expose every past contract — unlike `reused_pad` (Break #1), nothing here is encrypted twice under the same key. Signing the ephemeral public keys before trusting them blocks an active MITM, which an *unauthenticated* DH exchange would not. |
| **HKDF** | Deriving the AES session key from the raw ECDH shared secret | Turns a non-uniform DH output into a properly keyed, domain-separated symmetric key, rather than using raw DH output directly as a key. |
| **AES-256-GCM (AEAD)**, random 96-bit nonce per message, never reused under one key | Confidentiality **and** integrity of the contract in transit | GCM gives both properties in one authenticated construction, and — critically — its authentication tag is checked using a constant-time comparison inside any vetted library, closing the exact class of bug in Break #6 (`timing_compare`). We never use ECB (Break #2) and we enforce one-nonce-per-message discipline so the keystream-reuse attack behind Break #3 (`ctr_log`) cannot apply here: each session already has its own ephemeral key, so even a nonce collision would not reproduce the cross-message, cross-session attack. |
| **PKI (CA-issued certificates)** | Binding a long-term public key to "Alice" / "Bob" as real identities | A signature only proves *"the holder of this private key signed this,"* not *"Alice signed this."* The CA is what lets a verifier treat a raw public key as an identity — and it is exactly the guarantee's hidden condition the Control Scorecard example calls out. |

**Key generation note (ties to Break #5):** every keypair — long-term
signing keys and ephemeral ECDH keys alike — is generated using the host
operating system's cryptographically secure RNG (e.g. `os.urandom` /
`secrets`, never a fixed-seed `random.Random` as in the duel targets), and
the CA's enrollment step requires a signed proof-of-possession from a
freshly generated key rather than trusting a device to self-report one. This
is precisely the precondition `keygen_fleet` violated.

---

## 2. Message flow and trust boundaries

```mermaid
sequenceDiagram
    participant A as Alice (Provider)
    participant N as Network (untrusted — active attacker assumed)
    participant B as Bob (Client)
    participant CA as CA / PKI (trusted, out-of-band)

    Note over A,CA: Trust boundary 1 — identity binding, happens out of band, before any contract exists
    A->>CA: Enroll PK_A + proof of possession + identity proof
    B->>CA: Enroll PK_B + proof of possession + identity proof
    CA-->>A: Cert_A (binds PK_A to "Alice")
    CA-->>B: Cert_B (binds PK_B to "Bob")

    Note over A,B: Trust boundary 2 — the network is adversary-controlled from here on
    A->>N: ephPK_A, Sign(SK_A, ephPK_A), Cert_A
    N->>B: forwarded (attacker can read/drop/reorder, assumed unable to forge Sign(SK_A, ·))
    B->>N: ephPK_B, Sign(SK_B, ephPK_B), Cert_B
    N->>A: forwarded

    Note over A,B: Each side verifies the OTHER's cert chain + signature on the ephemeral key before trusting it — this is what blocks an active MITM from substituting their own ephemeral key
    A->>A: K_session = HKDF( ECDH(ephSK_A, ephPK_B) )
    B->>B: K_session = HKDF( ECDH(ephSK_B, ephPK_A) )

    A->>A: H_C = SHA256(contract); Sig_A = Sign(SK_A, H_C)
    A->>N: AES-256-GCM(K_session, nonce_A, contract), Sig_A
    N->>B: forwarded
    B->>B: decrypt, verify GCM tag, recompute H_C, verify Sig_A against Cert_A

    B->>B: Sig_B = Sign(SK_B, H_C ‖ Sig_A)      note: the receipt signs BOTH the contract hash AND Alice's signature
    B->>N: AES-256-GCM(K_session, nonce_B, Sig_B)
    N->>A: forwarded
    A->>A: decrypt, verify Sig_B against Cert_B

    Note over A,B: Both now independently hold (contract, Sig_A, Sig_B) — presentable to a third party (e.g. a court) without needing the other party's cooperation
```

**Trust boundaries, named explicitly:**

- **CA boundary** — crossed once, out of band, before any contract exists.
  Everything downstream inherits whatever the CA guarantees (see §3).
- **Network boundary** — every message after enrollment crosses it. The
  threat model (Control Scorecard axis 1) is an **active, network-resident
  attacker**: they can read, drop, delay, reorder, and inject, but cannot
  forge a signature without the corresponding private key and cannot break
  SHA-256 or AES-256-GCM as primitives.
- **No trust boundary is assumed inside Alice's or Bob's own device** — key
  storage, endpoint compromise, and insider threats are explicitly out of
  scope and named as such in `honesty.md`.

---

## 3. Control Scorecard — axis 2 (guarantee + condition) for every goal

> **Non-repudiation of origin** holds — anyone holding `(contract, Sig_A)`
> can prove Alice signed the contract whose hash is `H_C` — **provided**
> Alice's long-term private signing key has not been compromised, Alice's
> certificate was validly issued and had not been revoked at signing time,
> and SHA-256 remains collision-resistant (so `Sig_A` cannot be transplanted
> onto a different document sharing the same hash).

> **Non-repudiation of receipt** holds in a weaker form than it sounds:
> Alice can prove Bob received and verified the exact final contract —
> **provided Bob actually transmitted `Sig_B`** before the exchange was
> abandoned. This protocol gives non-repudiation of a *completed*
> acknowledgment; it does **not**, by itself, give fairness — nothing forces
> Bob to send `Sig_B` once he has decrypted the contract, so Bob can always
> walk away having read the terms but leaving Alice with no proof of
> receipt. Closing that gap needs an optional trusted-third-party
> escrow/notary step, which we deliberately scope out below (§4) rather than
> quietly assume away.

> **Integrity** holds — any undetected alteration of the contract, in
> transit or once both signatures exist, is detected — **provided** SHA-256
> remains collision- and second-preimage-resistant, and the AES-256-GCM
> authentication tag is verified (using a constant-time comparison) before
> any decrypted plaintext is trusted. Skipping tag verification for
> performance, or implementing it with an early-exit comparator, silently
> reintroduces Break #6's exact bug into a defense whose entire job is to
> catch tampering.

> **Confidentiality** of the contract terms in transit holds — **provided**
> the ephemeral ECDH exchange is authenticated (so no MITM can substitute
> their own ephemeral key before the session key is derived), each session
> derives an independent key via HKDF, and the per-message AES-GCM nonce is
> never reused under that session key. Reusing a session key across many
> contracts (Break #1's mistake) or reusing a nonce under one key (Break #3's
> mistake) does not degrade this guarantee gracefully — it breaks it
> catastrophically, the same way it did in Part A.

---

## 4. Which of the six broken deployments does SECS avoid, and how

| Break | Mistake | How SECS avoids it |
|---|---|---|
| #1 `reused_pad` | One long-lived key encrypts everything, forever | Every session derives a **fresh** key via ephemeral ECDH + HKDF; no symmetric key is ever reused across contracts |
| #2 `ecb_store` | Independent per-block encryption leaks plaintext structure | The whole contract is one AES-256-GCM call (authenticated, not block-independent); no deployment anywhere in SECS encrypts fixed-format records block-by-block |
| #3 `ctr_log` | Nonce reused under one key | GCM nonces are generated fresh per message and are already protected by the fact that each *session* has its own key — a nonce collision would need both a key reuse *and* a nonce reuse to be exploitable the way Break #3 was |
| #4 `token_mac` | `H(secret‖data)` used as a MAC | SECS never constructs a MAC this way; non-repudiation uses real asymmetric signatures, which are not length-extendable the way Merkle–Damgård secret-prefix constructions are |
| #5 `keygen_fleet` | Shared low-entropy randomness across a device fleet | All key generation (long-term and ephemeral) uses a vetted OS-level CSPRNG; CA enrollment requires a signed proof-of-possession rather than trusting a device-reported key |
| #6 `timing_compare` | Early-exit comparison leaks timing | Signature verification and GCM tag verification both go through vetted library primitives that compare in constant time — no hand-rolled byte-by-byte comparator appears anywhere in the design |

**What we are *not* claiming:** avoiding all six mistakes is a statement
about the *design*, not a guarantee that an *implementation* of this design
is bug-free — an implementer could still, for example, accidentally call a
non-constant-time comparison function. That gap is itself the kind of
condition axis 2 asks us to name rather than hand-wave, and we return to it
in `honesty.md`.

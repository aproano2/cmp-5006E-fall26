# Secure Electronic Contract Signing (SECS)

## 1. Scope and security goals

SECS lets Alice (the provider) deliver a contract to Bob (the client) over an
attacker-controlled network. The protocol produces an evidence package that
either party can later verify without trusting the transport connection.

The protocol assumes a network attacker can read, delay, replay, drop, reorder,
and modify messages, but cannot break the selected cryptographic primitives.
Alice and Bob have authenticated certificates issued by a trusted CA. The CA
and the endpoint key stores are trust boundaries: a compromised CA or signing
key invalidates the corresponding identity claim.

The protocol goals are:

1. **Confidentiality in transit:** encrypt the contract bytes against a passive
   network observer, subject to the public-digest limitation in section 5.
2. **Integrity:** a modified contract is rejected before acceptance.
3. **Non-repudiation of origin:** Alice's signature binds Alice to the exact
   contract and protocol session.
4. **Non-repudiation of receipt:** Alice's final signature acknowledges Bob's
   countersigned receipt, and Bob's final acknowledgment binds Bob to receiving
   and validating the final signed copy.

This is a signing-and-delivery protocol, not a guarantee that either party will
perform the contract. Its evidence proves the signed statements and the
cryptographic conditions below.

## 2. Primitives and rationale

| Purpose | Primitive | Reason and condition |
|---|---|---|
| Contract digest | SHA-256 | Gives a canonical, fixed-size identifier for the exact bytes; collision resistance is required for the integrity and evidence claims. |
| Key agreement | Ephemeral X25519, or the supplied week-5 DH group for the toy implementation | Fresh ephemeral secrets provide forward secrecy against later compromise of a long-term signing key, provided the implementation validates public keys and the discrete-log assumption holds. |
| Key derivation | HKDF-SHA-256 | Separates the traffic key from the raw DH result and binds it to the session transcript and both identities. |
| Contract encryption and transport authentication | AES-256-GCM | Provides confidentiality and tamper detection in one operation, provided every `(key, nonce)` pair is unique and the associated data is checked. |
| Identity and signatures | Ed25519 certificates and signatures; the supplied week-4 RSA signature code is the educational substitute | Digital signatures bind an identity to a transcript and evidence. The production choice avoids textbook RSA; the toy code is used only to illustrate the same signing flow. |
| Certificate validation | X.509-style chain validation with a pinned CA trust store, validity/revocation checks, and name/key-usage checks | Prevents an attacker from substituting an unrelated public key, provided the CA trust store and revocation information are correct. |
| Randomness | OS CSPRNG for ephemeral secrets, AES-GCM nonces, and identifiers | Prevents the predictable-key and reused-randomness failures seen in the fleet deployment. |

The contract is canonicalized before hashing: UTF-8 text is normalized to a
specified form, or, preferably, the contract is signed as an immutable byte
sequence. The digest is computed over those exact bytes, not over a rendering
that could differ between applications.

## 3. Signed and encrypted message format

All fields below are encoded canonically (for example, canonical CBOR with
sorted map keys). A signature covers the literal encoded bytes of the indicated
object. `sid` is a fresh random session identifier.

```text
Certificate:
  cert_subject, signing_public_key, key_usage, validity, issuer_chain

HELLO_A:
  version, sid, alice_cert, alice_ephemeral_DH_public, algorithms,
  signature_A(
    "SECS-HELLO-A" || version || sid || alice_ephemeral_DH_public || algorithms
  )

HELLO_B:
  version, sid, bob_cert, bob_ephemeral_DH_public,
  signature_B(
    "SECS-HELLO-B" || version || sid ||
    alice_ephemeral_DH_public || bob_ephemeral_DH_public || algorithms
  )

CONTRACT:
  sid, transcript_hash, contract_id, contract_hash, gcm_nonce, ciphertext, aad,
  signature_A(
    "SECS-CONTRACT" || sid || transcript_hash || contract_id || contract_hash ||
    hash(ciphertext) || gcm_nonce || aad
  )

RECEIPT_B:
  sid, transcript_hash, contract_id, contract_hash, hash(ciphertext), receipt_status,
  received_at, signature_B(
    "SECS-RECEIPT" || sid || transcript_hash || contract_id || contract_hash ||
    hash(ciphertext) || receipt_status || received_at
  )

FINAL_A:
  sid, transcript_hash, contract_id, contract_hash, hash(ciphertext), hash(RECEIPT_B),
  signature_A(
    "SECS-FINAL" || sid || transcript_hash || contract_id || contract_hash ||
    hash(ciphertext) || hash(RECEIPT_B)
  )

ACK_FINAL_B:
  sid, transcript_hash, contract_id, contract_hash, hash(FINAL_A),
  ack_status = "FINAL_RECEIVED_AND_STORED", final_received_at,
  signature_B(
    "SECS-ACK-FINAL" || sid || transcript_hash || contract_id || contract_hash ||
    hash(FINAL_A) || ack_status || final_received_at
  )
```

`transcript_hash` is the hash of the canonical `HELLO_A || HELLO_B` bytes.
`aad` includes `sid`, `transcript_hash`, both certificate fingerprints,
`contract_id`, protocol version, and algorithm identifiers. It is authenticated
but not encrypted.
The contract plaintext is encrypted as:

```text
key = HKDF(shared_DH_secret,
           salt = sid,
           info = "SECS-v1" || alice_cert_fingerprint || bob_cert_fingerprint)
(ciphertext, tag) = AES_256_GCM_Encrypt(key, gcm_nonce, contract_bytes, aad)
```

The `gcm_nonce` is generated once for this message with the CSPRNG and is never
reused with that derived key. A retransmission repeats the same authenticated
`CONTRACT` object rather than encrypting again with the same nonce.

The final signed copy consists of the exact contract bytes and the canonical
`HELLO_A`, `HELLO_B`, `CONTRACT`, `RECEIPT_B`, and `FINAL_A` objects. Bob already
holds the earlier objects; he verifies that `FINAL_A` matches their session,
transcript, contract, ciphertext, and receipt before acknowledging it. All object
hashes include the object's signature and all encoded fields. In particular,
`hash(FINAL_A)` binds the acknowledgment to Alice's exact signed final manifest.
The retained evidence package also includes `ACK_FINAL_B`, certificates, and
revocation evidence. `final_received_at` is Bob's signed assertion of time,
not an independently trusted timestamp.

## 4. Message flow and trust boundaries

```text
             Alice endpoint                    Untrusted network                 Bob endpoint
             --------------                    -----------------                 -----------
 [Alice key store + CA validation]                                             [Bob key store + CA validation]
          |                                                                   |
          |-- HELLO_A: cert_A, eph_A, sig_A ------------------------------->  |
          |                                                                   | validate cert_A
          |  <-------------------------- HELLO_B: cert_B, eph_B, sig_B -------|
          | validate cert_B                                                    |
          |                                                                   |
          | derive K = HKDF(DH(eph_A,eph_B), transcript)                       | derive same K
          |                                                                   |
          |-- CONTRACT: ciphertext, hash, nonce, AAD, sig_A ---------------->  |
          |                         [attacker may read/alter/replay]          |
          |                                                                   | verify sig_A
          |                                                                   | AES-GCM decrypt + verify tag
          |                                                                   | recompute H(contract_bytes)
          |  <---------------- RECEIPT_B: hash, status, timestamp, sig_B ------|
          | verify cert_B and sig_B                                            |
          |                                                                   |
          |-- FINAL_A: hash(receipt), sig_A -------------------------------->  |
          |                                                                   | verify final manifest
          |                                                                   | durably store final signed copy
          |  <----------- ACK_FINAL_B: hash(FINAL_A), status, sig_B ------------|
          | verify sig_B and final hash; store ack; mark COMPLETE              |

 Trust boundary 1: Alice's signing key and contract canonicalizer.
 Trust boundary 2: Bob's signing key and receipt verifier.
 Trust boundary 3: CA trust store, certificate issuance, and revocation data.
 The network between endpoints is not trusted.
```

### Verification and state transitions

1. Each endpoint validates the peer certificate chain to a pinned trust anchor,
   checks the subject name, key usage, validity interval, and revocation state,
   and rejects an invalid certificate before using its key.
2. Each endpoint verifies the signed hello transcript and checks that `sid` has
   not already been accepted. This prevents an attacker from replacing an
   ephemeral key or replaying an old session.
3. Bob verifies Alice's `CONTRACT` signature before decrypting or accepting the
   object. He then verifies the GCM tag and recomputes the contract hash. Any
   failure stops the protocol and produces no receipt.
4. Bob signs `RECEIPT_B` only after all checks pass and durably stores the exact
   contract bytes, ciphertext, transcript, certificates, and receipt.
5. Alice verifies Bob's receipt signature, status, transcript, and all hashes,
   durably stores the contract and countersigned receipt, and issues `FINAL_A`.
   Its signature acknowledges that exact receipt. Alice enters
   `WAIT_FINAL_ACK`; sending the final manifest alone is not completion.
6. Bob verifies Alice's `FINAL_A` signature and checks every bound field against
   the stored session, contract ciphertext, contract bytes, and signed receipt.
   He durably stores the final signed copy before creating `ACK_FINAL_B`, durably
   stores the signed acknowledgment for retransmission, and enters
   `FINAL_STORED_ACK_SENT` when he sends it. He signs no acknowledgment if any
   verification or storage operation fails.
7. Alice verifies Bob's acknowledgment signature, the exact `hash(FINAL_A)`,
   session/transcript/contract bindings, and the required acknowledgment status.
   She durably stores the valid acknowledgment before entering `COMPLETE`.
   Both parties retain their signed evidence and certificate/revocation records.

Duplicate messages are idempotent only when every signed field matches the
stored session. A conflicting message with the same `sid` is an alarm, not an
overwrite. Before any receipt is issued, a timeout causes `ABORT`. After a
signed receipt has been issued, timeouts are recorded as `INCOMPLETE` with the
phase and retained evidence; they do not erase or retract existing signatures.
If `FINAL_A` is dropped, Alice lacks a final acknowledgment and remains
incomplete. If `ACK_FINAL_B` is dropped, Bob has the final signed copy but Alice
lacks proof of that delivery and remains incomplete. Retries resend the exact
stored signed objects. Bob responds to an identical duplicate `FINAL_A` with
the stored acknowledgment. These rules provide evidence when the acknowledgment
is received, not guaranteed delivery, simultaneous completion, or fair exchange.

## 5. Control Scorecard: axis 2 guarantees and conditions

| Goal / control | Conditional guarantee |
|---|---|
| **Confidentiality** | AES-GCM protects the encrypted contract bytes **provided** Alice and Bob use a fresh valid DH exchange, the endpoint key stores and CSPRNG are uncompromised, nonces are unique, and peer certificates are validated. Full term secrecy additionally depends on the exposed plaintext digest not enabling feasible guesses; the current design does not meet that condition for contracts drawn from a small known candidate set. |
| **Integrity** | Bob rejects any modified, truncated, substituted, or replayed contract **provided** he verifies the canonical contract hash, Alice's signature, the GCM tag, the session identifier, and the authenticated associated data before acceptance. |
| **Non-repudiation of origin** | A valid `signature_A` on the contract manifest is evidence that Alice authorized those exact contract bytes and session **provided** Alice's private signing key was under her control, the key was validly bound by the CA, the signature algorithm remains secure, and the canonicalization rules are unambiguous. |
| **Non-repudiation of receipt** | Alice's valid `FINAL_A` signature acknowledges receipt of Bob's countersigned receipt; Bob's valid `ACK_FINAL_B` signature acknowledges receipt of the final signed copy **provided** both signing keys were under their owners' control, their certificates were valid, signatures and all session/transcript/contract/object hashes were checked, and each endpoint signed only after verification and durable storage. Alice claims completed final delivery only after validating and storing Bob's acknowledgment. |

**Confidentiality limitation:** `contract_hash` remains public in the contract,
receipt, final manifest, and final acknowledgment. An observer can hash candidate
contracts and compare their digests, potentially learning a price or other term
from a known template. This is an unresolved privacy cost of exposing evidence,
not an AES-GCM failure. Moving the plaintext digest into encrypted evidence and
using public ciphertext identifiers would require a revised message format.
See [honesty.md](./honesty.md) for this confidentiality-versus-auditability trade.

These are evidence guarantees, not absolute legal conclusions. A court,
endpoint compromise, CA mis-issuance, ambiguous identity policy, or a broken
signature primitive can defeat the corresponding condition.

## 6. How SECS avoids the six deployment mistakes

1. **Reused one-time pad:** SECS does not use a one-time pad. It derives a
   fresh session key from fresh ephemeral DH secrets and uses an AEAD nonce
   exactly once for that key.
2. **ECB storage:** SECS uses AES-GCM, not ECB. The contract is one authenticated
   stream of bytes, and repeated plaintext blocks do not become repeated
   ciphertext blocks under an ECB construction.
3. **CTR nonce reuse:** AES-GCM nonces are generated per contract and tracked as
   `(key, nonce)` pairs. A nonce collision is a fatal protocol error, not a
   recoverable condition.
4. **Length-extendable MAC:** SECS uses digital signatures over a canonical
   domain-separated message, rather than `SHA256(secret || data)`. It also
   authenticates the encrypted payload with GCM.
5. **Weak RSA fleet key generation:** Long-term keys and ephemeral DH secrets
   come from the operating system CSPRNG. Each public key is independently
   certified, and key generation includes uniqueness and validation checks.
6. **Timing comparison:** Signature, certificate, and tag verification are
   performed by vetted constant-time cryptographic libraries. Protocol errors
   return the same externally visible failure class and do not compare secret
   material with an early-exit application loop.

The design also avoids a related protocol mistake not directly required by the
targets: an unauthenticated DH exchange. The signed hello transcript binds both
ephemeral keys to certified identities, preventing a network MITM from choosing
two independent sessions.

## 7. Implementation and operational checklist

- Use a maintained cryptographic library rather than implementing AES-GCM,
  X25519, Ed25519, HKDF, or certificate parsing by hand.
- Reject non-canonical encodings, unknown protocol versions, invalid DH public
  values, expired certificates, wrong key usage, and revoked certificates.
- Use a monotonic local session/replay store for `sid`; retain accepted
  evidence and conflicting-message alerts.
- Rotate certificates before expiry and provide a documented compromise
  procedure that revokes a key and marks affected evidence.
- Log protocol version, `sid`, contract hash, certificate fingerprints, status,
  and verification failures. Never log plaintext contract terms or private
  keys.
- Test tampering, replay, truncation, nonce reuse, certificate substitution,
  invalid signatures, malformed encodings, dropped final manifests, dropped
  acknowledgments, acknowledgments for another final manifest/session, and
  duplicate delivery. Mark Alice `COMPLETE` only after validating and durably
  storing `ACK_FINAL_B`. Preserve incomplete-session evidence on timeout.
  Verification failures must **fail closed with an auditable error**.

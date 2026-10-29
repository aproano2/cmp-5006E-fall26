# Part B — Secure Electronic Contract Signing (SECS)

## Scope, adversary, and evidence

Alice is the provider and Bob is the client. A network attacker can observe, replay, drop, reorder, or change packets, but does not initially control either endpoint, the certification authority (CA), or the signing keys. A party may refuse to send a receipt. The protocol records evidence of each party's signed
acknowledgment of receiving the identical final package at a party-controlled endpoint, not proof that a human read or understood the text. The signed contract is completed only after Bob returns the final package with his receipt,
Alice verifies it and returns her receipt, and Bob stores Alice's receipt. If either party withholds a required receipt, the exchange remains pending; the protocol does not force cooperation.

An exact and consistent byte format is essential. We define `C` as the final contract bytes, and `M` as a structured message containing a fresh random transaction ID, `SHA-256(C)`, Alice's and Bob's certified identities and roles, contract version, signing policy version, and expiry. Every signed object is strictly formatted in a fixed order with clear lengths, and includes a specific label (context string) so that a signature from one step can never be reused in another step All verification checks the exact bytes, identity, purpose, transaction ID, version, and expiry.

## Primitive choices and their conditions

| Control | Why it is used | Guarantee and condition (axis 2) |
|---|---|---|
| SHA-256 digest | Binds large contract bytes to compact signed metadata. | A changed `C` is detected **if** collision resistance holds and the verifier recomputes the digest over the exact canonical contract bytes. |
| Ed25519 signatures | Alice signs her offer and finalization; Bob signs acceptance; both sign receipts. | A valid signature attributes its exact message to a certified signing key **if** the key was controlled by the named signer at the relevant time and the verifier checks the correct key, context, and message. |
| PKI with separate signing and transport certificates | Binds keys to Alice and Bob and separates identity from the key bytes. | A verified certificate binds a public key to an identity **if** the CA issued correctly, the trust anchor is authentic, the chain, name, key usage, validity period, and revocation status are checked, and the private key is protected. |
| Mutual TLS 1.3 with ephemeral X25519, HKDF, and an AEAD such as AES-GCM | Authenticates both endpoints and encrypts the contract in transit with fresh session keys. | Session confidentiality and channel integrity hold against the network attacker **if** certificate validation is correct, ephemeral secrets and endpoints are protected, the key exchange is authenticated, and the AEAD nonce is unique for its key. Forward secrecy additionally depends on ephemeral secrets being erased. |
| Cryptographic random generator | Produces transaction IDs, signing keys, and ephemeral key material. | Unpredictability and key independence hold **if** the generator has adequate entropy and is not cloned across devices. |
| Durable evidence storage | Preserves the final package, signatures, receipts, certificates, and validation results. | A later audit can check the record **if** evidence is retained without alteration and the applicable signing-time certificate state can be established. |

The deployment must use vetted implementations of these primitives. No handwritten block cipher, hash, RSA prime generator, or token MAC from the toy target module is reused.

## Message flow and trust boundaries

The CA boundary is the transfer of trusted identity bindings to each endpoint.
The network boundary is every message between Alice and Bob; mutual TLS protects the channel, while application signatures remain verifiable after that channel closes. Local storage and signing devices are a third trust boundary.

```text
                     [ CA / trust-store boundary ]
                 CA issues and validates identity-bound certs
                             |               |
                      [Alice endpoint]   [Bob endpoint]
                      signing key A      signing key B
                             |               |
                             +-- mutual TLS --+
                       [ untrusted network boundary ]

1  Alice -> Bob:  C, M, SA = Sign_A("SECS/OFFER/v1", M)
2  Bob -> Alice:  SB = Sign_B("SECS/ACCEPT/v1", M, SA)
3  Alice:         F0 = (C, M, SA, SB)
                  SF = Sign_A("SECS/FINAL/v1", SHA-256(F0))
                  F  = (F0, SF)
4  Alice -> Bob:  F
5  Bob -> Alice:  F, RB = Sign_B("SECS/RECEIVED/v1", tid, SHA-256(F))
                  (Bob sends RB only after verifying and storing F.)
6  Alice -> Bob:  RA = Sign_A("SECS/RECEIVED/v1", tid, SHA-256(F))
                  (Alice sends RA only after receiving the returned F and RB.)

Each arrow crosses the untrusted network boundary inside authenticated, encrypted TLS. CA checks cross the CA trust boundary. Signing and storing cross each party's local endpoint boundary.
```

Alice verifies Bob's certificate and `SB` before creating `F`. Bob verifies
`SHA-256(C)`, `M`, both signatures, and `SF`, then stores `F` before sending it
back with `RB`. Alice checks that the returned `F` is byte-for-byte identical
to her copy, verifies `RB`, stores the package, and signs `RA`. Bob verifies and
stores `RA`. Both retain `F`, `RA`, `RB`, certificate chains, and available
signing-time validation evidence. Replays with an old transaction ID, expired
metadata, or another contract digest are rejected. If either receipt is
withheld, the exchange is marked **pending**, not falsely marked complete.

## Four required Control Scorecard axis-2 statements

| Security goal | Guarantee **and condition** | Verifiable evidence |
|---|---|---|
| Non-repudiation of origin | Alice and Bob cannot credibly deny that their certified signing keys signed the exact `M` and contract digest **if** their private signing keys were under their control at signing time, the CA identity bindings and signing-time status were valid, and canonical encoding and signature verification were correct. This is cryptographic attribution, subject to legal and key-compromise disputes. | `C`, `M`, `SA`, `SB`, `SF`, certificate evidence. |
| Non-repudiation of receipt | Each party has signed an acknowledgment of receiving the identical final `F` **if** Bob received and verified `F` from Alice before issuing `RB`, Alice received and verified Bob's returned `F` and `RB` before issuing `RA`, both keys were controlled by their owners, and both receipts were retained. Either party can still withhold its receipt, leaving the exchange pending; the protocol cannot prove human reading. | `RA` and `RB` over `tid` and `SHA-256(F)`. |
| Integrity | Any change to the contract or signed protocol metadata is detected **if** SHA-256 remains collision resistant, canonical encoding is unambiguous, the signatures are unforgeable, and each party checks every digest and signature before acceptance. | Recomputed `SHA-256(C)` and verified `SA`, `SB`, `SF`, `RA`, `RB`. |
| Confidentiality in transit | A passive or active network observer cannot learn the contract terms in transit **if** the mutual TLS handshake authenticates the intended peers, endpoints and ephemeral secrets are protected, the AEAD uses unique nonces, and TLS is implemented correctly. Traffic length and timing may still leak. | TLS peer-authentication and session logs, plus configuration review; these are supporting evidence, not a proof of absence of endpoint compromise. |

## How SECS avoids the six deployment mistakes

| Local mistake | SECS response |
|---|---|
| Reused pad | Uses fresh TLS session keys and a vetted AEAD instead of a reused XOR pad. |
| ECB structure leakage | Uses an AEAD with fresh nonces; equal plaintext blocks are not encrypted independently to repeatable blocks. TLS record lengths can still leak approximate size. |
| CTR nonce reuse | TLS AEAD enforces nonce uniqueness per traffic key; rekey before counters wrap and abort on nonce-management failure. |
| Prefix-MAC length extension | Uses digital signatures over typed, canonical objects and TLS's authenticated record protection; no `hash(secret || data)` token. |
| Shared-prime RSA fleet | SECS uses Ed25519/X25519 keys generated by a cryptographic random generator with independent device entropy, rather than RSA keys from a weak fleet PRNG. If an RSA fleet is used elsewhere, batch-GCD audits detect shared factors; checking only for duplicate public keys does not. |
| Early-exit comparison | Vetted signature and AEAD verification routines use side-channel-resistant implementations; authentication errors are uniform. This condition must be checked in the actual deployment. |

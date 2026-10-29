# Part B: Secure Electronic Contract Signing (SECS)

Alice (provider) and Bob (client) sign a contract `M` with four goals:
non-repudiation of origin, non-repudiation of receipt, integrity, and
confidentiality of the terms in transit.

## 1. Primitives, and why each

| Primitive | Choice | Why (ties to weeks 2-5) |
|---|---|---|
| Hash | SHA-256 | Collision and second-preimage resistance bind a signature to the exact bytes of `M` and let us sign a short digest. (wk 2-3) |
| Digital signature | RSA-PSS-3072 or ECDSA-P256 over the digest | Only the private-key holder can produce it, and anyone can verify it with the cert. That asymmetry is what gives non-repudiation; a symmetric MAC proves nothing to a third party. (wk 4) |
| Authenticated key exchange | ECDHE (ephemeral), each party's share signed | Gives a fresh per-session symmetric key and forward secrecy. Signing the DH shares and validating the cert chain is what stops the week-5 MITM. (wk 5) |
| AEAD | AES-256-GCM, unique 96-bit nonce per message | Confidentiality and integrity of each wire message. Semantically secure, unlike ECB. (wk 2-3) |
| PKI | X.509 certs from a CA both parties trust, full chain validation | Binds a public key to a legal identity. Chain validation plus a pinned root prevents impersonation and trust-store poisoning. (wk 5) |

Notation: `Cert_X` is X's certificate; `sig_X(d)` is a signature by X over digest `d`;
`H` is SHA-256; `AEAD_K` is AES-256-GCM under key `K` with a fresh nonce each call.

## 2. Message flow and trust boundaries

```
        TRUST BOUNDARY: public, attacker-controlled network (passive + active MITM)
  ALICE (provider) ======================================================= BOB (client)
       |                                                                        |
  (0)  |  validate Cert_Bob to a pinned CA root        validate Cert_Alice ---> |
       |                                                                        |
  (1)  |  gA = g^a, sig_Alice(gA, "SECS-hello")   -------------------------->   |  verify sig,
       |                                                                        |  check Cert_Alice
  (2)  |   <--------------------------   gB = g^b, sig_Bob(gB, "SECS-hello")    |
       |                                                                        |
       |  K = KDF(g^{ab}, transcript)   [both derive the same session key]      |
       |- - - - - - - - - - - confidential, authenticated channel - - - - - - - |
       |                                                                        |
  (3)  |  AEAD_K( M , sig_Alice(H(M)) )  --------------------------------->      |  decrypt, verify
       |                                                            sig_Alice    |
  (4)  |   <-----  AEAD_K( sig_Bob(H(M)) , RECEIPT_B )                           |
       |           RECEIPT_B = sig_Bob(H("RCPT" ‖ H(M) ‖ ts ‖ nonce))           |
       |                                                                        |
  (5)  |  C = (M, sig_Alice(H(M)), sig_Bob(H(M)))   [the co-signed contract]     |
       |  AEAD_K( sig_Alice(H(C)) )  ------------------------------------->      |
  (6)  |   <-----  AEAD_K( RECEIPT_B' = sig_Bob(H("FINAL" ‖ H(C) ‖ ts ‖ n)) )   |
       |                                                                        |
  ===== Each party archives C, both signatures, and both receipts =============
```

- Trust boundary: everything between Alice and Bob is a hostile network; the
  endpoints and their private keys sit inside their own boundaries. The CA is a
  separate trusted authority outside both, the one party both must rely on.
- Steps (0)-(2) authenticate both ends and set up the confidential channel. Steps
  (3)-(4) exchange signatures on `M`. Steps (5)-(6) deliver and acknowledge the
  final co-signed copy `C`, which is what "receipt" refers to.

## 3. Axis-2 guarantee + condition per goal

| Goal | Guarantee and the condition it depends on |
|---|---|
| Non-repudiation of origin | Alice cannot deny signing `M`, **provided** (a) her signing private key is uncompromised, (b) the CA that bound her key did not mis-issue, and (c) SHA-256 is collision-resistant (otherwise she pleads a second document with the same digest). |
| Non-repudiation of receipt | Bob cannot deny receiving the final copy `C`, **provided** his key is uncompromised, the CA did not mis-issue, and the protocol forced `RECEIPT_B'` before releasing anything he wanted, that is, the fair-exchange assumption holds (see honesty.md; without a TTP this is only partially enforced). |
| Integrity | No undetected alteration of the contract, **provided** SHA-256 is second-preimage-resistant and every signature and GCM tag is verified before acting. Any altered byte flips the digest or fails the tag. |
| Confidentiality in transit | The terms stay secret from a network attacker, **provided** the ECDHE shares were signed and the cert chain validated (no MITM), AES-256-GCM uses a unique nonce per message under `K`, and the ephemeral keys `a,b` are erased after the session (forward secrecy). |

## 4. Which broken-deployment mistakes this avoids, and how

| Break | Mistake | How SECS avoids it |
|---|---|---|
| #1 / #3 keystream & nonce reuse | one pad or one nonce for many messages | `K` is per-session (fresh ECDHE each time) and GCM uses a fresh nonce per message. The never-reuse requirement is stated as the axis-2 condition for confidentiality, not assumed away. |
| #2 ECB | deterministic mode leaks equal blocks | AEAD (nonced AES-GCM) is semantically secure: identical plaintext never yields identical ciphertext. |
| #4 length extension | `H(secret‖data)` used as a MAC | Integrity and authenticity come from digital signatures and the GCM tag, never a raw Merkle-Damgard `H(secret‖·)`. Signatures and HMAC are not length-extendable. |
| #5 shared prime | low-entropy keygen | Keys are generated from an OS CSPRNG with adequate entropy and are at least 3072-bit RSA or P-256. A batch-GCD audit over the fleet's moduli runs before deployment as a regression check. |
| #6 timing | early-exit secret comparison | Every secret-dependent compare (tag or MAC verify) uses a constant-time primitive (`hmac.compare_digest`). Signature verification does not branch on the secret. |

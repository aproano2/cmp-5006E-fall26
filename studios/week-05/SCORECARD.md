# Week 5 — Control Scorecard (Task 4)

Axis 2 (Guarantee) stated as a **conditional**: guarantee + the condition it depends on,
and what breaks when that condition fails. Evidence comes from `test_dh_pki.py` (all 6 pass).

| Mechanism | Guarantee (axis 2) | Its condition / failure | Evidence in this studio |
|---|---|---|---|
| **Diffie–Hellman** | Two parties derive a shared secret `g^(ab) mod p` that a **passive** eavesdropper who sees only `A` and `B` cannot compute (discrete-log assumption over a large-enough group). | **Provided the endpoints are authenticated.** DH has no authentication: an **active** MITM (Mallory) injects her own `M` toward both sides and ends up holding one key with Alice and another with Bob, while Alice and Bob share nothing. Fails **silently** — neither side can tell. | `test_mitm_breaks_unauthenticated_dh`: `alice == mallory_alice`, `bob == mallory_bob`, `alice_equals_bob is False`. |
| **Certificate chain (PKI)** | Binds a public key to a name (`bank.example.com`): a chain leaf → intermediate → root validates only if every signature verifies **and** the root is in the trust store. Forgeries (self-signed, rogue CA) are rejected. | **Only as trustworthy as the root trust store.** If a rogue root is installed (malware, coerced admin) or a trusted CA is compromised/negligent (DigiNotar 2011), a forged chain validates cleanly. The signatures never break — the anchor does. CT is a *detective* control (makes mis-issuance public), not a preventive one. | Both forgeries fail at the **same** check: `anchor ... is not a trusted root`. `test_trust_store_poisoning_accepts_forgery`: the same rogue chain goes False → **True** after `poison_trust_store`. |
| **TLS 1.3** | A confidential **and** authenticated channel: ephemeral DH for secrecy (+ forward secrecy), the server's certificate chain + a signature over the handshake transcript (`CertificateVerify`) to authenticate the DH, and AEAD (AES-GCM) for the record layer. | **Every underlying condition must hold at once:** unique nonces in the AEAD (wk3), strong keys / good RNG (wk4), DH authenticated by the cert (§2), and a correct trust store (§4). Break any one layer and the channel's guarantee collapses. | Composition of the two rows above plus weeks 3–4. |

**Fast-finisher answer (Task 1):** In TLS 1.3 the "authenticated" in authenticated DH comes
from the server's `CertificateVerify` message — a signature over the handshake transcript
(including the DH key shares) made with the private key whose public key is bound to the
server's name by the certificate chain that validates to a trusted root.

**Task 2 one-liner:** Both forgeries fail at the trust-anchor check because Mallory can sign
anything with her own keys, but she cannot make the browser *trust* her signing key.

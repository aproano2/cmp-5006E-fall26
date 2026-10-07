| Mechanism | Guarantee (Axis 2) | Condition / Failure Mode |
|---|---|---|
| **Diffie–Hellman** | Shared secret against a passive eavesdropper | Lack of authentication = defeated by a MITM attack |
| **Certificate Chain** | Binds a public key to an identity/name | Only as trustworthy as the root trust store |
| **TLS 1.3** | Confidential and authenticated channel | All conditions must hold (nonce, key, trust store integrity) |
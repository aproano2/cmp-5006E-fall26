# Week 5 Control Scorecard: Authenticated Diffie-Hellman & PKI (TLS 1.3 Core)

This scorecard evaluates the security controls explored in Week 5, specifically focusing on unauthenticated Diffie-Hellman (DH), Certificate Chains, and the ultimate bypass through Trust Store Poisoning. It strictly follows the 8-axis framework defined in `resources/control-scorecard.md`.

## 1. The 8-Axis Control Scorecard

**System under test:** Authenticated Diffie-Hellman via PKI Certificate Chains (The foundational layer of TLS 1.3).

| Axis | Before | After control (PKI + DH) | Evidence |
|------|--------|--------------------------|----------|
| **Threat model** | Active MITM (Mallory) intercepting and modifying the wire, without valid credentials. | unchanged | Week 5 Studio setup (`mitm_keys`) |
| **Guarantee** | None (DH creates a secure channel with the attacker). | Provides a confidential and authenticated channel, **provided** the Root Trust Store remains completely uncompromised. | `test_mitm_breaks_unauthenticated_dh` |
| **Coverage** | 0/2 attacks stopped (MITM succeeds 100% on raw DH). | 2/2 malicious forged chains blocked (self-signed and Rogue CA). | `test_dh_pki.py` validation tests |
| **Bypass** | — | **Found: Trust-Store Poisoning.** Injecting the Rogue Root CA into the machine's store silently bypasses all math. | `test_trust_store_poisoning_accepts_forgery` |
| **FP cost** | 0% | High for internal tools: legitimate self-signed or developer certificates are aggressively blocked by default. | Known PKI limitation (requires manual whitelisting) |
| **Op cost** | — | RSA signature verification CPU overhead + massive global Trust Store management and distribution effort. | `dh_pki.py` (`validate()` loop) |
| **Observability** | Silent failure (victims don't know they are MITM'd). | Excellent: The validator returns exact reasons (e.g., "anchor not trusted root"). | `dh_pki.py` (lines 85-92) |
| **Failure mode** | — | **Fails closed** (connection drops) if signatures mismatch. **Silently fails open** if the trust store is poisoned. | `poison_trust_store` behavior |


## 2. Mechanism Summary (As requested in Task 4)

Here is the isolated Guarantee vs Condition breakdown for the specific mechanisms:

| Mechanism | Guarantee (Axis 2) | Its condition / failure |
|---|---|---|
| **Diffie-Hellman** | Shared secret against a passive eavesdropper. | **No authentication** — an active MITM defeats it instantly. |
| **Certificate Chain** | Cryptographically binds a public key to a specific entity name. | Only as trustworthy as the **Root Trust Store** on the device. |
| **TLS 1.3** | Fully confidential and authenticated communication channel. | **Every underlying condition must hold** (nonce uniqueness, key strength, and a clean trust anchor). |


## 3. The Honesty Clause: Where we may have been unfair

As required by the scorecard guidelines, here is a critical reflection on our evaluation:

*   **What we did not test (Revocation):** Our `validate()` function only checks signatures and trust anchors. Real-world PKI must also check expiration dates and **Certificate Revocation Lists (CRLs)** or **OCSP**. We completely ignored revocation, which is historically a massive source of operational failure and bypasses.
*   **Scale of the Math:** We used toy-sized parameters (64-bit RSA) to ensure the tests run instantly on a laptop. While the structural logic is identical to reality, real TLS uses 2048+ bit RSA or Elliptic Curves, which drastically increases the actual operational CPU cost.
*   **Malware assumptions:** We demonstrated that trust-store poisoning works, but we assumed Mallory already had the ability to install a root CA on Alice's machine. If Mallory is purely a network attacker (e.g., sitting at a coffee shop WiFi), she cannot poison the trust store and the defense holds perfectly.

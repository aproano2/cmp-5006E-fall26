---
marp: true
theme: default
paginate: true
header: 'CMP-5006 · Week 5 · Protocols, PKI & TLS 1.3'
---

<!--
Week 5. Beats: Diffie-Hellman (7) · MITM on unauthenticated DH (8) · PKI /
cert chains (8) · TLS 1.3 (2). Duel 1 due. Lesson plan: ../../weeks/week-05.md
-->

# Protocols, PKI & TLS 1.3

## Secrecy is not authentication

**CMP-5006** · Week 5 — *Duel 1 due*

---

# Diffie–Hellman — a secret over a public wire

- Alice picks **a**, sends **g^a mod p**
- Bob picks **b**, sends **g^b mod p**
- Both compute **g^(ab) mod p** — the shared secret

An eavesdropper sees only `g^a` and `g^b`. Computing `g^(ab)` needs a **discrete
log** — infeasible.

> DH defeats a **passive** eavesdropper completely.

---

# ⚠️ ...but DH has no idea who it's talking to

Eve runs DH with **each** side and relays:

```
Alice ⇄ Eve ⇄ Bob
   \_ key K₁ _/  \_ key K₂ _/
```

- Alice shares a key with **Eve** (thinking it's Bob).
- Bob likewise. Eve decrypts, reads, re-encrypts — invisibly.

> Secrecy without authentication is a **private conversation with an impostor.**

<!--
8 min. This is why raw DH is never used alone. An ACTIVE attacker defeats it.
-->

---

# PKI — bind a key to a name

A **Certificate Authority** signs "this key belongs to bank.example.com." Your
browser ships with the CA's key in a **trust store**.

```
leaf (bank.example.com)  ← signed by
  intermediate (ACME)    ← signed by
    root (trusted)        ← in your browser
```

Validation walks the chain to a **trusted anchor**.

---

# ⚠️ Why Eve can't just forge a cert

She can *make* a cert saying "bank.example.com → my key." She can't get it signed
by a key in your trust store.

```
self-signed forgery  → REJECTED (anchor not trusted)
rogue-CA chain       → REJECTED (anchor not trusted)
```

## ...which relocates the whole problem

> PKI's guarantee is only as strong as the **trust store**. Real failures: CA
> compromise (DigiNotar), mis-issuance, a **rogue root installed by malware**.

<!--
8 min. Add the rogue root to the store and the rogue chain validates. The math was
never the weak point. Certificate Transparency = detection, not prevention.
-->

---

# TLS 1.3 in one paragraph

**Authenticated DH** (forward-secret keys) + **certificate chain** (server
identity) + **AEAD** (AES-GCM — nonce discipline and all).

TLS 1.3 *removed* insecure options (static RSA, CBC, renegotiation) — a protocol
getting simpler **and** safer.

> Every weakness in this course lives somewhere in that stack: nonce reuse (wk3),
> a weak key (wk4), a MITM (today), a bad trust anchor (today).

---

# Studio — and Duel 1

1. **DH + MITM** — implement the exchange; mount the man-in-the-middle.
2. **Cert-chain validation** — build a 3-level chain; reject two forgeries.
3. **Trust-store attack** — add a rogue root; watch the rogue chain validate.
   Connect to DigiNotar.
4. Scorecard DH, cert chains, TLS: guarantee + condition.

> **Duel 1 is due** — the DH/PKI toolkit is how you argue a protocol's guarantees.

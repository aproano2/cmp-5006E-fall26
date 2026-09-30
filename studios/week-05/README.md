# Week 5 Studio — Diffie–Hellman, MITM & the Trust Anchor

**Companion to** [`../../weeks/week-05.md`](../../weeks/week-05.md) — Session 5B.
**Time budget:** Recap 5 · Lab 45 · Demos 20 · Debrief 10 (80 min total).
**Deliverables:** all provided tests pass, and a filled-in Control Scorecard row
for DH, cert chains, and TLS.

> ### ⚠️ Duel 1 (Crypto & Protocols) is DUE this week.
> Starter, targets, and submission format:
> [`../../projects/duel-1-crypto/`](../../projects/duel-1-crypto/) — full spec in
> [`../../projects/duel-1-crypto.md`](../../projects/duel-1-crypto.md). This studio
> is the DH/PKI *toolkit* you use to argue Part B (the SECS design) rigorously.
> Leave time in the briefing for Duel 1 questions.

> **Warm-up (5 min).** *DH gave Alice and Bob a shared secret over a wire the
> attacker controls. Why isn't that enough — and what fills the gap?*

## Files in this folder

| File | Purpose | You edit it? |
|---|---|---|
| [`dh_pki.py`](dh_pki.py) | Given: the DH group, toy-RSA signatures, `make_cert`, and the `validate` chain-walker — verbatim from the notebook | ❌ |
| [`fixtures.json`](fixtures.json) | Given: the real 1024-bit MODP group + the exact cert chain and two forgeries from class (RSA seed 7) | ❌ |
| [`starter.py`](starter.py) | **Tasks 1 & 3** — implement DH, the MITM, and the trust-store poisoning | ✅ |
| [`test_dh_pki.py`](test_dh_pki.py) | Provided tests, incl. two *guarantee* tests that watch a guarantee collapse | ❌ |
| [`_generate_fixtures.py`](_generate_fixtures.py) | Regenerates `fixtures.json` (only if you rotate the RSA seed) | ❌ |

The math here is real but small: a genuine RFC 2409 group-2 1024-bit MODP prime for
DH, and 64-bit toy RSA (from week 4) for the signatures — small enough to run on a
laptop, large enough that the *structure* is honest. No `seclab` import this week;
it is pure Python.

## Task 1 — DH + the man-in-the-middle (12 min)

Open `starter.py`. Implement:

- `dh_public(private)` — the public value `g^private mod p` sent over the wire.
- `dh_shared(their_public, my_private)` — the secret `their_public^my_private mod p`.
- `mitm_keys(a, b, m)` — Mallory injects her own public value toward **both** Alice
  and Bob, then relays. Return the four half-secrets and `alice_equals_bob`.

Then:

```bash
python3 test_dh_pki.py
```

The guarantee test — `test_mitm_breaks_unauthenticated_dh` — is the point. It
asserts Mallory shares a key with each side while **Alice and Bob share nothing**.
DH gave perfect *secrecy* on each leg and *zero authentication* of the endpoints.
State DH's guarantee as a conditional: *shared secret vs. a passive eavesdropper,
**provided** the endpoints are authenticated.* Remove the proviso and the MITM walks
straight in. **Secrecy without authentication is a private conversation with an
impostor.**

Fast-finishing pairs: *Where in TLS 1.3 does the "authenticated" in "authenticated
DH" actually come from?* (Answer in one sentence — it involves §2 below.)

## Task 2 — Cert-chain validation & forgery rejection (13 min)

`validate(chain, trust_store)` is **given** — a leaf → intermediate → root walker
that terminates in a trusted anchor. Load the notebook's real chain and its two
forgeries from `fixtures.json` and run them:

```python
from dh_pki import validate, load_fixtures
fx = load_fixtures()
validate(fx["chain"], fx["trust_store"])                     # -> (True, ...)
validate([fx["self_signed_forgery"]], fx["trust_store"])     # -> (False, ...)
validate([fx["rogue_leaf"], fx["rogue_ca"]], fx["trust_store"])  # -> (False, ...)
```

Two forgeries, two rejections — and they fail at the **same** check. Be ready to say
why in one sentence: Mallory can sign anything, but she cannot make your browser
trust her signing key. That is exactly what PKI buys, and it relocates the whole
problem to one question — *is the trust store correct?*

## Task 3 — The trust-store attack (15 min)

Implement `poison_trust_store(trust_store, rogue_root)` — install the rogue root's
public key into a **new** trust store (don't mutate the caller's). Then watch the
*same rogue chain* that just failed now validate:

The guarantee test `test_trust_store_poisoning_accepts_forgery` asserts exactly
this: rejected under a clean store, **accepted** the instant the rogue root is
trusted. The signatures never broke — the trust anchor did. This is the real-world
failure mode, not a math failure:

- A CA is **compromised or coerced** and mis-issues a valid cert for your domain —
  **DigiNotar (2011)**, used to MITM Gmail for Iranian users.
- A CA is merely **negligent** and signs a cert it shouldn't.
- **Malware installs a rogue root** in your store — now any chain it forges chains
  cleanly to a "trusted" anchor.

Certificate Transparency doesn't *prevent* mis-issuance; it makes it public and
*detectable* — foreshadowing week 7's theme: when you can't prevent, you instrument.

## Task 4 — Control Scorecard (5 min)

Fill one row each for DH, cert chains, and TLS 1.3 — **guarantee + condition**, in
the axis-2 conditional form. Use the notebook's §6 table as your model:

| Mechanism | Guarantee (axis 2) | Its condition / failure |
|---|---|---|
| Diffie–Hellman | shared secret vs. a passive eavesdropper | **no authentication** — MITM defeats it |
| Certificate chain | binds a key to a name | only as trustworthy as the **root trust store** |
| TLS 1.3 | confidential, authenticated channel | every underlying condition (nonce, key, trust) must hold |

TLS 1.3 = authenticated **DH** + a **certificate chain** + **AEAD** (AES-GCM, wk3).
Every crypto-week flaw lives somewhere in that stack: nonce reuse in the AEAD (wk3),
a weak key (wk4), a MITM on unauthenticated DH (§2), a bad trust anchor (§4).

## Demos (20 min)

- Prioritize a pair who demonstrated the **trust-store poisoning** cleanly — the
  before/after flip on one rogue chain is the whole lesson in two lines of output.
- Prioritize a pair who tied a **specific real-world PKI failure** (DigiNotar, a
  malware root, a mis-issuance) to their toy model.
- Solicit: *did anyone's MITM accidentally let Alice and Bob agree?* If so, Mallory
  wasn't injecting toward both sides — a live debugging moment.

## Debrief (10 min)

- Secrecy and authentication are **different properties**; a channel needs both.
- ⚠️ Unauthenticated DH → MITM. Authentication comes from PKI binding keys to names.
- PKI's guarantee is only as strong as the trust store; real failures are CA
  compromise / mis-issuance / rogue roots, and CT is the *detective* control.
- TLS 1.3 composes it all — same lesson as every crypto week: **name the condition,
  find the attack.**

## Links

- Session A notebook — [`../../notebooks/week-05-protocols-tls-pki.ipynb`](../../notebooks/week-05-protocols-tls-pki.ipynb)
- **Duel 1 (due this week)** — [`../../projects/duel-1-crypto/`](../../projects/duel-1-crypto/) · spec: [`../../projects/duel-1-crypto.md`](../../projects/duel-1-crypto.md)
- Control Scorecard — [`../../resources/control-scorecard.md`](../../resources/control-scorecard.md)
- AI policy (`AI_LOG.md`) — [`../../resources/ai-policy.md`](../../resources/ai-policy.md)
- Ethics & scope — [`../../resources/ethics-and-scope.md`](../../resources/ethics-and-scope.md)

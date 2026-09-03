# Week 2 Studio — Perfect Secrecy, and the One Misuse That Destroys It

**Companion to** [`../../weeks/week-02.md`](../../weeks/week-02.md) — Session 2B.
**Time budget:** Recap 5 · Lab 45 · Demos 20 · Debrief 10 (80 min total).
**Deliverables:** all provided tests pass, and a filled Control Scorecard row for
the one-time pad — its guarantee, its condition, and its failure mode.

> **Recap (5 min).** *Substitution has more key entropy than DES (88 bits vs. 56).
> So why did it fall in a second while DES stood for decades?*

Week 1 broke a cipher by exploiting an assumption. This week explains *why that
break was inevitable* (entropy + unicity distance), shows the one cipher it could
never touch (the one-time pad, with **provable** perfect secrecy) — and then
destroys even that guarantee with a single misuse: reuse the key once. That break
is the payload. Everything here is pure Python; no `seclab` import, no network.

## Files in this folder

| File | Purpose | You edit it? |
|---|---|---|
| [`otp.py`](otp.py) | Given: the engine — XOR, entropy, unicity distance, the crib-drag printability test, OTP encrypt/decrypt — extracted verbatim from the notebook | ❌ |
| [`twotimepad.json`](twotimepad.json) | Given: the intercepted ciphertext pair `c1`, `c2` — two messages under ONE reused key (same messages/key as the notebook) | ❌ |
| [`starter.py`](starter.py) | **Tasks 1–3** — fill in unicity, the perfect-secrecy demo, and the two-time-pad break | ✅ |
| [`test_otp.py`](test_otp.py) | Provided tests, incl. the two-part guarantee test | ❌ |

## Task 1 — Entropy & unicity (10 min)

Open `starter.py`. Fill in `unicity_for_substitution()` using the engine's
`entropy_bits` and `unicity_distance`. You should get **H(K) ≈ 88.4 bits** and
**U ≈ 27.6 characters**.

Then answer, in one sentence each (scorecard axis 2 warm-up):

- Why did week 1's frequency attack succeed? (The message was hundreds of chars,
  far past U, so the key was uniquely pinned.)
- At what message length would the break have become *ambiguous*? (Below ≈ 28
  chars — multiple keys give readable English.)

## Task 2 — One-time pad: perfect secrecy, made concrete (10 min)

Fill in `key_that_decrypts_to(ciphertext, decoy_plaintext)`. This is the whole
intuition behind Shannon's proof: for **any** plaintext of the right length there
*exists* a key making the ciphertext decrypt to it (`key = ciphertext ⊕ decoy`).
So the same ciphertext decrypts to two *different meaningful* messages under two
keys — it cannot favour the real one. That is perfect secrecy: a guarantee with
**no condition on the attacker's compute**, the strongest in the course.

## Task 3 — The two-time-pad break (20 min)

Now break it. `twotimepad.json` holds `c1` and `c2`: two messages under one
**reused** key — exactly what an attacker intercepts (no key, no plaintext). The
key cancels:

```
c1 ⊕ c2 = (p1 ⊕ K) ⊕ (p2 ⊕ K) = p1 ⊕ p2
```

Fill in:

- `crib_drag(x, crib)` — slide a guessed common word across `x = c1 ⊕ c2`; where
  the crib sits at its true spot in one message, the *other* message's text
  surfaces (use `otp.printable_word` to spot readable fragments amid noise).
- `recover_other_plaintext(c1, c2, p1_known)` — once you have a full crib for one
  message, the keystream falls out (`c1 ⊕ p1`) and the other plaintext with it.

Report **which cribs cracked which positions** and how you chained fragments into
both full messages. Dragging `please` hits position 0 → reveals `the la` (start of
message 1); dragging `target` hits inside message 2.

Then:

```bash
python3 test_otp.py
```

All four tests must pass. The two-part **guarantee test** is the point:
`test_otp_perfect_secrecy_when_key_used_once` shows the OTP is unbreakable when the
key is used once (one ciphertext, two meaningful decryptions); then
`test_two_time_pad_leaks_and_crib_drag_recovers` shows the *same* cipher collapse
completely the moment the key is reused. A test that watches a provable guarantee
fail is not a mistake — watching it fail *once* is how you know the condition was
load-bearing.

## Task 4 — Control Scorecard (5 min)

Fill a Control Scorecard row ([`../../resources/control-scorecard.md`](../../resources/control-scorecard.md))
for the one-time pad. State **axis 2** as a clean conditional — the guarantee
*and* its condition — plus the failure mode:

- **Guarantee:** perfect secrecy — ciphertext statistically independent of
  plaintext, **against unbounded compute** …
- **Condition:** … *provided* the key is random, ≥ message length, and used
  **exactly once**.
- **Failure mode:** reuse → `c1 ⊕ c2 = p1 ⊕ p2` → total break by crib-dragging.

Then the real question: **why does essentially nobody deploy the one
provably-unbreakable cipher?** (Key distribution is as hard as message
distribution — you must share as much secret key as you have plaintext.)

## Demos (20 min)

- Prioritize a pair who recovered **both** plaintexts from cribs alone (no known
  plaintext handed to them) — that is the real cryptanalytic skill.
- And a pair who articulated the OTP's guarantee as a clean conditional (axis 2).
  Naming the condition is the same skill as naming the assumption in week 1.

## Debrief (10 min)

- Entropy measures the attacker's uncertainty; it is **necessary but not
  sufficient** — plaintext redundancy is the other half of security.
- Unicity distance *quantifies* why week 1 worked: enough ciphertext pins the key.
- The OTP has the course's strongest guarantee (perfect secrecy, unbounded
  compute) — and a condition (use once) whose violation is total collapse.
- ⚠️ **A provable guarantee is only as good as its condition.** Real crypto
  (weeks 3–4: AES, RSA) trades perfect secrecy for *usable* computational security
  — breakable in principle, infeasible in practice — and carries conditions of its
  own. Naming those conditions is the job.

## Links

- Session A notebook — [`../../notebooks/week-02-guarantees.ipynb`](../../notebooks/week-02-guarantees.ipynb)
- Week 2 plan — [`../../weeks/week-02.md`](../../weeks/week-02.md)
- Control Scorecard — [`../../resources/control-scorecard.md`](../../resources/control-scorecard.md)
- Ethics & scope — [`../../resources/ethics-and-scope.md`](../../resources/ethics-and-scope.md)
- AI policy (`AI_LOG.md`) — [`../../resources/ai-policy.md`](../../resources/ai-policy.md)

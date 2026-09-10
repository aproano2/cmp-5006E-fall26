# Week 3 Studio — Modes and Misuse

**Companion to** [`../../weeks/week-03.md`](../../weeks/week-03.md) — Session 3B.
**Time budget:** Recap 5 · Lab 45 · Demos 20 · Debrief 10 (75 min total).
**Deliverables:** all provided tests pass, and a filled Control Scorecard row for
each of the four constructions.

> **Recap (5 min).** *AES-CTR is strong. What one discipline must you never
> violate, and what happens if you do?*

Weeks 1–2 were about *ciphers*. This week is about **how you use them**. AES and
SHA-256 are, as far as anyone knows, unbroken — yet every exploit in this studio
succeeds. None of them breaks the primitive; each one is a **misuse of the mode
or the construction** wrapped around it. That distinction is the whole studio,
and it is scorecard axis 2: state the guarantee *and its condition*.

## Files in this folder

| File | Purpose | You edit it? |
|---|---|---|
| [`modes.py`](modes.py) | Given: the block-cipher primitive + ECB/CBC/CTR modes, verbatim from the notebook | no |
| [`mdhash.py`](mdhash.py) | Given: the toy Merkle–Damgard hash, the `bad_mac` (`H(secret‖msg)`) and the real-`hmac` `good_mac` | no |
| [`data.py`](data.py) | Given: the ECB "image", the two CTR messages, and the MAC secret/msg/extension — same values as the notebook | no |
| [`starter.py`](starter.py) | **Tasks 1–3** — fill in the three exploits | yes |
| [`test_modes.py`](test_modes.py) | Provided tests, incl. the guarantee test `test_length_extension_breaks_bad_mac_guarantee` | no |

`seclab` is not imported — this is a crypto week: pure Python, stdlib only, no
lab target, no Docker (extends the weeks 1–2 pattern).

## Task 1 — ECB vs CBC (10 min)

Open `starter.py`, implement `ecb_leak_count(image, key)`: ECB-encrypt the image
and return the number of **distinct ciphertext blocks**. Because a block cipher
is deterministic, identical plaintext blocks map to identical ciphertext blocks,
so the count equals the distinct *plaintext* blocks — the structure leaks 1:1.

For the provided `IMAGE` (two flat regions), ECB yields **2** distinct blocks;
CBC, over the same image and cipher, yields **96** — the chaining destroys the
structure. Same image, same cipher, different **mode**. That is the point: "we
use AES" tells you nothing until you know the mode.

Bonus for the demo: render the image with matplotlib to see the penguin.

## Task 2 — CTR nonce reuse (15 min)

Implement `recover_second_plaintext(c1, c2, known_m1)`. Two messages were
CTR-encrypted under the **same key and the same nonce** — the bug. They share a
keystream, so it cancels:

```
c1 ⊕ c2 == m1 ⊕ m2      ⇒      m2 == c1 ⊕ c2 ⊕ m1
```

This is **week 2's two-time pad, verbatim**, on a modern mode. The strong cipher
gives *zero* protection; its guarantee was conditional on nonce uniqueness. State
that connection out loud — it is the week's spine, and nonce reuse is a real,
recurring CVE class. (Try crib-dragging `data.CRIB` too, exactly as in week 2.)

## Task 3 — Length extension (15 min)

Implement `forge_extension(observed_msg, observed_tag, secret_len, extension)`.
Knowing only `(msg, tag, len(secret))` — never the secret — forge a valid
`bad_mac` (= `H(secret‖msg)`) tag for `msg ‖ glue-pad ‖ extension`. A
Merkle–Damgard digest *is* the full internal state, so you **resume hashing**
from the observed tag:

1. `total = secret_len + len(observed_msg)`
2. `pad = bytes((-total) % 4)` — replicate the hash's internal padding
3. `forged_msg = observed_msg + pad + extension`
4. `forged_tag = md_hash(extension, iv=observed_tag)`

Then confirm HMAC (`good_mac`) defeats the same attempt — it nests the hashing,
so the resumable inner state is never exposed. The lesson: a better
**construction**, not a better hash.

## Task 4 — Control Scorecard (5 min)

For each construction, fill one scorecard row — the guarantee **and its
condition** (axis 2), and classify the failure as *primitive break* vs. *misuse*.
They are **all misuses**; that is the point. Starting point from the notebook:

| Construction | Guarantee (axis 2) | Its condition / failure |
|---|---|---|
| ECB mode | confidentiality of individual blocks only | **leaks structure** — identical blocks visible |
| CBC / CTR | confidentiality of the message | CTR: **nonce must never repeat** (else two-time pad) |
| `H(secret‖msg)` MAC | *appears* to authenticate | **length extension** forges tags without the key |
| HMAC | authentication, no length-extension | needs a secret key; that's it |

The scorecard rubric (all 8 axes, scoring, honesty clause) lives in
[`../../resources/control-scorecard.md`](../../resources/control-scorecard.md).

## Run the tests

```bash
python3 test_modes.py
```

All four tests must pass. The third —
`test_length_extension_breaks_bad_mac_guarantee` — is the point of the week: it
watches the `H(secret‖msg)` **guarantee collapse** (a valid tag forged without
the key), and the fourth shows HMAC rejecting the same forgery. A test that
expects a guarantee to *fail* is not a mistake; watching a guarantee break once
is how you know it was only ever conditional.

Fast-finishing pairs: **if the CTR nonce were unique but the KEY were reused
across a million messages, is CTR still safe? State the condition precisely.**

## Demos (20 min)

- Prioritize a pair who rendered the ECB penguin, and a pair who articulated the
  CTR-nonce condition as a clean scorecard axis-2 conditional.
- Solicit: *did anyone forge a tag that the server accepted?* Walk the glue
  padding on the board — the moment the internal state becomes the attacker's
  resume point is the "aha."

## Debrief (10 min)

- The cipher isn't the control; the **mode and construction** are.
- CTR/GCM nonce reuse = two-time pad. Never reuse a nonce under a key.
- `H(secret‖msg)` is forgeable by length extension; use HMAC.
- Every break this week left AES / SHA-256 intact — misuse, not a broken
  primitive. Naming the condition is the whole skill.

## Links

- Session A notebook — [`../../notebooks/week-03-symmetric-hashes.ipynb`](../../notebooks/week-03-symmetric-hashes.ipynb)
- Control Scorecard — [`../../resources/control-scorecard.md`](../../resources/control-scorecard.md)
- Ethics & scope — [`../../resources/ethics-and-scope.md`](../../resources/ethics-and-scope.md)
- Duel 1 (Crypto & Protocols, due week 5) folds in these studios — [`../../projects/duel-1-crypto.md`](../../projects/duel-1-crypto.md)

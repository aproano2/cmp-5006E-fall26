# Week 4 Studio — Breaking RSA Without Factoring

**Companion to** [`../../weeks/week-04.md`](../../weeks/week-04.md) — Session 4B.
**Time budget:** Recap 5 · Lab 45 · Demos 20 · Debrief 10 (80 min total).
**Deliverables:** all provided tests pass, a cost-vs-corpus-size note for the
shared-factor scan, and a Control Scorecard row for RSA and for secret-comparison.

> **Recap (5 min).** *To break RSA-2048 you do NOT factor it. Name two things you
> attack instead.* (Shared factors from weak RNG; timing side channels.)

RSA's guarantee rests on one clean assumption: **factoring `n` is hard**. This
studio builds RSA, then breaks it **twice without factoring a strong modulus** —
because real attacks target the conditions *around* the algorithm, not the math.
The math holds; the entropy assumption and the constant-time assumption don't.

Pure Python. No `seclab` import, no lab target, no Docker — this is a crypto week.

## Files in this folder

| File | Purpose | You edit it? |
|---|---|---|
| [`rsa_lab.py`](rsa_lab.py) | Given: RSA keygen/encrypt/decrypt, prime gen, `factor_from_shared`, and the timing oracle (`insecure_equal`, `make_oracle`, `time_guesses`) — verbatim from the notebook | ❌ |
| [`keys.json`](keys.json) | Given: 8 public moduli; exactly one pair shares a prime (weak-RNG sim, seed 1 — same values as the notebook) | ❌ |
| [`starter.py`](starter.py) | **Your tasks** — batch-GCD recovery, the timing attack, and the constant-time fix | ✅ |
| [`test_rsa.py`](test_rsa.py) | Provided tests, incl. the two *guarantee* tests | ❌ |
| [`_generate_keys.py`](_generate_keys.py) | Regenerates `keys.json` (only if you rotate the seed) | ❌ |

> ⏱️ **Runtime note.** `test_rsa.py` runs a real timing attack (two full
> 256-candidate scans). Budget **~1 second** on a modern laptop — not instant, not
> minutes. If it flaps, you are on a loaded machine; close other work and re-run.

## Task 1 — RSA by hand (10 min)

Read `rsa_lab.py`'s `rsa_keygen` / `encrypt` / `decrypt`. Run it:

```bash
python3 rsa_lab.py
```

Trace the reduction on the board with the tiny primes (61, 53): to get `d` you
need `φ`; to get `φ` you need the factorization of `n`. For a 2048-bit `n` that is
infeasible — **provided** `p` and `q` were good. The next two tasks show what
happens when they weren't, and when the implementation leaks.

## Task 2 — Shared-factor attack (batch-GCD) (15 min)

Open `starter.py`, implement `batch_gcd_recover(corpus)`. You are given 8 public
keys. Any one of them looks fine. But two were generated on a device with poor
boot-time entropy and **share a prime** — and `gcd(n_i, n_j)` reveals it
*instantly*, no factoring. This is the *Ps and Qs* attack (Heninger et al. 2012),
which factored ~0.2% of live TLS keys.

- Pairwise-GCD scan the corpus; any pair with `gcd != 1` shares a prime.
- Recover `d` for **both** keys of that pair (`factor_from_shared` in `rsa_lab`).
- Return `{index: d}` for the vulnerable keys only.

```bash
python3 starter.py        # smoke test: prints the recovered indices
python3 test_rsa.py
```

**The guarantee test** — `test_shared_factor_recovers_both_keys` — asserts *both*
keys fall from one scan. Each key's guarantee ("infeasible to factor `n`") is true
**in isolation** and false **across a population**. Watching an "each-key-is-fine"
guarantee fail at population scale is the point of the week.

Fast-finishing pairs: **how does the scan's cost grow with corpus size?** Naive
pairwise is O(k²) GCDs; the real attack uses a product/remainder tree to do it in
near-linear time over *millions* of keys. Be able to say in one sentence why the
internet-wide scan was still cheap.

## Task 3 — Timing side channel + the fix (15 min)

Even with perfect keys, variable-time code leaks. `insecure_equal` returns at the
first mismatched byte, so its **duration reveals how long a prefix matched**.
Implement, in `starter.py`:

- `timing_attack(secret_len, oracle, rounds=41)` — recover the secret one byte at a
  time. For each position, time all 256 candidates with `time_guesses` (it
  *interleaves* candidates so CPU drift can't bias one of them — read its
  docstring), and keep the **slowest** byte: the correct one matches one extra
  position before the early exit.
- `constant_time_equal(a, b)` — the fix. Examine **every** byte regardless of
  mismatches, so the duration carries no information. (In real code, call
  `hmac.compare_digest` — never hand-roll this in production.)

**The guarantee test** — `test_constant_time_defeats_timing_attack` — runs the
*same* attack against your constant-time compare and asserts it recovers nothing.
The algorithm didn't change; the *condition* (constant time) did.

Note in your write-up **how many rounds** you needed for a stable signal — timing
is noisy, and the median-over-interleaved-rounds is what makes it work.

## Task 4 — Control Scorecard (5 min)

For **RSA** and for **secret comparison**, fill a Control Scorecard row: state the
guarantee (axis 2) and the *condition outside the algorithm* it depends on, with
your evidence from Tasks 2–3.

| Control | Guarantee | Its condition (what the algorithm can't enforce) |
|---|---|---|
| RSA-2048 | infeasible to factor `n` | `p, q` from good entropy, chosen independently |
| any secret compare | — | constant time, or it leaks |

## Demos (20 min)

- Prioritize a pair who **scaled the shared-factor scan** to a larger generated
  corpus, and a pair who **characterized measurement noise** in the timing attack
  (how many rounds until the signal was stable? what made it flap?).
- Solicit: *did anyone's constant-time "fix" still leak?* A lingering early-exit
  (e.g. the length check, or a `break`) is a live debugging moment.

## Debrief (10 min)

- RSA's security is **conditional** on good, independent primes. Weak RNG → shared
  factors → instant key recovery by GCD. This was a real, measured, internet-wide
  finding — not a toy.
- Timing is a first-class attack surface. Variable-time secret handling leaks;
  square-and-multiply modular exponentiation leaks key bits the same way.
- ⚠️ The recurring pattern of the crypto unit, sharpest here: **the algorithm's
  guarantee is conditional on things the algorithm can't enforce.** Attackers break
  the conditions, not the math. Name the condition (week 1's move) and you've found
  the attack surface.
- **Duel 1 (crypto & protocols) is due end of week 5** — this week's shared-factor
  and timing attacks are exactly the implementation flaws it rewards you for finding.

## Links

- Session 4A notebook — [`../../notebooks/week-04-asymmetric-sidechannels.ipynb`](../../notebooks/week-04-asymmetric-sidechannels.ipynb)
- Control Scorecard — [`../../resources/control-scorecard.md`](../../resources/control-scorecard.md)
- Ethics and scope — [`../../resources/ethics-and-scope.md`](../../resources/ethics-and-scope.md)
- Duel 1 spec — [`../../projects/duel-1-crypto.md`](../../projects/duel-1-crypto.md)
- Reading — Heninger et al. (2012), *Mining Your Ps and Qs*

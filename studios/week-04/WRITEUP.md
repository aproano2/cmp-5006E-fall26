# Week 4 Studio — Breaking RSA Without Factoring

Code: [`starter.py`](starter.py) (Tasks 2–3). All six provided tests pass.

```bash
cd studios/week-04
python3 rsa_lab.py        # Task 1: RSA by hand
python3 test_rsa.py       # 6/6 pass, ~2.3 s
```

Measurements below: single core, Python 3.14.3, Intel i5-6200U @ 2.30 GHz.

---

## Task 1 — RSA by hand

`rsa_keygen(61, 53, e=17)`:

| | |
|---|---|
| `n = p·q` | 3233 |
| `φ = (p−1)(q−1)` | 3120 |
| `d = e⁻¹ mod φ` | 2753 (17 · 2753 = 46801 = 15·3120 + 1) |
| `encrypt(42)` | 2557 → `decrypt` → 42 |

The reduction, concretely: `d` needs `φ`, and `φ` needs `p` and `q`. Give the
factorization away and `d` falls out — `factor_from_shared(3233, 61, e=17)` returns
the same 2753 without ever seeing the private key. For a 2048-bit `n` that step is
infeasible **provided `p` and `q` were good**. Tasks 2 and 3 never attempt it.

## Task 2 — Shared-factor attack (batch-GCD)

`batch_gcd_recover` scans all `k(k−1)/2` pairs; `math.gcd(n_i, n_j) != 1` means the
pair shares a prime, and `factor_from_shared` turns that prime into `d` for **both**
moduli — division, not factoring.

| | |
|---|---|
| Corpus | 8 public keys, 128-bit `n` (64-bit primes), `e = 65537` |
| Pairs scanned | 28 |
| Hits | 1 pair → indices **0 and 4** |
| Shared prime | `17324573639174612641` (64-bit) |
| Verified | both recovered `d` round-trip `encrypt`/`decrypt` (test asserts it) |
| Safe keys | 6, `gcd = 1` with everyone, none recovered |

Each of those two keys is fine **in isolation**: nothing about `n₀` alone is
factorable. The guarantee fails only across the **population**, and the attacker is
the only party who ever looks at the population. The victim cannot detect this by
auditing their own key.

### Cost vs corpus size

Naive pairwise is `k(k−1)/2` GCDs. Measured on random odd integers of the stated
width (GCD cost depends on operand size, not primality):

| k | pairs | seconds | µs/GCD |
|---|---|---|---|
| 8 (studio, 128-bit `n`) | 28 | 0.000059 | 2.1 |
| 64 (2048-bit) | 2 016 | 0.080 | 39.8 |
| 128 | 8 128 | 0.325 | 39.9 |
| 256 | 32 640 | 1.284 | 39.3 |
| 512 | 130 816 | 5.025 | 38.4 |
| 1 024 | 523 776 | 20.87 | 39.8 |
| 2 048 | 2 096 128 | 85.73 | 40.9 |

Clean quadratic: ×32 in `k` (64 → 2048) gives ×1068 in time, against ×1024
predicted. The µs/GCD column is flat, so the growth is entirely the pair count.

Extrapolating at 40.9 µs/GCD to **10⁷ keys** (the order of the Heninger et al.
scan): ≈ 5·10¹³ GCDs ≈ 2.0·10⁹ s ≈ **65 CPU-years**. That is why nobody runs the
naive scan.

**Why the internet-wide scan was still cheap, in one sentence:** the real attack
never does pairwise GCDs — it builds a product tree of all moduli and a remainder
tree back down, computing every key's GCD-against-all-others in `O(k log²k)`, which
turns 65 CPU-years into hours on one machine.

## Task 3 — Timing side channel + the fix

`timing_attack` recovers the secret one byte at a time. Guesses are always
**full length** (`insecure_equal` rejects a length mismatch before the timed loop
ever runs), and each position times all 256 candidates through `time_guesses`,
which interleaves them so CPU drift hits every candidate equally. The correct byte
matches one extra position before the early exit, so it is the **slowest**.

`constant_time_equal` accumulates `x ^ y` over every byte and returns
`diff == 0` — no `break`, no early `return` inside the loop.

### Signal separation (position 0, secret `a5 3c`, rounds = 41)

| Candidate | Median time |
|---|---|
| correct byte `a5` | **314.2 µs** |
| wrong bytes, median | 0.9 µs |
| wrong bytes, loudest | 3.3 µs |

The correct byte stands **310.9 µs clear** of the loudest wrong one — ~95×. One
extra matched position means one extra `AMPLIFY = 12000` busy loop, and that is the
entire signal.

### How many rounds for a stable signal

8 attack runs per row, against the early-exit oracle:

| rounds | full secret recovered | bytes correct | s/attack |
|---|---|---|---|
| 1 | 0/8 | 6/16 | 0.09 |
| 3 | 1/8 | 9/16 | 0.50 |
| 5 | 2/8 | 10/16 | 0.30 |
| 9 | 5/8 | 13/16 | 0.57 |
| **17** | **8/8** | **16/16** | 0.95 |
| 25 | 8/8 | 16/16 | 1.45 |
| 41 | 8/8 | 16/16 | 2.30 |

**17 rounds** is where it becomes reliable here; the default 41 is ~2.4× more than
needed and buys margin on a loaded machine. Note that even 1 round gets 6/16 bytes
right — far above the 0.06/16 expected from guessing — so the signal is present
immediately; what the median over interleaved rounds buys is *not detecting* the
leak but **not being wrong on any single position**, and a 2-byte secret needs every
position right at once.

### The fix, tested

Same attack, same rounds, constant-time oracle — 5 runs recovered
`2201`, `2350`, `23d6`, `0048`, `50d6`. None is `a53c`; the bytes are noise. The
algorithm did not change, the *condition* did.

## Task 4 — Control Scorecard

| Control | Guarantee (axis 2) | Its condition — what the algorithm can't enforce | Evidence | Primitive break or misuse? |
|---|---|---|---|---|
| **RSA-2048** | infeasible to recover `d` from `(n, e)`, because that needs `φ`, which needs the factorization of `n` | **`p` and `q` drawn from good entropy and chosen independently of every other key ever generated.** Holds per key; a population-wide condition no single key-holder can check. Violated → one GCD, no factoring | Task 2: keys 0 and 4 of 8 fell from 28 GCDs in 59 µs; shared prime `1732…2641`; both recovered `d` verified by round-trip | **misuse** — the modulus was never factored; the RNG failed |
| **secret comparison** | none on its own. `insecure_equal` is a *correct* equality test and promises nothing about duration | **constant time**, or the duration itself is an oracle. Nothing in "compare two byte strings" implies it | Task 3: 310.9 µs separation on the correct byte, secret recovered 8/8 at 17 rounds with no read access; same attack recovers noise against `constant_time_equal` | **misuse** — no primitive involved at all, just a `return` in a loop |

Both failures are conditions, not mathematics. Consistent with week 3, where 4 of 4
were misuses.

## Where we may have been unfair, and what we did not test

- **`AMPLIFY = 12000` is a synthetic amplifier, and it does most of the work.** It
  turns a per-byte delta that would be nanoseconds into 311 µs, ~95× above our
  noise floor. A real early-exit `memcmp` differs by a handful of nanoseconds per
  byte — under local scheduler jitter, and orders of magnitude under network
  jitter. We demonstrated the attack's **mechanism**, not its **feasibility**. Our
  "17 rounds" does not transfer to anything real; remote timing attacks need
  millions of samples and statistical tests, or a co-resident attacker.
- **The attacker was handed `secret_len` for free.** `timing_attack(secret_len, …)`
  takes the length as a parameter. Recovering it is a separate attack — and our own
  `constant_time_equal` leaks it, because `if len(a) != len(b): return False`
  early-exits on length. We never tested that leak, and the provided tests never
  feed a wrong-length guess, so our "fix" has an untested hole the test suite is
  structurally blind to.
- **`constant_time_equal` is constant-time only at the Python level.** We never
  verified it on the machine: CPython's small-int cache, branch prediction, and
  memory access patterns are all still data-dependent. `hmac.compare_digest` exists
  because hand-rolling this is not reliable, which is exactly why the README says
  never to ship ours.
- **The corpus is rigged and we were told so.** Exactly one sharing pair among 8
  keys, with `_ground_truth` in the file. The real scan had no oracle confirming a
  pair existed, faced a ~0.2% hit rate, and its hard part was the scale — which we
  never faced. Our 28-pair scan is the easy 1% of that problem.
- **The cost extrapolation is weak where it matters.** Random odd integers, one
  core, one laptop, no parallelism, and it extrapolates a naive algorithm that the
  real attack never used. The 65-CPU-year figure is an upper bound on a strawman;
  we did not implement the product/remainder tree, so we never measured the number
  that actually explains the result.
- **`gen_prime` uses a Fermat test.** Carmichael numbers pass it, so a "prime" in
  our corpus may be composite. That would break `factor_from_shared`'s φ, not the
  GCD. We did not check, and the round-trip test would not necessarily catch it.
- **Not tried for lack of time**: timing square-and-multiply modular exponentiation
  to leak bits of `d` directly (the deck's other example), and any attempt to defeat
  the interleaving in `time_guesses` — we used the defense-friendly measurement
  harness the studio provided and never asked whether a weaker one would still work.

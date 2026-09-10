# Week 2 Studio Results

## Task 1 — Entropy and unicity

Week 1's frequency attack succeeded because the message was hundreds of
characters long, far beyond the substitution cipher's unicity distance of about
27.6 characters, so English redundancy constrained the ciphertext enough to pin
down a unique key.

The break would become ambiguous below approximately 28 characters because
multiple substitution keys could still produce plausible English plaintexts.

The implementation computes the substitution keyspace as `26!`, passes that
integer to `entropy_bits`, and then passes the resulting key entropy to
`unicity_distance`:

```python
N = math.factorial(26)
H_K = entropy_bits(N)
U = unicity_distance(H_K)
return H_K, U
```

This produces `H_K = 88.38195332701626` bits and
`U = 27.61936041469258` characters. `math.factorial(26)` gives the number of
permutations of the alphabet. `entropy_bits(N)` computes `log2(N)`, the number of
bits needed to distinguish uniformly chosen keys. `unicity_distance(H_K)` divides
the key entropy by the default English redundancy of 3.2 bits per character.

## Task 2 — One-time-pad perfect secrecy

`key_that_decrypts_to` returns `ciphertext XOR decoy_plaintext`:

```python
return xor(ciphertext, decoy_plaintext)
```

XOR is its own inverse. If `K_decoy = C XOR P_decoy`, then decrypting gives
`C XOR K_decoy = C XOR C XOR P_decoy = P_decoy`. Therefore, for every candidate
plaintext of the correct length, a corresponding key exists. A ciphertext by
itself cannot distinguish the real plaintext from the decoy, even if the attacker
has unlimited computing power.

## Task 3 — Two-time-pad break

The attack begins by XORing the intercepted ciphertexts:

```text
x = c1 XOR c2
  = (p1 XOR K) XOR (p2 XOR K)
  = p1 XOR p2
```

The two copies of `K` cancel because `K XOR K = 0`. This exposes a relationship
between the plaintexts without recovering the key first.

### Crib-drag implementation

`crib_drag` stores the crib length once, checks every position where the complete
crib fits, XORs the crib with that slice of `x`, and retains only fragments accepted
by `printable_word`:

```python
crib_len = len(crib)
hits = []
for i in range(len(x) - crib_len + 1):
    fragment = xor(x[i:i + crib_len], crib)
    if printable_word(fragment):
        hits.append((i, fragment))
return hits
```

The `+ 1` in the range includes the final valid starting position. At the correct
position, a crib taken from one plaintext cancels that plaintext's bytes in
`p1 XOR p2`, revealing the bytes from the other plaintext. The readability filter
only identifies candidates; short accidental lowercase fragments remain possible
and must be checked using context and overlapping cribs.

### Cribs, positions, and chaining

| Crib | Position | Fragment revealed from the other message | Use in the chain |
|---|---:|---|---|
| `please` | 0 | `the la` | Establishes the start of message 2 and suggests that message 1 begins `the launch...`. |
| `the launch` | 0 | `please wat` | Confirms the first guess and extends message 2 toward `please water...`. |
| `launch code` | 4 | `se water my` | Overlaps both earlier fragments and confirms `please water my...`. |
| `target` | 38 | `t whil` | Places `target` in message 1 and exposes the middle of message 2's `cat while...`. |
| `while i am away` | 40 | `rget is the nor` | Confirms the overlap with `target is the north...` in message 1. |
| `north bridge` | 52 | `way for the ` | Extends message 2 to `away for the...`. |
| `weekend` | 64 | ` tonigh` | Reveals the end of message 1 and suggests `tonight`. |
| `tonight` | 65 | `eekend ` | Confirms the truncated end of message 2 as `weekend `. |

The raw short-crib results also contain false positives. For example, `please`
at position 48 produces `ei  jk`, and `target` at position 65 produces `ekwklx`.
They pass the lowercase-and-space filter but do not form sensible overlapping
English, so the chain rejects them.

Alternating cribs between the two sides and extending only mutually consistent
overlaps reconstructs the two 72-byte plaintexts:

```text
p1 = the launch code is four seven two the target is the north bridge tonight
p2 = please water my plants and feed the cat while i am away for the weekend<space>
```

The final space in `p2` is significant: the provided ciphertext pair contains the
messages truncated to their common length of 72 bytes.

### Full recovery implementation

Once one full plaintext has been reconstructed, `recover_other_plaintext` first
derives the reused keystream and then decrypts the second ciphertext:

```python
keystream = xor(c1, p1_known)
return xor(c2, keystream)
```

Because `c1 = p1 XOR K`, calculating `c1 XOR p1_known` produces `K` when the
plaintext guess is correct. XORing `c2` with that keystream gives
`(p2 XOR K) XOR K = p2`. The provided `xor` helper uses `zip`, so both XOR
operations naturally stop at the shortest input; in this function that limits the
result to the known plaintext/derived-keystream length.

## Task 4 — Control Scorecard: one-time pad

| Axis | Before | After control | Evidence |
|---|---|---|---|
| Guarantee | No confidentiality for plaintext sent directly. | **Perfect secrecy:** the ciphertext is statistically independent of the plaintext, even against an attacker with unbounded computing power, **provided** the key is uniformly random, at least as long as the message, kept secret, and used exactly once. | `test_otp_perfect_secrecy_when_key_used_once`: one ciphertext decrypts to two different meaningful messages under two corresponding keys. |
| Failure mode | — | Reusing a key causes catastrophic and potentially silent loss of confidentiality: `c1 XOR c2 = p1 XOR p2`, enabling crib-dragging and complete plaintext recovery. | `test_two_time_pad_leaks_and_crib_drag_recovers` and the crib chain above. |

Essentially nobody deploys a one-time pad for ordinary communication because key
distribution is as hard as securely distributing the message itself: participants
must securely generate, exchange, store, track, and destroy uniformly random secret
key material at least as long as every plaintext they exchange.

## Where we may have been unfair, and what we did not test

The exercise uses lowercase English plaintexts and helpful, topic-relevant cribs,
so the readability filter and human language guesses have an advantage that may
not exist for compressed, encoded, multilingual, or binary plaintext. It does not
measure the effort needed to recover the messages without any initial crib, nor
does it evaluate secure random-key generation, key distribution, key storage, or
reliable prevention of reuse. The test demonstrates the algebraic leak and one
complete recovery on the provided pair; it does not claim that every reused-key
pair is equally easy to turn into readable plaintext.

## Verification

Running `python3 test_otp.py` reports:

```text
ok  substitution 88.4 bits > DES 56 bits (yet broke first)
ok  unicity U = 27.6 chars (why week 1's long message pinned the key)
ok  OTP used once: one ciphertext -> two meaningful messages (unbreakable)
ok  two-time pad LEAKS p1 XOR p2; crib-drag recovers both plaintexts

all 4 tests pass
```

# Part C — Where our breaks or design might be unfair

Six honest self-critiques. The first three are about the breaks; the last three
are about the SECS design, covering all four prompts in the assignment.

## 1. Break #4's *forgery* is certain, but its *escalation* rests on an unmodelled parser

`verify_token` only checks the tag — and our forged tag verifies, with certainty,
without the secret. That part is airtight. But the privilege escalation claim
assumes the application parses `user=alice&role=user\x00\x00\x00&role=admin` with
**last-value-wins** semantics. The target never specifies the parser. If it takes
the *first* `role=`, our token authenticates but still reads `role=user`, and the
escalation fails even though the MAC is forged. We are confident in the crypto
break; we are importing an assumption the deployment didn't actually state for the
*impact*. (A real attacker would also try a leading `&role=admin&` and padding
variants.)

## 2. Break #2 recovers equivalence classes with no key, but *naming* the admins imports a crib the deployment didn't give

The key-free, fully-confirmed result is structural: records 0 and 2 are
byte-identical in their role+dept blocks, and 1 and 3 share the role block. That
is a genuine confidentiality break. But our headline — "alice and carl are
admins" — needs one labelled record, and `ecb_store` exposes **no labelling or
chosen-plaintext oracle**. We supplied that label ourselves (`record 0 ==
admn:engr`). So the naming step is conditional on an external datum an attacker
would have to obtain separately; without it we know *that* two employees match,
not *what* they are. We flagged this in the script rather than overclaiming.

## 3. Break #6's "5 trials/byte" is the number we are *least* confident reproduces

The timing attack is the noisiest break, and the reported threshold is
machine-, load-, and run-dependent. It verified at 5 trials/byte **on an idle
laptop, against a target with a 4000-iteration amplifier** that inflates the
per-byte signal to ~15–20 µs. Three honest caveats: (a) on a busy machine, median
jitter can exceed that margin and the recovery needs far more trials or picks a
wrong byte; (b) without the amplifier the signal would be sub-microsecond and
likely unrecoverable from Python; (c) **over a network**, scheduling and transport
jitter would almost certainly swamp the margin, so the "5" says nothing about a
remote attack. The *existence* of the leak is certain (the oracle confirms exact
recovery); the *cost* is the soft number. Break #1's crib list is the only other
semi-manual step, but it is self-validating (a wrong crib is rejected across all
four ciphertexts), so its reproducibility for this fixed `SEED` is not in doubt —
only its generality to a different message set.

## 4. The SECS design hand-waves the CA — and goals #1–#3 are only as strong as it

Non-repudiation of origin and receipt all carry the condition "provided the CA did
not mis-issue". We never specify *how* the CA authenticates an identity before
issuing a cert, how revocation is checked (OCSP/CRL), or how a judge establishes
that a signing key was valid **at signing time** rather than later revoked. That
last point quietly leans on the TSA: without a trusted timestamp, "the key was
valid when Alice signed" is itself disputable. A mis-issued cert, a stolen key
used before its revocation propagates, or an unavailable OCSP responder each
breaks a guarantee we stated as holding. The CA root's distribution is assumed
out-of-band and trusted — an unexamined trust anchor.

## 5. Phase-3 fairness assumes an honest, available TTP — a single point we only sketch

Non-repudiation of receipt for the *final* copy leans on the TSA `T` when a party
aborts. We assumed `T` is honest and available. A `T` that colludes with Alice,
back-dates a token, or is simply offline when Bob needs it reopens the unfair
window the protocol was meant to close. True fair exchange without *any* trusted
party is known to be impossible for deterministic two-party protocols, so some
trust is unavoidable — but we did not analyse what happens when `T` misbehaves,
only when it behaves. We also did not specify `T`'s dispute SLA or how `A` is
notified, which matters for liveness.

## 6. The design trades auditability (and recoverability, and deniability) for confidentiality

Named trade-offs:

- **Confidentiality vs. auditability.** Because the terms `C` are end-to-end
  encrypted and `T` sees only `H(C)` and signatures, a regulator or auditor
  **cannot inspect the contract** without a party volunteering `C`. We optimised
  for secrecy at the cost of third-party oversight — the opposite choice some
  compliance regimes require.
- **Forward secrecy vs. recoverability.** Erasing the ephemeral DH secrets means a
  party who later loses its copy of `C` **cannot** reconstruct it from captured
  traffic. Good for secrecy, bad for disaster recovery.
- **Non-repudiation vs. privacy/deniability.** Signatures are permanent,
  transferable evidence, so the signed bundle proves Bob's dealings **forever** to
  anyone who later obtains it. A protocol built for non-repudiation is by
  construction the opposite of deniable — a cost if the contract's *existence* is
  itself sensitive.

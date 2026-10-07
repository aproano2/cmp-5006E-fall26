# Part C: Where our breaks or design might be unfair

## 1. Breaks #1 and #3 assume a known plaintext the deployments never granted

Both the two-time pad and the CTR nonce-reuse recovery finish with a
known-plaintext crib: in #1 we complete one message and use it as the pad; in #3 we
assume the attacker can generate one log line (a forced `bob00` login) and knows it
exactly. The deployments do not state the attacker has any plaintext. Two points in
our defense. First, space-anchoring recovered the skeleton of every message in #1
with zero known plaintext, so the completed message is a well-justified guess rather
than a gift, and the target module's own `--check` uses the same crib assumption.
Second, the log format is fixed and public, and forcing a failed login is realistic.
The assumption is still real: if the messages were high-entropy tokens instead of
English, or if we could not induce a known log line, the crib step would not start.

## 2. Two bytes were not cryptographically recovered, only guessed

We are least confident about the single under-constrained column in each XOR break.
In #1 the final byte of the target is reached by only the longest message, so no
cross-message vote exists; we set it from English context (`...o?` resolves to `ok`).
In #3 the final IP-octet digit is likewise unreachable and we left it as `?`. Neither
is a cryptographic recovery. The material artifacts (the launch-authorization
sentence, the `user=admin action=export` line) are fully recovered, but we flag these
two bytes rather than claim them.

## 3. The timing break's signal is synthetic and machine-conditional

Break #6 recovered the secret 3 of 3 times, but that reliability is conditional on a
quiet, local machine and on the target's artificial 4000-iteration amplifier. Real
early-exit comparisons leak tens of nanoseconds, not the microseconds we measured
here, and over a network the jitter would swamp the per-byte signal. Our min-of-500
statistic works because the amplifier dwarfs local noise; we did not demonstrate the
attack under realistic conditions, and we cannot claim a given trial count without
re-measuring on the target host. "Works 3/3 here" is an honest and narrow claim, not
"this attack is reliable in general."

## 4. Break #4's privilege escalation assumes a parser the deployment never specified

The length-extension forgery is unconditional: `verify_token` accepts a tag we built
without the 9-byte secret. The escalation is not. Our forged data contains both
`role=user` and `role=admin`, so it only grants admin if the server resolves a
duplicate `role=` key to the last occurrence. `issue_token` defines the token format
but not how the server parses it, so this last-value assumption is ours, not the
deployment's. A first-value or reject-duplicates parser would read `role=user` and
the escalation would fail. The forgery would still be a genuine integrity break, but
not a privilege gain.

## 5. The SECS design hand-waves a trusted CA, a trust anchor, and fair exchange

Every non-repudiation guarantee is conditional on a CA that does not mis-issue and on
private keys that stay uncompromised, and we assume both. We also assume a secure
out-of-band channel to distribute and pin the CA root (the week-5 trust-store lesson
turned inward). The real hole we did not close is fair exchange: in steps (5) and (6),
a party who aborts after receiving the co-signed `C` but before sending their receipt
gets non-repudiation of origin while denying the other non-repudiation of receipt. A
correct fix needs a trusted notary or TTP, or an optimistic fair-exchange protocol;
we specified neither.

## 6. The design trades confidentiality (forward secrecy) against auditability

By discarding the ephemeral ECDHE keys we get forward secrecy, but a later auditor
holding the recorded ciphertext cannot decrypt the transit logs. Long-term proof
rests entirely on the retained signatures and `C`, not on the wire traffic; the GCM
tags prove integrity only to the two endpoints at the time, not to a third party
afterward. This is a deliberate trade: stronger confidentiality in transit, weaker
after-the-fact decryptable audit trail. We chose the former and name the cost.

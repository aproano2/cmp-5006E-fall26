# Where our breaks or design might be unfair

## 1. Did a break rely on an assumption the deployment didn't actually make?

Partly, in two places:

- **Break #1 (`reused_pad`):** the deployment's docstring says the four
  messages "are all English," which is a fair assumption to exploit. But our
  recovery of the **very last byte** of the target message is not forced by
  the ciphertexts at all — that column is covered by only one message, so
  no XOR relationship constrains it. We picked the letter `k` (completing
  "...courier ok") because it's the only plausible way to finish an English
  sentence there, not because the attack derived it. We flag this
  explicitly in the script's output rather than silently presenting a fully
  "solved" plaintext — the honest claim is "recovered except one
  context-filled byte," not "recovered."
- **Break #3 (`ctr_log`):** the same gap appears, more severely — one
  trailing digit of an IP address is never covered by the known-format
  lines we used as cribs, and the log's own field format (`from=10.0.0.X`)
  narrows it to one of ten digits, not to a single value. We report the
  recovered line with that digit left as `?`, rather than guessing and
  presenting a guess as a recovered fact.

In both cases the *underlying* vulnerability (key/nonce reuse → the keys
cancel under XOR) is real and fully demonstrated; what's honestly uncertain
is only the last few bits of *this particular* target string.

## 2. Is SECS's guarantee conditional on something we hand-waved?

Yes, in at least three places, beyond what §3 of `secs-design.md` already
states as conditions:

- **The CA is trusted, not verified.** We assume enrollment ("prove you are
  Alice, here is your key") happens correctly and out of band, and that the
  CA never mis-issues a certificate. We do not design, or even sketch, how
  the CA itself authenticates Alice and Bob before issuing — that's a whole
  separate (and classically hard) problem we've pushed outside the diagram's
  trust boundary rather than solved.
- **Non-repudiation of receipt is weaker than the name suggests** — we say
  this plainly in the design doc's axis-2 statement, but it's worth
  repeating here: SECS gives non-repudiation of a *completed* receipt, not
  fairness. A two-party signed-ACK protocol like ours cannot, on its own,
  stop Bob from reading the contract and then simply never sending `Sig_B`.
  Fixing that for real requires a trusted third party or a gradual-release
  scheme — a known hard problem in the fair-exchange literature, not an
  oversight we can patch with one more signature.
- **Endpoint security is entirely out of scope.** Every guarantee assumes
  Alice's and Bob's private keys are never exposed on their own machines.
  If either device is compromised, every axis-2 guarantee in §3 of the
  design doc is vacuous — we name the condition but do nothing to enforce
  it.

## 3. Which of our breaks are we least confident are reproducible?

**Break #6 (`timing_compare`), clearly.** It is the only break that depends
on wall-clock measurement rather than pure math, and our own script shows
this concretely: at our chosen trial count, 2 of 3 independent full
recovery runs succeeded; at a much smaller batch size, the same method
failed outright. On a different machine — especially a multi-core host
under real load, or a cloud VM with a noisier scheduler — these counts
would need to be retuned, possibly significantly. We consider the *existence*
of the side channel fully demonstrated (the timing difference between a
matching and non-matching byte is large and consistent — tens of
microseconds against a near-zero baseline), but the exact "how many trials
needed" number is an artifact of this specific environment, not a universal
constant, and we say so rather than reporting only our best run.

Secondarily, **Break #1's** dictionary-repair step leans on a closed
vocabulary list built from the specific four messages in this deployment.
It would not generalize as-is to English text outside that topic area — a
limitation worth naming even though the core two-time-pad attack it
sits on top of is general.

## 4. Does our design trade one goal for another?

Yes — **non-repudiation versus long-term confidentiality.** The whole point
of non-repudiation is that `(contract, Sig_A, Sig_B)` can be shown to a
third party (a court, an arbitrator) later, by either party, without the
other's cooperation. But that is also exactly what breaks confidentiality
*as evidence*: the same bundle that proves the deal was made is a bundle
that reveals the deal's terms to whoever adjudicates it. Our axis-2
confidentiality claim is carefully scoped to "in transit" for this reason —
we are not claiming the contract stays secret forever, only that no one on
the network path between Alice and Bob can read it while it's being signed.
A design that wanted long-term secrecy *and* strong non-repudiation
simultaneously would need something like a commit-and-reveal scheme or
zero-knowledge proof of signature validity, which is a meaningfully
different (and harder) system than the one specified here.

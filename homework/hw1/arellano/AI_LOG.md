# AI use log: Homework 1 (Crypto & Protocols)

Group: Santiago Arellano, Isabela Tulcán, Martín Montero.
All work ran against the local, synthetic `duel1_targets.py`; no secrets or real data
were given to any assistant.

## 2026-10-06: Breaks and SECS design

**Who:** Martín Montero

**Tool:** Claude Opus 5.5.

**What I asked:** Read the `homework/hw1` instructions, the target module, the AI
policy, and the Control Scorecard, then help me build all six breaks, a break report
with the assumption and misuse classification per attack, the SECS design with an
axis-2 conditional per goal, and the honesty section. Code and comments in English,
no filler.

**What I got:** Six standalone Python attack scripts that call only the module's
public functions; a `breaks/README.md` with assumptions, recovered artifacts, misuse
labels and reliability notes; a `secs-design.md` with a message-flow diagram, trust
boundaries and a conditional guarantee for each of the four goals; and a `honesty.md`
with self-critiques.

**What I did with it / verification:** I ran the six scripts with Python 3.14 on
Linux; each exits 0 and prints its recovered artifact (the launch-authorization
sentence, the `user=admin action=export` log line, forged tag `4024164909`, shared
prime `14723961130838400979`, timing secret `83fabf35`). I dropped the first draft's
claim of full 70-byte pad/CTR recovery once I saw the last target byte has no
overlapping ciphertext, so the write-up now flags that byte as a guess, not a
recovery.

**Did I understand it?** Yes. The XOR in `reused_pad` and `ctr_log` cancels the
key/keystream, so `C_i ⊕ C_j = P_i ⊕ P_j`, and a known crib recovers plaintext only
over the length where the messages overlap. I can also explain why ECB leaks: it
encrypts equal plaintext blocks to equal ciphertext blocks, so the structure shows
through without any decryption. Writing the scripts and watching the last byte fail to
resolve is what made the overlap-length limit concrete for me.

**What I kept or rejected:** Kept the verified local artifacts and the conditional
claims. Rejected full-length recovery claims and any "confirmed admin access"
wording.

## 2026-10-06: Review and corrections

**Who:** Santiago Arellano

**Tool:** Claude Opus 5.5.

**What I asked:** Audit the completed folder against the full assignment and rubric,
check that every attack still produces its artifact, and flag anything that breaks the
"every guarantee is a conditional" rule.

**What I got:** A review that confirmed all six scripts run and use only public
outputs, that the four SECS goals are phrased as axis-2 conditionals, and that one
rigor gap was left: the token break claimed admin escalation unconditionally.

**What I did with it / verification:** I re-ran the six scripts (all exit 0) and fixed
the token break myself. The forgery is unconditional, since `verify_token` accepts a
tag I built without the secret, but the escalation only holds if the server resolves
the duplicate `role=` key to the last value, so I added that condition to the script,
the README and the honesty section. I also confirmed the RSA break recovers a private
key from the public moduli by pairwise GCD (the product-tree batch-GCD is the same
idea at fleet scale) and checked it with a `42 → 42` round trip.

**Did I understand it?** Yes. Signing a receipt before verifying the returned final
package would break non-repudiation of receipt, which is why our flow verifies first.
For the RSA break, a shared prime means `gcd(n_i, n_j) > 1`, and that single GCD
factors both moduli and proves the key generation ran out of entropy. Tracing the
duplicate-`role=` case by hand is what convinced me the forgery and the escalation are
two separate claims.

**What I kept or rejected:** Kept the escalation-condition correction and the
misuse-vs-primitive labels. Preserved the note that the assignment and starter README
give different submission paths, instead of guessing which one is current.

## 2026-10-06: Rubric validation and honesty refinement

**Who:** Isabela Tulcán

**Tool:** Claude Opus 5.5.

**What I asked:** Validate the three documents against the rubric step by step, and
help me clean the prose so the answers are clear and direct, without dense jargon or
filler.

**What I got:** A step-by-step check confirming the scripts output their artifacts,
the six attacks are labeled as misuses, and the SECS guarantees are axis-2
conditionals, plus suggestions to tie the honesty section to our real console output
rather than generic claims.

**What I did with it / verification:** I rewrote the three documents for clarity and
cut the AI-writing tells. I confirmed the empirical points myself: the timing break
recovers `83fabf35` using the minimum of 500 trials per byte (about 1.5 M timed calls
over three rounds, reliable 3 times out of 3), and the instructor's own `--check`
fails on the timing case on our machine because it runs only 41 trials, which is
exactly the fragility we claim.

**Did I understand it?** Yes. I can state the difference between mathematically forging
a MAC and actually escalating privilege in an application, and I understand the
fair-exchange gap in our SECS design: cryptography alone cannot force Bob to send a
receipt, so that guarantee needs a trusted third party. Rewriting the honesty section
made me check each claim against what the scripts actually printed, which is where I
caught the wording that overstated the pad recovery.

**What I kept or rejected:** Kept the clearer, jargon-free wording and the note about
the instructor's `--check` failing locally. Rejected any unconditional security claim.

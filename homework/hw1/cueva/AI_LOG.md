# AI use log — Homework 1

## 2026-09-29 — Crypto duel and SECS design

**Who:** Jorge Gomez

**Tool:** OpenAI Codex (GPT-6).

**What we asked:** Review the files in `HomeWork1` in detail, complete the work requested in the Markdown instructions, write the solutions and scorecard notes in English, and save all results locally.

**What we got:** Six Python attack scripts; a break report with assumptions, artifacts, misuse classifications, conditional control statements, and reliability notes; a SECS design with a message flow and conditional claims for all four goals; and an honesty section. Codex also read the course's local AI policy, ethics document, and Control Scorecard.

**What we did with it / verification:** We ran the scripts against the provided local `duel1_targets.py` and revised the initial pad/CTR claims after noticing that the final target byte has no overlapping ciphertext. We revised the timing script after initial noisy failures and ran the successful version repeatedly. The token claim was narrowed to a valid forged token because no application authorization parser exists. These files remain local; no pull request was made.

**Did we understand it?** Yes. We understand that the XOR operations in the `reused_pad` and `ctr_log` attacks cancel out the key/keystream, allowing us to recover the plaintext if we have a known crib, but strictly limiting recovery to the overlapping length. We also understand how ECB mode deterministically encrypts identical plaintext blocks into identical ciphertext blocks, leaking structural equality. For the MAC token, we grasped that a naive hash allows a length extension attack because the signature acts as a valid internal state to continue hashing. Finally, we understand that timing attacks exploit early-return conditionals by measuring side-channel latency.

**What we kept or rejected:** Kept verified local artifacts and conditional claims. Rejected claims of full 70-byte pad/CTR recovery, confirmed admin access, and unconditional non-repudiation of receipt.

## 2026-10-06 — Review and corrections

**Who:** Santiago Reátegui

**Tool:** OpenAI Codex (GPT-6).

**What we asked:** Review the completed Homework 1 folder against the full assignment, correct the issues found, and check that the attack scripts still produce their claimed artifacts.

**What we got:** A review identified that Alice's receipt was signed before she received the final package back, that the RSA attack used pairwise GCD rather than batch-GCD, and that local assignment/resource links and submission paths were inconsistent.

**What we did with it / verification:** Changed the SECS flow so Bob returns the same final package with his signed receipt and Alice signs her receipt only after verifying that returned package. Changed the RSA script to batch-GCD over the fleet's public moduli, fixed local links, and documented the conflicting submission paths. We ran all six attack scripts with Python 3.14.7 on Linux; each exited successfully. The timing script recovered `83fabf35` in 200,246 oracle calls, with the third byte ranked third. We reviewed the remaining document and link changes by inspection.

**Did we understand it?** Yes. We realized that signing a receipt before actually receiving the validated final package breaks the non-repudiation of receipt condition. For the RSA attack, we understand that Batch-GCD is much more efficient: by multiplying all public moduli into a single fleet product, we can isolate a shared prime ($p$) using the Greatest Common Divisor against each individual modulus, proving the lack of entropy during key generation.

**What we kept or rejected:** Kept the receipt-order correction and batch-GCD change. Preserved the submission-path discrepancy for confirmation against the course's authoritative instructions instead of guessing which path is current.

## 2026-10-06 — Final Rubric Validation & Honesty Clause Refinement

**Who:** María Emilia Cueva

**Tool:** Gemini.

**What we asked:** Review the completed Homework 1 files (attack scripts, SECS design, and honesty section) step-by-step against the rubric to validate correctness. We also asked for a conceptual breakdown of the mathematical attacks in simple terms to verify our understanding, and help refining our Honesty Clause to remove overly dense jargon.

**What we got:** A step-by-step conceptual validation confirming our scripts successfully output the artifacts, the six attacks were correctly labeled as misuses, and the SECS guarantees were properly phrased as Axis-2 conditionals. Gemini also suggested linking our real console outputs (like the 199,734 oracle calls and the failure of the instructor's `--check` script) directly into the Honesty Clause to provide empirical evidence for our claims.

**What we did with it / verification:** We rewrote the Honesty Clause to be much clearer, integrating our actual terminal outputs to prove the mathematical boundaries of the attacks (e.g., pointing out that the XOR texts drop the last byte, and showing the exact injected padding `\x00\x00\x00` in the MAC forgery). We locally tested and verified that the instructor's `--check` script fails on our machine due to OS background noise (since it only runs 41 trials), which perfectly supported our claim about the fragility of timing attacks.

**Did we understand it?** Yes. Breaking down the concepts into simpler terms solidified our understanding of the real-world limits of cryptography. For example, we now clearly see the difference between mathematically breaking a MAC and actually achieving authorization escalation in an application, and we fully grasp the "fair-exchange" problem in our SECS design (cryptography cannot force Bob to send a receipt). 

**What we kept or rejected:** Kept the clearer, jargon-free explanations for the Honesty Clause, and included the note about the instructor's `--check` failing locally to demonstrate the necessity of our 200,000-call batching strategy.
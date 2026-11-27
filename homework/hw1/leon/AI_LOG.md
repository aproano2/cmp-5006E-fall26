# AI LOG for Homework01

> **Group:** Mauricio Mantilla, James Soto, Julian Leon.
> Mauricio got ahead of the group and implemented the first version of the
> solutions (Tasks 1–5, logged in his words). I (Julian Leon) then reviewed
> that implementation with Claude: how each break and the SECS design were
> implemented, whether they were correct against the assignment and rubric,
> and whether anything could be fixed or strengthened (Task 6).

## Task 1: Implementation and verification of 'Part A: Break the deployments'

**Tool:** Github Copilot: gpt-5.6-luna

**What I asked:** "Asked it to implement the code to break the four chosen deployments. Also explain the results in the `breaks_report.md` file"

**What I got:** 4 code files inside the [breaks](./breaks/) folder. Plus a [breaks_report.md](./breaks_report.md) file explaining the **Assumption**, 
**Break**, **Primitive break or misuse**, and **Confirmation**

**What I did with it:** Ran the tests, checked and understood the code, and verified that the answers were coherent. 

**Did I understand it?** Yes, all the attacks were implemented exploiting cryptographic weaknesses as the ones described in class. 

## Task 2: Design and implementation of Part B SECS

**Tool:** Github Copilot: gpt-5.6-luna

**What I asked:** "Asked to design the SECS protocol for Part B using the
repository's week 4-5 cryptographic material."

**What I got:** A [secs-design.md](./secs-design.md) file describing the message
flow, primitives, trust boundaries, guarantees, and how the design avoids the
six Part A mistakes.

**What I did with it:** Reviewed the design against the Part B requirements and
checked that every guarantee includes its condition.

**Did I understand it?** Yes, Alice signs the contract, Bob verifies and signs
the receipt, and both signatures are bound to the authenticated session.

## Task 3: Code review and Part C honesty report

**Tool:** Codex: gpt-6.1-sol

**What I asked:** Review `hw1` for hand-waved SECS trust conditions, the least
reproducible breaks, and security-goal tradeoffs; record findings in `honesty.md`.

**What I got:** An [honesty.md](./honesty.md) review identifying unresolved PKI
provisioning and evidence assumptions, timing portability and cumulative trial
counts, hard-coded plaintext cribs and unconfirmed suffixes, confidentiality
versus auditability, and the missing acknowledgment of the final signed package.

**What I did with it:** The assistant inspected the local design and scripts,
ran all four scripts successfully once, and checked that altering only the last
target ciphertext byte in memory did not invalidate either plaintext script's
assertion. It recorded those observations separately from reliability claims.

**Did I understand it?** Yes, the limitations presented were double-checked and tested.

## Task 4: Strengthen plaintext evidence and update the honesty findings

**Tool:** Codex: gpt-6.1-sol

**What I asked:** I identified some inconsistencies in the generated files, thus I asked to strengthen the plaintext evidence. 

**What I got:** Revised pad and CTR scripts that report 69 recovered bytes and
one unknown byte, explicit provenance for the assumed plaintexts, a
separate [fixture verifier](./verify_plaintext_evidence.py) with negative checks,
a [breaks README](./breaks/README.md), and matching report/honesty updates.

**What I did with it:** The assistant ran both revised scripts and the verifier.
The verifier confirmed both prefixes against fixture reference plaintexts,
rejected corrupted prefixes and incorrect cribs, and checked that the uncovered
byte remains unknown when its ciphertext changes. The supplied target was not
modified, and reference target plaintexts were not passed to recovery functions.

**Did I understand it?** Yes, the logic behind the fixture verifier and negative checks, confirming why the 69 recovered bytes are provably sound while the final byte remains indeterminate under ciphertext modification

## Task 5: Final-copy acknowledgment and accurate timing-call reporting

**Tool:** Codex: gpt-6.1-sol

**What I asked:** Add a signed acknowledgment of `FINAL_A`, report the
confidentiality issue in `honesty.md`, and correct the timing attack's worst-case
count and unsupported common-case claim.

**What I got:** A revised SECS design with `ACK_FINAL_B`, verification and durable
storage conditions, completion rules, and handling of dropped final messages.
The timing script now reports cumulative measurement and validation calls;
the report states a 7,680,004-call worst case and makes no typical-case claim.
The honesty section documents the remaining public-digest confidentiality issue
and delivery limitations. A regression test file checks timing-call reporting.

**What I did with it:** The assistant checked the signed acknowledgment's
bindings, the state transitions, and consistency with the scorecard and honesty
section. Four mocked retry/count tests passed; their results do not establish
timing-attack reliability or test a runnable SECS implementation. A run of the
revised timing attack recovered `83fabf35` on the first attempt and reported
512,001 total calls, including validation.

**Did I understand it?** Partially, I understand the acknowledgment flow and the 7,680,004 worst-case call bound, the architecture and necessity of the multiple regression/mock test files generated by the assistant remain questionable and redundant. 

## Task 6: Review of the implementation and reliability measurement (Julian Leon)

**Tool:** Claude (Claude Code, Opus 5.5)

**What I asked:** Review the group's hw1 against every requirement in
`hw-1-crypto.md` and the rubric, run every script to confirm the breaks are
reproducible on a second machine, explain how each break and the SECS design
work, look for errors or weak points that could be fixed, and adapt the
submission to my folder (`homework/hw1/leon/`).

**What I got:** A requirement-by-requirement check (4 breaks with ≥1 per tier,
SECS design, honesty section, AI log) and an independent re-run on macOS /
Python 3.14.7: `reused_pad.py` and `ctr_log.py` recovered 69/70 bytes,
`keygen_fleet.py` recovered device0's private exponent with a passing round
trip, `verify_login.py` recovered `83fabf35`, and the verifier and the 4
regression tests passed. It also listed weak points: the plaintext breaks rely
on known cribs rather than ciphertext-only crib-dragging, the timing
reliability rested on only one or two runs, the "batch GCD" is a pairwise GCD,
and the public `contract_hash` leaks guessable terms.

**What I did with it:** I went through each break and the SECS flow to
understand how they were implemented, and checked that each weak point was
already disclosed in `honesty.md` rather than hidden. To strengthen the
weakest evidence, I measured the timing attack's success rate on a second
machine: 10/10 first-attempt recoveries of `83fabf35` (Apple M1 Pro, Python
3.14.7, 512,001 oracle calls per run, ~28 s each), and added this result and
its limits to `breaks_report.md` and `honesty.md`. I fixed the two hard-coded
`homework/hw1/mantilla` paths so the instructions work from my folder, and
re-ran every script from `leon/` to confirm.

**Did I understand it?** Yes, mostly. Reused pad and CTR nonce reuse are the
same mistake: reusing the keystream lets XOR cancel it, so C1 ⊕ C2 = P1 ⊕ P2,
and one known plaintext reveals the keystream for every other message. At
first I thought the CTR attack also recovers the nonce; it doesn't — the
nonce is public, and what is recovered is the keystream, not the AES key.
For RSA, gcd of two moduli exposes the shared prime p, n/p gives q, and from
p and q we compute d. I had initially misread the "42" as part of the
factoring; it is just a test message encrypted with the public key and
decrypted with the recovered d to prove the key is correct. The timing
attack turns a 256⁴ brute force into 4 × 256 guesses because the early-exit
comparison takes longer for each correct byte. SECS applies those lessons,
and I agree no design is unconditionally secure — that's why every guarantee
is stated with its condition. I agree with all points in the honesty section.

# AI LOG for Homework01

Tasks 1-5 were logged by Mantilla and describe his sessions. Task 6 was logged by Soto.

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

## Task 6 (Soto): Guided verification of the deliverable against the rubric

**Tool:** Claude Code: Claude Opus 5.5 (2026-10-06)

**What I asked:** To accompany me while I verified what the group had
implemented, to compare the deliverable against the rubric, and to act as a tutor
on the topics I did not understand. 

**What I got:** A breakdown of Parts A-C and the rubric weights, with a short
explanation of the mechanism behind each of the six deployments: why a reused pad
or CTR nonce cancels in `c1 XOR c2`, how repeated ECB blocks leak structure, how
`H(secret || data)` can be extended from its tag, how a GCD between moduli exposes
a shared prime, and how an early-exit comparison leaks the matching prefix through
its duration. It also explained why non-repudiation of receipt cannot be achieved
between two parties without a trusted third party. The rubric comparison flagged
three gaps: the pad and CTR scripts use known plaintexts instead of crib-dragging,
only the minimum four breaks are present, and one timing run is not a success
rate. 

**What I did with it:** We ran the four break scripts,
`verify_plaintext_evidence.py`, and `test_timing_counts.py` on my machine and
checked the outputs against what the report claims. All passed; the timing attack
recovered `83fabf35` on its first attempt with 512,001 oracle calls. The
explanations were at the level of each attack's idea, not a line-by-line trace of
the scripts, and I have not yet read `secs-design.md` or `honesty.md` in depth.

**Did I understand it?** Partially. The pad and CTR breaks are the same idea I
worked through in the week 2-3 studios: a reused keystream cancels in `c1 XOR c2`,
so a known plaintext reveals the other. I follow the shared-prime GCD and the
early-exit timing attack as ideas, but I have not traced those scripts line by
line, and I still need to review the later topics, the key exchange and PKI behind
the SECS design, before I can defend that design.

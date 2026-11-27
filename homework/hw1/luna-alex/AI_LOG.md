# AI_LOG.md — Homework 1

## Entry 1 — Part A, Tier 1 breaks (#1 reused_pad, #2 ecb_store, #3 ctr_log) and Part C (honesty section)

**Who:** Alex Luna
**Tool:** Claude (claude.ai)
**What I asked:** Help designing attack scripts for the three Tier-1
deployments in `duel1_targets.py` (key/nonce/mode misuse), confirmed only
against the module's own public functions — never its private keys. I also
asked for help identifying genuine weak points for the honesty section
rather than cosmetic ones.

**What I got:** Working scripts for #1–#3 (two-time-pad XOR cancellation
for #1, ECB block-equality comparison for #2, the same XOR-cancellation
attack reapplied to a nonce-reuse case for #3), and a draft of `honesty.md`.

**What I did with it:** I ran every script against the real
`duel1_targets.py` from our repo and checked the recovered artifact against
what the deployment's docstring claims — e.g. for #1 I traced through why
the very last byte of the recovered message isn't actually forced by the
ciphertexts (only one message covers that column), which is why the script
reports it as a context-filled guess rather than silently presenting a
"fully solved" plaintext. While testing #2 on my own machine (Windows,
PowerShell) locally I actually found and reported a real bug — the helper
module that locates `duel1_targets.py` only knew how to find it under a
`projects/duel-1-crypto/` layout, not our repo's actual
`homework/hw1/duel-1-crypto/` layout — which needed a real fix before any
of this would run outside the original testing setup. For the honesty
section, the receipt-protocol fairness gap (see Entry 2) came up in
conversation while I was reviewing the design doc, and I pushed to have it
named explicitly here too rather than only in `secs-design.md`.

**Did I understand it?** Yes for #1–#3 — the shared XOR-cancellation idea
behind both #1 and #3 is the piece I'd want to be able to re-derive from
scratch in the week 8 checkpoint, and I think I could. For the honesty
section, the hardest part to really own was separating "the deployment's
flaw is real" from "our specific recovery of this message has an honest
gap" — those are different claims and the first drafts blurred them.

## Entry 2 — Part A, Tier 2 breaks (#4 token_mac, #5 keygen_fleet, #6 timing_compare), the breaks/ README and run scripts, and Part B (SECS design)

**Who:** Kevin
**Tool:** Claude (claude.ai)
**What I asked:** Help with the three Tier-2 deployments (integrity/key
misuse), and help structuring the SECS design — which primitives to use
and why, how to diagram the message flow with trust boundaries, and
specifically how to phrase each of the four required guarantees as a
conditional (axis 2) rather than an absolute claim.

**What I got:** Working scripts for #4 (length-extension forgery), #5
(batch-GCD factoring from shared RSA primes), and #6 (a timing side
channel), plus a full draft of `secs-design.md`.

**What I did with it:** #6 took real iteration, not a first-try success —
the initial single-call timing measurement was too noisy to reliably
recover more than the first byte or two in our sandboxed test environment,
and getting it working meant understanding *why* (one-sided OS/scheduler
noise, fixed by batching calls and taking the minimum instead of a median)
rather than just copying a fix. I reran the full recovery several times
myself to see the actual success rate before deciding what to report,
instead of keeping only a lucky run. For the SECS design, the part I pushed
back on and reworked was the non-repudiation-of-receipt guarantee — the
first draft stated it as unconditional, and once I thought through what
actually stops Bob from just not sending his receipt signature, it became
clear that's a real gap, which is why the design doc states it as
conditional on Bob actually transmitting `Sig_B`, with the fairness
limitation named rather than hidden. I also went back through the
primitive table in §4 and checked that every "avoids Break #N" claim
actually matches what that break's script does.

**Did I understand it?** The length-extension (#4) and batch-GCD (#5)
reasoning, yes, cleanly. The timing attack (#6) I understand well enough to
explain the batching fix, but I'd want more practice before I'd call my
intuition for "why is the noise one-sided" solid. The fair-exchange
limitation in the SECS design (why a simple signed-ACK protocol can't be
fully fair without a trusted third party) is something I understood well
enough to argue for in the design doc, but it's an area I'd want to read
more about before I could design the trusted-third-party extension myself.

---

*Per the course AI policy: both of us used an assistant heavily on this
assignment, for code, design argument, and self-critique. We're logging
that plainly — the policy says heavy use isn't penalized, only hiding it
is.*

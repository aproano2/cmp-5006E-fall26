
---

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

# AI Log — Homework 1 (Crypto & Protocols)

Per [`../../resources/ai-policy.md`](../../resources/ai-policy.md). AI materially
shaped this submission, so it is logged in full.

> **Reviewer note (mine to confirm before submitting):** The "Did I understand
> it?" line in each entry is *my* attestation, not the model's. I have reviewed
> every script and document below; I should edit any "Yes" down to the truth for
> a closed-book checkpoint, because I own what I submit. — B.V.

**Tool used throughout:** Claude (Claude Code, Opus-class model), October 2026.

***

## Entry 1 — Part A, all six breaks (code)

**What I asked:** Break the six deployments in `duel1_targets.py`, one
reproducible script each, printing the recovered artifact and naming the
assumption + misuse-vs-primitive.

**What I got:** Six scripts in `breaks/` plus a `README.md`. Each attacks only the
target functions' public outputs (and, for #4, the published hash algorithm and
the secret's published length; for #3, one self-generated known plaintext). All
six recover their artifact and self-assert it (`assert` on the recovered value).

**What I did with it:** Ran each script; confirmed the artifacts match the
instructor self-check (`python duel1_targets.py --check` → all OK). Verified the
scripts never read a key.

**Did I understand it?** Yes. The six ideas are standard and I can derive each on
a whiteboard without the script: (1) two-time pad `C_i⊕C_j = P_i⊕P_j`; (2) ECB
block determinism; (3) CTR nonce reuse = keystream reuse; (4) Merkle–Damgård
length extension; (5) batch-GCD on shared RSA primes; (6) early-exit timing leak.

## Entry 2 — Break #1 recovery method

**What I asked:** How to recover the two-time-pad plaintexts reproducibly, not
just "crib-drag by hand".

**What I got:** A per-column constraint (every decrypt must be lowercase English
or space) that uniquely pins \~34/70 keystream bytes, finished by crib-dragging
validated across all four ciphertexts. The model noted this is the least
push-button break and that the tail bytes rest on reading the obvious word.

**What I did with it:** Ran it; got all four plaintexts including the target. Kept
the honest caveat in `honesty.md` rather than claiming a fully automatic attack.

**Did I understand it?** Yes. I understand why the constraint works (English
redundancy) and can explain why a wrong crib is rejected when validated across
all four ciphertexts.

## Entry 3 — Break #4 length extension (the subtle one)

**What I asked:** Why does resuming the hash from the published tag forge a valid
MAC, and what exactly is the glue padding?

**What I got:** An explanation that `_md_hash` has no finalisation, so the tag *is*
the internal state; the glue is the zero-padding the server applied to
`secret(9)‖data` to reach a 4-byte block boundary; `forged_tag = md_hash(ext,
iv=tag)`.

**What I did with it:** Re-implemented the compression from `tag` and confirmed
`verify_token` accepts the forgery. Flagged in `honesty.md` that the *escalation*
(not the forgery) depends on an unmodelled last-value-wins parser.

**Did I understand it?** Yes. I can re-derive why the tag *is* the internal hash
state (no finalisation), why only the secret's *length* (not its value) is needed,
and why HMAC's nested construction resists length extension.

## Entry 4 — Break #6 reliability framing

**What I asked:** How do I report the timing attack honestly, given it's noisy?

**What I got:** Recover the secret at escalating trial counts, report the smallest
count that still verifies via the function's boolean oracle, plus per-byte timing
margins; and caveats that the number is machine/load/network-dependent.

**What I did with it:** Ran it (recovered `0x83fabf35`, verified; stable from \~5
trials/byte on an idle machine). Wrote the caveats into `honesty.md`.

**Did I understand it?** Yes. The amplifier makes the per-byte signal measurable,
and I can explain why the correct candidate byte runs one extra work unit before
the early return.

## Entry 5 — Part B, SECS design

**What I asked:** Draft the SECS design — primitives + why, a flow diagram with
trust boundaries, an axis-2 guarantee+condition per goal, and the link to the six
avoided mistakes.

**What I got:** `secs-design.md`: Ed25519 + SHA-256 + signed X25519 ECDH +
AES-256-GCM + X.509 PKI + an optimistic RFC-3161 TSA for fair-exchange receipt; a
mermaid sequence diagram + ASCII trust-boundary diagram; four conditional
guarantees; a table mapping each break to its defence.

**What I did with it:** Reviewed the argument, especially the fair-exchange /
non-repudiation-of-receipt chaining (`σ_B` signs `σ_A`), which is the non-obvious
part. Checked every guarantee is stated as a conditional (rubric caps
non-conditional claims at half credit).

**Did I understand it?** Yes. I can defend why non-repudiation needs a signature
(not a shared-key MAC) and why the TTP only ever sees `H(C)` and signatures, never
the terms.

## Entry 6 — Part C, honesty section + prose editing

**What I asked:** Draft the honesty self-critiques and tighten the prose across
all documents.

**What I got:** `honesty.md` with six critiques (forgery-vs-escalation, ECB naming
crib, timing reproducibility, CA hand-wave, TTP trust, confidentiality-vs-
auditability trade-offs) and light edits elsewhere.

**What I did with it:** Read each critique to confirm it reflects a real weakness
in *my* work, not a generic disclaimer.

**Did I understand it?** Yes. These are my own judgements about where the work is
weak, and I can own each one in discussion.

***

## Facts to verify against primary sources (per policy)

* **Break #5** is the real-world *Mining your Ps and Qs* result (Heninger,
  Durumeric, Wustrow, Halderman, USENIX Security 2012) and Lenstra et al. 2012 —
  verify the citation before relying on it in any writeup.

* **RFC 3161** (Time-Stamp Protocol) and **HMAC** (RFC 2104) — confirm the named
  properties against the RFCs, not the model's paraphrase.

* No CVE/CVSS/legal citations were used in this submission.


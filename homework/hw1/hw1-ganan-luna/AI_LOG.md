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

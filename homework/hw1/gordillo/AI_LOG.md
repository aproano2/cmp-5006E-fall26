# AI_LOG.md — Duel 1 / Homework 1

> **Team:** Juan Diego Cadena · Omar Gordillo · Pablo Jarrín · Santiago Rodríguez

## Tool used

- **Assistant:** Claude (Anthropic), via chat, on October 6, 2026.
- **Mode:** Code execution sandbox and document drafting.

## Part A — Cryptographic breaks

### What we asked

The AI was asked to help build and debug the cryptographic break scripts for
Homework 1 / Duel 1. We asked about the vulnerabilities present in the provided
`duel1_targets.py` deployments, possible attack strategies, implementation
details, and how to verify the recovered artifacts.

The main topics discussed were two-time-pad weaknesses, space detection and
crib-dragging, ECB block equality, Merkle–Damgård length extension, shared-prime
detection using GCD, and timing side channels.

### What we got

The AI provided explanations, attack approaches, implementation suggestions,
and code for:

- `breaks/break1..6_*.py` — six reproducible break scripts.
- Two-time-pad space detection, crib-dragging, and bigram refinement (#1, #3).
- ECB block-equality detection (#2).
- Merkle–Damgård length extension (#4).
- Batch-GCD shared-prime recovery (#5).
- Interleaved timing side-channel analysis (#6).

The AI also provided debugging and testing suggestions for running the attacks
against the provided `duel1_targets.py` module.

### What we did with it

The team reviewed the proposed attack strategies and implementations, then
executed every break script against the provided local target.

The deterministic breaks (#1–#5) reproduced the expected recovered artifacts
using the fixed `SEED`. Break #6 was tested separately because timing-based
side-channel measurements are probabilistic and depend on the execution
environment.

The instructor-provided `--check` option was also run. Five of the six checks
passed; the short timing check failed consistently with the reliability
limitations observed for break #6.

### Did we understand it?

Yes. The team reviewed each break and can explain the vulnerability, the
assumption being violated, how the attack works, and what artifact was recovered
without relying solely on the AI-generated implementation.

---

## Part B — SECS design

### What we asked

The AI was asked to help review the security design for Part B, including
primitive selection, system flow, trust boundaries, conditional security
guarantees, and common cryptographic mistakes to avoid.

### What we got

The AI provided design suggestions and explanations that were used while
developing `secs-design.md`.

### What we did with it

The team evaluated those suggestions against the requirements of the assignment
and the concepts covered in class. The resulting document includes the selected
primitives, system flow, trust boundaries, conditional guarantees, and an
avoided-mistakes table.

### Did we understand it?

Yes. The team reviewed the final design and can explain the purpose of the
selected primitives, the assumptions behind the security guarantees, and the
conditions under which those guarantees hold.

---

## Documentation

### What we asked

The AI was asked for help structuring and reviewing `breaks/README.md` and the
other assignment documentation.

### What we got

The AI suggested documenting the security assumption, misuse-vs-primitive
distinction, recovered artifact, and verification oracle for each break.

### What we did with it

The team incorporated the relevant suggestions into the documentation and
reviewed the resulting explanations against the behavior of the implemented
attacks.

### Did we understand it?

Yes. The team can explain the assumptions, attack results, and verification
methods documented in the README.

---

## Human verification

The team is responsible for all submitted code, explanations, and security
claims. AI-generated suggestions and code were reviewed and tested rather than
accepted solely because the AI produced them.

Before submission, the team will:

1. Re-run break #6 on the team's own machine and record its observed reliability,
   since timing measurements are machine-dependent.
2. Confirm that the SECS argument reflects the team's own design judgment.
3. Verify this log against the actual `resources/ai-policy.md`.
4. Ensure that the test-harness copy of `duel1_targets.py` is not committed if
   it is not part of the required submission.

## Scope / ethics

All testing was performed against the local, sandboxed `duel1_targets.py`
environment provided for the assignment, in accordance with
`resources/ethics-and-scope.md`.

No external or networked targets were used.

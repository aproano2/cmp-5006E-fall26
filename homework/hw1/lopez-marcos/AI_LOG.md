# AI Log for Duel 1 — Homework 1

**Names:** Luis Eduardo Zaldumbide, Miguel Jarrin, Josue Lopez  
**Class:** Computer Security  
**Date:** 5/10/2026

Per the course AI policy (`../../../resources/ai-policy.md`), this log records the material use of AI assistants in the submitted work.

## Part A — Deployment Breaks

**Tool used:** ChatGPT 5.6 Sol

**Purpose:**  
Used ChatGPT to review the homework instructions and `duel1_targets.py`, explain the intended vulnerabilities, help structure the attack scripts, and improve the written explanations for Part A.

**Main assistance received:**
- Clarified the reused one-time pad, ECB structure leakage, length-extension MAC, and RSA shared-prime attacks.
- Reviewed `breaks_script.py` for correctness and reproducibility.
- Helped improve the wording for assumptions, recovered artifacts, misuse vs. primitive break, and reliability.
- Explained the requirements for Part B.

**Student contribution:**  
The scripts, attack execution, interpretation of results, and final submission decisions were completed and reviewed by the group.

---

## Part B — SECS Design Document (`secs-design.md`)

**Tool used:** Claude Code (Claude Opus 5.5)

**Purpose:**  
Used Claude Code to help develop the Part B design document for the Secure Electronic Contract Signing system, including primitive selection, message flow, trust boundaries, guarantee-and-condition statements, and the mapping back to the Duel-1 mistakes.

**Main assistance received:**
- Helped structure the document according to the Part B requirements.
- Proposed the primitives table using PKI certificates, RSA-PSS/ECDSA signatures, SHA-256, AES-256-GCM, signed ephemeral Diffie–Hellman, and nonces/timestamps.
- Drafted the message-flow diagram and marked the main trust boundaries.
- Helped phrase the four required goals as guarantees together with the conditions they depend on.
- Helped map the Duel-1 flaws to the controls used in the SECS design.

**Student contribution:**  
The group reviewed the whole design against the rubric and made the final submission decisions. We understood the main design choices, including why digital signatures are needed for non-repudiation, why Diffie–Hellman must be authenticated to prevent MITM attacks, and why AES-GCM nonces must not repeat under the same key. Some smaller design details still require further study.

---

## Part C — Honesty Section (`honesty.md`)

**Tool used:** Claude Code (Claude Opus)

**Purpose:**  
Used Claude to help draft the section titled **"Where our breaks or design might be unfair"**, based on the Part A attacks and the Part B SECS design.

**Main assistance received:**
- Identified breaks that relied on information provided by the assignment rather than independently recovered, such as the token MAC secret length and the ECB record structure.
- Identified conditional assumptions in the SECS design, including trust in the CA, key protection, and revocation handling.
- Identified the reused-pad attack as the least fully reproducible because the last byte of the target plaintext was inferred from context rather than recovered through ciphertext overlap.
- Identified design tradeoffs such as evidence of receipt versus atomic fairness, and forward secrecy versus later inspection of encrypted traffic.

**Student contribution:**  
The group reviewed each critique against `breaks_script.py` and `secs-design.md` to confirm that it accurately reflected the submitted work. We understand the break-related critiques well, while some of the design-side issues, especially CA/revocation assumptions and the forward-secrecy tradeoff, still require more study before we could defend them fully without assistance.

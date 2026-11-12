Names: Luis Eduardo Zaldumbide, Miguel Jarrin, Josue Lopez
Class: Computer Security
Date: 5/10/2026

# Part C — Where our breaks or design might be unfair

CMP-5006 · Homework 1 · Part C (honesty section)

The grading stance rewards a team that finds a real hole in its own work over one that claims perfection. Below we name four such holes, two about the breaks
(Part A), two about the SECS design (Part B), and state each as honestly as we can, with the condition that makes it fair or unfair.

---

## 1. Did a break rely on an assumption the deployment didn't actually make?

Yes, two of our four breaks lean on information the attacker was handed rather
than recovered.

- #4 length extension (token_mac). Our forge hardcodes secret_length = 9,
  and we take that number straight from the docstring (secret length is 9). A real H(secret‖data) deployment does not publish its secret length. The attack is still sound, length extension only needs the length, which an attacker can brute force over a small range by testing each forgery against the verify oracle, but as submitted we did not do that search. We read the answer off the target. So our script proves the primitive misuse is exploitable, not that we could find the length blind. That is a fairness gap we should name, not hide.

- #2 ECB (ecb_store). Our attack correctly shows that records 0 and 2 repeat
  the same trailing blocks, i.e. they share a role+dept field. But our printed result ("Record 0 and Record 2 share the same role and department structure, infer who is an admin") quietly upgrades "two records share a field" into "these two are the admins." ECB leakage alone does not tell us which field value repeated, it could just as well have been two user accounts. Reading the repeated block as admn specifically relies on the out-of-band name:role:dept format the challenge gave us. The structural leak is real. The label "admin" is an assumption layered on top.

By contrast, #1 (two-time pad) and #5 (shared RSA prime) do not over-claim.
The pad reuse and the shared factor are genuinely recovered from the ciphertexts and moduli alone.

Additionally, the plaintext target recovered in #1 (two-time pad), cannot use crib dragging to figure out the last letter due to the length, and that letter is guessed. The crib dragging is influenced by having the message already and the real process could easily be more manual. 

---

## 2. Is the SECS design's guarantee conditional on something we've hand-waved?

Yes, the entire non-repudiation story is load-bearing on a trust anchor we specify but never actually build.

- The CA is assumed, not designed. §2 places the CA "above the double line,
  outside the session," with cert_Alice and cert_Bob "pre-provisioned offline," and §3.1 makes "the CA bound the key correctly and has not mis-issued" a
  condition. That condition is doing enormous work. If the CA mis-issues a cert for sk_attacker under the name "Alice," every signature still verifies and our non-repudiation guarantee is void, yet we never specify how the root key reaches both trust stores securely, which is itself the "secure channel for key distribution" the honesty prompt warns about. We assumed a secure out-of-band bootstrap and called it an anchor.

- Revocation is missing entirely. §3.1's condition says the signing key must be
  "not compromised," but our flow has no CRL or OCSP step. In reality a key can be compromised after issuance. Without revocation, a stolen sk_Alice keeps producing verifiable signatures until the cert expires. We stated the condition (uncompromised key) but hand-waved the mechanism that would let a verifier notice compromise.

- "Sole control" of the signing key (HSM or secure store, §2) is asserted, not
  enforced. We draw the private key inside the party's box and say it "never leaves," but a design document cannot guarantee the endpoint isn't malware-ridden. Non-repudiation is only as strong as that unmodeled endpoint.

---

## 3. Which of our four+ breaks are we least confident are reproducible, and why?

All four targets are deterministic (fixed SEED = 20250807), so in the narrow sense
every break reruns identically. Our honest ranking is about whether the recovery
is fully automated and complete, not about RNG noise.

- Least confident: #1 (two-time pad). Two reasons. (a) The recovery is
  human-in-the-loop. crib_drag and looks_like_english only surface candidate words. A person still has to guess authorization, will be, separate courier,
  and the rest. A different analyst running the same script would not deterministically land the same sentence, the script assists, it does not decide.
  (b) The final byte is guessed, not recovered. The target is 70 bytes, but the longest other message is 69, so index 69 (…courier o?) has no ciphertext overlap with any crib source and cannot be XOR-recovered at all. We inferred k ("ok") from
  English context. That one byte is a genuine guess, and we should say so plainly.

- Middle: #4 (length extension). Reproducible against the oracle every run, but
  (per section 1) only because we were given the secret length. The blind version is untested by our script.

- Most confident: #5 (shared prime) and #2 (ECB). Both are pure, deterministic
  computations, gcd of two moduli, and byte-equality of ciphertext blocks, with no human judgment and no guessed bytes. If anything, #5 is the cleanest. The recovered d is checked by a full encrypt and decrypt round-trip.

---

## 4. Does the design trade one goal for another? Name the trade.

Yes, two explicit trades.

- Evidence-of-receipt vs. atomic fairness. §3.2 already admits this, and we
  stand behind naming it as a limitation. Our ladder (steps 3–5) gives each party the other's signature only if the protocol runs to completion. If the attacker (who controls the wire, Dolev–Yao) drops message 4, Alice has proof she sent the contract but no proof Bob received it, while Bob may already hold Alice's signed contract. That is an unfair state. We traded true atomic fairness away to avoid
  requiring a trusted third party or an optimistic fair-exchange sub-protocol. The guarantee is honestly scoped to "evidence-of-receipt," but the trade means the receipt goal is weaker than the origin goal.

- Forward secrecy (confidentiality) vs. auditability of the wire. §3.4 requires
  the ephemeral exponents a and b to be erased so a later key leak can't decrypt past contracts. The cost: once erased, no one, not the parties, not a court appointed auditor, can re-derive K and decrypt the recorded transit ciphertext. Our non-repudiation still works (it rests on the archived signatures and plaintext, not on the wire), but any auditor who only has the network capture is locked out by design. We bought forward secrecy at the price of wire-level auditability, and that is a deliberate, named trade rather than a free win.

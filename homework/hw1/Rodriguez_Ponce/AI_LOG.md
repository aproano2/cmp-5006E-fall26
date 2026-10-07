## Homework 1 — Converting hexadecimal to bytes

**Tool:** Codex.
**What I asked:** How to convert a hexadecimal string to bytes in Python.
**What I got:** Use `bytes.fromhex(hex_string)`. Each pair of hexadecimal
characters represents one byte. For example, `bytes.fromhex("d8f6f831")`
produces four bytes. Use `.hex()` to convert bytes back to hexadecimal.
**What I did with it:** Related the explanation to
`ciphertext = bytes.fromhex(ciphertext_hex)` in `breaks/ecb_leak.py`.
**Did I understand it?** Yes. `bytes.fromhex()` converts each pair of hexadecimal
characters into one byte, and `.hex()` converts bytes back into hexadecimal text.

## Homework 1 — Constructing forged data

**Tool:** Codex.
**What I asked:** Help construct the forged data for the token MAC attack.
**What I got:** Code to calculate the zero padding using the secret length of 9
given in the exercise, then combine `data + padding + b"&role=admin"`.
**What I did with it:** Used this construction for `forged_data` in
`breaks/token_forge.py`.
**Did I understand it?** The padding depends on the combined length of the secret
and the original data, because the server hashes both together. The forged data
includes the original data, that padding, and `&role=admin`; the secret itself is
not included in what I send.

## Homework 1 — Crib-dragging

**Tool:** Codex.
**What I asked:** Help implement crib-dragging for the reused-pad attack.
**What I got:** Code that XORs two ciphertexts, slides guessed plaintext
fragments across the result, and checks for lowercase letters and spaces.
**What I did with it:** Used the implementation in `breaks/reused_pad.py` to
recover the target prefix and decrypt `msg1`, assuming the cribs are correct.
**Did I understand it?** The main idea is that XORing two ciphertexts encrypted
with the same pad cancels the pad. Sliding a guessed phrase across that result
produces possible fragments of the other message. Recovery depends on correct
guesses; readable text alone is not proof. The last target byte remains unknown
because none of the other messages reaches that position.

## Homework 1 — Non-repudiation of receipt

**Tool:** Codex.
**What I asked:** Help review and correct non-repudiation of receipt in the SECS design, using concepts covered in class.
**What I got:** An explanation that acknowledging a receipt is different from acknowledging receipt of the final signed contract. Codex helped specify separate signed receipts from Alice and Bob, each tied to the hash of the final copy containing the contract and both acceptance signatures. The guarantee depends on obtaining and verifying the corresponding receipt, protecting the signing keys, validating certificates, and preserving the evidence.
**What I did with it:** Used the revised receipt flow and conditional guarantee in `secs-design.md` and the updated diagram.
**Did I understand it?** The key distinction is that signing a contract expresses acceptance, while signing a receipt acknowledges receiving it. Each receipt covers the hash of the final copy containing the contract and both acceptance signatures, so it identifies the exact copy received. A party can claim evidence of the other party's receipt only after obtaining and verifying that party's signed receipt. If the exchange stops before that receipt arrives, the evidence is incomplete. These guarantees also depend on protected signing keys, correctly validated certificates, and preserved evidence.

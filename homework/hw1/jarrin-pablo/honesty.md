# Part C — Where our breaks or design might be unfair

> **Team:** Juan Diego Cadena · Omar Gordillo · Pablo Jarrín · Santiago Rodríguez

Per the rubric's scoring stance: evidence quality over "we won." Here are the
places our own work is weakest or leans on assumptions the deployment didn't force.

### 1. Break #3 (CTR log) assumes we can guess the two benign lines verbatim
Our recovery treats the two non-target log entries as **fully known plaintext**
cribs, then confirms the keystream by checking one benign line decrypts the other.
That cross-check is a real oracle, but it only works *because* we guessed both
benign lines correctly from the fixed log format. If the deployment used free-text
log messages instead of a rigid `date user= action= result= from=` template, we'd
have to fall back to the weaker column/space-detection crib-dragging (as in Break
#1), which recovers less and needs analyst judgement. So #3 is confirmed, but its
ease is partly a gift of the format, not purely the nonce-reuse flaw. (The nonce
reuse is still the root cause — with a unique nonce, knowing the benign lines buys
the attacker nothing.)

### 2. Break #1's last few characters aren't recovered from ciphertext alone
Crib-dragging recovers the keystream only up to the **shortest** message length
(64 chars). The target's tail ("...er ok") sits past that, where no second
ciphertext overlaps, so we finished it by crib/context, not by the two-time-pad
math. We flag this rather than claim a clean 100% automated recovery. Likewise the
final IP octet in #3 is one byte past the shortest line and is really a 1-of-10
guess.

### 3. Break #6 (timing) is the one we are *least* confident reproduces
It recovered the secret **2–3 of 3 runs** in our sessions, and the instructor's own
`--check` timing pass *fails*. The signal (one extra ~4000-iteration loop per
matched byte) is tiny against Python/OS jitter, and the **last byte is the
noisiest** (top-vs-second time margin ~2–17% vs thousands of % for byte 1). On a
loaded machine, a different OS scheduler, or PyPy, our numbers would shift. We
report reliability and call-counts instead of a single lucky run — but this break
should be read as "the channel exists and is exploitable," not "deterministic."

### 4. Break #4: the forgery needs the server to resolve duplicate keys as last-wins
Our forged token is `user=alice&role=user\x00\x00\x00&role=admin` — it contains
**both** `role=user` and `role=admin`. The length-extension math is airtight and
`verify_token` accepts the tag, but whether this *escalates privilege* depends on
how the application parses duplicate `role=` keys. Last-value-wins (common) → admin;
first-wins → still user. The crypto break is real; the privilege impact is an
assumption about the parser we didn't get to test.

### 5. The SECS design hand-waves the trust anchor and key distribution
G1/G2 (non-repudiation) are explicitly **conditional on an honest, non-mis-issuing
CA** — and that's precisely the real-world failure mode (DigiNotar, week 5). We rely
on Certificate Transparency to *detect* mis-issuance, but detection is after the
fact, not prevention. We also assume each party's private key lives in an
uncompromised store (HSM/keychain); if `sk_A` leaks, G1 collapses and no amount of
protocol design saves it. We state these as conditions rather than pretend they're
guaranteed.

### 6. The design trades auditability against confidentiality
We encrypt the contract terms end-to-end (G4), which means a third party (regulator,
auditor, the courts) **cannot read `C`** from the transcript without a party
disclosing `K` or `C`. Strengthening confidentiality weakened external
auditability. A deployment that needs supervised audit would have to add key escrow
or a disclosed-but-signed copy — which in turn weakens G4. We name the trade rather
than claim both at full strength.

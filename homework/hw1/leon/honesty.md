# Where our breaks or design might be unfair

This review covers [secs-design.md](./secs-design.md), the four scripts in
[breaks/](./breaks/), [breaks_report.md](./breaks_report.md), and the supplied
[local target](../duel-1-crypto/duel1_targets.py). Successful execution on a
fixed classroom fixture does not establish reliability against other deployments.

## 1. Are the SECS guarantees conditional on hand-waved trust?

**Yes.** The design explicitly names a trusted CA, protected signing keys, and
certificate validation in sections 1, 2, and 5. However, it does not specify how
the pinned CA trust anchor is initially authenticated, how certificate subjects
are mapped to the intended Alice and Bob, or how fresh revocation information
and trustworthy time are obtained. Those are prerequisites for the claimed
identity guarantees, rather than consequences of using signatures. An attacker
who controls initial trust-store provisioning or obtains a mis-issued peer
certificate can authenticate an attacker-controlled DH exchange.

No confidential channel for exchanging the DH public keys is required by the
proposed flow. It **does** require authentic provisioning of the CA public key
and the expected peer identity through a trusted installation or independently
verified mechanism. Signing keys must also remain under the appropriate party's
control. The document names these conditions but leaves their operational
enforcement unresolved.

Receipt evidence has another condition: section 4 requires Bob to sign only
after validation and durable storage. A signature proves that his key signed
the statement; it cannot independently prove that his software actually stored
the contract. Also, Bob supplies `received_at` himself. Retained certificates
and revocation evidence alone do not make that timestamp an independently
trusted signing time. Historical certificate-validity claims need an explicit
time/evidence policy. Forward secrecy additionally needs erasure of ephemeral
secrets and session keys; the design does not specify their deletion lifecycle.

## 2. Which breaks are least confidently reproducible, and why?

**The timing attack in [verify_login.py](./breaks/verify_login.py) is the least
portable.** It uses local `process_time_ns()` measurements, attempts CPU affinity
pinning, and attacks a target that deliberately performs 4,000 loop iterations
per matching byte. These favorable conditions are stronger than a remote login
oracle with network noise, rate limits, or an unamplified comparison. CPU/runtime
variation can change candidate rankings; an incorrect early byte undermines
the subsequent prefix search. Affinity permission failures can also stop the
script before measurement. A successful local run establishes recovery in that
environment, not a measured success rate across environments.

The initial trial report counted only the successful attempt and incorrectly
called 4,096,000 calls the worst case. The revised script accumulates failed
attempts and validation calls. Exhausting 500, 1,000, 2,000, and 4,000 samples
per candidate takes `4 * 256 * (500 + 1000 + 2000 + 4000) = 7,680,000`
measurement calls plus four validation calls: **7,680,004 total**. First-attempt
success costs **512,001 total**. The unsupported "common case" claim has been
removed from the break report. Deterministic tests cover reporting after retries
and exhaustion, but they mock the expensive sampling and do not estimate attack
reliability. More independent runs and a measured success/failure rate would
support a stronger reliability claim.

**Follow-up measurement:** a second team member re-ran the unmodified script 10
times on a different machine (Apple M1 Pro, macOS, Python 3.14.7, where the
affinity pinning is unavailable). It succeeded **10/10 times on the first
attempt**. This narrows the reproducibility gap for this fixture but does not
remove the fairness limit above: both environments are local and the target
amplifies each matching byte 4,000×. Ten runs on one machine are still a small
sample and say nothing about a networked login oracle.

**The revised plaintext attacks establish partial known-plaintext recovery.**
[reused_pad.py](./breaks/reused_pad.py) embeds three exact known plaintexts;
[ctr_log.py](./breaks/ctr_log.py) embeds one. The public target interfaces provide
ciphertexts, not those known messages. This demonstrates a known-plaintext attack
under an additional assumption; it does not demonstrate deriving all these cribs
from ciphertext-only observations.

The initial scripts appended `k` and `2` as their respective 70th bytes and
compared the results with hard-coded expected plaintexts. Changing just that
ciphertext byte left those assertions passing, exposing unconfirmed guesses.
The revised scripts remove those guesses and print 69 recovered bytes plus one
unknown byte. The supplied companion ciphertexts do not cover the final
keystream position; neither English plausibility nor the log format uniquely
determines its plaintext.

The new [fixture verifier](./verify_plaintext_evidence.py) confirms both prefixes
against the target's literal reference plaintexts, separately from recovery. It
rejects corrupted recovered prefixes and incorrect cribs and checks that changing
the uncovered byte leaves it unknown. This gives stronger evidence for the
**69/70-byte recovery claim**. However, the reference plaintexts are accessible
only through source inspection, not a public oracle. The verifier depends on the
classroom fixture's source layout; its successful comparison does not prove a
ciphertext-only attack, independent discovery of the cribs, or recovery of the
last byte. These attacker-knowledge assumptions remain the main fairness limit
for the plaintext breaks.

The fleet RSA script uses public moduli and confirms its recovered exponent with
an encrypt/decrypt round trip. It has the strongest direct confirmation among
these deterministic scripts, though the report calls its pairwise GCD search a
batch GCD, and one test message is limited validation.

## 3. Does SECS trade one goal for another?

**Yes: confidentiality versus auditability and durable evidence.** Sections 3
and 7 expose and log the plaintext `contract_hash`, session identifiers, and
certificate fingerprints. These support correlation and evidence checking, but
also reveal relationships between sessions and participants. More seriously,
an observer can hash plausible contract byte sequences and compare them with
the public digest. For a known template with a small set of possible prices or
terms, this can disclose the terms without breaking AES-GCM. The new final
acknowledgment also exposes this digest. The revised scorecard explicitly limits
the confidentiality claim and identifies feasible contract guessing as an
exception; the message format still exposes the digest, so the underlying
confidentiality issue remains unresolved. Acknowledging it does not restore term
secrecy for contracts with a small known set of possible contents.

The design also requires storing exact plaintext contract bytes for later proof.
That supports disputes while increasing exposure through endpoint archives;
forward secrecy of traffic keys does not protect retained plaintext. A tighter
privacy design would encrypt the plaintext digest along with the contract,
expose ciphertext identifiers where sufficient, and restrict access to retained
evidence. This reduces what an outside auditor can check without authorized
disclosure. The guarantee should distinguish encrypted transport from metadata,
guessable-content leakage, and evidence-storage confidentiality.

## 4. Final receipt evidence and its remaining delivery limits

The initial design had no acknowledgment covering `FINAL_A`, even though the
[assignment](../hw-1-crypto.md) asks for receipt of the final signed copy by both
parties. The revised design adds `ACK_FINAL_B`: Bob signs the exact hash of
Alice's signed final manifest, the session/transcript/contract bindings, and the
status `FINAL_RECEIVED_AND_STORED`. He signs only after verifying and durably
storing the final signed copy. Alice validates and stores that acknowledgment
before entering `COMPLETE`. Alice's own final signature acknowledges Bob's
countersigned receipt. These signed statements close the missing-evidence gap
for a completed exchange, subject to key control, certificate validation, and
correct endpoint behavior.

This remains a design document, not an implemented or tested SECS system. The
added acknowledgment does not guarantee delivery or fair exchange. If `FINAL_A`
is dropped, Bob lacks the final signed copy and Alice lacks his acknowledgment.
If `ACK_FINAL_B` is dropped, Bob has the final copy while Alice lacks proof of
that delivery. Alice records `INCOMPLETE` and retains earlier signatures rather
than treating a timeout as a retraction. Exact retransmissions may complete the
exchange if messages eventually arrive; a permanently blocking attacker or an
uncooperative party can still prevent completion. Bob also has no further
signed confirmation that Alice received his acknowledgment. Guaranteed fair
exchange or mutual knowledge of completion would require additional assumptions
or a dispute-resolution mechanism.

## Review validation

All four scripts completed successfully once under Python 3.12.3 using
`PYTHONDONTWRITEBYTECODE=1 python3 homework/hw1/leon/breaks/<script>.py`
from the repository root. The timing script recovered `83fabf35` and the target
accepted it, using 500 samples per candidate: 512,000 measurement calls plus
one validation call. This is one successful run, not an estimate of its success
rate. The original plaintext scripts printed their expected candidates; the RSA
script recovered a `device0` private exponent whose round trip passed. The two
in-memory last-ciphertext-byte mutation checks described above also passed the
original scripts' assertions. No target or attack script was edited for those
initial checks.

After strengthening the plaintext evidence, both revised recovery scripts
reported a 69-byte prefix and one unknown byte. The separate verifier confirmed
both prefixes against fixture ground truth, rejected corrupted prefixes and
incorrect cribs, and preserved the unknown-byte count when only the uncovered
ciphertext byte changed. The supplied target remains unmodified. The updated
SECS sections above distinguish the added acknowledgment from the unresolved
confidentiality and delivery limitations.

The revised timing script also recovered `83fabf35` on its first attempt and
reported **512,000 measurement + 1 validation = 512,001 total calls**. Four
mocked regression tests passed, including successful and unsuccessful exhaustion
of the retry budget with a 7,680,004-call total. These checks verify counting,
not a statistical success rate. The final-acknowledgment message, diagram,
verification rules, completion state, and scorecard were checked for consistency
as a design; there is no executable SECS implementation to test.

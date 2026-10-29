# Running the local breaks

Python 3.10 or newer is sufficient for the plaintext recovery scripts and their
verifier; they use only the standard library. From `homework/hw1/soto/`, run:

```bash
python3 breaks/reused_pad.py
python3 breaks/ctr_log.py
python3 verify_plaintext_evidence.py
python3 breaks/keygen_fleet.py
python3 breaks/verify_login.py
```

Run `python3 test_timing_counts.py` from the same directory for fast regression
checks of cumulative timing-call reporting. These tests mock sampling and cover
first-attempt success, success after retries, and exhaustion. They do not measure
the timing attack's success rate.

The scripts locate the supplied target relative to their own files, so they
also work when invoked by path from the repository root. The timing attack may
take substantially longer and depends on local CPU measurements. All attacks
use only the supplied local target.

| Break | Misuse | Evidence |
|---|---|---|
| `reused_pad.py` | Reusing the pad, assuming it preserves confidentiality | 69/70 target bytes recovered under assumed knowledge of three companion plaintexts |
| `ctr_log.py` | Reusing the CTR key/nonce, assuming logs stay confidential | 69/70 target bytes recovered under assumed knowledge of `log1` |
| `keygen_fleet.py` | Reusing RSA primes through weak fleet randomness | Shared factor and private exponent, checked by an encrypt/decrypt round trip |
| `verify_login.py` | Exposing early-exit comparison timing | Recovered four-byte secret accepted by the comparison oracle |

These are deployment misuses, not breaks of the correctly used primitives.
See [breaks_report.md](../breaks_report.md) for each designer assumption.

The exact companion plaintexts were obtained from the visible classroom fixture
and are explicitly assumed attacker knowledge. This models a known-plaintext
attack; it does not claim that the ciphertext API provides those messages or that
the scripts independently derive them through crib-dragging. Neither recovery
script reads the source, secret keys, or reference target plaintext.

`verify_plaintext_evidence.py` is a separate reviewer check. Because the supplied
target has no public plaintext-check oracle, this verifier parses only its
literal plaintext lists and compares the recovered prefixes with the fixture
ground truth. Reference target plaintexts are never inputs to recovery. The
check also rejects wrong prefixes and wrong cribs and verifies that an altered
uncovered ciphertext byte remains unknown. This confirmation depends on the
provided fixture's source layout and does not establish a remote oracle.

The two longest pad companions and the known CTR entry are 69 bytes; each target
is 70 bytes. The final byte uses a keystream position absent from the companions.
It cannot be uniquely recovered from these ciphertexts and cribs. Both scripts
therefore print the recovered prefix and the unknown-byte count separately.

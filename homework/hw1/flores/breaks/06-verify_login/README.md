# Break 06 — verify_login (timing_compare)

## Assumption that was violated
The comparison assumes that its runtime does not depend on its inputs. This
implementation returns at the first mismatched byte, so the duration reveals how
many leading bytes of the guess matched: a correct byte runs one more amplified
iteration before the function returns.

## Misuse vs. primitive
This is a misuse, not a flaw in the primitive.

- **Primitive:** the comparison returns the correct result, and no hash or cipher
  is attacked. The leak is in the execution time, not in the result.
- **Misuse:** the secret is compared in variable time.

The fix is a constant-time comparison: `constant_time_equal` from the week-4
studio examines every byte without early exit (in production code,
`hmac.compare_digest`). With it, the same attack recovers nothing (see the
notebook).

## Recovered artifact
`_TIMING_SECRET = 83fabf35` (4 bytes), recovered byte by byte from the timing of
`timing_compare`, and confirmed with the deployment's own check
(`timing_compare(recovered) == True`).

## Reliability
Timing measurements are noisy, so the break reports trials:

- Estimator: `time_guesses` from the week-4 studio (`rsa_lab.py`) interleaves the
  256 candidate bytes per round, so CPU drift does not bias the candidates
  measured last (a sequential per-candidate median is unreliable for a full
  scan).
- Trials: 41 interleaved rounds per candidate (41 timed calls per candidate,
  41,984 calls per full recovery).
- Measured: 5/5 full recoveries of `83fabf35`, about 2.4 s each, with about 34 us
  of separation per byte (42.9 / 33.3 / 34.4 / 34.2 us for bytes 0–3).

See `verify_login.ipynb` for the full execution, including the constant-time fix
against the same attack.

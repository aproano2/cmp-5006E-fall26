# Break 04 — ctr_log

## Assumption that was violated
CTR mode is only secure if every (key, nonce) pair is used for exactly one message,
because the keystream depends only on the key, the nonce and the counter. This
deployment encrypts every log entry with the same key and the same nonce, so all entries
share one keystream and it cancels out: `C_i ⊕ C_j = P_i ⊕ P_j`. The log format is fixed
and predictable (timestamp, `user=`, `action=`, `result=`, `from=`), which gives the
attacker plenty of cribs.

## Misuse vs. primitive
This is a misuse, not a flaw in the primitive.

- **Primitive:** the block cipher / keystream generator is fine, and CTR is a secure mode
  when its nonce is unique. Nothing in the break attacks the cipher itself.
- **Misuse:** the deployer fixed the nonce for every entry. That turns CTR into the same
  two-time pad as `reused_pad`, so the strong cipher gives no protection at all.

Fixing it does not mean replacing the cipher. It means respecting the mode's contract: a
fresh nonce per entry (or, better, an AEAD such as AES-GCM with unique nonces, which also
protects the log's integrity).

## Recovered artifact
`log2` = `2025-03-01 12:09 user=admin action=export result=success from=10.0.0.?`

The last byte (the final digit of the IP) cannot be recovered: `log2` is one byte longer
than the other entries, so that keystream byte never appears in any XOR. Our guess of
`log0` is confirmed because the same guess also decrypts `log1` into a valid log line.
See `ctr_log.ipynb` for the full crib-dragging sequence.

# Break 02 — token_mac

## Assumption that was violated
The designer assumed that `H(secret ‖ data)` behaves as a MAC, that is, that nobody
without the secret can produce a valid tag for new data. With a Merkle-Damgard hash this
fails: the tag is the hash's full internal state after `secret ‖ data ‖ padding`, so an
attacker can resume hashing from it and append data (`&role=admin`) without knowing the
secret. The secret's length only needs to be guessed, and the server's own check tells
us which guess is right.

## Misuse vs. primitive
This is a misuse, not a flaw in the primitive.

- **Primitive:** the hash is not "broken" here. We find no collision and no preimage; we
  use its normal, documented Merkle-Damgard structure.
- **Misuse:** the deployer built a MAC by prepending a secret to a hash. That
  construction is known to be length-extendable for any MD hash (MD5, SHA-1, SHA-256).

Fixing it does not mean picking a stronger hash. It means using a proper MAC
construction: HMAC (`hmac.new(secret, data, sha256)`), which nests the hashing so the
resumable inner state is never exposed.

## Recovered artifact
Forged token, accepted by `verify_token` without knowing the secret:

- `data = b'user=alice&role=user\x00\x00\x00&role=admin'`
- `tag  = 4024164909`

The server accepts the forgery for every secret length `≡ 1 (mod 4)` (1, 5, 9, ...),
because only the glue padding depends on that length. The escalation to admin assumes
the application parses parameters with "last value wins". See `token_mac.ipynb` for the
full execution.

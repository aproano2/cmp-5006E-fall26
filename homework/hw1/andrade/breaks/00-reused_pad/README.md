# Break 00 — reused_pad

## Assumption that was violated
A one-time pad is only perfectly secret if the key is truly random, at least as long as
the message, and used for exactly one message. This deployment breaks the last
condition: the key is used for every message. The security argument depends on the key
being independent of each ciphertext, and once it is reused, the ciphertexts leak
the XOR of the plaintexts.

## Misuse vs. primitive
This is a misuse, not a flaw in the primitive.

- **Primitive:** the one-time pad (XOR with a random key) is information-theoretically
  secure when its conditions hold (Shannon). Nothing is wrong with XOR or the construction.
- **Misuse:** the deployer reused the pad. This turns a provably secure scheme into a
  trivially breakable one, and no cryptanalysis of the cipher itself is needed.

Fixing it does not mean replacing the primitive. It means respecting its contract: never
reuse a key.

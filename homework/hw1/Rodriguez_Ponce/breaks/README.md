# Reused one-time pad

**Assumption:** The designer assumed that the same one-time pad could safely
encrypt multiple messages.

**Misuse vs. primitive break:** Misuse. This is pad reuse. XORing two ciphertexts cancels
the pad. Given correct phrase guesses for `msg2`, crib-dragging recovers TARGET
except its final byte and allows complete recovery of `msg1`. The script assumes
lowercase English text and spaces; readable matches alone do not confirm guesses.
This does not break a correctly used one-time pad.

# ECB structure leakage

**Assumption:** The designer assumed that encrypting blocks independently would
hide relationships between records.

**Misuse vs. primitive break:** This is ECB misuse. Identical plaintext blocks
encrypted under the same key produce identical ciphertext blocks, exposing
repeated fields without breaking the cipher primitive or recovering the key.

# Token MAC length extension

**Assumption:** The designer assumed that hashing `secret || data` would prevent
an attacker from creating a valid tag for modified data.

**Misuse vs. primitive break:** This is MAC construction misuse. The script
continues the exercise's toy hash from a public tag and appends padding followed
by `&role=admin`. With correct padding, `verify_token` accepts the forgery without
the secret. This confirms tag forgery.


# RSA shared prime

**Assumption:** The designer assumed that devices with little randomness at boot
would generate independent RSA prime factors.

**Misuse vs. primitive break:** This is RSA key-generation misuse. A simple
batch-GCD computes `gcd(n, product // n)` for each public modulus, where `product`
contains all moduli. If this reveals a proper shared prime factor, the script
recovers a private key and confirms it by decrypting four test messages.
It does not break RSA with properly generated keys.

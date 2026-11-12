# Break 01 — ecb_store

## Assumption that was violated
The designer assumed that encrypting each block under a strong keyed cipher hides the
structure of the data. It does not. ECB encrypts every block independently and
deterministically, so identical plaintext blocks give identical ciphertext blocks, and
the ciphertext leaks which blocks are equal. Here the records are `name:role:dept` and the
names are all 4 characters, so the 4-byte blocks line up with the fields. Alice and Carl
share the blocks `:adm`, `n:en` and `gr..`, so the ciphertext shows they have the same
role and department without the key. Bob and Dave share only the `:use` block.

## Misuse vs. primitive
This is a misuse, not a flaw in the primitive.

- **Primitive:** the block cipher is a keyed deterministic map and is not broken
  here. Nothing in the attack recovers the key or inverts a block.
- **Misuse:** the deployer chose ECB mode for structured records. ECB is deterministic
  by design, so it cannot hide equality of plaintext blocks. The attack needs no
  cryptanalysis of the cipher, only a comparison of ciphertext blocks.

Fixing it does not mean replacing the cipher. It means using a mode that randomizes the
output: CBC with a random IV, or better an AEAD such as AES-GCM with a unique nonce per
record, so identical plaintexts produce different ciphertexts.

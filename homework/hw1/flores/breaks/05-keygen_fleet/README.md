# Break 05 — keygen_fleet

## Assumption that was violated
RSA assumes that each modulus is generated from independent, high-entropy
randomness. In this deployment the fleet's PRNG reused one prime across two
devices, so their public moduli share a factor: `gcd(n_i, n_j)` returns that
prime. Each key is secure on its own; the problem appears when the keys are
compared.

## Misuse vs. primitive
This is a misuse, not a flaw in the primitive.

- **Primitive:** the RSA algorithm is not attacked. No modulus is factored; the
  shared prime is obtained with one GCD. Factoring n remains hard for keys
  generated correctly.
- **Misuse:** the key generation used low-entropy randomness, so two keys share a
  prime.

The fix is to generate p and q independently from a CSPRNG (for example,
`secrets`) with per-device entropy. The break reuses `factor_from_shared` from the
week-4 studio (`studios/week-04/rsa_lab.py`).

## Recovered artifact
Private keys for the two vulnerable devices, using only the public moduli:

- `p = 14723961130838400979` (shared prime, `gcd(n_device0, n_device2)`)
- `device0`: `d = 155006092543738932355592225651672081825`
- `device2`: `d = 101591964428919489627153881052022337249`
- Both keys satisfy `(m^e)^d mod n == m` for the sample messages.

See `keygen_fleet.ipynb` for the full execution.

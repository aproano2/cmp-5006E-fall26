# Where our breaks or design might be unfair

## 1. Did a break rely on an assumption the deployment didn't actually make?

Yes. In the reused-pad attack, we supplied specific phrases from `msg2` as
guesses. The exercise says the messages are in English, but that does not mean
an attacker would know those exact phrases. Together, our guesses cover the
whole reference message, so the attack depends on a lot of plaintext information.
We also assume the text contains only lowercase letters and spaces. In the ECB
attack, we assume we know Alice's role to infer Carl's role from the matching
blocks. The matching blocks alone do not tell us what that role is.

## 2. Is our SECS design's guarantee conditional on something we have hand-waved?

Yes. The SECS design depends on the CA being trustworthy and on the certificate validation process working correctly. We assume that the CA correctly binds Alice's and Bob's identities to their public keys and does not issue a certificate to an attacker.

The design also assumes that Alice's and Bob's private keys are generated securely and are not compromised. If an attacker obtains Alice's private signing key, they could create a valid-looking signature without Alice actually signing the contract. Similarly, if Bob's private key is compromised, an attacker could create a fraudulent receipt.

Therefore, our non-repudiation guarantees are conditional rather than absolute. We also assume that the cryptographic primitives remain secure and that signed contracts and receipts are preserved as evidence. These assumptions are necessary for the guarantees claimed by our design.


## 3. Which of the four breaks are we least confident are reproducible, and why?

The reused-pad attack is the one we are least confident would work on different
messages. It runs consistently on the supplied example, but its phrases are
specific to that example. With other messages, those guesses could fail or match
more than one position. Readable output also does not prove a guess is correct.

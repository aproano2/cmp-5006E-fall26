Names: Luis Eduardo Zaldumbide, Miguel Jarrin, Josue Lopez
Class: Computer Security
Date: 5/10/2026

# Part A — Deployment Breaks 

**CMP-5006 · Homework 1 · Part A (writing part, the scripts are in /breaks_script.py)**

### 1. reused_pad
The assumption: The designer assumes all messages will remain encrypted whiile using the same pad to encrypt them all safely, as long as the pad was being kept a secret.  

The break: From the script, the recovered artifact shows the decrypted target message: 
Recovered artifact: "the launch authorization code will be delivered by separate courier ok". 
The break is achieved by XORing message pair together, and since the pad is the same, using crib dragging with common english words and structures to decypher the encypted target plaintext. This is evidenced in the script as the plaintext is recovered through crib dragging. By testing plausible words and progressively extending the recovered fragments, the target plaintext can be reconstructed. The script confirms the attack by recovering the plaintext through this process.

Misuse: The attack exploits a misuse of the one time pad, as it does not attack the encryption process, it takes advantage of the mistake of using the same pad to encrypt several messages, which permits for an attacker with only access to the ciphertexts, to XOR them and uncover the message through crib dragging one with the others, knowing the plaintext messages are in English. The one time pad is only safe when the pad is secret, as long as the message and never reused. 

Reliability: The attack is deterministic and produces the same results. The somewhat mechanical process of crib dragging, that requires knowledge of English language structures, but even through a more brute force approach, eventually the plaintext would be recovered, as it becomes deterministic after the crib is discovered. The last letter of the message was recovered through an educated guess. 

### 2. ECB 
The assumption: Blocks that are encrypted independently using the same keyed function have everything from themseleves hidden from an attacker, including structure, even when identical plaintext appears within them. 

The break: From the script the recovere artifact is the records that share plaintext, so structure is leaked. 
Recovered artifact: Record 0 and Record 2 share blocks: [1, 2, 3]
Record 1 and Record 3 share blocks: [1]
Record 0 and Record 2 share the same role and department structure.
Record 1 and Record 3 share the same role.

This information, together with the known name:role:dept structure of the ciphertexts allow the attacker to know record 1 and 3 have the same role and records 0 and 2, to have the same role and dept. Without decrypting the message, it allows an attacker to leak repeated plaintext within the ciphertexts and make assumptions about them, like who is an admin. 

Misuse: The attacker is exploiting the misuse of ECB, because he is not targeting to break the encryption process, he is taking advantage of the fact the same key was used to encrypt several messages, even when this were encrypted independently. As ECB is deterministic, this causes for same plaintext to be encrypted producing the same ciphertext, allowing for structure to leak. 

Reliability: The attack is deterministic (to reveal structure and the blocks records share), however as it only reveals structure, in this case with th prior knowledge that the messages are name:role:dept, inferring that some pattern belongs to a role is only an educated guess. 

### 3. token_mac 
The assumption: The designer assumes that computing a tag as H(secret || data), while using a Merkle-Damgård based hash is sufficient to provide message integrity and authentication, as long as the secret itself remains unknown to the attacker.

The break: The issued token contains the public data and its corresponding tag. The attacker does not know the secret, but the secret length is known to be 9 bytes.

The original token data is:
user=alice&role=user

The attacker appends:
&role=admin

Because the hash construction is length-extendable, the original tag can be reused as the internal hash state. After accounting for the padding that would have been added after secret || data, the attacker computes a valid new tag for the extended message without knowing the secret.

Recovered Artifact: is the new valid tag: 4024164909
The script confirms the attack by passing the forged message and tag to verify_token(), which returns:
Valid forgery: True

Misuse: The attack does not break the hashing function, instead it exploits the construction of H(secret || data), which allows an attacker to continue hashing from the published tag when the underlying hash construction supports length extension. A secure MAC construction should not expose this property. For example, a proper MAC such as HMAC would avoid this type of length-extension attack.

Reliability: The attack is deterministic once the original valid tag, the data, and the secret length are known. The same padding and extension always produce the same forged tag. The only assumption required for the attack is the correct secret length. In this deployment, the secret length is 9 bytes, so the forged token is reproducible and consistently accepted by verify_token().

### 4. RSA and Shared Prime
The assumption: Generating RSA key pairs pseudo-randomly independently on multiple devices produces all different primes even when there is weak entropy during the key generation. 

The break: The attacker has available to him the public RSA moduli and exponents and can use them to discover a common prime component through GCD. The script finds the pair that produces such common prime component and uses it to uncover both primes, Then the attacker computes:

phi(n) = (p - 1)(q - 1)

and recovers the private exponent:

d = e^(-1) mod phi(n)

The script confirms the recovered private key by encrypting a test message using the public key and then successfully decrypting it using the recovered private exponent.

Recovered Artifact: private exponent d = 155006092543738932355592225651672081825

Misuse: The attack is not breaking RSA, but its exploting an error during the key generation, as weak entropy causes for one prime factor to be shared which allows for the break to occur. RSA security depends on each modulus being generated from independent, unpredictable prime numbers. When two moduli share a prime, computing their greatest common divisor immediately reveals that prime and allows both moduli to be factored.

Reliability: The break is deterministic. 

**Week 3 Studio: Control Scorecard Responses**  
**Constructions Evaluation Table**  
| | | |  
|-|-|-|  
| **Construction** | **Guarantee (Axis 2)** | **Condition for the Guarantee / Failure Mode** |   
| **ECB Mode** | Confidentiality for individual blocks | Since it is a block-based process, if they have identical plaintext, they result in identical ciphertext. |   
| **CBC / CTR Mode** | Confidentiality for the message | In CTR mode, the nonce must NEVER be repeated with the same key. If it is reused, the keystream cancels out (c1 ⊕ c2 = m1 ⊕ m2), turning it into a vulnerable two-time pad. |   
| **H(secret‖msg)** ** MAC** | Authentication and message integrity | Flaw (Length Extension Attack): The state of a Merkle-Damgård hash is exposed in its tag. This allows for the forgery of a tag for an extended message by resuming the hashing process from the observed tag—using the correct padding—without knowing the secret key. |   
| **HMAC** | Strong authentication and is immune to length-extension attacks | **Condition:** Relies strictly on the key remaining secret. By nesting the hash operations, the internal state is never fully exposed, completely preventing the length extension attack we exploited earlier. |   
   
**Extra Question**  
**Question:** *If the CTR nonce were unique but the KEY were reused across a million messages, is CTR still safe? State the condition precisely.*  
**Our Answer:**  
   
 Yes, CTR remains secure. The strict condition is that the (Key, Nonce) pair must be unique for each encryption operation. Even if you use the same key a million times, a unique nonce ensures the keystream never repeats, thereby avoiding the "two-time pad" vulnerability and protecting confidentiality.  

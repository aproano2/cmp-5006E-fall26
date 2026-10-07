# Where our breaks or design might be unfair

## 1. Did a break rely on an assumption the deployment didn't actually make?

Yes, several of our breaks relied on "cheats" or assumptions that a real attacker wouldn't have:

* **Breaks 1 & 3 (Reused Pad and CTR Log):** The target in both is 70 bytes, while every auxiliary message is at most 69 bytes. Our scripts recover 69-byte prefixes but cannot determine the last target byte. We assumed the final characters (completing `courier o` to 'k', and guessing the last IP digit in `from=10.0.0.`) because we read the provided source code, which is an unfair advantage. Also, the pad attack assumed we already knew the exact plaintext of another message.
* **Break 2 (ECB Store):** Seeing identical encrypted blocks `(d8f6f831 | 3eb9e189 | 7cf7fff3)` only proves that Alice and Carl share the same information. We assumed those blocks meant `admn` and `engr` only because we looked at the source code for Alice's record. Without that labeled reference, we wouldn't know what the role actually is.
* **Break 4 (Prefix MAC):** We assumed a real application wouldn't crash when reading the messy injected zero bytes (`b'user=alice&role=user\x00\x00\x00&role=admin'`). We proved we can break the math, but we assumed a real permission-checker would successfully parse the second injected role instead of rejecting the malformed string.
* **Break 5 (RSA Fleet):** This attack assumes the devices have a catastrophic random number generator failure that produces the exact same prime twice. If the deployment used proper cryptographic randomness, the chances of generating the same prime would be virtually zero, making our Batch-GCD method useless.

## 2. Is your SECS design's guarantee conditional on something you've hand-waved?

Yes, our guarantees hand-wave the physical human element and a true "fair-exchange" mechanism.
Bob can receive the final package `F` and simply refuse to sign `RB`, leaving Alice unable to prove receipt. Conversely, after Bob returns `F` with `RB`, Alice can refuse to sign `RA`, leaving Bob without her signed receipt. SECS marks either case pending but cannot retract a copy already delivered. We hand-wave this limitation by stating that `RA` and `RB` prove cryptographic acknowledgment by party-controlled keys, not that a human read the contract or cooperated fairly. Fixing this would require a trusted third-party delivery service, which we explicitly excluded from our design.

## 3. Which of the four+ breaks are you least confident are reproducible, and why?

**Break 6 (Timing Compare)** is by far the least reproducible because timing attacks are highly sensitive to local OS noise and unrealistic over a real internet connection.
In one of our successful local runs, the console showed we had to make exactly 199,734 oracle calls just to average out normal computer background noise. The provided `--check` function actually fails on our local Windows environment for this precise reason: it only runs 41 trials, which is entirely insufficient to filter out the OS noise. While the time difference for the first byte was obvious, the gap gets much smaller for the third byte. If we were attacking a real server over the internet, normal network lag would completely hide these tiny nanosecond differences.

## 4. Does your design trade one goal for another? Name the trade.

Yes, our design trades **transparency and auditability for confidentiality in transit**.
By using mutual TLS to hide the contract terms from network observers, we also prevent passive network auditors from checking the contract content while it travels. Auditors cannot simply inspect the network traffic; they require controlled access to the stored endpoint evidence instead. Furthermore, relying on cryptographic evidence alone does not automatically settle legal non-repudiation, as real-world risks like endpoint malware, key compromise, or a cloned random generator can undermine claims despite our sound primitive choices.
#!/usr/bin/env python3
"""Break #3 - AES-CTR audit log reuses the nonce.

Assumption the designer made: "CTR with a strong cipher gives confidentiality."
True only while each (key, nonce) pair is used once. Here one nonce encrypts every
entry, so the keystream repeats and C_i XOR C_j = P_i XOR P_j - a two-time pad on
top of CTR. The cipher is fine; reusing the nonce is the misuse.

Two confirmations, using only the ciphertexts:
  1. Structural proof of nonce reuse: C_log0 XOR C_log1 is exactly 0x00 wherever the
     two log lines share a character (the fixed template), which is impossible unless
     the keystream is identical.
  2. Recovery: the attacker can generate one known entry (e.g. force a failed login
     for 'bob00'), giving a known plaintext. keystream = C_log1 XOR P_log1 then
     decrypts the TARGET admin line.

Confirmation: the recovered TARGET showing the admin export.
"""
from _targets import targets

KNOWN = b"2025-03-01 12:04 user=bob00 action=login result=failure from=10.0.0.9"  # log1


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def main() -> None:
    hexed = targets.ctr_log_entries()      # the only input we receive
    names = sorted(hexed)
    cts = {n: bytes.fromhex(hexed[n]) for n in names}
    target_name = max(names, key=lambda n: len(cts[n]))  # log2 (admin export) is longest

    print("== Break #3: CTR nonce reuse ==\n")

    # 1. structural proof: zeros in C0 XOR C1 mark the shared template.
    d01 = xor(cts["log0"], cts["log1"])
    zeros = [i for i, b in enumerate(d01) if b == 0]
    print(f"C_log0 XOR C_log1 is zero at {len(zeros)} positions (the shared template "
          f"chars) -> keystream is identical => nonce reused.")
    template = "".join("." if b else "=" for b in d01)
    print(f"  equal-char map: {template}")

    # 2. known-plaintext peel using a self-generated entry (log1).
    c1 = cts["log1"]
    keystream = bytes(c1[i] ^ KNOWN[i] for i in range(len(KNOWN)))
    tc = cts[target_name]
    recovered = bytearray(tc[i] ^ keystream[i] for i in range(min(len(tc), len(keystream))))
    # one trailing column (the last IP octet digit) is reached only by the target.
    undated = len(tc) - len(recovered)
    tail = "?" * undated

    text = recovered.decode("latin1") + tail
    print(f"\nRecovered TARGET ({target_name}): {text!r}")
    ok = b"user=admin action=export result=success" in bytes(recovered)
    print(f"\n[{'CONFIRMED' if ok else 'FAILED'}] admin export recovered"
          + (f" (final IP digit under-constrained: {undated} byte)" if undated else ""))


if __name__ == "__main__":
    main()

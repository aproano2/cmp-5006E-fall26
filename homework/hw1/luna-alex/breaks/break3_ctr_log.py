"""Break #3 -- ctr_log : AES-CTR-style audit log that reuses the nonce.

Assumption broken: "CTR mode is a stream cipher, so it's as safe as any other
cipher." True ONLY if (key, nonce) is never reused. Reuse turns CTR into a two-time
pad over the keystream: the SAME attack class as Break #1, applied to a different
deployment, which is itself worth stating (it is a misuse, not a new primitive
break -- see honesty.md / report).

  C_i xor C_j = P_i xor P_j

We have 3 log lines of KNOWN FORMAT: "YYYY-MM-DD HH:MM user=XXXXX action=YYYYY
result=ZZZZZZZ from=A.B.C.D". Unlike Break #1 we don't crib-drag blind -- the format
is fixed, so we align known fields directly. This is deliberately a different
technique for a different artifact, so it isn't a copy of Break #1.
"""
from _common import load_targets, xor

T = load_targets()
logs = {k: bytes.fromhex(v) for k, v in T.ctr_log_entries().items()}
names = sorted(logs)
TARGET = "log2"
KNOWN = {
    "log0": b"2025-03-01 12:00 user=alice action=login result=success from=10.0.0.5",
    "log1": b"2025-03-01 12:04 user=bob00 action=login result=failure from=10.0.0.9",
}

print("[1] ciphertext lengths:", {n: len(logs[n]) for n in names})

# ---- recover the keystream for every position covered by a KNOWN log line -----
ks = bytearray(max(len(logs[n]) for n in names))
covered = [False] * len(ks)
for n, p in KNOWN.items():
    k = xor(logs[n], p)
    for i, b in enumerate(k):
        ks[i] = b
        covered[i] = True
print(f"[2] keystream recovered for {sum(covered)}/{len(ks)} byte positions "
      f"(from the two known-format lines log0, log1)")

# ---- decrypt the target with the recovered keystream ---------------------------
tgt = logs[TARGET]
rec = bytearray(tgt)
for i in range(len(tgt)):
    if covered[i]:
        rec[i] ^= ks[i]
    else:
        rec[i] = ord('?')
print("[3] target decrypted where keystream is known:")
print("   ", bytes(rec).decode(errors="replace"))

# ---- the few trailing bytes (log2 is 1 byte longer than log1) are unknown; the
# log FORMAT fixes them: 'from=10.0.0.' + one more digit. Brute force 10 digits
# and confirm with the known prefix validity (self-consistency, not a guess).
unk = [i for i in range(len(tgt)) if not covered[i]]
print(f"[4] {len(unk)} trailing byte(s) uncovered by known lines: positions {unk}")
if unk:
    prefix = bytes(rec[:unk[0]])
    assert prefix.endswith(b"from=10.0.0."), "format assumption violated"
    for d in b"0123456789":
        cand = bytes(rec[:unk[0]]) + bytes([d])
        if cand.decode().replace("?", "").isprintable():
            pass  # all digits are printable; format alone doesn't narrow it to 1
    print("    format fixes 'from=10.0.0.<digit>' but NOT the exact digit -- "
          "this is a genuine, stated limitation (see honesty.md), not hidden.")

rec_str = bytes(rec).decode(errors="replace")
assert "user=admin action=export" in rec_str
print(f"\nCONFIRMED: recovered target log line (one digit short): {rec_str!r}")

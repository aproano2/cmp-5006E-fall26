"""Break #4 -- token_mac : tag = H(secret || data), H is Merkle-Damgard-style.

Assumption broken: "SHA-like hash + secret prefix = a MAC." False in general for any
Merkle-Damgard hash (MD5, SHA-1, SHA-256, and this toy _md_hash are all MD-style):
knowing H(secret || data) and len(secret) lets an attacker compute
H(secret || data || padding || extension) for ANY extension, without the secret.
This is THE textbook length-extension attack (flagged in the course material).

We are told len(secret) == 9 (the docstring says so -- a classic plausible leak: a
config file, a comment, a changelog). We do NOT know the secret's bytes.
"""
from _common import load_targets

T = load_targets()
tok = T.issue_token()                       # public: {"data": "...", "tag": N}
data, tag = tok["data"].encode(), tok["tag"]
print(f"[1] observed token: data={data!r} tag={tag}")

SECLEN = 9                                   # from the module's own docstring
EXT = b"&role=admin"

# ---- reproduce the padding scheme used by _md_hash (we can read the source; this
# is public algorithm knowledge, same as knowing SHA-256 is Merkle-Damgard) --------
def md_padding(total_len: int) -> bytes:
    return bytes((-total_len) % 4)           # matches `msg + bytes((-len(msg)) % 4)`

def md_compress(state: int, block: bytes) -> int:
    s = state
    for b in block:
        s = ((s * 31) + b) & 0xFFFFFFFF
    return s

def md_hash_from_state(state: int, msg: bytes) -> int:
    msg = msg + md_padding(len(msg))
    s = state
    for i in range(0, len(msg), 4):
        s = md_compress(s, msg[i:i + 4])
    return s

# ---- the forgery: resume hashing from `tag` (the internal state after
# secret||data||padding) and feed it EXT. The forged message the server must
# accept is data || glue_padding || EXT.
total_secret_data = SECLEN + len(data)
glue_pad = md_padding(total_secret_data)
forged_data = data + glue_pad + EXT
forged_tag = md_hash_from_state(tag, EXT)

print(f"[2] glue padding (secret+data length={total_secret_data}): {glue_pad!r}")
print(f"[3] forged data : {forged_data!r}")
print(f"[4] forged tag  : {forged_tag}")

ok = T.verify_token(forged_data, forged_tag)
print(f"\n[5] server-side verify_token(forged_data, forged_tag) = {ok}")
assert ok and b"role=admin" in forged_data
print("CONFIRMED: forged a token with role=admin, accepted by verify_token(), "
      "WITHOUT ever learning the 9-byte secret -- only its length.")

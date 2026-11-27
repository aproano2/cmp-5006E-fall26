#!/usr/bin/env python3
"""Break #4 - length-extension forgery on tag = H(secret || data).

Assumption the designer made: "prefixing a secret to the data and hashing it
authenticates the data - nobody can produce a valid tag without the secret." False
for a Merkle-Damgard hash: the tag IS the full internal state after hashing
secret||data, so anyone can resume hashing from it and append bytes, producing a
valid tag for secret||data||pad||extension - all WITHOUT the secret.

The hash algorithm is public (Kerckhoffs); only the 9-byte secret is private. We
reimplement the public hash, resume from the issued tag, and append '&role=admin'.

Confirmation: the server's own verify_token() accepts our forged (data, tag) and
the data now ends in role=admin.

Scope of the escalation: the forged data holds BOTH role=user and role=admin
(user=alice&role=user\x00\x00\x00&role=admin). The cryptographic forgery is
unconditional: verify_token accepts a tag built without the secret. The privilege
escalation is conditional: it only grants admin IF the server resolves a duplicate
role= key to the LAST occurrence. A server that takes the first value, or rejects
duplicate keys, sees role=user and is unaffected.
"""
from _targets import targets

SECRET_LEN = 9      # stated in the deployment; also brute-forceable (try 1..N)
IV = 0x12345678     # the hash's public IV


def md_compress(state: int, block: bytes) -> int:
    s = state
    for b in block:
        s = ((s * 31) + b) & 0xFFFFFFFF
    return s


def md_hash(msg: bytes, iv: int = IV) -> int:
    msg = msg + bytes((-len(msg)) % 4)      # the hash's public padding rule
    s = iv
    for i in range(0, len(msg), 4):
        s = md_compress(s, msg[i:i + 4])
    return s


def forge(data: bytes, tag: int, secret_len: int, ext: bytes):
    """Length-extend: resume from `tag` and append `ext`."""
    glue = bytes((-(secret_len + len(data))) % 4)   # padding the hash applied after secret||data
    forged_msg = data + glue + ext
    forged_tag = md_hash(ext, iv=tag)               # continue hashing from the captured state
    return forged_msg, forged_tag


def main() -> None:
    tok = targets.issue_token()                     # a legitimately issued (data, tag)
    data, tag = tok["data"].encode(), tok["tag"]
    print("== Break #4: length-extension token forgery ==\n")
    print(f"Captured token: data={data!r} tag={tag}")

    # If the secret length were unknown, we'd try candidates until verify_token accepts.
    forged_msg, forged_tag = forge(data, tag, SECRET_LEN, b"&role=admin")
    accepted = targets.verify_token(forged_msg, forged_tag)

    print(f"\nForged data: {forged_msg!r}")
    print(f"Forged tag : {forged_tag}")
    print(f"verify_token(forged) -> {accepted}")
    ok = accepted and b"role=admin" in forged_msg
    print(f"\n[{'CONFIRMED' if ok else 'FAILED'}] server accepts a tag we built without "
          f"the secret.")
    print("Note: the forgery is unconditional; the admin escalation holds only if the "
          "server resolves the duplicate role= key to the LAST value.")


if __name__ == "__main__":
    main()

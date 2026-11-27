import sys
from pathlib import Path

HW1 = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(HW1 / "duel-1-crypto"))

from duel1_targets import _md_hash, issue_token, verify_token


def forge_token(data: bytes, tag: int, secret_len: int, extension: bytes):
    # The tag IS the hash's internal state after processing secret || data || pad,
    # so we rebuild that glue padding and resume hashing from the tag.
    total = secret_len + len(data)
    glue_pad = bytes((-total) % 4)
    forged_data = data + glue_pad + extension
    forged_tag = _md_hash(extension, iv=tag)
    return forged_data, forged_tag


def find_secret_len(data: bytes, tag: int, extension: bytes, max_len: int = 32):
    # The secret length is unknown, so we try every guess and let the server's
    # own check (verify_token) tell us which forgeries it accepts.
    accepted = []
    for secret_len in range(1, max_len + 1):
        forged_data, forged_tag = forge_token(data, tag, secret_len, extension)
        if verify_token(forged_data, forged_tag):
            accepted.append(secret_len)
    return accepted


if __name__ == "__main__":
    token = issue_token()
    data, tag = token["data"].encode(), token["tag"]
    extension = b"&role=admin"
    accepted = find_secret_len(data, tag, extension)
    forged_data, forged_tag = forge_token(data, tag, accepted[0], extension)
    print(f"forged data: {forged_data}")
    print(f"forged tag:  {forged_tag}")
    print(f"server accepts forged token: {verify_token(forged_data, forged_tag)}")

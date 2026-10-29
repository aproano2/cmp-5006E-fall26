#!/usr/bin/env python3
"""Break #4 (Tier 2) -- length-extension forgery of a SHA-256(secret||data) MAC.

ASSUMPTION the designer made:
    "Prefixing a secret and hashing authenticates the data -- only someone with
    the secret can produce a matching tag." That is false for any Merkle-Damgard
    hash (MD5, SHA-1, SHA-256, and the toy `_md_hash` here). The hash's output
    IS its full internal state, so anyone can resume hashing from a published
    tag and append data without knowing the secret.

THE FLAW:
    tag = H(secret || data). Given (data, tag) and the secret's LENGTH, an
    attacker computes a valid tag for
        secret || data || glue_padding || extension
    by running the compression function forward from `tag`, with no secret.

PRIMITIVE BREAK or MISUSE?
    MISUSE. The hash is a fine one-way/collision-resistant primitive (by
    assumption); using it as H(secret||data) is the wrong MAC construction. The
    fix is HMAC, which wraps the secret so the output state cannot be resumed.

METHOD / CONFIRMATION:
    `_md_hash` pads a message to a multiple of 4 bytes with zero bytes, then
    folds each 4-byte block into the state with no finalisation -- so the tag of
    (secret||data) is exactly the state after that message. We:
      1. Rebuild the glue padding the server applied to secret(9)||data.
      2. Resume from `tag` as the IV and hash our extension "&role=admin".
      3. Submit (data || glue || extension, forged_tag).
    verify_token -- the server's own check, which DOES use the secret -- accepts
    it. We never read the secret; we only used its length (9, as published) and
    the public tag.

RELIABILITY:
    Deterministic; a single run forges a valid admin token. If the secret length
    were unknown we would try candidate lengths and keep whichever verifies.
"""

from __future__ import annotations

from _common import targets

SECRET_LEN = 9  # published in issue_token's docstring; the only secret-derived fact we use
EXTENSION = b"&role=admin"


def md_hash_from(state: int, message: bytes) -> int:
    """Re-implementation of the target's MD hash starting from a chosen state.

    This is the published ALGORITHM (not the secret). With state == a known tag
    it continues the hash as if more data followed -- the length-extension core.
    """
    message = message + bytes((-len(message)) % 4)  # same zero padding
    s = state
    for i in range(0, len(message), 4):
        block = message[i:i + 4]
        for b in block:
            s = ((s * 31) + b) & 0xFFFFFFFF
    return s


def main() -> None:
    token = targets.issue_token()  # the honestly issued user token
    data = token["data"].encode()
    tag = token["tag"]

    print("=== Break #4: length-extension MAC forgery ===")
    print(f"captured token : data={data!r} tag={tag}")

    # Glue padding the server added after secret||data (both to a 4-byte multiple).
    glue = bytes((-(SECRET_LEN + len(data))) % 4)
    forged_msg = data + glue + EXTENSION
    # Resume hashing from the captured tag -- no secret involved.
    forged_tag = md_hash_from(tag, EXTENSION)

    print(f"forged data    : {forged_msg!r}")
    print(f"forged tag     : {forged_tag}")

    accepted = targets.verify_token(forged_msg, forged_tag)
    print("\nRECOVERED ARTIFACT (forged admin token):")
    print(f"  data = {forged_msg!r}")
    print(f"  tag  = {forged_tag}")
    print(f"  server verify_token() -> {accepted}")
    assert accepted and b"&role=admin" in forged_msg
    print("\n[confirmed] forged a tag the server accepts, escalating to role=admin "
          "without the secret (used only its published length).")


if __name__ == "__main__":
    main()

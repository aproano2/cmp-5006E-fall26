"""Length-extend the local toy prefix-MAC without reading its secret."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from duel1_targets import issue_token, verify_token


def continue_hash(state: int, extension: bytes) -> int:
    extension += bytes((-len(extension)) % 4)
    for value in extension:
        state = (state * 31 + value) & 0xFFFFFFFF
    return state


def main() -> None:
    issued = issue_token()
    data = issued["data"].encode("ascii")
    extension = b"&role=admin"
    for guessed_secret_length in range(1, 33):
        glue = bytes((-(guessed_secret_length + len(data))) % 4)
        forged_data = data + glue + extension
        forged_tag = continue_hash(issued["tag"], extension)
        if verify_token(forged_data, forged_tag):
            print("Accepted secret-length guess (padding class only):",
                  guessed_secret_length)
            print("Forged data (repr):", repr(forged_data))
            print("Forged tag:", forged_tag)
            print("Verifier accepted:", True)
            assert extension in forged_data
            return
    raise AssertionError("No secret-length guess produced a valid forged token")


if __name__ == "__main__":
    main()

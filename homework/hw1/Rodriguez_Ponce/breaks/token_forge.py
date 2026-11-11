import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "duel-1-crypto"))
from duel1_targets import issue_token, verify_token, _md_hash


def main():
    token = issue_token()
    data = token["data"].encode()
    tag = token["tag"]
    extension = b"&role=admin"

    forged_tag = _md_hash(extension, iv=tag)

    secret_length = 9
    padding = bytes((-(secret_length + len(data))) % 4)
    forged_data = data + padding + extension

    assert verify_token(forged_data, forged_tag)
    assert not verify_token(forged_data, tag)
    print("Original data:", data)
    print("Original tag:", hex(tag))
    print("Forged data:", forged_data)
    print("Forged data (hex):", forged_data.hex())
    print("Forged tag:", hex(forged_tag))
    print("CONFIRMED: verify_token accepts the extended data and forged tag.")


if __name__ == "__main__":
    main()

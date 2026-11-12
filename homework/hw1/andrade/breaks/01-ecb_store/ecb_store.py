import sys
from pathlib import Path

HW1 = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(HW1 / "duel-1-crypto"))

from duel1_targets import ecb_store_records, _block_cipher, _BS, _ECB_KEY


def cipher(msg: bytes) -> bytes:
    r = msg + bytes((-len(msg)) % _BS)

    return b"".join(
        _block_cipher(r[i : i + _BS], _ECB_KEY) for i in range(0, len(r), _BS)
    )


def discoverWhoIsAdmin():
    records: list[bytes] = [bytes.fromhex(h) for h in ecb_store_records()]
    users = [b"alic:xxxx:xxxx", b"bob0:xxxx:xxxx", b"carl:xxxx:xxxx", b"dave:xxxx:xxxx"]
    admn = b"xxxx:admn:xxxx"
    admn_c = cipher(admn)
    users_c = [cipher(u) for u in users]

    similars = []

    for r in records:
        if r[4:8] == admn_c[4:8]:
            similars.append(r)

    for r in similars:
        for i in range(len(users_c)):
            u = users_c[i]
            if r[0:4] == u[0:4]:
                print("admin found: ", users[i][0:4].decode())


if __name__ == "__main__":
    discoverWhoIsAdmin()

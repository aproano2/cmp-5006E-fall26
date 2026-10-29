import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "duel-1-crypto"))
from duel1_targets import reused_pad_ciphertexts, _xor


def main():
    messages = reused_pad_ciphertexts()
    reference = bytes.fromhex(messages["msg2"])
    target = bytes.fromhex(messages["msg3"])
    difference = _xor(reference, target)
    recovered = bytearray(b"?" * len(target))

    cribs = [
        b"remember to rotate ",
        b"the encryption keys ",
        b"every ninety days ",
        b"without fail",
    ]

    for crib in cribs:
        matches = []
        for position in range(len(difference) - len(crib) + 1):
            part = _xor(difference[position:position + len(crib)], crib)
            if all(byte == 32 or 97 <= byte <= 122 for byte in part):
                matches.append((position, part))
                print("Crib:", crib.decode(), "->", position, part.decode())

        if len(matches) != 1:
            raise SystemExit("No unique match for this crib.")
        position, part = matches[0]
        recovered[position:position + len(part)] = part

    print("\nTARGET:", recovered.decode())
    print("? = unknown byte: TARGET is longer than all reference messages.")

    prefix = recovered[:len(difference)]
    if b"?" in prefix:
        raise SystemExit("The cribs did not cover the whole shared prefix.")
    pad = _xor(target, prefix)
    other = bytes.fromhex(messages["msg1"])
    assert len(pad) >= len(other)
    print("Recovered msg1:", _xor(other, pad).decode())
    print("Recovery depends on the guessed phrases being correct.")
    print("Readable output alone does not prove a guess is correct.")


if __name__ == "__main__":
    main()

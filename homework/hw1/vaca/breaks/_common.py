"""Shared helpers for the Duel 1 break scripts.

Every break script imports the target module through this helper so the scripts
run from any working directory. We only ever touch the *public outputs* of the
target functions (the artifacts a real attacker would see) plus, where the
assignment explicitly says so, the published *algorithm* (e.g. the hash used by
the length-extension token). We never read the secret keys.
"""

from __future__ import annotations

import pathlib
import sys

# homework/hw1/vaca/breaks/_common.py -> parents[2] == homework/hw1
_DUEL_DIR = pathlib.Path(__file__).resolve().parents[2] / "duel-1-crypto"
if str(_DUEL_DIR) not in sys.path:
    sys.path.insert(0, str(_DUEL_DIR))

import duel1_targets as targets  # noqa: E402  (path set up above)


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

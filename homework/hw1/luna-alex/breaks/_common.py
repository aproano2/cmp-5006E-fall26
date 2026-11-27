"""Shared helper: locate and import the instructor's `duel1_targets.py`.

Lookup order:
  1. env var DUEL1_PATH (directory that contains duel1_targets.py)
  2. the current directory and every parent, looking for a `duel-1-crypto`
     folder
We only ever call the module's PUBLIC functions / oracles (never its `_private` keys).
"""
import importlib
import os
import sys
from pathlib import Path


def load_targets():
    cands = []
    if os.environ.get("DUEL1_PATH"):
        cands.append(Path(os.environ["DUEL1_PATH"]))
    here = Path(__file__).resolve().parent
    for base in [here, *here.parents, Path.cwd(), *Path.cwd().parents]:
        cands.append(base)
        cands.append(base / "duel-1-crypto")              
        cands.append(base / "projects" / "duel-1-crypto")   
    for c in cands:
        if (c / "duel1_targets.py").is_file():
            sys.path.insert(0, str(c))
            return importlib.import_module("duel1_targets")
    raise SystemExit(
        "duel1_targets.py not found. Set DUEL1_PATH to the folder that contains it, e.g.\n"
        "  PowerShell:  $env:DUEL1_PATH = \"..\\..\\duel-1-crypto\"\n"
        "  bash:        export DUEL1_PATH=../../duel-1-crypto"
    )


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def printable(bs: bytes) -> bool:
    return all(32 <= b < 127 for b in bs)

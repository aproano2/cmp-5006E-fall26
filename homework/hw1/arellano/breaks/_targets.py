"""Shared import shim: let each break script reach the provided target module.

The attacker only ever calls the PUBLIC functions exposed here (the same ones a
real deployment would expose) and never touches the secret keys.
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_TARGETS_DIR = os.path.normpath(os.path.join(_HERE, "..", "..", "duel-1-crypto"))
if _TARGETS_DIR not in sys.path:
    sys.path.insert(0, _TARGETS_DIR)

import duel1_targets as targets  # noqa: E402  (re-exported for the break scripts)

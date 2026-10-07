"""Locate duel1_targets.py no matter where the breaks/ folder sits in the tree."""
import sys, pathlib
_here = pathlib.Path(__file__).resolve().parent
for up in (_here, *_here.parents):
    for cand in (up, up / "duel-1-crypto"):
        if (cand / "duel1_targets.py").exists():
            sys.path.insert(0, str(cand)); break
    else:
        continue
    break

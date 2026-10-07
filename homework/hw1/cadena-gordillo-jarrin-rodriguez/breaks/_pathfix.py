"""Locate duel1_targets.py no matter where the breaks/ folder sits in the tree."""
import sys, pathlib
_here = pathlib.Path(__file__).resolve().parent
for up in (_here, *_here.parents):
    if (up / "duel1_targets.py").exists():
        sys.path.insert(0, str(up)); break

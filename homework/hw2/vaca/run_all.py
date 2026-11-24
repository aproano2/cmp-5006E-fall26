"""Run the laptop-only parts of Homework 2 end to end (A, B1, B2).

Part C (the duel) needs the live target up for sqlmap and the ollama models for
the LLM arm, so run it separately:

    PORT=8099 python3 labs/vuln-web/app/vulnweb_app.py &
    python3 homework/hw2/vaca/duel/run_duel.py
"""

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
STEPS = [
    ("Part A — attacks", HERE / "attack" / "confirm_attacks.py"),
    ("Part B1 — WAF (coverage / bypass / FP)", HERE / "defend" / "measure_waf.py"),
    ("Part B2 — parameterization", HERE / "defend" / "positive_fix.py"),
]


def main() -> int:
    rc = 0
    for title, script in STEPS:
        print("\n" + "#" * 70 + f"\n# {title}\n" + "#" * 70)
        r = subprocess.run([sys.executable, str(script)], cwd=script.parent)
        rc |= r.returncode
    print("\n" + ("ALL LAPTOP-ONLY PARTS OK" if rc == 0 else "SOME PART FAILED"))
    print("Run the Part C duel separately (needs :8099 + ollama).")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())

"""Part C, classical arm: run real scanners, save their raw output to duel/raw/.

  semgrep  static, community registry rulesets (default rules, untuned)
  bandit   static, default Python SAST ruleset
  sqlmap   dynamic, against every endpoint of the running app on 127.0.0.1

Needs semgrep, bandit and sqlmap on PATH:  pip install semgrep bandit sqlmap
score.py turns the raw files into ScanResults and scores them.

    python3 duel/run_scanners.py      # from homework/hw2/soto/
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import common as c                                    # noqa: E402

SRC = c.ROOT / "labs" / "vuln-web" / "app" / "vulnweb_app.py"
RAW = HERE / "raw"
SEMGREP_CONFIGS = ["p/python", "p/security-audit", "p/owasp-top-ten"]

# endpoint label -> sqlmap target args (data marks the parameters to test)
SQLMAP_TARGETS = {
    "login": ["-u", "{base}/login", "--data", '{{"user":"alice","pw":"x"}}'],
    "ping":  ["-u", "{base}/ping", "--data", '{{"host":"127.0.0.1"}}'],
    "reflect": ["-u", "{base}/?name=bob"],
    "safe":  ["-u", "{base}/safe?name=bob"],
}


def run(cmd):
    print("  $", " ".join(cmd)[:110])
    return subprocess.run(cmd, capture_output=True, text=True, timeout=900)


def main():
    RAW.mkdir(exist_ok=True)
    cfg = [a for c_ in SEMGREP_CONFIGS for a in ("--config", c_)]
    r = run(["semgrep", "scan", *cfg, "--metrics", "off", "--json", "--quiet", str(SRC)])
    (RAW / "semgrep.json").write_text(r.stdout)

    r = run(["bandit", "-q", "-f", "json", str(SRC)])
    (RAW / "bandit.json").write_text(r.stdout)

    base, stop = c.serve()
    try:
        with tempfile.TemporaryDirectory() as out:
            for name, args in SQLMAP_TARGETS.items():
                args = [a.format(base=base) for a in args]
                r = run(["sqlmap", *args, "--batch", "--flush-session",
                         "--output-dir", out])
                (RAW / f"sqlmap_{name}.txt").write_text(r.stdout)
    finally:
        stop()
    print("  raw scanner output saved in duel/raw/")


if __name__ == "__main__":
    main()

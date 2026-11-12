"""Single import location for the unmodified copied target module."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parents[2]

sys.path.insert(0, str(REPO_ROOT / "labs" / "vuln-web" / "app"))
import vulnweb_app as original  # noqa: E402

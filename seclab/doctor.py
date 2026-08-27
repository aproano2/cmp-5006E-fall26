"""Environment check. Run this before you ask for help.

    python -m seclab.doctor

Exit 0 means every REQUIRED check passed. Docker and Ollama are checked but a
missing one is a WARNING, not a failure: the manual LLM backend always works, and
labs that need Docker document a hosted-sandbox fallback.
"""

from __future__ import annotations

import importlib
import platform
import shutil
import sys

from .cache import Cache
from .llm import LLM, backends_available
from .targets import docker_available

OK, WARN, FAIL = "✔", "!", "✗"
REQUIRED = [("numpy", "1.24"), ("requests", "2.31")]
OPTIONAL = [("matplotlib", None), ("pytest", None), ("pandas", None)]


def _ver(m):
    for a in ("__version__", "version"):
        v = getattr(m, a, None)
        if isinstance(v, str):
            return v
    return "?"


def check_python():
    v = sys.version_info
    ok = (v.major, v.minor) >= (3, 10)
    print(f"{OK if ok else FAIL} Python {platform.python_version()}"
          f"{'' if ok else '  — need 3.10+'}")
    return ok


def check_packages():
    ok = True
    found = []
    for name, _ in REQUIRED:
        try:
            found.append(f"{name} {_ver(importlib.import_module(name))}")
        except ImportError:
            print(f"{FAIL} {name} missing — pip install -e .")
            ok = False
    if found:
        print(f"{OK} " + ", ".join(found))
    opt = []
    for name, _ in OPTIONAL:
        try:
            opt.append(f"{name} {_ver(importlib.import_module(name))}")
        except ImportError:
            opt.append(f"{name} MISSING")
    print(f"{OK} optional: " + ", ".join(opt))
    return ok


def check_docker():
    ok, why = docker_available()
    if ok:
        print(f"{OK} Docker usable — lab targets will run locally")
    else:
        print(f"{WARN} Docker: {why}")
        print("    Weeks 6-10 need it. Install Docker Desktop / docker-ce, or use")
        print("    the hosted-sandbox fallback in each lab guide.")
    return True                       # not a hard fail


def check_llm():
    for name, status in backends_available().items():
        mark = OK if name in ("manual", "echo") or "serving (" in status else WARN
        print(f"{mark} backend {name:<7} {status}")
    llm = LLM(backend="auto")
    if llm.backend == "manual":
        print(f"{OK} LLM backend: manual — a PASS. Every lab is completable this way.")
        return True
    r = llm.complete("Reply with exactly the word: ready", use_cache=False)
    if r.error:
        print(f"{WARN} {llm.backend} probe failed: {r.error} (manual is fine)")
    else:
        print(f"{OK} LLM backend: {llm.backend} ({llm.model}) — "
              f"{r.elapsed:.1f}s")
    return True


def check_cache():
    c = Cache()
    if not c.writable():
        print(f"{FAIL} .llm_cache/ not writable")
        return False
    print(f"{OK} .llm_cache/ writable ({len(c)} entries)")
    return True


def main(argv=None):
    print("CMP-5006 environment check")
    print("-" * 58)
    results = [check_python(), check_packages(), check_docker(),
               check_llm(), check_cache()]
    print("-" * 58)
    if all(results):
        print("→ Ready.")
        return 0
    print("→ Some REQUIRED checks failed (✗). Fix those. ! lines are warnings.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

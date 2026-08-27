"""CMP-5006 course harness.

Everything you need for the labs, and nothing that requires a GPU, a paid API
key, or a cloud account:

    llm      — a cached, multi-backend LLM client (same as CMP-4004's aicourse)
    cache    — content-addressed response storage; your audit trail
    targets  — Docker lab-target lifecycle (up / down / wait / logs)
    scan     — run a classical scanner and an LLM on the same target, compare
    attack   — payload + verifier harness for injection-style findings
    doctor   — environment check; run it before you ask for help

This is a fork of CMP-4004's `aicourse`. If you took the AI course, the llm and
cache modules are the ones you already know.

Design constraint: laptop-only. Every backend is optional except the manual LLM
backend (always works) and the "none" target driver (works without Docker, for
students who cannot install it).
"""

__version__ = "1.0.0"

__all__ = [
    "Cache", "LLM", "LLMResponse", "backends_available",
    "Target", "Scanner", "Payload", "Finding", "__version__",
]


def __getattr__(name):
    # Lazy imports so `python -m seclab.llm` (etc.) does not trip the runpy
    # "already in sys.modules" warning.
    if name == "Cache":
        from .cache import Cache
        return Cache
    if name in ("LLM", "LLMResponse", "backends_available"):
        from . import llm as _llm
        return getattr(_llm, name)
    if name in ("Target",):
        from . import targets as _t
        return getattr(_t, name)
    if name in ("Scanner",):
        from . import scan as _s
        return getattr(_s, name)
    if name in ("Payload", "Finding"):
        from . import attack as _a
        return getattr(_a, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

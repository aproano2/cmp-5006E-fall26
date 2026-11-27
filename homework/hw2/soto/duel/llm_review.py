"""Part C, LLM arm: ask a local model to review vulnweb_app.py, several times.

Backend: seclab.LLM(backend="ollama"), model qwen3.8:27b (override with
SECLAB_MODEL). Everything stays on this machine; the source is course code.

Runs (axis 9, non-determinism):
  t0-a, t0-b   temperature 0, seed 0, cache OFF  -> does pinning make it repeatable?
  t07-s1..s3   temperature 0.7, seeds 1,2,3       -> how a chat-style review varies
Raw responses are saved to duel/raw/llm_<run>.json; score.py parses them, so the
scoring can be re-done without re-running the model.

    python3 duel/llm_review.py        # from homework/hw2/soto/   (~15-30 min on CPU/M1)
"""
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import common as c                                    # noqa: E402
from seclab import LLM                                # noqa: E402

MODEL = os.environ.get("SECLAB_MODEL", "qwen3.8:27b")
SOURCE = (c.ROOT / "labs" / "vuln-web" / "app" / "vulnweb_app.py").read_text()

# Deliberately plain: one honest attempt, not a prompt tuned until it wins.
PROMPT = """You are a security code reviewer. Review the following Python web application
and list every security vulnerability you find.

Answer ONLY with a JSON array. One object per vulnerability, with keys:
  "vulnerability": the vulnerability class (e.g. "SQL injection")
  "function": the name of the Python function that contains it
  "severity": HIGH, MEDIUM or LOW
  "reason": one sentence

```python
{source}
```"""

RUNS = [("t0-a", 0.0, 0), ("t0-b", 0.0, 0),
        ("t07-s1", 0.7, 1), ("t07-s2", 0.7, 2), ("t07-s3", 0.7, 3)]


def main():
    llm = LLM(backend="ollama", model=MODEL, timeout=1800,
              cache_dir=str(HERE / ".llm_cache"))
    out_dir = HERE / "raw"
    out_dir.mkdir(exist_ok=True)
    for name, temp, seed in RUNS:
        path = out_dir / f"llm_{name}.json"
        if path.exists():
            print(f"  {name}: already have {path.name}, skipping")
            continue
        r = llm.complete(PROMPT.format(source=SOURCE), temperature=temp, seed=seed,
                         use_cache=False)            # every run is a real inference
        if r.error:
            sys.exit(f"  {name}: {r.error}")
        path.write_text(json.dumps({"run": name, "model": r.model, "temperature": temp,
                                    "seed": seed, "elapsed_s": round(r.elapsed, 1),
                                    "text": r.text}, indent=2))
        print(f"  {name}: {r.elapsed:.0f}s, {len(r.text)} chars -> {path.name}")


if __name__ == "__main__":
    main()

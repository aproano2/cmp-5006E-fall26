"""Part C follow-up: does the LLM need the `# VULN` hints? (comment ablation)

honesty.md (section 1) admits that vulnweb_app.py names every bug in a `# VULN`
comment, which helps an LLM reader and not sqlmap. This script measures that
effect instead of only stating it.

Same prompt as llm_review.py, same model, two versions of the target source:
  original  the file as the group's main duel scored it
  stripped  every comment and docstring removed (ast round-trip), so the code
            is identical but nothing tells the reader where the bugs are
Five runs per version (T=0 seed 0 x2, T=0.7 seeds 1/2/3), as in the main duel.

The main duel's raw outputs (qwen3.8:27b, run on Julian's machine) are not
touched. This ablation uses the model that is installed here (default
gemma4:12b, override with SECLAB_MODEL), so the comparison that counts is
original-vs-stripped WITH THE SAME MODEL, not this model vs. qwen.

    python3 duel/llm_ablation.py          # from the submission folder; writes duel/raw_ablation/
    python3 duel/ablation_score.py        # scores them
"""
import ast
import json
import os
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE.parent), str(HERE)]
import common as c                                    # noqa: E402
from seclab import LLM                                # noqa: E402
from llm_review import PROMPT, RUNS                   # noqa: E402  identical prompt + run plan

MODEL = os.environ.get("SECLAB_MODEL", "gemma4:12b")
SRC_PATH = c.ROOT / "labs" / "vuln-web" / "app" / "vulnweb_app.py"
OUT = HERE / "raw_ablation"


def strip_comments(source: str) -> str:
    """Remove comments (ast drops them) and docstrings; keep the code identical."""
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(
                    getattr(body[0], "value", None), ast.Constant) and isinstance(body[0].value.value, str):
                node.body = body[1:] or [ast.Pass()]
    return ast.unparse(tree) + "\n"


def model_digest(name: str) -> str:
    try:
        url = os.environ.get("OLLAMA_URL", "http://localhost:11434") + "/api/tags"
        with urllib.request.urlopen(url, timeout=5) as r:
            for m in json.load(r)["models"]:
                if m["name"] == name:
                    return m["digest"]
    except Exception as e:                            # noqa: BLE001
        return f"unknown ({e})"
    return "unknown (model not listed)"


def main():
    original = SRC_PATH.read_text()
    stripped = strip_comments(original)
    assert "VULN" not in stripped, "a hint survived the stripping"
    OUT.mkdir(exist_ok=True)
    (OUT / "vulnweb_app_stripped.py.txt").write_text(stripped)

    # A per-run timeout keeps one slow generation from stalling the whole ablation.
    # Override with SECLAB_TIMEOUT; a run that times out is recorded, not fatal.
    per_run_timeout = float(os.environ.get("SECLAB_TIMEOUT", "300"))
    # Three runs per variant are enough to see the hint effect (T=0 x2 + one T=0.7).
    runs = [r for r in RUNS if r[0] in ("t0-a", "t0-b", "t07-s1")]

    digest = model_digest(MODEL)
    llm = LLM(backend="ollama", model=MODEL, timeout=per_run_timeout,
              cache_dir=str(HERE / ".llm_cache"))
    for variant, source in (("original", original), ("stripped", stripped)):
        for name, temp, seed in runs:
            path = OUT / f"llm_{variant}_{name}.json"
            if path.exists():
                print(f"  {variant}/{name}: already have {path.name}, skipping", flush=True)
                continue
            r = llm.complete(PROMPT.format(source=source), temperature=temp, seed=seed,
                             use_cache=False)
            if r.error:
                print(f"  {variant}/{name}: ERROR after {r.elapsed:.0f}s: {r.error}", flush=True)
                path.write_text(json.dumps({
                    "run": f"{variant}:{name}", "variant": variant, "model": MODEL,
                    "model_digest": digest, "temperature": temp, "seed": seed,
                    "elapsed_s": round(r.elapsed, 1), "error": r.error, "text": "[]"}, indent=2))
                continue
            path.write_text(json.dumps({
                "run": f"{variant}:{name}", "variant": variant, "model": r.model,
                "model_digest": digest, "temperature": temp, "seed": seed,
                "elapsed_s": round(r.elapsed, 1), "text": r.text}, indent=2))
            print(f"  {variant}/{name}: {r.elapsed:.0f}s, {len(r.text)} chars", flush=True)


if __name__ == "__main__":
    main()

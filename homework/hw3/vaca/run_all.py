"""Re-run every measurement in Homework 3 and regenerate results/summary.md.

    ollama serve &                 # 127.0.0.1:11434
    ollama pull qwen2.5:1.5b       # the app's default VULN_LLM_MODEL
    python3 run_all.py             # ~10 min on an M-series laptop

Without Ollama, pass --mock-only: the deterministic half still runs.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
STEPS_MOCK = [["attack/part_a.py", "--backend", "mock"],
              ["defend/b1_filter.py", "--backend", "mock"],
              ["defend/b2_containment.py", "--planner", "mock"]]
STEPS_MODEL = [["attack/part_a.py", "--backend", "ollama"],
               ["defend/b1_filter.py", "--backend", "ollama"],
               ["defend/b2_containment.py", "--planner", "llm"]]

if __name__ == "__main__":
    steps = STEPS_MOCK + ([] if "--mock-only" in sys.argv else STEPS_MODEL)
    for step in steps + [["report.py"]]:
        print(f"\n>>> {' '.join(step)}", flush=True)
        subprocess.run([sys.executable, "-I", str(HERE / step[0]), *step[1:]], check=True)

"""Run the course seclab LLM reviewer against vulnweb_app.py N times.

Example from repository root:
  python homework/hw2/luna/duel/llm_review.py labs/vuln-web/app/vulnweb_app.py --runs 5 --backend ollama --temperature 0.7 --out homework/hw2/luna/duel/llm_runs.jsonl

Calls are uncached (`use_cache=False`) and use distinct seeds. A five-run
experiment is recommended by the control scorecard; HW2 requires at least 2.
"""
from __future__ import annotations
import argparse, hashlib, json, sys
from pathlib import Path

def find_repo_root(start: Path) -> Path:
    for parent in [start, *start.parents]:
        if (parent/'seclab'/'llm.py').is_file() or (parent/'seclab'/'__init__.py').is_file():
            return parent
    raise RuntimeError('Could not find repository root containing seclab/. Run from your course repository and check its layout.')
HERE=Path(__file__).resolve().parent
REPO_ROOT=find_repo_root(HERE)
sys.path.insert(0,str(REPO_ROOT))
from seclab.llm import LLM  # noqa: E402

REVIEW_PROMPT="""You are a security code reviewer. Review the complete Python source below.
Return every distinct vulnerability you can point to in the source.
For each finding return exactly: rule (short lowercase label such as sqli, xss,
cmdi, broken-access-control), location (exact function name), evidence (one
concise sentence tied to a construct in that function), confidence (high,
medium, or low). Do not invent functions, files, CVEs, or behavior. Do not
report a vulnerability in a fixed function merely because a similarly named
vulnerable function exists elsewhere. The command-injection lab intentionally
simulates shell interpretation; distinguish simulation from actual execution.
Respond ONLY with a JSON array. If no findings, respond with [].

SOURCE:\n```python\n{source}\n```"""

def extract_array(text:str):
    decoder=json.JSONDecoder()
    for i,ch in enumerate(text):
        if ch=='[':
            try:
                value,end=decoder.raw_decode(text[i:])
                if isinstance(value,list):return value
            except json.JSONDecodeError:pass
    raise ValueError(f'No valid JSON array found in model output: {text[:300]!r}')

def normalize_findings(parsed):
    """Robust against the shapes qwen2.5:3b actually produces across runs,
    not just the one shape the prompt asks for. Observed in real runs:
      (a) flat list of dicts                         -- the asked-for shape
      (b) each item wrapped in its own [single_dict]  -- model nests one extra level
      (c) a list of positional lists
          [rule, location, evidence, confidence]      -- model drops dict keys
    An earlier version of this function only handled (a) and silently
    DROPPED every finding in shapes (b)/(c) -- a parsing bug, not a sign the
    model found nothing. Always inspect raw_text before concluding a run
    produced zero findings; an empty `findings` list can mean the model said
    so, or that this normalizer didn't recognize its shape.
    """
    out = []
    for item in parsed:
        if isinstance(item, list) and len(item) == 1 and isinstance(item[0], dict):
            item = item[0]                      # unwrap shape (b)
        if isinstance(item, dict):
            out.append({**item,
                        'rule': str(item.get('rule', '')).strip().lower(),
                        'location': str(item.get('location', '')).strip().lower()})
            continue
        if isinstance(item, list) and len(item) >= 2 and all(isinstance(x, str) for x in item[:2]):
            out.append({                        # shape (c): positional list
                'rule': item[0].strip().lower(),
                'location': item[1].strip().lower(),
                'evidence': item[2] if len(item) > 2 else '',
                'confidence': item[3] if len(item) > 3 else '',
            })
    return out


def review_once(source,llm,seed):
    prompt=REVIEW_PROMPT.format(source=source)
    response=llm.complete(prompt,seed=seed,use_cache=False)
    record={'run':seed+1,'seed':seed,'backend':response.backend,'model':response.model,
            'temperature':response.temperature,'cached':response.cached,
            'elapsed_seconds':response.elapsed,'error':response.error,
            'raw_text':response.text,'findings':[]}
    if response.error:return record
    try:
        parsed=extract_array(response.text)
        record['findings']=normalize_findings(parsed)
    except Exception as exc:record['parse_error']=f'{type(exc).__name__}: {exc}'
    return record

def main():
    ap=argparse.ArgumentParser();ap.add_argument('source_path');ap.add_argument('--runs',type=int,default=5);ap.add_argument('--backend',default='ollama',choices=['auto','ollama','api','manual','echo']);ap.add_argument('--temperature',type=float,default=0.7);ap.add_argument('--out',default=str(HERE/'llm_runs.jsonl'));args=ap.parse_args()
    if args.runs<2:ap.error('--runs must be at least 2 for the non-determinism requirement')
    source_path=Path(args.source_path).resolve()
    if not source_path.is_file():ap.error(f'source file not found: {source_path}')
    source=source_path.read_text(encoding='utf-8');source_hash=hashlib.sha256(source.encode()).hexdigest()
    llm=LLM(backend=args.backend,temperature=args.temperature,verbose=True)
    results=[]
    for seed in range(args.runs):
        print(f'[LLM run {seed+1}/{args.runs}] seed={seed}',file=sys.stderr)
        rec=review_once(source,llm,seed);rec['source_sha256']=source_hash;results.append(rec)
        print(f"  findings={len(rec['findings'])}; error={rec['error']!r}; cached={rec['cached']}",file=sys.stderr)
    out=Path(args.out);out.parent.mkdir(parents=True,exist_ok=True)
    with out.open('w',encoding='utf-8') as f:
        for rec in results:f.write(json.dumps(rec,ensure_ascii=False)+'\n')
    print(f'Wrote {len(results)} uncached run(s) to {out}')
    if any(r.get('error') or r.get('parse_error') for r in results):
        print('WARNING: one or more runs failed or produced unparseable output; report them, do not silently drop them.')
if __name__=='__main__':main()

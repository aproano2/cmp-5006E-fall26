"""Run the WAF against the instructor's benign corpus and export evidence."""
from __future__ import annotations
import argparse, csv, json, sys
from pathlib import Path
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from waf import check

def main(corpus_path: str | None = None):
    path = Path(corpus_path) if corpus_path else HERE/'benign_traffic.json'
    corpus = json.loads(path.read_text(encoding='utf-8'))
    rows=[]
    for field, values in corpus.items():
        if field.startswith('_'): continue
        for value in values:
            verdict=check(field, value)
            rows.append({"field":field, "value":value, "blocked":verdict.blocked,
                         "rule":verdict.rule or "", "classification":"false_positive" if verdict.blocked else "true_negative"})
    fps=[r for r in rows if r['blocked']]
    total=len(rows)
    report={"corpus":path.name, "total_checked":total, "false_positive_count":len(fps),
            "false_positive_rate":len(fps)/total if total else 0.0,
            "false_positives":fps,
            "interpretation":"Rate over the instructor-provided synthetic benign corpus, not production traffic."}
    (HERE/'fp_report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    with (HERE/'benign_traffic_results.csv').open('w', newline='', encoding='utf-8') as f:
        w=csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
    print(f"Benign entries checked: {total}")
    print(f"False positives: {len(fps)} ({report['false_positive_rate']:.2%})")
    for r in fps: print(f"  [{r['field']}] {r['value']!r} -> {r['rule']}")
    print(f'Wrote {HERE / "fp_report.json"} and {HERE / "benign_traffic_results.csv"}')
    return report
if __name__ == '__main__':
    ap=argparse.ArgumentParser(); ap.add_argument('corpus', nargs='?'); a=ap.parse_args(); main(a.corpus)

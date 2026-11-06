"""Regression checks for evidence integrity; no DVWA/model calls are made."""
import ast
import csv
import hashlib
import json
import re
from pathlib import Path

from seclab.attack import Payload
from seclab.scan import ScanResult, compare_scanners

HERE = Path(__file__).resolve().parent


def test_notebook_syntax():
    notebook = json.loads((HERE / 'hw2_web_attack_defend.ipynb').read_text(encoding='utf-8'))
    for cell in notebook['cells']:
        if cell['cell_type'] == 'code':
            ast.parse(''.join(cell['source']))


def test_xss_oracles_require_the_reflected_sink():
    notebook = json.loads((HERE / 'hw2_web_attack_defend.ipynb').read_text(encoding='utf-8'))
    namespace = {'re': re, 'Payload': Payload}
    for cell in notebook['cells']:
        if cell['cell_type'] != 'code':
            continue
        tree = ast.parse(''.join(cell['source']))
        functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                     and node.name in {'xss_script_oracle', 'xss_event_oracle'}]
        exec(compile(ast.Module(body=functions, type_ignores=[]), '<oracles>', 'exec'), namespace)
    for name, text in [('xss_script_oracle', '<ScRiPt>window.__HW2_XSS__=1</ScRiPt>'),
                       ('xss_event_oracle', '<img src=x onerror=window.__HW2_XSS_BYPASS__=1>')]:
        oracle = namespace[name]
        payload = Payload(text)
        assert oracle(payload, f'<pre>Hello {text}</pre>')[0]
        assert not oracle(payload, f'{text}<pre>Hello Ada</pre>')[0]
        assert not oracle(payload, '<pre>Hello &lt;script&gt;safe</pre>')[0]
        assert not oracle(payload, 'login page or error response')[0]


def test_archived_duel_metrics_match_findings_and_source():
    artifact = json.loads((HERE / 'duel' / 'part_c_results.json').read_text(encoding='utf-8'))
    truth = json.loads((HERE / artifact.get('ground_truth_document', 'ground_truth.json')).read_text(encoding='utf-8'))
    keys = {(item['rule'], item['location']) for item in truth['findings']}
    findings = {name: [ScanResult(**item) for item in items]
                for name, items in artifact['findings'].items()}
    scores = compare_scanners(findings, keys)
    for name, score in scores.items():
        for metric in ('tp', 'fp', 'fn', 'precision', 'recall', 'f1'):
            assert score[metric] == artifact['comparison'][name][metric]
    if 'source_files' in artifact:
        paths = [HERE / 'duel' / 'dvwa_source' / name for name in artifact['source_files']]
        source = '\n\n'.join(f'FILE: {path.name}\n{path.read_text(encoding="utf-8")}' for path in paths)
    else:
        source = (HERE.parents[2] / 'labs' / 'vuln-web' / 'app' / 'vulnweb_app.py').read_text(encoding='utf-8')
    assert hashlib.sha256(source.encode()).hexdigest() == artifact['source_sha256']


def test_reviewed_fix_matches_deployment():
    deployed = (HERE / 'defend' / 'medium_parameterized.php').read_text(encoding='utf-8')
    reviewed = (HERE / 'duel' / 'dvwa_source' / 'sqli_fixed.php').read_text(encoding='utf-8')
    assert deployed == reviewed
    truth = json.loads((HERE / 'ground_truth_manual.json').read_text(encoding='utf-8'))
    assert all((HERE / 'duel' / 'dvwa_source' / item['location']).is_file()
               for item in truth['findings'] + truth['true_negatives'])


def test_deployed_evidence_has_bypasses_and_functioning_fix():
    with (HERE / 'defend' / 'dvwa_deployed_results.csv').open(encoding='utf-8', newline='') as handle:
        rows = list(csv.DictReader(handle))
    waf = [row for row in rows if row['stage'] == 'deployed-waf']
    fixed = [row for row in rows if row['stage'] == 'own-parameterized-fix']
    assert len(waf) == len(fixed) == 6
    assert all(row['error'] == '' and row['trials'] == '3' for row in rows)
    assert {row['payload'] for row in waf if row['successes'] == '3'} == {
        '1/**/OR/**/1=1', '1 OR TRUE', '1 OR 2>1'}
    assert all(row['successes'] == '0' for row in fixed)


def test_php_and_python_benign_classifications_agree():
    with (HERE / 'defend' / 'dvwa_waf_benign_results.csv').open(encoding='utf-8', newline='') as handle:
        php = {(r['original_field'], r['input']): r['blocked'] for r in csv.DictReader(handle)}
    with (HERE / 'defend' / 'benign_results.csv').open(encoding='utf-8', newline='') as handle:
        python = {(r['field'], r['input']): r['blocked'] for r in csv.DictReader(handle)}
    assert php == python
    assert len(php) == 26 and sum(value == 'True' for value in php.values()) == 2


def test_duel_runs_share_reviewed_inputs_and_are_uncached():
    artifact = json.loads((HERE / 'duel' / 'part_c_results.json').read_text(encoding='utf-8'))
    frozen = json.loads((HERE / 'duel' / 'reviewed_inputs.json').read_text(encoding='utf-8'))
    assert artifact['source_sha256'] == frozen['source_sha256']
    assert hashlib.sha256((HERE / 'ground_truth_manual.json').read_bytes()).hexdigest() == frozen['ground_truth_sha256']
    first, second = artifact['llm']['run_1'], artifact['llm']['run_2']
    assert first['prompt'] == second['prompt']
    assert first['meta']['format_schema'] == second['meta']['format_schema']
    assert [first['seed'], second['seed']] == [11, 29]
    for response in [first, second]:
        assert response['backend'] == 'ollama'
        assert response['model'] == artifact['llm']['model']
        assert response['temperature'] == 0.7
        assert response['cached'] is False and response['error'] is None

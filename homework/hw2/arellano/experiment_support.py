"""Docker-backed operations used by the notebook. Only the HW2 container is modified."""
import csv
import hashlib
import json
import os
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent


def docker(*arguments):
    completed = subprocess.run([os.environ.get('DOCKER_EXE', 'docker'), *map(str, arguments)],
                               check=True, text=True, capture_output=True, timeout=180)
    return completed.stdout.strip()


def evaluate_deployed_defenses(client, cases, sqli_bypasses, oracle, run_payloads):
    """Deploy both defenses at the very same DVWA Medium endpoint, then restore it."""
    container = os.environ.get('DVWA_CONTAINER', 'hw2-arellano-dvwa-1')
    remote = '/var/www/html/vulnerabilities/sqli/source/medium.php'
    from seclab.attack import Payload
    payloads = [case['payload'] for case in cases.values()] + list(sqli_bypasses)
    records = []
    with tempfile.TemporaryDirectory(prefix='hw2-defense-') as temporary:
        backup = Path(temporary) / 'medium.php'
        docker('cp', f'{container}:{remote}', backup)
        docker('cp', backup, f'{container}:/tmp/hw2-original-medium.php')
        try:
            assert client.security_level() == 'medium'
            def send(value):
                body = client.post_form('vulnerabilities/sqli/', {'id': value, 'Submit': 'Submit'})
                if '<title>Vulnerability: SQL Injection' not in body and 'HW2 WAF blocked' not in body:
                    raise RuntimeError('Unexpected SQLi response: login/error page cannot count as defense.')
                return body

            for stage, patch, attacks in [
                ('deployed-waf', 'medium_waf.php', payloads),
                ('own-parameterized-fix', 'medium_parameterized.php', payloads),
            ]:
                docker('cp', HERE / 'defend' / patch, f'{container}:{remote}')
                docker('exec', container, 'php', '-l', remote)
                # Apache's OPcache revalidates timestamps periodically, not on docker cp.
                time.sleep(3)
                control = send('1')
                marker = 'HW2 deployed WAF' if stage == 'deployed-waf' else 'HW2 parameterized fix'
                assert marker in control, f'{stage}: stale PHP implementation served'
                assert 'First name: admin' in control and not oracle(Payload('1'), control)[0]
                findings = run_payloads(attacks, send=send, oracle=oracle, trials=3, progress=True)
                for index, finding in enumerate(findings):
                    expected = stage == 'deployed-waf' and index >= len(cases)
                    assert finding.successes == (3 if expected else 0), (stage, finding)
                    if stage == 'deployed-waf' and index < len(cases):
                        assert 'HW2 WAF blocked' in send(finding.payload.text)
                    records.append(dict(stage=stage, payload=finding.payload.text,
                                        successes=finding.successes, trials=finding.trials,
                                        evidence=finding.evidence, error=finding.error or ''))
                print(stage, ': benign ID 1 functional; all expected effects confirmed')
                if stage == 'deployed-waf':
                    corpus = json.loads((HERE / 'benign_traffic.json').read_text(encoding='utf-8'))
                    benign_rows = []
                    for field, values in corpus.items():
                        if field.startswith('_'):
                            continue
                        for value in values:
                            body = client.post_form('vulnerabilities/sqli/', {'id': value, 'Submit': 'Submit'})
                            benign_rows.append({'original_field':field, 'input':value,
                                                'blocked':'HW2 WAF blocked' in body})
                    with (HERE / 'defend' / 'dvwa_waf_benign_results.csv').open('w', newline='', encoding='utf-8') as handle:
                        writer = csv.DictWriter(handle, fieldnames=list(benign_rows[0]))
                        writer.writeheader()
                        writer.writerows(benign_rows)
                    blocked = sum(row['blocked'] for row in benign_rows)
                    print(f'Deployed PHP WAF, provided generic corpus: {blocked}/{len(benign_rows)} blocked')
                    assert blocked == 2 and len(benign_rows) == 26
        finally:
            docker('cp', backup, f'{container}:{remote}')
            time.sleep(3)
            assert client.security_level() == 'medium'
    output = HERE / 'defend' / 'dvwa_deployed_results.csv'
    with output.open('w', newline='', encoding='utf-8') as handle:
        writer = csv.DictWriter(handle, fieldnames=list(records[0]))
        writer.writeheader()
        writer.writerows(records)
    print('Wrote', output)


def freeze_manual_truth(source):
    """Record the reviewed inputs before executing the new scanners/model calls."""
    record = {
        'frozen_at_utc': datetime.now(timezone.utc).isoformat(),
        'source_sha256': hashlib.sha256(source.encode()).hexdigest(),
        'ground_truth_sha256': hashlib.sha256((HERE / 'ground_truth_manual.json').read_bytes()).hexdigest(),
        'method': 'Manual source review, prior historical-results exposure disclosed in ground_truth_manual.json',
    }
    (HERE / 'duel' / 'reviewed_inputs.json').write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')


def structured_reviewer(**kwargs):
    """seclab.LLM with a JSON shape constraint; finding labels remain unconstrained."""
    import urllib.request
    from seclab.llm import LLM, OLLAMA_URL

    class StructuredOllama(LLM):
        def _ollama(self, prompt, temperature, seed):
            fields = ['rule', 'location', 'severity', 'confidence', 'evidence']
            schema = {'type':'array', 'items':{
                'type':'object', 'properties':{key:{'type':'string'} for key in fields},
                'required':fields, 'additionalProperties':False}}
            body = {'model':self.model, 'prompt':prompt, 'stream':False, 'format':schema,
                    'options':{'temperature':temperature, 'seed':seed, 'num_predict':2048}}
            request = urllib.request.Request(f'{OLLAMA_URL}/api/generate',
                data=json.dumps(body).encode(), headers={'Content-Type':'application/json'})
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                data = json.load(response)
            metadata = {key:data[key] for key in ('eval_count','prompt_eval_count','total_duration') if key in data}
            metadata['format_schema'] = schema
            return data.get('response', ''), metadata

    return StructuredOllama(**kwargs)

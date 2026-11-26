"""Reproducible, in-process SQLi defense experiment; no external services.

This SQLite numeric-ID lab is a supplemental target, NOT a fresh DVWA run.
Run from anywhere: python homework/hw2/montero/defend/evaluate.py
"""
import csv
import html
import json
import re
import sqlite3
from pathlib import Path
from urllib.parse import unquote_plus

HERE = Path(__file__).resolve().parent
RULES = [
    (r'(?i)\b(?:or|and)\b\s+\d+\s*=\s*\d+', 'numeric SQL tautology'),
    (r'(?i)union[\s/*]+select', 'SQL UNION'),
    (r'(?i)<\s*script\b', 'script tag'),
    (r'(?i)\bdrop[\s/*]+table', 'DROP TABLE'),
    (r'[;&|`$()]', 'shell metacharacter'),
]
ATTACKS = [
    ('part-a', '1 OR 1=1'),
    ('comment-separators', '1/**/OR/**/1=1'),
    ('boolean-constant', '1 OR TRUE'),
    ('comparison-operator', '1 OR 2>1'),
]


def waf_block(value):
    normalized = html.unescape(unquote_plus(value))
    return next((name for pattern, name in RULES if re.search(pattern, normalized)), None)


def vulnerable(db, value):
    return db.execute(f'SELECT id, secret FROM users WHERE id = {value}').fetchall()


def fixed(db, value):
    # The placeholder keeps the entire input in one data value.
    return db.execute('SELECT id, secret FROM users WHERE id = ?', (value,)).fetchall()


def through_waf(db, value):
    if waf_block(value) is not None:
        return []
    return vulnerable(db, value)


def oracle(rows):
    return any(secret == 'HW2-PRIVATE-ROW-CANARY' for _, secret in rows)


def main():
    db = sqlite3.connect(':memory:')
    try:
        db.execute('CREATE TABLE users (id INTEGER PRIMARY KEY, secret TEXT)')
        db.executemany('INSERT INTO users VALUES (?, ?)',
                       [(1, 'ordinary-row'), (2, 'HW2-PRIVATE-ROW-CANARY')])
        assert vulnerable(db, '1') == fixed(db, '1') == [(1, 'ordinary-row')]
        rows = []
        for name, value in ATTACKS:
            before = sum(oracle(vulnerable(db, value)) for _ in range(3))
            after = sum(oracle(fixed(db, value)) for _ in range(3))
            blocked = waf_block(value) is not None
            waf_successes = sum(oracle(through_waf(db, value)) for _ in range(3))
            assert before == 3 and after == 0
            assert blocked == (name == 'part-a')
            assert waf_successes == (0 if blocked else 3)
            rows.append(dict(case=name, payload=value, waf_blocked=blocked,
                             vulnerable_successes=before, waf_successes=waf_successes,
                             fixed_successes=after, trials=3))
        with (HERE / 'sqli_results.csv').open('w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
        corpus = json.loads((HERE.parent / 'benign_traffic.json').read_text(encoding='utf-8'))
        traffic = [(field, value) for field, values in corpus.items()
                   if not field.startswith('_') for value in values]
        with (HERE / 'benign_results.csv').open('w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['field', 'input', 'blocked', 'rule'])
            for field, value in traffic:
                writer.writerow([field, value, waf_block(value) is not None, waf_block(value) or ''])
        fp = sum(waf_block(value) is not None for _, value in traffic)
        print('Supplemental target: in-process SQLite numeric-ID lab (not DVWA)')
        print('Initial SQLi coverage: 1/1; same-intent SQLi bypasses: 3/3')
        print('Parameterized fix: 0/4 payloads leak the canary; benign ID lookup works')
        print(f'Benign false positives: {fp}/{len(traffic)} = {fp/len(traffic):.2%}')
    finally:
        db.close()


if __name__ == '__main__':
    main()

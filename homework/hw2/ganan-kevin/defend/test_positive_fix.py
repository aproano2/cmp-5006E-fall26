"""B2: exercise the structural fixes against Part-A inputs and WAF bypasses.

This is a local unit-level harness for the functions in positive_fix.py. It
does not modify the instructor's vulnweb_app.py; integration is represented
by replacing the corresponding vulnerable handler with the fixed function.
"""
from __future__ import annotations
import csv, json, sqlite3, sys
from html.parser import HTMLParser
from pathlib import Path
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from positive_fix import do_login_fixed, do_reflect_fixed, do_ping_fixed
from cases import PART_A_XSS, XSS_BYPASSES
CANARY='FLAG-sqli-9f2c-admin-session'
SQLI="admin' OR '1'='1"
CMDI='127.0.0.1; whoami'

class TagCollector(HTMLParser):
    def __init__(self): super().__init__(convert_charrefs=True); self.tags=[]; self.hrefs=[]
    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        for k,v in attrs:
            if k.lower()=='href': self.hrefs.append(v or '')

def make_db():
    db=sqlite3.connect(':memory:')
    db.execute('CREATE TABLE users (id INTEGER, user TEXT, pw TEXT, secret TEXT)')
    db.execute('INSERT INTO users VALUES (1,?,?,?)',('admin','s3cr3t',CANARY))
    db.execute('INSERT INTO users VALUES (2,?,?,?)',('alice','password','ordinary-row'))
    db.commit(); return db

def main():
    rows=[]
    db=make_db()
    body=do_login_fixed(db, SQLI, 'irrelevant')
    parsed=json.loads(body)
    rows.append({'test':'SQLi Part-A payload','payload':SQLI,'passed':CANARY not in body and parsed.get('ok') is False,'evidence':body})
    apostrophe_body=do_login_fixed(db, "o'brien", 'irrelevant')
    apostrophe_result=json.loads(apostrophe_body)
    rows.append({'test':'Benign apostrophe username','payload':"o'brien",'passed':'error' not in apostrophe_result and apostrophe_result.get('ok') is False,'evidence':apostrophe_body})
    xss_inputs=[('XSS Part-A baseline',PART_A_XSS)]+[(item['id'],item['payload']) for item in XSS_BYPASSES]
    for label,payload in xss_inputs:
        body=do_reflect_fixed(payload); parser=TagCollector(); parser.feed(body)
        # The wrapper's normal html/body/h1 tags are expected; no user-supplied
        # script or anchor tags may be parsed as active markup.
        passed=('script' not in parser.tags and 'a' not in parser.tags and not parser.hrefs)
        rows.append({'test':label,'payload':payload,'passed':passed,'evidence':body})
    cmd=json.loads(do_ping_fixed(CMDI))
    rows.append({'test':'CMDi Part-A payload','payload':CMDI,'passed':cmd.get('rejected') is True and cmd.get('would_run') is None,'evidence':json.dumps(cmd)})
    out=HERE/'positive_fix_results.csv'
    with out.open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=['test','payload','passed','evidence']);w.writeheader();w.writerows(rows)
    for r in rows: print(f"{'PASS' if r['passed'] else 'FAIL'} {r['test']}: {r['evidence']}")
    print(f"\n{sum(r['passed'] for r in rows)}/{len(rows)} checks passed. Wrote {out}")
    db.close()
    if not all(r['passed'] for r in rows): raise SystemExit(1)
if __name__=='__main__': main()

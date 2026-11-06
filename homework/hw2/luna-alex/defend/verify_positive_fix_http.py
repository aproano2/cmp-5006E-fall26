"""Verify the integrated B2 fixed target over HTTP, including all lab payloads."""
from __future__ import annotations
import argparse, csv, json
from html.parser import HTMLParser
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen
import sys
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from cases import PART_A_XSS, XSS_BYPASSES
CANARY="FLAG-sqli-9f2c-admin-session"
SQLI="admin' OR '1'='1"
CMDI="127.0.0.1; whoami"
class Tags(HTMLParser):
    def __init__(self): super().__init__(convert_charrefs=True); self.tags=[]; self.hrefs=[]
    def handle_starttag(self,tag,attrs):
        self.tags.append(tag.lower())
        self.hrefs.extend(v or '' for k,v in attrs if k.lower()=='href')
def request(url,data=None):
    req=Request(url,data=data,headers={'Content-Type':'application/json'} if data is not None else {},method='POST' if data is not None else 'GET')
    try:
        with urlopen(req,timeout=5) as r:return r.status,r.read().decode('utf-8',errors='replace')
    except HTTPError as e:return e.code,e.read().decode('utf-8',errors='replace')
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--base-url',default='http://127.0.0.1:8002');ap.add_argument('--out',default=str(HERE/'positive_fix_http_results.csv'));a=ap.parse_args();base=a.base_url.rstrip('/')
    rows=[]
    status,body=request(base+'/login',json.dumps({'user':SQLI,'pw':'x'}).encode())
    rows.append({'test':'SQLi Part-A payload','http_status':status,'passed':CANARY not in body,'evidence':body})
    status,body=request(base+'/login',json.dumps({'user':"o'brien",'pw':'irrelevant'}).encode())
    try: apostrophe=json.loads(body)
    except json.JSONDecodeError: apostrophe={}
    rows.append({'test':'Benign apostrophe username','http_status':status,'passed':status==200 and 'error' not in apostrophe and apostrophe.get('ok') is False,'evidence':body})
    for label,payload in [('XSS Part-A baseline',PART_A_XSS)]+[(x['id'],x['payload']) for x in XSS_BYPASSES]:
        status,body=request(base+'/?name='+quote(payload,safe=''))
        parsed=Tags();parsed.feed(body)
        passed=status==200 and not any(t in parsed.tags for t in ('script','a')) and not parsed.hrefs
        rows.append({'test':label,'http_status':status,'passed':passed,'evidence':body})
    status,body=request(base+'/ping',json.dumps({'host':CMDI}).encode())
    try:payload=json.loads(body)
    except json.JSONDecodeError:payload={}
    passed=status==200 and payload.get('rejected') is True and payload.get('would_run') is None
    rows.append({'test':'CMDi Part-A payload','http_status':status,'passed':passed,'evidence':body})
    out=Path(a.out);out.parent.mkdir(parents=True,exist_ok=True)
    with out.open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=['test','http_status','passed','evidence']);w.writeheader();w.writerows(rows)
    for r in rows:print(f"{'PASS' if r['passed'] else 'FAIL'} {r['test']} (HTTP {r['http_status']})")
    print(f"{sum(bool(r['passed']) for r in rows)}/{len(rows)} passed. Wrote {out}")
    if not all(r['passed'] for r in rows):raise SystemExit(1)
if __name__=='__main__':main()

"""Optional browser proof for the three XSS bypasses (requires Playwright Chromium).

Install once: py -m pip install playwright ; py -m playwright install chromium
Run with the WAF proxy listening on port 8001.
"""
from __future__ import annotations
import argparse, csv, json, sys
from pathlib import Path
from urllib.parse import quote
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from cases import XSS_BYPASSES
from waf import check
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--base-url',default='http://127.0.0.1:8001');ap.add_argument('--out',default=str(HERE/'browser_bypass_results.json'));args=ap.parse_args()
    try: from playwright.sync_api import sync_playwright
    except ImportError: raise SystemExit('Playwright is not installed. Run: py -m pip install playwright')
    results=[]
    with sync_playwright() as p:
        try: browser=p.chromium.launch(headless=True)
        except Exception as exc: raise SystemExit(f'Chromium is unavailable. Run: py -m playwright install chromium. Details: {exc}')
        for item in XSS_BYPASSES:
            verdict=check('search_or_name',item['payload'])
            record={'id':item['id'],'payload':item['payload'],'waf_allowed':not verdict.blocked,'dialog_fired':False,'dialog_message':None,'error':None}
            if verdict.blocked:
                record['error']='WAF blocked the candidate; this is not a bypass.'
                results.append(record); continue
            page=browser.new_page()
            dialogs=[]
            def handle_dialog(dialog):
                dialogs.append(dialog.message); dialog.accept()
            page.on('dialog',handle_dialog)
            try:
                page.goto(args.base_url.rstrip('/')+'/?name='+quote(item['payload'],safe=''),wait_until='domcontentloaded',timeout=10000)
                page.locator('a').click(timeout=5000)
                record['dialog_fired']=bool(dialogs)
                record['dialog_message']=dialogs[0] if dialogs else None
                if not dialogs: record['error']='Link click completed but no JavaScript dialog was observed.'
            except Exception as exc:
                record['error']=f'{type(exc).__name__}: {exc}'
            finally: page.close()
            results.append(record)
        browser.close()
    out=Path(args.out);out.write_text(json.dumps(results,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    for r in results: print(f"{r['id']}: allowed={r['waf_allowed']} dialog_fired={r['dialog_fired']} error={r['error']}")
    print(f'Wrote {out}')
    if not all(r['waf_allowed'] and r['dialog_fired'] for r in results): raise SystemExit('At least one browser-level bypass was not confirmed. Report the exact result.')
if __name__=='__main__': main()

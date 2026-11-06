"""Local reverse proxy that deploys the B1 WAF in front of vuln-web.

Keep the upstream target and this proxy bound to loopback for the class lab.
Example:
  python defend/waf_proxy.py --upstream http://127.0.0.1:8000 --port 8001
Test through http://127.0.0.1:8001, not directly against port 8000.
"""
from __future__ import annotations
import argparse
import json
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request, urlopen
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from waf import check

class ProxyHandler(BaseHTTPRequestHandler):
    upstream = "http://127.0.0.1:8000"

    def log_message(self, fmt, *args):
        logging.info("%s - %s", self.client_address[0], fmt % args)

    def _body(self):
        length = int(self.headers.get('Content-Length', '0') or 0)
        return self.rfile.read(length) if length else b''

    def _block(self, field, value):
        verdict = check(field, value)
        if verdict.blocked:
            logging.warning("action=block method=%s path=%s field=%s rule=%s",
                            self.command, self.path, field, verdict.rule)
            body = json.dumps({"blocked": True, "field": field,
                               "rule": verdict.rule,
                               "message": "Request blocked by local lab WAF"}).encode()
            self.send_response(403)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return True
        logging.info("action=allow method=%s path=%s field=%s", self.command, self.path, field)
        return False

    def _inspect(self, body):
        parsed = urlsplit(self.path)
        if self.command == 'GET' and parsed.path in ('/', '/safe'):
            value = parse_qs(parsed.query, keep_blank_values=True).get('name', [''])[0]
            return self._block('search_or_name', value)
        if self.command == 'POST' and parsed.path == '/login':
            try:
                obj = json.loads(body.decode('utf-8') or '{}')
            except (UnicodeDecodeError, json.JSONDecodeError):
                obj = parse_qs(body.decode('utf-8', errors='replace'))
                obj = {k: (v[0] if v else '') for k, v in obj.items()}
            return self._block('login_username', str(obj.get('user', '')))
        if self.command == 'POST' and parsed.path == '/ping':
            try:
                obj = json.loads(body.decode('utf-8') or '{}')
            except (UnicodeDecodeError, json.JSONDecodeError):
                obj = parse_qs(body.decode('utf-8', errors='replace'))
                obj = {k: (v[0] if v else '') for k, v in obj.items()}
            return self._block('ping_host', str(obj.get('host', '')))
        return False

    def _forward(self):
        body = self._body() if self.command in ('POST', 'PUT', 'PATCH') else None
        if self._inspect(body or b''):
            return
        url = self.upstream.rstrip('/') + self.path
        headers = {}
        for key in ('Content-Type', 'Accept', 'User-Agent'):
            if self.headers.get(key):
                headers[key] = self.headers[key]
        req = Request(url, data=body, headers=headers, method=self.command)
        try:
            with urlopen(req, timeout=10) as response:
                status, response_body = response.status, response.read()
                content_type = response.headers.get('Content-Type', 'application/octet-stream')
        except HTTPError as exc:
            status, response_body = exc.code, exc.read()
            content_type = exc.headers.get('Content-Type', 'application/octet-stream')
        except (URLError, TimeoutError, OSError) as exc:
            status = 502
            response_body = json.dumps({"error": "upstream unavailable", "detail": str(exc)}).encode()
            content_type = 'application/json; charset=utf-8'
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(response_body)))
        self.end_headers()
        self.wfile.write(response_body)

    do_GET = _forward
    do_POST = _forward
    do_PUT = _forward
    do_PATCH = _forward

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--upstream', default='http://127.0.0.1:8000')
    ap.add_argument('--host', default='127.0.0.1', help='Loopback only by default.')
    ap.add_argument('--port', type=int, default=8001)
    args = ap.parse_args()
    if args.host not in ('127.0.0.1', 'localhost', '::1'):
        raise SystemExit('For this homework, bind the WAF proxy to loopback only.')
    ProxyHandler.upstream = args.upstream
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    server = ThreadingHTTPServer((args.host, args.port), ProxyHandler)
    print(f'WAF proxy listening on http://{args.host}:{args.port} -> {args.upstream}')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

if __name__ == '__main__':
    main()

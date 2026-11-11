"""Original course target and optional defenses; loopback only."""
import argparse
import json
import sys
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "labs/vuln-web/app"))
import vulnweb_app as app
from defend import controls


def handler(mode):
    if mode == "original":
        return app.Handler
    if mode not in ("waf", "positive"):
        raise ValueError(f"Unknown mode: {mode}")

    class Handler(app.Handler):
        def do_GET(self):
            u = urlparse(self.path)
            if u.path not in ("/", "/safe"):
                return super().do_GET()
            name = parse_qs(u.query).get("name", [""])[0]
            if mode == "positive" or u.path == "/safe":
                body = controls.reflect(name)
            else:
                body = app.do_reflect(name)
            self._send(200, body, "text/html")

        def do_POST(self):
            path = urlparse(self.path).path
            form = self._form()
            if path == "/login":
                user, pw = form.get("user", ""), form.get("pw", "")
                if mode == "positive":
                    return self._send(200, controls.login(app.DB, user, pw))
                if mode == "waf":
                    reason = next((controls.waf_reason(v) for v in (user, pw)
                                   if controls.waf_reason(v)), None)
                    if reason:
                        return self._send(403, json.dumps({"blocked": reason}))
                return self._send(200, app.do_login(user, pw))
            if path == "/ping":
                host = form.get("host", "")
                if mode == "positive":
                    code, body = controls.ping(host)
                    return self._send(code, body)
                return self._send(200, app.do_ping(host))
            self._send(404, json.dumps({"error": "not found"}))
    return Handler


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("original", "waf", "positive"), default="original")
    parser.add_argument("--port", type=int, default=8974)
    args = parser.parse_args()
    with ThreadingHTTPServer(("127.0.0.1", args.port), handler(args.mode)) as server:
        print(f"{args.mode}: http://127.0.0.1:{args.port}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass

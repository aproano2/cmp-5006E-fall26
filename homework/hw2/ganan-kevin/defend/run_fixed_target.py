"""Run a patched copy of vuln-web with the B2 structural fixes on loopback."""
from __future__ import annotations
import argparse
import importlib.util
import sys
from pathlib import Path
from http.server import ThreadingHTTPServer

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from positive_fix import do_login_fixed, do_reflect_fixed, do_ping_fixed

def load_module(path: Path):
    spec = importlib.util.spec_from_file_location("vulnweb_app_fixed", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load target app: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--app-path", required=True, help="Path to labs/vuln-web/app/vulnweb_app.py")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8002)
    args = ap.parse_args()
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        raise SystemExit("The fixed teaching target must bind to loopback only.")
    app = load_module(Path(args.app_path).resolve())
    app.DB = app.make_db()
    app.do_login = lambda user, pw: do_login_fixed(app.DB, user, pw)
    app.do_reflect = do_reflect_fixed
    app.do_ping = do_ping_fixed
    server = ThreadingHTTPServer((args.host, args.port), app.Handler)
    print(f"Fixed vuln-web listening on http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

if __name__ == "__main__":
    main()

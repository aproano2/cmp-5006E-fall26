# B2 — Positive model: structural fixes

**Selected vulnerability for the required B1/B2 comparison: reflected XSS (`do_reflect`).** The function `do_reflect_fixed` applies `html.escape` before inserting `name` into an HTML text node. The guarantee is conditional: every path that renders this value must call the fixed function, and the result must remain in an HTML text context (not be decoded, concatenated into JavaScript, or reparsed as raw HTML).

The helper file also contains a parameterized SQL query (`do_login_fixed`) and a hostname allowlist (`do_ping_fixed`) so the entire three-sink sample can be regression-tested. These are additional structural examples; the scored B1/B2 comparison remains the XSS sink.

To test the real request handlers with the fixes wired in, start a patched local copy on port 8002:

```powershell
python defend/run_fixed_target.py --app-path labs/vuln-web/app/vulnweb_app.py --port 8002
```

In another terminal run:

```powershell
python defend/verify_positive_fix_http.py --base-url http://127.0.0.1:8002
```

The CSV must show that the SQLi canary is absent, the XSS `<script>` and all three bypass candidates are encoded as text rather than parsed as links, and the CMDi host is rejected before a command string is constructed. This is an integrated test of a patched copy; it does not modify the instructor's original source or container.

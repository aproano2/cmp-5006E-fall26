# Lab: vuln-web

A small, deliberately vulnerable web app for week 6. It does double duty: you
**attack the running app** (SQLi, reflected XSS, command injection) and you
**scan its source** in the LLM-vs-scanner duel — and because the target and the
scan-subject are the *same readable file*, you can check every tool's finding by
eye.

> ⚠️ **Scope.** Runs on `127.0.0.1` only. See
> [`../../resources/ethics-and-scope.md`](../../resources/ethics-and-scope.md).

## Bring it up

```bash
docker build -t seclab/vuln-web:local labs/vuln-web    # first time only
python -m seclab.targets --up vuln-web
python -m seclab.targets --down                        # tear down
```

No Docker? It's stdlib-only, so run it directly:

```bash
PORT=8000 python labs/vuln-web/app/vulnweb_app.py
```

The [`../../notebooks/week-06-injection.ipynb`](../../notebooks/week-06-injection.ipynb)
notebook uses the Docker target if present and otherwise runs the app in-process,
so it works either way.

## The sinks

| Endpoint | Bug | Confirm it by |
|---|---|---|
| `POST /login {user,pw}` | **SQL injection** (string-formatted query) | leaking the admin canary `FLAG-sqli-...` |
| `GET /?name=<x>` | **reflected XSS** (unescaped into HTML) | `<script>` returned un-encoded |
| `POST /ping {host}` | **command injection** (string-built command) | a shell metacharacter reaching the command |
| `GET /safe?name=<x>` | **fixed** XSS (html.escape) | a **true negative** — nothing to find |

The command-injection sink *simulates* execution (it reports what would run rather
than running it), so the lab is safe to run anywhere while the bug — untrusted data
reaching a command context — stays real and detectable.

## Two ways to find bugs, both in the notebook

1. **Dynamically** — attack the running app, confirm with a `seclab.attack` oracle.
   A reflected string is not XSS; a canary leak *is* SQLi.
2. **Statically** — the duel: a classical scanner and an LLM both read `app/vulnweb_app.py`,
   scored against a hand-built ground-truth set with `seclab.scan`. The scanner is
   precise but misses the SQLi (its rule is line-oriented and the query spans two
   lines — a real scanner failure mode); the LLM catches all three but hallucinates
   a bug in code that has none. **Neither cleanly finds access-control issues,
   because the app has none and that class needs app context, not pattern-matching.**

## The bug, in one sentence

All three sinks are the same bug: **untrusted data crosses into a control
channel** — SQL, HTML, or a shell command. Read `app/vulnweb_app.py`; every intentional
weakness is commented `# VULN`, and the fixes rhyme (parameterize / encode / don't
build the command from strings).

## Verify the lab

```bash
pytest labs/vuln-web/test_vuln_web.py -q
```

Pins that the three sinks are exploitable, `/safe` is a true negative, and benign
input never confirms — so the lab can't silently rot into un-attackability.

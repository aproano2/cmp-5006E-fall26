# Part A — Attack Results

> **Team:** Juan Diego Cadena · Omar Gordillo · Pablo Jarrín · Santiago Rodríguez

All tests were run only against the course's local `vuln-web` application. The
target does not include a security-level switch, so we added a small modeled
Medium pre-filter in the harness. Each normal payload is blocked by that filter,
while the modified payload reaches the real application.

| Class | Payload that bypassed the filter | Bypass | Oracle result | OWASP 2021 |
|---|---|---|---|---|
| SQL injection | `admin' oR 1=1--` | Mixed-case SQL keyword | Admin canary leaked in 2/2 trials | A03: Injection |
| Reflected XSS | `<ScRiPt>alert('HW2-XSS')</ScRiPt>` | Mixed-case HTML tag | Unescaped script element returned in 2/2 trials | A03: Injection |
| Command injection | `127.0.0.1 && whoami` | Used `&&` instead of the blocked semicolon | Target reported the extra shell operator in 2/2 trials | A03: Injection |

The oracles check a security effect rather than a different-looking response.
SQLi must leak `FLAG-sqli-...`, XSS must return an unencoded script element, and
command injection must set `injection_detected` to true.

## Broken Access Control

We do not classify these findings as A01 Broken Access Control. The application
has no sessions, roles, ownership checks, or protected routes. SQL injection
does expose the admin row, but the root cause is attacker-controlled SQL syntax.
Calling it access control would hide the actual fix, which is parameterization.

The detailed reproducible evidence is in `attack_results.csv`.

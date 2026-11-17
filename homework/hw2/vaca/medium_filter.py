"""The "Medium" built-in filter each Part-A attack must bypass.

`vuln-web` ships NO input filter, so to satisfy Part A's requirement — confirm
each class "at the Medium filter level, so each requires a bypass of the built-in
filter" — this module reproduces DVWA's Medium filters verbatim in Python, one
per sink, and applies them to the input before it reaches the vulnerable
`vuln-web` sink. These are the actual DVWA `medium.php` defenses:

  * SQLi  (login): mysqli_real_escape_string — backslash-escape quotes/specials.
  * XSS   (name) : str_replace('<script>', '', name) — drop the literal tag.
  * cmdi  (host) : blacklist '&&' and ';' (str_replace to '').

Each is a *negative* filter, and each has a five-minute bypass (case / alternate
tag / alternate separator / encoding) — that is the Part-A lesson and it feeds
straight into Part B.  Reference: DVWA `vulnerabilities/{sqli,xss_r,exec}/source/
medium.php` (read from the running DVWA Medium container, 2026-11-06).
"""

from __future__ import annotations


def sqli_medium(user: str) -> str:
    """mysqli_real_escape_string equivalent: backslash-escape the characters it
    escapes. Note vuln-web's query wraps the value in single quotes, so a bypass
    must avoid an un-escaped quote (use a comment/`\\`-swallow or keyword-only
    tautology)."""
    out = []
    for ch in user:
        if ch in ("'", '"', "\\", "\x00", "\n", "\r", "\x1a"):
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "".join(out)


def xss_medium(name: str) -> str:
    """DVWA Medium reflected-XSS filter: strip the literal lowercase `<script>`
    opening tag once. Bypassed by case variation or a non-script tag."""
    return name.replace("<script>", "")


def cmdi_medium(host: str) -> str:
    """DVWA Medium command-injection filter: blacklist `&&` and `;`. Bypassed by
    `|`, a backtick, `$()`, or a newline — none of which are on the list."""
    for bad in ("&&", ";"):
        host = host.replace(bad, "")
    return host

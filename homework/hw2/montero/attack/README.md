# Part A — Current DVWA Medium evidence

Current execution: [results.csv](results.csv) and notebook Part A.
Historical group output: [recorded_results.txt](recorded_results.txt).

| Class | Payload | Medium bypass | Oracle | Successes |
|---|---|---|---|---:|
| SQLi | `1 OR 1=1` | Escaping quoted strings does not validate an unquoted numeric expression | Extra seeded row `Surname: Smith`, absent for ID 1 | 3/3 |
| XSS | `<ScRiPt>window.__HW2_XSS__=1</ScRiPt>` | Case-sensitive removal of lowercase script syntax | Raw unique script in the reflected sink | 3/3 |
| cmdi | `127.0.0.1 \| whoami` | Pipe survives the separator blocklist | `www-data` on its own line inside command output | 3/3 |

Each benign control stayed negative in all three trials. The notebook uses
seclab.attack and rejects request/oracle errors. The loopback target is explicitly
set to Medium in the same session before testing.

All map to OWASP 2021 A03 (Injection). SQLi uses an additional synthetic user row
as a data-disclosure canary, not the literal vuln-web token. XSS confirms raw
executable markup as specified in the assignment; browser execution is not measured.

No independent role/ownership-policy violation is demonstrated, so these tests
do not establish a separate A01 finding. DVWA has authentication; this result
does not assert that authentication or access-control code is absent.

# Ground-truth provenance and source verification

`ground_truth.json` is a verbatim copy of the instructor fixture in
`../duel-2-web/ground_truth.json`; `benign_traffic.json` is also copied unchanged.
The set was supplied by the course, not independently discovered by our team.
The following source review documents its basis without using scanner output
as truth. This documentation was added during the submission audit, after the
original tool runs; it does not establish a pre-registered student benchmark.

| Key | Source evidence in labs/vuln-web/app/vulnweb_app.py |
|---|---|
| sqli, do_login | user and pw are interpolated into query before DB.execute(query); Part A retrieves the admin canary with the wrong password. |
| xss, do_reflect | name is inserted directly into an HTML text context without escaping; Part A confirms a script element. |
| cmdi, do_ping | host is concatenated into command; a metacharacter detector simulates injection. No OS command runs. |
| True negative: do_reflect_safe | html.escape(name) protects the HTML text context. |
| Absent: broken-access-control | No sessions, roles or protected resource policy exist to establish an independent access-control defect. |

Part A uses the original handler; the local WAF and positive fixes belong to
Part B. Both tools in Part C review the same original source, as identified by their saved invocation
and runner configuration.

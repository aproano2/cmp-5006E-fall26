# Control Scorecard — SQL Injection Defense

> **Team:** Juan Diego Cadena · Omar Gordillo · Pablo Jarrín · Santiago Rodríguez

| Axis | Before / WAF blocklist | After parameterization | Evidence or limitation |
|---|---|---|---|
| 1 · Threat model | An unauthenticated local attacker controls the `user` and `pw` values. | Unchanged. | The attack harness sends values to the local `/login` endpoint. |
| 2 · Guarantee | No general guarantee. Three regular expressions block only matching text. | User values cannot alter SQL structure, provided all values use placeholders and no other path concatenates SQL. | `parameterized_login` uses `?` placeholders. |
| 3 · Coverage | 1/1 known Part A SQLi payload blocked. | 0/4 tested injections succeeded. | `waf_coverage.csv` and `positive_model_results.csv`. |
| 4 · Bypass | 3/3 changed tautologies passed and leaked the admin canary. | No payload-level bypass was found in this test set. A different unsafe query path would be outside the guarantee. | `waf_bypasses.csv`. |
| 5 · False-positive cost | 4/26 benign inputs blocked: 15.4%. | No benign input is rejected by a security pattern; normal credential checks still apply. | `false_positives.csv`. |
| 6 · Operational cost | Rules need continued tuning as new syntax appears. | Developers must use placeholders consistently and review dynamic query fragments. | Production latency and staffing cost were not measured in this small local lab. |
| 7 · Observability | The WAF returns the matching rule name, which is recorded in CSV. | The demo returns only login success/failure and has no audit log. | This is a limitation of the teaching app. |
| 8 · Failure mode | Fails open on unknown variants and can silently miss attacks. | The tested query treats attacker input as data. Database errors would raise rather than authenticate the user. | Another concatenated query would silently lose the guarantee. |

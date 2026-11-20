# Where our attack, defense, or comparison might be unfair
**Members**: Daniel Andrade - Andrés Vega - Carlos Flores

- **Was your ground-truth set built independently of the tools you scored?**

    The ground truth employed in Part C is independent by construction. It is the one provided in [`ground_truth.json`](../duel-2-web/ground_truth.json), which was hand-built by reading the source of `vuln-web`, not by running any tool. Because it was never derived from scanner or LLM output, scoring our tools against it does not rig the result.

    The one caveat is that it is a small set (3 real findings plus one true negative and one not-present class), so precision and recall move in coarse 0.33 steps and a single flaky finding swings recall noticeably.

    A second caveat is about judgement calls. Two of the LLM's v2 findings are literally true but not in the ground truth: a hard-coded `CANARY_SECRET` in `make_db`, and a missing Content-Security-Policy header in `Handler`. We count both as false positives because the secret is the lab's deliberate canary and a missing CSP header is absent hardening, not an exploitable bug. Counting them as correct would raise mean v2 precision from 0.67 to 0.83, so this choice moves the result.

---

- **Did you tune the WAF for an hour but use a default LLM prompt (or vice versa)?**

    In Part C the effort was not symmetric. The LLM side got several rounds of work, and some of them happened *after* we had seen its answers:

    1. We shaped the prompt so each answer line matches our parser (`[SEVERITY] <type> in <function>: <reason>`) and added a `NONE` fallback.
    2. After prompt v1 reported style issues (missing type hints), we wrote **prompt v2**, which adds a generic rule: "Report only security vulnerabilities (OWASP Top 10 / CWE classes). Do not report code style, typing, naming, or other code-quality issues." The rule names no specific finding, but we wrote it after seeing v1. That is why we report v1 and v2 side by side.
    3. The parser was also revised after seeing the answers. In 4 of the 6 v2 runs the model put the function name or a generic word ("Injection") in the vulnerability-type field and named the bug only in the reason (e.g. `LOW do_ping in do_ping: ... command injection ...`). We made the parser read the bug class from the reason in that case and recorded each such mapping (`mapped_by = model:reason` in `findings.csv`). This rule raised v2's score: if the parser only trusted the type field, v2 recall would be 0.33 in seeds 0 and 4 and 0 in the other four runs, instead of 0.33–0.67.

    The scanner got much less. We ran `semgrep` with three registry configs (`auto`, `p/security-audit`, `p/python`) and nothing more: no custom rules, and no positive control, i.e. no file these configs are known to flag. So semgrep's 0/3 is partly a real limitation (registry rules are framework/taint-oriented and do not match a stdlib `http.server` + `sqlite3` app), partly a consequence of our own effort, and we cannot fully rule out that no applicable rule ran at all. A small custom rule for an f-string passed to `execute()` would be the natural positive control; we did not write one.

    In short, we compare an LLM whose prompt and parser were adjusted to this target against an out-of-the-box scanner.

    On the WAF side (Part B1), our filter only ever saw the `user` field: our harness always sends `pw = "x"`. The app builds the password into the query the same way, so a real deployment of this blocklist would be bypassed simply by putting the payload in the password field. Our coverage and bypass numbers describe a one-field filter.

---

- **Is your benign-traffic corpus realistic, or does it dodge your rules by luck?**

    First, it is important to mention that the invented cases were deliberately chosen to include blocklist-tripping shapes (`anita--jones`, `name or id=1`, `o'brien--legacy`). The idea behind this reasoning was to test the WAF on adversarially-plausible usernames. Therefore, they do not dodge the rules by luck — they are designed to stress exactly the three patterns our blocklist uses, and they produce an 18.8% false-positive rate (3/16).

    In contrast, both groups of the benign traffic provided in [`benign_traffic.json`](../duel-2-web/benign_traffic.json) scored 0% blocked: `login_username` 0/9 and `search_or_name` 0/12. The second group is the interesting one, because it deliberately contains attack-adjacent English (e.g. `select the union option`, `drop table tennis`) meant to trip a *broad* blocklist. Ours passes it not by luck but because our three patterns are narrow: our `union ... select` rule requires that order (and `select the union option` has them reversed), and `drop table tennis` matches none of `--`, `union...select`, or `or ... =`. So the 0% on provided traffic is honest, but it mostly tells us our blocklist is narrow, not that it is safe on real traffic.

    The consequence is that our false-positive evidence rests almost entirely on the invented corpus, and that corpus is biased *upwards*: we wrote it knowing our three rules, and an entry like `name or id=1` is not a realistic username. The 18.8% is therefore an upper bound we built on purpose, not an estimate of the rate on real traffic. A second limitation is that we sent the `search_or_name` group to the login filter, which is not where that text would normally be submitted.

---
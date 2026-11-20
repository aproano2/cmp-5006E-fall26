# Where Our Attack, Defense, or Comparison Might Be Unfair

> **Team:** Juan Diego Cadena · Omar Gordillo · Pablo Jarrín · Santiago Rodríguez

1. **The Semgrep result reflects our rules, not Semgrep.** We wrote the three
   rules in `duel/semgrep_rules.yml` after reading the source. Two of them are
   regexes that match literal lines of `vulnweb_app.py`, so those two true
   positives were effectively decided by us. The SQLi rule only matches a SELECT
   f-string on a single line, so its miss on the two-line query was predictable.
   This is a limitation of our rule, not of Semgrep: its normal pattern syntax
   matches multi-line constructs. A fair comparison would use the community
   registry (`p/python`), which we did not run.

2. **The ground truth is not independent of the scanner.** The same team built
   `ground_truth.json` and wrote the Semgrep rules, both from the same reading of
   the source. The LLM comparison is also easier than real code review: the
   source contains comments marking the intentional vulnerabilities, and the LLM
   received the whole file while the WAF and scanner received a few rules.

3. **There is no real Medium level.** The course `vuln-web` target has no Medium
   switch. We wrote a small case-sensitive pre-filter so each attack needed a
   bypass. Because we designed the filter, we also set how hard it was to bypass;
   this is not equivalent to testing DVWA Medium.

4. **WAF coverage rests on one known attack.** We report 1/1 coverage on the
   Part A payloads for the defended endpoint. One payload is too few to say the
   WAF covers known attacks; it only shows the rule matches that payload.

5. **The positive fix was not tested through the real endpoint.** The
   parameterized login was evaluated against a separate SQLite database in
   `defend/controls.py`, not by patching `/login` in the running app. It shows
   the technique works; it does not show the deployed app is fixed.

6. **The false-positive rate only describes this corpus.** The 26 benign inputs
   were provided by the course and contain deliberately attack-adjacent phrases.
   The 15.4% rate (4/26) does not estimate the rate on real user traffic.

7. **We observed no hallucination, but the LLM did fail.** Two runs returned the
   same three correct findings. Two runs are too few to claim the model never
   hallucinates. The model did show a real failure: in run 2 it ignored the
   requested severity format, so its output was not stable even when its
   findings were.

8. **XSS was confirmed without a browser.** The oracle checks that an unescaped
   script element is reflected in the response. That is a strong necessary
   condition for this sink, but we did not execute JavaScript in a browser.
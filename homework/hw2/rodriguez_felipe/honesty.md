# Where our attack, defense, or comparison might be unfair

## 1. Ground truth independence

The Part C ground truth was taken from the instructor's `ground_truth.json` and checked against the application source, not copied from Semgrep or the LLM output. This reduces circular scoring, but it is still a small, hand-written benchmark with only three known findings. The precision, recall, and F1 values describe this target and these rules; they should not be generalized to other applications.

## 2. Unequal tool scope and tuning

Semgrep uses a small custom rule set written specifically for this homework. It is not a broad, default security scan, and its rules are intentionally limited to the SQL injection and reflected-XSS patterns in the selected functions. Therefore, a missed command-injection finding reflects the rule set's limited coverage, not proof that Semgrep as a product cannot detect command injection. The LLM receives the complete source and a purpose-written prompt, so the tools do not have identical analysis methods or scope. Both configurations are included in the repository to make this limitation visible.

## 3. Realism of the benign corpus and WAF

The benign corpus is supplied by the course and contains only 26 examples. It deliberately includes words such as `select` and `union` that can trigger a broad blocklist. This is useful for demonstrating false positives, but it is not representative of all production traffic, languages, or user behavior. The measured false-positive rates in `defend/benign_results.csv` should be interpreted only as results on this fixed corpus.

## 4. Least certain attack reproduction

The command-injection finding is the one whose real-world impact we describe most carefully. The course target does not execute an operating-system command; it simulates the command string and reports whether shell metacharacters are present. The oracle confirms the intended injection condition in the simulator, but it does not prove that a real shell command ran. The SQLi canary and reflected-XSS checks also have bounded oracles: the XSS test confirms an unescaped script element in returned HTML, not JavaScript execution in a browser.

## 5. LLM variability and interpretation

The LLM was run twice with the same source and prompt, nonzero temperature, different seeds, and caching disabled. Two runs are the minimum required to expose possible variation, not enough to estimate a stable statistical rate. A different model, prompt, temperature, or seed could change the findings. Any LLM claim that is not supported by the source—especially a claim about broken access control when no sessions, roles, or authorization checks exist—must be treated as a false positive rather than accepted because it sounds plausible.
In the second recorded LLM run, the explanation for `do_login` incorrectly associated reflected XSS with that function, even though the XSS vulnerability is located in `do_reflect`. The parser preserves the reported label and scores invalid labels as unmatched without inferring vulnerability classes from function names; the rationale hallucination is documented separately.

## 6. Target and defense scope

Part A uses the original course HTTP handler without added filters. Part B1
adds only our SQLi WAF, while B2 applies parameterization, HTML escaping, and
host validation. The original application source remains unchanged. The
recorded evidence includes HTTP responses and source hashes for these modes.

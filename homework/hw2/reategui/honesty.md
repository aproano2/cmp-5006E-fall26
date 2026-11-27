**Group:** María Emilia Cueva (00328938), Santiago Reátegui (00331329), Jorge Gomez (00329264)

# Where our attack, defense, or comparison might be unfair.

## 1. Was your ground-truth set built independently of the tools you scored?

Yes, the ground-truth set (`ground_truth.json`) was supplied by the instructor as a hand-reviewed fixture independent of Semgrep or the local LLM, and all three vulnerability effects were verified using separate HTTP oracles. However, this universe is extremely small—consisting of only three primary findings (`sqli`, `xss`, `cmdi`). Because of this tiny sample size, it cannot reliably estimate how these tools would perform on a real-world codebase, and `seclab.scan` treats any discovery outside those three keys as a false positive, making location mapping and exact label matching rigid.

Furthermore, both human and model reviewers benefit directly from the source code containing explicit `# VULN` comments, making this an easier review than inspecting unknown code.

## 2. Did you tune the WAF for an hour but use a default LLM prompt (or vice versa)?

Yes, there is a clear asymmetry in how much effort went into tuning each mechanism. We deliberately chose `or`, `union`, `select`, and `drop` substrings after reading the target and corpus, making the SQLi WAF deliberately weak and broad. The three bypasses use the already known admin username and comment out the password. They are genuine canary leaks, but a filter with comment/quote normalization could change the result.

Tuning a WAF while keeping the scanner rules narrow also makes a cross-tool 'winner' narrative unfair; instead, we report each tool's exact configuration. In contrast, the LLM review used the standard course prompt template (`seclab.llm`) with fixed temperatures and seeds (11 and 29) without iterative prompt engineering or adversarial prompt tuning.

## 3. Is your benign-traffic corpus realistic, or does it dodge your rules by luck?

The benign-traffic corpus (26 requests across three fields) is synthetic and deliberately shaped to expose the weaknesses of naive blocklists. It does not reflect a realistic production web workload. Words like `select` and `union` were intentionally embedded into otherwise normal strings (such as `select_committee_chair` and `unionrep_delegate`) specifically to trigger our substring regexes and generate a measurable 22.22% field-specific false-positive rate on login usernames (compared to 7.69% across all requests).

Additionally, our evaluation relies on a local **Medium layer** (`lab.py`), as the supplied `vuln-web` app has no Medium setting. We wrote three simple pre-handler rules and showed each obvious form is blocked before testing a bypass. While this makes the exercise reproducible in our harness, we further validated these concepts by deploying DVWA in Docker configured to its Medium security level. Testing our bypass techniques live—such as case-variant XSS (`<ScRiPt>alert(1)</ScRiPt>`) and pipe-concatenated command injection (`127.0.0.1 | whoami`)—confirmed that these payloads successfully defeat real-world blocklist filters, proving they operate on standard application flaws rather than being isolated to our custom setup.

## 4. Which Part-A finding are you least sure reproduces, and why?

**Command injection (CMDI)** and our oracle limits are initially what we were least sure about reproducing in a real production environment. In the course's `vuln-web` app, the cmdi sink only echoes a constructed command and an injection flag (`injection_detected=true` and `would_run`); it never actually executes `whoami` via a live shell. Similarly, the XSS oracle detects an unescaped script node but does not run a browser, and the fixed ping code constructs an argument vector without proving a future subprocess behavior.

However, **validating equivalent command injection logic against a real application instance (such as DVWA Medium in Docker)** confirmed that pipe-concatenated payloads like `127.0.0.1 | whoami` successfully escape weak filters and execute live shell commands (returning `www-data`). This proved that the simulation limitation was specific to the course's safe lab design rather than the vulnerability class itself.

Finally, LLM variation provides bounded evidence: two uncached calls with different seeds reveal how these two runs differed, but they do not estimate a stable distribution or prove that the model will behave the same on another Ollama version or machine.

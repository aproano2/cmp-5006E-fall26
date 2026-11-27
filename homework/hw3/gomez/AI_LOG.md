# AI use log — Homework 3

## 2026-11-25 — Local red team runner, experiments, and initial report

*Who:* Jorge Gomez

*Tool:* OpenAI Codex (GPT-6).

*What we asked:* Build a local HTTP red-team runner (redteam.py) against labs/vuln-llm/app/vulnllm_app.py covering all Part A attacks, Part B1 level-2 filtering and bypasses, and Part B2 least-privilege containment, with 5 trials per case and oracle confirmation. Also asked to make path resolution portable across Windows and Linux and to draft the initial README.md, report.md, and honesty.md.

*What we got:* redteam.py using loopback HTTP servers and seclab.attack.contains_oracle, separate JSON evidence outputs for the deterministic mock and local Ollama, and initial drafts of the report, README, and honesty section.

*What we did with it / verification:* We ran redteam.py against the local app on both the deterministic mock and local Ollama (qwen2.5:3b) with 5 trials per case, saving per-trial evidence to evidence/mock-results.json and evidence/ollama-results.json. We revised the private RAG query after noticing the first version also retrieved poisoned-promo, updated bypass_oracle to detect the complete canary after stripping separators while confirming the literal token is absent, and discarded an early Ollama run that hit a timeout. We also verified cross-platform execution on Windows and Linux without modifying any course target files, and confirmed the course's labs/vuln-llm/test_vuln_llm.py suite still passes 13/13.

*Did we understand it?* Yes. We understand how direct and indirect prompt injections cross the trust boundary from untrusted data into instructions, why unscoped RAG leaks private-vip due to missing retrieval authorization, and why level-2 exact-substring redaction (out.replace(SECRET, "[REDACTED]")) is easily bypassed by character/separator transformations and never mediates tool outputs. We also understand why enforcing the ["get_faq"] allow-list inside the Python dispatcher (run_agent) guarantees 100% containment of email exfiltration even though the injection still fires the tool plan (0% coverage).

*What we kept or rejected:* Kept all oracle-confirmed results, the separator-normalized bypass check, and the conditional framing of the dispatcher guarantee (including the caveat that /policy is unauthenticated in this lab app). Rejected treating mock 5/5 runs as model reliability, pooling mock and Ollama results, and claiming the tool policy prevents the injection itself.

## 2026-11-26 — Rubric validation, local verification, and wording refinement

*Who:* María Emilia Cueva

*Tool:* Gemini.

*What we asked:* Audit all submission files (redteam.py, README.md, report.md, honesty.md, and both evidence JSONs) against the Homework 3 instructions, map each requirement to its exact implementation in redteam.py, and refine the Markdown files to be clearer, more direct, and consistent with our actual results.

*What we got:* A full rubric check confirming that all four Part A attacks, the Part B1 filter/bypass runs, the Part B2 containment checks, and the JSON evidence match the reported tables. Gemini also flagged a few inconsistencies—such as omitting the 4/5 hyphen-bypass case in honesty.md, stating that the spacing bypass only worked on the mock, and leaving redundant draft notes in README.md and report.md—and helped restructure honesty.md to directly answer the three Part C questions.

*What we did with it / verification:* Independently ran python3 redteam.py --backend mock --trials 5 on Linux and verified that all 15 cases matched evidence/mock-results.json with 0 invalid trials (5/5 on Part A attacks, 0/5 on filtered text endpoints, 5/5 on agent_filtered and both bypasses, and 5/5 on agent_contained, benign_faq, and legitimate_balance_denied). Updated README.md, report.md, and honesty.md to remove unnecessary boilerplate, directly address the Part C questions, and accurately reflect all reliability-limited Ollama cases (2/5 direct, 3/5 indirect, and 4/5 hyphen bypass) as well as bypasses on both backends.

*Did we understand it?* Yes. Mapping redteam.py line by line to the rubric made each oracle crystal clear—particularly how bypass_oracle checks both separator-normalized recovery and absence of the literal canary, and how agent_contained proves 0% coverage (the planner still requests lookup_balance and send_email) alongside 100% containment (sent == [] and DENIED_BY_POLICY). It also reinforced the axis-5 false-positive tradeoff shown by legitimate_balance_denied: restricting /policy to ["get_faq"] deterministically stops exfiltration, but breaks legitimate account-balance queries.

*What we kept or rejected:* Kept the rubric mapping, the cleaner wording across README.md and report.md, and the restructured honesty.md with the corrected 4/5 bypass caveat and both-backend note. Rejected keeping leftover local-draft notes and redundant portability details in the final submission.

## 2026-11-26 — Final submission review

*Who:* Santiago Reátegui

*Tool:* Antigravity (Gemini).

*What we asked:* Review the completed Homework 3 submission against the
assignment instructions to verify that all technical requirements, code, and
reports were properly done.

*What we got:* A full checklist review of Parts A, B1, B2, and C, the Control
Scorecard, the oracles in redteam.py, and consistency between report.md,
honesty.md, and the JSON evidence files.

*What we did with it / verification:* Re-ran `python3 redteam.py --backend
mock --trials 5` locally and verified that all 15 cases passed with 0 invalid
trials, that regenerating evidence/mock-results.json matched the saved file,
and that all counts in report.md matched both evidence/mock-results.json
and evidence/ollama-results.json. No technical errors were found; all parts
of the assignment are complete and verified.

*Did we understand it?* Yes — we reviewed the direct/indirect prompt
injection, RAG exfiltration/poisoning, confused-deputy tool abuse, level-2
output-filter bypasses, least-privilege containment guarantee, and honesty
limitations, and confirmed everything is accurate and ready for submission.

*What we kept or rejected:* Kept all verified code, evidence files, and
final report sections with no further technical changes needed.
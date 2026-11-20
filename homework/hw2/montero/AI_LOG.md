# AI Log — Homework 2

## Assistance and authorship

Codex assisted with interpreting the rubric, implementing local experiment
support, reviewing source, drafting reports, and checking artifact consistency.
The exact assistant model identifier was not exposed in this session.

AI assistance covered the notebook senders and seclab.attack oracles, the PHP
WAF and parameterized SQLi patch, the SQLite supplement, Semgrep integration,
local Ollama prompts, result normalization, tests, and reproduction instructions.
The group remains responsible for understanding and reviewing the submission.
AI-generated explanations are not experimental evidence.

## Reference and evidence provenance

- The historical target was labs/vuln-web/app/vulnweb_app.py. Its
  ground_truth.json is an instructor fixture, not an independently constructed
  group reference. Historical outputs were imported from Santiago's branch
  homework/hw-2-arellano, commit 65cee0f, and retained separately.
- The current Part C target is duel/dvwa_source/: three DVWA Medium PHP
  snapshots and our fixed SQLi negative control. The upstream snippets retain
  their license; they are not group-authored vulnerable code.
- ground_truth_manual.json records AI-assisted manual reasoning about the PHP
  before the new tool calls. Historical outputs were already known. This is
  not a blinded study, and final human group review remains necessary.
- Current attack and defense CSVs record local DVWA execution. Supplemental
  SQLite results and historical macOS results are labeled separately.
- The supplied benign_traffic.json is a generic teaching corpus. Its 2/26
  blocked inputs measure signature false positives, not valid-ID usability.

## Recorded implementation and experiment work

Codex helped prepare Windows reproduction instructions, a dedicated local lab,
CSV exports, and the three-member attribution in the README and notebook.
The experiment support deploys our PHP WAF and prepared-statement patch at the
same Medium SQLi endpoint and restores the original source afterward.
A cached PHP response invalidated an early fix test; implementation markers and
revalidation checks were added before the defense experiment was repeated.

The retained current evidence reports three Medium attack classes confirmed
3/3 each, three same-intent SQLi WAF bypasses confirmed 3/3 each, and no extra-row
leak for the six replayed strings at our parameterized sink. These statements
refer to recorded experiments, not new runs performed during this document review.

Part C retains actual Semgrep and local Ollama responses. Semgrep's custom rules
miss SQL built through a variable. Two structured qwen2.5:0.5b calls use identical
inputs, temperature 0.7, seeds 11/29, and disabled cache reads. An earlier
formatting attempt is preserved in duel/format_attempt rather than hidden.
Recorded F1 scores are 0.800, 0.333, and 0.000; run-to-run Jaccard is 0.167.
Unsupported access-control claims and the invented SQL query in exec_medium.php
are discussed instead of removed from the scores.

## Final submission review — 2026-11-06

The user requested another review because edits appeared unsaved, and required
English throughout the submission documents. Codex saved English versions of
this log and REVISION.md, retained the substantive honesty limitations, and
checked that the notebook contains the same honesty text.

Corrections retained: instructor-fixture attribution, prior-results exposure,
the distinction between generic benign prose and valid IDs, the limited scope
of the SQLi guarantee, and command injection as the least portable Part-A result.
Rejected claims: that AI assistance constitutes human group review, that the
historical reference was group-authored, or that old test results are fresh runs.

The prior review recorded 29 passing tests. Those tests and DVWA/LLM experiments
were not rerun in this document-only review: .hw2-venv is unavailable and the
existing .venv Python trampoline is broken. Artifact checks confirmed the
reference hash, matching honesty text, no notebook error outputs, 12 deployed
defense rows, and 2/26 corpus blocks. Final group review and committing all required evidence remain
necessary. No commit, PR, or message to another person was sent.

## Scope

Experiments target only the authenticated loopback lab with synthetic data.
Raw outputs, rather than screenshots or AI prose, support the reported results.
The group must verify each claim and review the AI-assisted manual reference
before submission, following resources/ethics-and-scope.md.

## Fork publication preparation

The user authorized committing the submission and pushing it to the configured
myfork remote for group review. Codex removed the README link to the excluded
internal REVISION.md note and prepared only homework/hw2/tulcan files for the
submission commit. No PR or messages to classmates are part of this step.

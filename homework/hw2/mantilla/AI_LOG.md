# AI assistance log

## 2026-11-05 — HW2 workspace preparation

**Tool:** OpenAI Codex.

**What I asked:** Prepare the local repository for an HW2 submission by pull
request under `homework/hw2/mantilla/`, making that folder the main working
directory for the homework.

**What I got:** The assistant inspected repository state and assignment policies,
refreshed the remote references, created `hw2-mantilla` from course `upstream/main`,
and drafted the directory layout, README, working instructions, and report
templates. It copied the instructor's benign corpus unchanged and created an
explicitly empty ground-truth template for later independent source review. It
identified that the supplied `vuln-web` has no Medium filter mode. No homework
attacks, defenses, scanner comparison, or result CSVs were produced during setup.

**What I did with it:** The scaffold is saved for my review and further work.
Earlier committed studio work remains on `main`; unrelated uncommitted work is
preserved. I still need to implement and run the experiments, complete the
reports, and review every claim before submission.

**Did I understand it?** The repo was fixed for a clean hw2 submission. Then I read and verified the information in the homework to start the implementation with my work.

## 2026-11-05 — Review and local import of the group's implementation

**Tool:** OpenAI Codex.

**What I asked:** Review the group's HW2 results in
`jjjulianleon/cmp-5006E-fall26`, branch `hw2`, under `homework/hw2/leon/`, and bring
the checked work into my local submission directory for a later PR.

**What I got:** The assistant downloaded source commit
`1805e412dbacf2685e264fc4ac51d8984f3ae03d` to a temporary checkout, inspected the
code and evidence against the assignment, and reproduced the attack, defense,
and saved-output scoring commands. All six original result CSVs matched the
committed source exactly. It also checked DVWA's primary-source Medium examples,
verified the benign corpus, and checked `/safe` and the WAF/Medium composition.
It found that adjusted scoring excluded by rule name alone and incorrectly
excused Bandit's canary finding. The local scorer now excludes only exact
`(rule, location)` matches, making Bandit's adjusted precision 33.33% instead of
50%, with strict scores unchanged. It documented the custom Medium ambiguity,
Low-baseline WAF measurements, B2 replay scope, and model-output provenance limits
in `REVIEW.md` and clarified the reports.

**What I did with it:** The reviewed group implementation is saved locally under
`homework/hw2/mantilla/`, with raw scanner/LLM outputs preserved. The source group's
log is retained verbatim in `AI_LOG_GROUP.md`; its first-person understanding
statements remain those of the original author and are not my personal
confirmation. I still need to review the implementation and remaining rubric
questions with the group before the final submission. No new scanner or LLM
inference run was performed during this review, and no push or PR was made.

**Did I understand it?** Yes, the review showed the gaps in implementation between group's members, the work is now to fix and harmonize implementation details.

## 2026-11-05 — Readiness and group contributions

**Tool:** OpenAI Codex.

**What I asked:** Check whether the deliverable is ready and account for the
other members' changes.

**What I got:** Confirmation that the files are present and the recorded checks
pass, with the custom Medium interpretation and Part-B scope still identified
as rubric questions. The submission instructions now explicitly say to merge
every member's contributions with the review corrections and rerun affected
experiments before copying the shared version into individual folders.

**What I did with it:** These instructions are recorded in README.md and
REVIEW.md. Changes outside the pinned source and the reviewed local corrections
still require verification; personal AI-log confirmations remain pending.

**Did I understand it?** Yes, there were some changes needed still, so we organized a session to fix problems. 

## 2026-11-05 — Verifiable readiness gaps and full replay

**Tool:** OpenAI Codex.

**What I asked:** Determine which missing information can be verified in this
environment and what I can do to be sure the assignment is ready.

**What I got:** The assistant checked local runtime availability and attempted to
refresh the remote requirements; Git/web retrieval failed during this follow-up.
Ollama lists qwen2.5:3b, not the group's recorded qwen3.8:27b; the Docker command
is an inactive WSL integration stub, and the scanners are not installed. It added
`verify_readiness.py`, which reproduces all six original CSVs in an isolated,
renamed submission copy and records the complete payload replay separately.
It also found the general scorecard's 20-distinct-payload guidance and added a
self-contained supplementary corpus using input strings from my Week 7 work.
Every HW2 outcome was freshly measured; no prior studio results were copied.
The final check passed with 882 HTTP replay trials, 14 controls, and 30 distinct
SQLi strings. Both fixed configurations blocked every tested SQLi; the checker
confirmed three SQLi bypasses of V1 before Medium. The assistant added the
required before/after scorecard table and a concrete checklist in READINESS.md.

**What I did with it:** The additional code, corpus, reports, and new evidence
are saved for group review and synchronization. The original group raw tool
outputs and six original CSVs are preserved. I need to resolve the custom
Medium interpretation, merge any later contributions, and review the claims
personally before submitting. The assistant clarified that fixing one class is
explicitly required, so other unfixed routes alone do not invalidate a SQLi fix.

**Did I understand it?** After the last check, inspected the output files and confirmed that the implementation was correct. 

# Where our attack, defense, or comparison might be unfair.

1. **Reference exposure and authorship.** The original duel used instructor
   fixtures and retrospective review. The new PHP reference was manually reasoned
   with AI assistance before the new PHP tool calls, after exposure to historical
   vuln-web results. It is not blinded; group members must review it before submission.
2. **Unequal tool tuning.** Custom Semgrep rules intentionally miss SQL assembled
   in a variable. Scores describe these teaching rules, not Semgrep's standard
   security rules or a fair general ranking of models and scanners.
3. **Corpus realism.** The 26 examples mix names, usernames and hosts. Sending
   them through an ID-boundary filter measures its signatures, not whether they
   are valid numeric-ID requests. The 7.69% FP rate is not a production estimate.
   For example, `drop table tennis lessons for beginners` is legitimate search
   text, but not a legitimate ID for this form. Thus 2/26 measures false positives
   on the supplied generic corpus, not two valid DVWA lookups wrongly denied.
4. **Oracle scope.** XSS verifies raw script markup, not browser execution. SQLi
   discloses an additional seeded user row rather than the literal course canary.
   Current command tests run the real local shell effect; historical vuln-web
   command injection was simulated.
   **Least portable Part-A finding: command injection.** Its oracle expects
   `www-data` from `whoami`; a different container user, shell, or missing ping
   utility can change the response. It succeeded 3/3 in the recorded environment,
   but this is repeatability within one image, not across deployments.
5. **Fix scope.** Our PHP parameterized fix protects the chosen SQLi statement.
   It does not repair separate XSS/command endpoints or establish authorization.
   DVWA Impossible remains supplied code; SQLite remains a supplemental target.
6. **Model budget.** The new CPU experiment selects a smaller model than the
   historical 3B run. Its behavior must not be generalized to larger models.
   Comments and a recognizable teaching target can make review easier.
7. **Scoring and variability.** Findings collapse to class/filename keys, and
   duplicate database branches count once. Two samples are a small variability
   measurement, not proof of determinism. No hallucination may be invented to
   satisfy a report item; actual false positives are retained and discussed.
8. **Access-control context.** Authentication is outside the reviewed snippets.
   No observed A01 finding does not prove DVWA has no access-control weaknesses.
9. **Execution provenance.** Historical macOS outputs are preserved separately.
   Current CSVs/notebook record actual Windows-driven DVWA execution. Cached PHP
   initially invalidated a fix test; implementation markers and revalidation
   checks were added, and the final defense experiment was rerun successfully.
10. **Format retries and explanation quality.** An initial model attempt failed
    JSON parsing; both responses are retained in duel/format_attempt. Two new
    structured-output calls are scored, with the same schema for both seeds.
    Labels remain unconstrained. Even the one matching XSS finding has an
    incorrect explanation; class/file precision does not measure reasoning
    quality. The reference scores three intended findings rather than claiming
    an exhaustive audit of all possible DVWA issues.

# Reading List

**One anchor reading per week**, due *before* that week's Session A. You post a
short reading response 24 hours ahead, and one of you leads the 15-minute paper
discussion (instructor-led in week 1 only, to model it).

Two principles behind the choices:

1. **Primary sources where they exist.** The actual 1975 paper, the actual RFC, the
   actual law. Secondary explainers appear only where no primary source fits, or as
   an on-ramp to one.
2. **"Skim" means skim.** Where a lesson plan says to skim, it means it — Shannon
   1949 is dense and you are not expected to follow every derivation. Read for the
   *claim and its condition*, which is the habit this whole course is built on.

Every link below was checked and resolved on 2026-08-20. Where a source is
paywalled, a free author or archive copy is given.

---

## Week 0 — Getting ready

Course documents rather than external reading:
[`ethics-and-scope.md`](ethics-and-scope.md) (**required, and you sign it**) and a
skim of [`../syllabus.md`](../syllabus.md).

## Week 1 — Threat modeling & the four goals

**Saltzer, J. H. & Schroeder, M. D. (1975).** *The Protection of Information in
Computer Systems.* Proceedings of the IEEE 63(9), 1278–1308.
→ <https://web.mit.edu/Saltzer/www/publications/protection/>

Read **§I.A, the eight design principles** — economy of mechanism, fail-safe
defaults, complete mediation, open design, least privilege, and the rest. Fifty
years old and still the best short statement of what security engineering *is*. You
will meet least privilege again in week 10, where it is the only thing that
contains a hijacked agent.

## Week 2 — Why the guarantees hold

**Shannon, C. E. (1949).** *Communication Theory of Secrecy Systems.* Bell System
Technical Journal 28(4), 656–715.
→ <https://pages.cs.wisc.edu/~rist/642-spring-2014/shannon-secrecy.pdf>

Skim for the **perfect-secrecy result** and the idea of unicity distance. This is
the one week where a guarantee is *proved* rather than argued — and the lab then
breaks a one-time pad anyway, by violating its condition.

## Week 3 — Symmetric crypto in practice: modes, hashes, HMAC

No single paper. Three short reference items:

- **The ECB penguin** — the ECB section of *Block cipher mode of operation*:
  <https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation>
- **Length extension attacks** — the mechanism you exploit in the lab:
  <https://en.wikipedia.org/wiki/Length_extension_attack>
- **Krawczyk, Bellare & Canetti (1997).** *HMAC: Keyed-Hashing for Message
  Authentication*, RFC 2104 — the fix, and a primary source worth reading for how
  precisely it states what it promises: <https://www.rfc-editor.org/rfc/rfc2104>

## Week 4 — Asymmetric crypto & side channels

**Heninger, N., Durumeric, Z., Wustrow, E. & Halderman, J. A. (2012).** *Mining
Your Ps and Qs: Detection of Widespread Weak Keys in Network Devices.* USENIX
Security 2012.
→ <https://factorable.net/weakkeys12.extended.pdf> · project page:
<https://factorable.net/>

Skim the introduction and results. RSA's guarantee is clean; the deployment was
not. They factored keys belonging to live internet hosts because entropy at boot
was poor. The lab reproduces the shared-factor attack.

*Optional, for the broader picture:* **Boneh, D. (1999).** *Twenty Years of Attacks
on the RSA Cryptosystem.* Notices of the AMS 46(2).
→ <https://crypto.stanford.edu/~dabo/pubs/papers/RSA-survey.pdf>

## Week 5 — Protocols, TLS & PKI

**RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3 (2018).**
Skim **§1–2** only. → <https://www.rfc-editor.org/rfc/rfc8446>

Paired with a real mis-issuance case: the DigiNotar compromise, where a trusted
certificate authority issued fraudulent certificates later used against Iranian
Gmail users.

- ENISA, *Operation Black Tulip*:
  <https://www.enisa.europa.eu/media/news-items/operation-black-tulip>
- Background: <https://en.wikipedia.org/wiki/DigiNotar>

The lesson the lab makes concrete: the mathematics of the handshake was never the
weak part. The trust store was.

## Week 6 — Web attack surface & injection

**OWASP Top 10 — 2021 edition.** Read the list and the "what changed from 2017"
discussion. → <https://owasp.org/Top10/>

⚠️ Make sure you are reading the **2021** list and not 2017. Broken Access Control
moved to #1, and that matters here: it is also the category *least* amenable to
automated detection, as your week-6 scanner-versus-LLM duel will show.

*Optional:* the OWASP Web Security Testing Guide sections on injection and XSS.

## Week 7 — Web defense: WAFs, validation, and their costs

No paper; three practitioner sources, read for the *trade-off* rather than the
recipe:

- **OWASP Input Validation Cheat Sheet** — the positive-model argument:
  <https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html>
- **OWASP: Web Application Firewall** — what a WAF is and is not for:
  <https://owasp.org/www-community/Web_Application_Firewall>
- **OWASP CRS: False Positives and Tuning** — the operational cost nobody
  advertises, and the source of this week's uncomfortable result:
  <https://coreruleset.org/docs/concepts/false_positives_tuning/>

## Week 8 — Systems & supply chain

Two writeups, both about trusting a *name* instead of an *artifact*:

- **Freund, A. (2024).** The original oss-security disclosure of the **xz-utils
  backdoor** — a primary source, and a short one:
  <https://www.openwall.com/lists/oss-security/2024/03/29/4>
- **Birsan, A. (2021).** *Dependency Confusion: How I Hacked Into Apple, Microsoft
  and Dozens of Other Companies.*
  <https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610>
  *(Medium blocks automated link checking, so this is the one entry unverified by
  script; it loads normally in a browser.)* Vendor guidance on the fix, if you want
  it: <https://learn.microsoft.com/en-us/nuget/concepts/security-best-practices>

## Week 9 — Prompt injection

**Greshake, K., Abdelnabi, S., Mishra, S., Endres, C., Holz, T. & Fritz, M.
(2023).** *Not What You've Signed Up For: Compromising Real-World LLM-Integrated
Applications with Indirect Prompt Injection.* → <https://arxiv.org/abs/2302.12173>

Plus **OWASP Top 10 for LLM Applications (2025)**, entry **LLM01: Prompt
Injection** → <https://genai.owasp.org/llm-top-10/>

This is the flagship week. Read the paper asking one question throughout: *what
would the PreparedStatement equivalent be here?* There is not one, and that is the
point.

## Week 10 — RAG, agents & least privilege

**Greshake et al. (2023) revisited** — the application-integration sections, this
time for the retrieval and tool-use angle: <https://arxiv.org/abs/2302.12173>

Plus **OWASP LLM Top 10 (2025)**: **LLM06 Excessive Agency** and **LLM08 Vector &
Embedding Weaknesses** → <https://genai.owasp.org/llm-top-10/>

## Week 11 — Privacy: re-identification & differential privacy

**Narayanan, A. & Shmatikov, V. (2008).** *Robust De-anonymization of Large Sparse
Datasets.* IEEE Symposium on Security and Privacy 2008 — the Netflix Prize
de-anonymization.

The free preprint is the **2006** arXiv version, published under a different title,
*How To Break Anonymity of the Netflix Prize Dataset*:
→ <https://arxiv.org/abs/cs/0610105>

⚠️ Cite whichever version you actually read, with its own title and year. Treating
the preprint and the S&P paper as interchangeable is precisely the sloppiness the
week-0 CVE exercise was about.

*Optional:* **Sweeney, L. (2000).** *Simple Demographics Often Identify People
Uniquely* — the {ZIP, date of birth, sex} result your linkage attack reproduces:
→ <https://dataprivacylab.org/projects/identifiability/paper1.pdf>

## Week 12 — Governance, LOPDP & measurable harm

**Ecuador, Ley Orgánica de Protección de Datos Personales (LOPDP, 2021).** Read the
articles on the **right against solely-automated decisions**, **proportionality**,
and **cross-border transfer**.
→ <https://www.gob.ec/regulaciones/ley-organica-proteccion-datos-personales>

The only legal primary source in the course, and the reason the week exists: a right
is enforceable only if the harm can be *measured*, which is what the studio does.

## Week 13 — AI for defense: measurement, not vibes

**Fei, Q., Liu, X., Li, S., Wu, S., Hou, J., Chen, P. & Kang, Z. (2025).** *Large
Language Models Cannot Reliably Detect Vulnerabilities in JavaScript: The First
Systematic Benchmark and Evaluation.* → <https://arxiv.org/abs/2512.01255>

Chosen deliberately: a systematic benchmark with a negative result, not a vendor
claim. Read it for the *benchmark construction* as much as the conclusion — your own
week-13 measurement lives or dies on the same choices, and the notebook's
ground-truth bug is a worked example of getting one wrong.

*Alternate, if you prefer the older and broader study:* **Gao, Z., Wang, H., Zhou,
Y. et al. (2023).** *How Far Have We Gone in Vulnerability Detection Using Large
Language Models.* → <https://arxiv.org/abs/2311.12420>

Pair either with any serious **SOC alert-fatigue** writeup. The week's headline —
the automation paradox — is about analyst capacity, not model accuracy.

## Week 14 — AI-enabled offense, ethics & wrap-up

A recent threat report on phishing and deepfakes at scale. Either of:

- **ENISA Threat Landscape 2024**:
  <https://www.enisa.europa.eu/publications/enisa-threat-landscape-2024>
- **FBI Internet Crime Report 2024** (IC3):
  <https://www.ic3.gov/AnnualReport/Reports/2024_IC3Report.pdf>

Read for **base rates and reported losses**, not anecdotes. The week's demo argues
that durable defenses target what AI cannot change — sender provenance, domain age,
transaction structure — rather than the prose quality it just fixed.

---

## Term-long

**Perlroth, N. (2021).** *This Is How They Tell Me the World Ends: The Cyberweapons
Arms Race.* Bloomsbury.

Carried over from the fall-2025 offering, where it anchored the final project. Read
it across the term at your own pace; it supplies the market and policy context the
technical weeks deliberately hold constant. Weeks 8 and 14 refer to it directly.

---

## Notes for the instructor

- **Weeks 3, 7, 13 and 14 are the volatile entries.** Weeks 3 and 7 point at living
  documents (OWASP, CRS) that get reorganized; weeks 13 and 14 name a *recent* paper
  and a *recent* report, which by definition need replacing each offering.
  Everything else is a fixed primary source and will not rot.
- **Re-check the links before each term.** All verified 2026-08-20; the Medium
  article (week 8) cannot be script-checked.
- **The stub this file replaced listed "Wk4 Boneh 1999"**, but `weeks/week-04.md`
  assigns **Heninger et al. 2012**, which is what the lab reproduces. Boneh is kept
  as optional here. If you promote it back to the anchor, change the lesson plan too.
- **Weeks 3, 7, 13 and 14 previously had no named source at all** — their plans ask
  for "a short primer", "a short WAF-bypass piece", "a recent critical evaluation",
  "a recent threat report". Those are now specific. If you swap one, update the
  lesson plan's Reading line in the same commit so the two never drift.

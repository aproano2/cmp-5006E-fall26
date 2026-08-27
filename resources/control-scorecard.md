# The Control Scorecard

The single rubric used in **every week of this course**. By week 6 students should
reach for it unprompted; by week 14 they should be able to fill one in for a
control they have never seen.

Its purpose is to replace *"we added a WAF, so we're protected"* with a table that
survives a hostile reader.

> ## The question the scorecard forces:
> ## What does this control guarantee, against which adversary, and how do you know?

---

## The eight axes

| # | Axis | Question it answers | How to measure it |
|---|------|--------------------|--------------------|
| 1 | **Threat model** | Who is the adversary, and what can they do? | Named capabilities: network position, credentials held, compute, insider or not |
| 2 | **Guarantee** | What does it promise *before* you run it? | Prose claim **plus the condition it depends on** |
| 3 | **Coverage** | What fraction of the attack class does it stop? | Payloads blocked / payloads attempted, on ≥ 20 distinct payloads |
| 4 | **Bypass** | How does a motivated attacker get around it? | At least one working bypass, or a stated argument why none exists |
| 5 | **Cost — false positives** | What does it break for legitimate users? | FP rate on a benign-traffic corpus. **A control nobody can live with is not deployed.** |
| 6 | **Cost — operational** | What does it cost to run? | Latency added, CPU/RAM, hours of tuning, who is on call |
| 7 | **Observability** | If it fails, will you know? | Can you produce a log line, an alert, or a certificate of the decision? |
| 8 | **Failure mode** | When it breaks, *how* does it break? | Classify: fails closed, fails open, silently degrades, alerts nobody |

---

## Axis 2 is the one students undervalue

These are not the same kind of claim, and the difference is most of what this
course teaches:

> AES-256-GCM provides confidentiality and integrity **provided the nonce is never
> reused under the same key**. Reuse breaks integrity catastrophically and leaks
> plaintext relationships.

> The WAF blocked 18 of our 20 SQLi payloads. **No claim is made about the 21st.**

Push students to state every guarantee as a **conditional**, and grade it strictly.
"AES is secure" earns roughly half of the sentence above.

## ⚠️ Axis 4 is what makes this a security course

**A defense you have not tried to bypass is a defense you have not evaluated.**

Every studio requires an attempted bypass. Three outcomes are acceptable:

| Outcome | Credit |
|---|---|
| A working bypass, documented | **full** — this is the best case |
| A serious attempt, documented, with why it failed | **full** |
| No attempt | **zero for the axis** |

Finding a bypass is not a failure of your defense; **not looking** is a failure of
your evaluation.

## ⚠️ Axis 5 is what makes it an engineering course

Students love controls that block everything. Blocking everything is trivial —
unplug the server.

Every control must be measured against **benign traffic**, and the false-positive
cost stated in something a stakeholder cares about: legitimate requests dropped,
support tickets, hours of analyst time, revenue.

> A WAF that blocks 100 % of attacks and 4 % of real users will be turned off
> within a month, at which point its true coverage is 0 %.

---

## Scoring

Each axis is scored on **evidence quality**, not on whether the control won:

| Score | Meaning |
|-------|---------|
| 0 | Not addressed |
| 1 | Asserted without evidence ("the WAF handles that") |
| 2 | Tested once, with one payload |
| 3 | Tested across payloads, with a summary statistic |
| 4 | Tested across payloads **and** a bypass attempted **and** false positives measured, with a stated limitation |

A student who runs a careful evaluation concluding *"our control is weaker than we
thought"* scores higher than one who runs a sloppy evaluation concluding *"we are
secure."* **We grade the evaluation, not the verdict.**

---

## Required table format

Every duel, studio report, and the capstone includes this table, filled in:

| Axis | Before | After control | Evidence |
|------|--------|---------------|----------|
| Threat model | unauthenticated remote attacker, no creds | unchanged | `threat-model.md` |
| Guarantee | none | blocks known SQLi patterns **if** the CRS ruleset matches | — |
| Coverage | 0/20 payloads blocked | 18/20 blocked | `results/coverage.csv` |
| **Bypass** | — | **found: case-mixing + inline comment evades rule 942100** | `results/bypass.md` |
| FP cost | 0 % | **2.1 % of benign requests blocked** | `results/benign.csv` |
| Op cost | — | +12 ms p95, 180 MB RAM, ~3 h tuning | `results/perf.csv` |
| Observability | no logging | rule ID + payload in audit log | `logs/modsec_audit.log` |
| Failure mode | — | **fails open** if the proxy container dies | `results/failure.md` |

---

## The AI-specific axes

When the control or the system under test involves a model, **three axes change
meaning** and one is added. This is not decoration — it is the substance of weeks
9–13.

| Axis | What changes for AI systems |
|---|---|
| **2 · Guarantee** | Most model-level defenses (system prompts, output filters, "instruction hierarchy") provide **no guarantee at all** — only a raised cost. Say so. A conditional you cannot state is a red flag, not a gap in your write-up. |
| **3 · Coverage** | Attack surface is open-ended: there is no finite payload list for prompt injection the way there is for SQLi. Report coverage over *your* corpus and state that it is a sample, not the space. |
| **4 · Bypass** | Rephrasing is a bypass. Encoding is a bypass. Another language is a bypass. Expect to find one, every time. |
| **9 · Non-determinism** ⭐ | *(new)* Same input, same output? Run each payload **5×** and report how many distinct outcomes appear. **A control that blocks an attack 3 times out of 5 has not blocked it.** |

⚠️ **Axis 9 is why AI security is not just security.** A deterministic control
either blocks a payload or does not. A model-based control blocks it *sometimes* —
and a defense with a 60 % block rate is closer to a coin flip than a control.
Students must measure this, not assume it.

---

## The honesty clause

Every report includes a section titled **"Where we may have been unfair, and what
we did not test."**

Belongs there:

- Did you give the attacker and the defender the same information and effort?
- Did you tune the WAF for an hour but use a default prompt (or the reverse)?
- Is your payload corpus copied from a blog post the ruleset was written against?
- Did you test on benign traffic that looks nothing like real users?
- What attack did you *think* of and not have time to try?
- For AI systems: **would a larger model change your result, and can you know
  without running it?**

This section is worth real credit. **A student who identifies a genuine flaw in
their own evaluation has learned the thing this course is actually teaching.**

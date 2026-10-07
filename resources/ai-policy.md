# AI Use Policy

## The short version

**You may use AI assistants on any work in this course. You must log it, and you
own what you submit.**

An undisclosed AI-assisted submission is an honor code violation. A disclosed one
is normal professional practice.

---

## Why this policy

This is partly a course *about* using AI in security work, so banning AI
assistance would be incoherent. But it is also a course about what you can prove,
and the risk with an assistant is not that it helps you — it is **unexamined
delegation**: accepting output you cannot defend.

Security has a specific version of that failure. A model will produce a CVE
identifier, a CVSS score, a legal citation, or a "this code is safe" verdict in
exactly the same confident register whether it is right or not. In Week 0 you
measure this yourself, on purpose, before it can cost you anything.

> **You are responsible for what you submit.** A hallucinated CVE number, an
> invented LOPDP article, or a security claim the model made up becomes *your*
> error the moment you paste it into a report.

---

## The AI log

Maintain `AI_LOG.md` in your repository. Append an entry every time an assistant
materially shapes work you submit.

```markdown
## Week 0 — CVE check

**Tool:** Claude / ChatGPT / Copilot / local qwen2.5:3b
**What I asked:** "What is the CVE number for the xz-utils backdoor?"
**What I got:** CVE-2024-3094, plus a confident claim it was disclosed in
  February 2024.
**What I did with it:** Checked both against MITRE. The identifier was right;
  the date was wrong (published 2024-03-29). Recorded it as a partial hit in
  my results table and kept the model's exact wording as evidence.
**Did I understand it?** Yes — and I now check dates separately from
  identifiers, because the model was right about one and wrong about the other
  in the same sentence.
```

**That last field is the one that matters.** Writing "no" is allowed and costs you
nothing. Writing "yes" when you cannot defend it in a closed-book checkpoint is a
different matter.

### What needs logging

| Situation | Log it? |
|---|---|
| AI wrote code or a payload you submitted | **Yes** |
| AI explained a concept and you then wrote the code | **Yes** |
| AI debugged your exploit or your defense | **Yes** |
| AI drafted or edited your report prose | **Yes** |
| AI suggested which vulnerability class to look for | **Yes** |
| AI produced a fact you cite — a CVE, a CVSS score, a legal article | **Yes, and verify it against the primary source** |
| The model *is the subject of the experiment* (weeks 9–14, Duel 3) | No — that belongs in the report itself |
| Autocomplete finishing a variable name | No |

### Grading

The log carries credit in every duel and in the capstone:

- **Complete and reflective** — full marks. A log showing you got stuck, got help,
  and then went and understood the underlying idea is exactly the behavior this
  course wants.
- **Present but hollow** ("used AI for the code") — partial.
- **Absent when the work says otherwise** — an honor code matter.

There is no penalty for heavy use. There is a penalty for hiding it.

---

## ⚠️ Two rules specific to security work

**1. Never paste real secrets or personal data into a hosted model.** Not
credentials, not client data, not a colleague's personal information, not anything
you happen to discover while working on a lab. A hosted model is a third party you
have disclosed data to; you generally cannot unring that bell. This is not merely
policy — it is the week 11 and 12 material applied to your own conduct, and
"I pasted the database dump into a chatbot to ask what was in it" is a breach in
its own right.

Synthetic and lab data are fine. Everything in this course's labs is synthetic by
design.

**2. Verify every factual claim against a primary source before you cite it.**
CVE identifiers against MITRE or NVD; standards against the RFC or the OWASP page;
LOPDP obligations against the law's text. "The model said so" is not a citation,
and a fabricated citation in a security report is worse than no citation, because
a reader who trusts you will act on it.

---

## The checkpoint backstop

Two checkpoints (weeks 8 and 14) are individual and closed-book. They ask you to
trace an algorithm or protocol by hand, state what a control guarantees and under
exactly what condition, and read unfamiliar code or reasoning and find the defect.

No assistant can sit those for you. That is deliberate: it is what allows the
policy above to stay permissive. If you have genuinely understood the work your log
describes, the checkpoints are straightforward.

---

## A note on the irony

You are in a course that attacks AI systems, uses AI as a measured instrument, and
asks you to govern AI — while logging your own use of AI. Take the meta-lesson
seriously. The discipline of recording what a tool did for you, and whether you
understood it, is the same discipline that makes a penetration test report
credible. Both are the difference between *having a finding* and *being able to
defend it*.

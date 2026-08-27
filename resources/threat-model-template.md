# Threat Model Template

A threat model is a written answer to four questions:

1. **What are we building?** (or using — it need not be yours)
2. **What can go wrong?**
3. **What are we going to do about it?**
4. **Did we do a good job?**

That is the whole discipline. Everything below is scaffolding to stop you from
skipping question 2, which is the one people skip.

> **If you have never written one:** you are not expected to be comprehensive, and
> a threat model is never finished. A short model that names three real threats
> beats a long one that lists every threat in the textbook. Start with the Week 0
> version in §5 — it takes twenty minutes.

You reuse this template every week and in the capstone.

---

## 1 · Draw the thing first

Before listing threats, sketch where data goes. Boxes for components, arrows for
data, and — the part that matters — a dashed line wherever data crosses from
something you control to something you do not. That dashed line is a **trust
boundary**, and *almost every real vulnerability lives on one*.

```
   [ browser ]                                  ← you control nothing here
        │  login form
════════╪════════════════════ trust boundary ══════════
        ▼
   [ web app ]  ──── SQL query ────▶ [ database ]
        │
        └──── log line ───────────▶ [ log file ]
```

Hand-drawn and photographed is fine. ASCII is fine. The diagram is a thinking
tool, not a deliverable in its own right.

**Ask of every arrow crossing a boundary:** who can send this? what happens if
they send something unexpected? who can read it in transit? Those three questions
generate most of the table below on their own.

---

## 2 · STRIDE — the six things that go wrong

STRIDE is a checklist so you do not have to be brilliant. Walk each letter against
each component and each arrow.

| Letter | Threat | Plain question | Example |
|---|---|---|---|
| **S** | **Spoofing** | Can someone pretend to be someone else? | Logging in as another user with a guessed session token |
| **T** | **Tampering** | Can someone change data they should not? | Editing the price in a request before it reaches the server |
| **R** | **Repudiation** | Can someone deny doing it, with no way to prove otherwise? | No audit log, so a fraudulent transfer cannot be attributed |
| **I** | **Information disclosure** | Can someone read data they should not? | An error page that prints the SQL query, or a database backup on a public URL |
| **D** | **Denial of service** | Can someone make it unavailable? | One expensive search request repeated until the site stalls |
| **E** | **Elevation of privilege** | Can someone do something only an admin should? | Changing `?role=user` to `?role=admin` and being believed |

**The letter is a prompt, not a taxonomy exam.** If a threat plausibly fits two
letters, pick one and move on; nobody is grading the classification.

---

## 3 · The AI extension

Use these five *in addition* to STRIDE whenever the system includes a model. They
are not exotic variants — they are the same six failures with a component that has
no reliable way to tell instructions from data.

| Threat | Plain question | Where you meet it |
|---|---|---|
| **Prompt injection** | Can attacker-controlled text reach the model and be followed as an instruction? | Weeks 9–10 |
| **Training-data / corpus poisoning** | Can an attacker get content into what the model learns from, or retrieves? | Week 10 |
| **Memorization** | Can the model be made to repeat data it was trained on? | Week 12 |
| **Model extraction** | Can someone reconstruct the model or its data by querying it? | Weeks 11–12 |
| **Excessive agency** | If the model is wrong or hijacked, what can it *do* — what tools and permissions does it hold? | Week 10 |

⚠️ **Excessive agency is the one to internalize early.** Every other AI threat gets
much worse or nearly harmless depending on the answer. A hijacked model that can
only produce text is an embarrassment; a hijacked model holding a
`send_email` tool is a breach.

---

## 4 · The table

One row per threat. This is the deliverable.

| # | Threat (STRIDE letter) | Where it enters | What an attacker gains | Mitigation | Guarantee — and its condition (axis 2) | Evidence |
|---|---|---|---|---|---|---|
| 1 | Tampering (T) | login form → SQL query | reads any user's row | parameterized queries | Input can never be parsed as SQL — **provided every query uses parameters, with no string concatenation anywhere** | week-06 notebook: 0/8 injections succeed |
| 2 | Information disclosure (I) | error page | learns schema and query text | generic error page; details to logs only | Nothing about the query reaches the user — **provided debug mode is off in production** | manual check, 4 error classes |
| 3 | Elevation of privilege (E) | `role` parameter | full admin access | server-side authorization check | Client-supplied role is never trusted — **provided the check is on the server, not in the UI** | *not yet tested* |

**The two columns that carry the grade** are *Guarantee — and its condition* and
*Evidence*.

- **A guarantee without its condition is not a guarantee.** "We use parameterized
  queries, so we are safe from SQL injection" is worth roughly half of "…provided
  every query uses parameters — and one legacy report builder still concatenates,
  so the guarantee does not hold there." The second sentence is what a real review
  produces. See [`control-scorecard.md`](control-scorecard.md), axis 2.
- **"Not yet tested" is an acceptable and valuable entry.** An honest gap tells a
  reader where to look. A fabricated "mitigated ✔" is the failure mode this whole
  course is built to prevent.

For systems with a model, add the ninth column from the scorecard: **does the
control behave the same way every time?** A defense that blocks an attack three
times out of five has not blocked it.

---

## 5 · The Week 0 version (twenty minutes)

For your first threat model, pick something you use every day — a banking app, the
university LMS, a food-delivery app, your email. You do not need internal
knowledge; model it as an outsider from what you can observe.

Deliver `week00/warmup_threat_model.md` containing:

1. **The system, in one sentence**, and who its users are.
2. **A sketch** with at least one trust boundary marked. Photo, ASCII, or drawing.
3. **Three to five rows** of the table above. Three real ones beat ten copied from
   the textbook.
4. **One sentence on what you could not determine from the outside**, and what you
   would need to look at to find out. This is the most professionally realistic
   part of the exercise.

You are graded on whether the threats are plausible for *this* system and whether
each mitigation states its condition — **not** on coverage, and not on getting the
STRIDE letters "right". Week 1 uses this vocabulary in anger; this is just to make
sure you have it.

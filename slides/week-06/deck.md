---
marp: true
theme: default
paginate: true
header: 'CMP-5006 · Week 6 · Web I: OWASP Top 10 & a Duel'
---

<!--
Week 6. Beats: injection general form (8) · SQLi + confirmation (7) · XSS as
trust (5) · filters & bypasses (5). Lesson plan: ../../weeks/week-06.md
-->

# Web Security I

## The OWASP Top 10 (2021) — and a Duel

**CMP-5006** · Week 6

---

# Injection is one bug in three costumes

Every injection is the same thing: **untrusted data crosses into a control
channel** because a boundary wasn't enforced.

| Attack | data → | channel |
|---|---|---|
| SQLi | → | SQL |
| XSS | → | HTML / JS |
| Command injection | → | shell |

> One bug, three costumes — and the defenses rhyme: parameterize / encode / don't
> build the command from strings.

<!--
8 min. Once they see it's ONE bug, the defenses generalize. Note the 2021 list:
Broken Access Control is now #1 (was #5 in 2017) — foreshadow section 4.
-->

---

# SQLi — and the confirmation problem

```sql
' OR '1'='1        -- famous, but...
```

A login that *behaves* differently is **suggestive**. Proof is a
**security-relevant effect** you can confirm:

- UNION-extracted data with a **canary**
- a controlled, reproducible time delay (blind)

> A reflected string is not a vulnerability until an **oracle** confirms it.
> This is scorecard axis 3 and the `seclab.attack` discipline.

---

# XSS is really about *trust*, not alert boxes

Reflected · Stored · DOM. The impact isn't `alert(1)` — it's **running in the
victim's origin with their session**.

```html
<script>alert('XSS-FIRED-7f3a')</script>   ← the alert is just a canary
```

The canary proves *execution*, not mere reflection. Cookie theft, session
hijack, and account takeover are what actually follow.

---

# Filters lose — the bypass is a mutation away

DVWA "Medium" adds `mysql_real_escape_string`, case filters, separator blocks.
Every one is bypassable:

```
UNION SELECT      → UnIoN/**/SeLeCt      (case + comment)
<script>          → <img src=x onerror=> (no script tag)
; whoami          → && whoami / %0a       (other separators)
```

> **Blocklists lose.** The fix is a different architecture, not a longer blocklist
> — the through-line to week 7's WAF and week 9's prompt-injection filters.

<!--
5 min. Plant this now; the bypass mindset is the whole course. Blocklist = the
wrong layer.
-->

---

# ⚠️ The duel: LLM vs. scanner, same source

Point a classical scanner (**sqlmap/semgrep**) and an **LLM** at the same target,
score both against a hand-built ground-truth set (`seclab.scan`).

| tool | precision | recall | the tell |
|---|---|---|---|
| scanner | high | **misses** what it has no rule for | quiet, narrow |
| LLM | **hallucinates** | high | cries wolf |

> Neither cleanly finds **Broken Access Control** — the #1 category — because
> that needs app *context*, not pattern-matching. The most important bug is the
> one tools are worst at.

---

# Read it like an engineer, not a leaderboard

- **LLM**: high recall, high hallucination → every false positive is analyst time.
- **Scanner**: precise, narrow → what it misses is what hurts you.
- The interesting cells: the LLM's **hallucination** and the scanner's **miss**.

> Print both, read them aloud. That comparison is the deliverable — not the F1.
> ⚠️ Run the LLM twice: the findings change (non-determinism, axis 9).

---

# Studio

1. **Three confirmed findings** — SQLi, XSS, cmdi at Medium, each confirmed by a
   `seclab.attack` oracle (not a screenshot).
2. **The duel** — real scanner vs. real LLM on the same target; score with
   `seclab.scan`; build the ground truth by hand.
3. Report the LLM's best **hallucination** and the scanner's worst **miss**. Did
   either find access control?
4. Scorecard one finding + the two-line responsible-disclosure note.

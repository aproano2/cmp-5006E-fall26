---
marp: true
theme: default
paginate: true
header: 'CMP-5006 · Week 7 · Web II: Defense & Detection'
---

<!--
Week 7. Beats: negative vs positive security (6) · WAF bypasses (7) · false
positives (6) · positive model + detection (6). Lesson plan: ../../weeks/week-07.md
-->

# Web Security II

## Blocklists lose, boundaries win

**CMP-5006** · Week 7

---

# Negative vs. positive security

| | Negative model | Positive model |
|---|---|---|
| Idea | enumerate **bad** | enumerate/enforce **good** |
| Example | WAF blocklist | parameterization, allowlist |
| Can it be complete? | **no** — badness is open-ended | yes — goodness is bounded |
| Guarantee | none | **structural** |

> Every durable web defense is positive. Every "we added more rules" arms race is
> negative.

---

# A WAF blocks the attacks you thought of

```
coverage on the week-6 attacks:  4/4   ← looks great!
```

The attacker's job is to write one you **didn't**.

<!--
6 min. Set the trap: coverage on KNOWN attacks tells you nothing about the ones
you didn't enumerate.
-->

---

# ⚠️ ...and loses on both blades

## Blade 1 — bypass (axis 4)
```
OR 1=1      → OR 'a'='a'          <img onerror> instead of <script>
```
Same intent, new surface. **3/4 bypasses get through.**

## Blade 2 — false positives (axis 5)
```
"the drop table at the cafe was reserved"  → BLOCKED
```
**2/6 legitimate requests blocked.** A WAF that blocks users gets **turned off** —
at which point its coverage is zero.

<!--
Loosen rules → bypasses multiply. Tighten → users suffer. No good setting, because
you're enumerating badness.
-->

---

# The positive model makes the bug impossible

Parameterized query: **structure and data travel separately.** Input can only ever
be a value — it can never become code.

```
injections tried against parameterization:  0/8 succeed
```

Not "blocked by a rule" — **structurally unable to inject.**

> Guarantee (axis 2): *user input cannot alter query structure, for any input.*
> The WAF could never say that.

---

# So why run a WAF at all?

Not as the fix — as **defense in depth** and **detection**:

- **Virtual patching**: hold off a known CVE for the hours a code fix takes.
- **Logging**: someone is probing — from where, with what.
- Raises attacker cost (real value), *as long as you never mistake it for a
  guarantee*.

> A smoke detector, not a fireproof wall. And you still don't fix the code by
> buying a smoke detector.

<!--
Detection widens the net for a human, but every flag is analyst time — week 13's
automation paradox, foreshadowed.
-->

---

# Scorecard — negative vs. positive

| Control | Guarantee | Bypass | FP cost |
|---|---|---|---|
| WAF blocklist | **none** | trivial | high |
| Parameterized queries | **yes** | none | zero |
| Allowlist validation | strong | hard | low |
| WAF as detection | visibility | — | analyst load |

> Enumerating badness is a losing game; enforcing goodness wins. Defend at the
> **boundary**, not with a pattern list.

---

# Studio

1. **Deploy a WAF filter**; confirm coverage on the week-6 attacks.
2. **Bypass it (axis 4)** — ≥ 3 same-intent payloads that evade your rules.
3. **Measure false positives (axis 5)** on benign traffic.
4. **Fix it properly** — parameterize; show the injections now fail structurally.
5. Scorecard WAF vs. parameterization: which gives a *guarantee*, and why run the
   other anyway.

> **Duel 2 (web attack & defend) is due next week.**

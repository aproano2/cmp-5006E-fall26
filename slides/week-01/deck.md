---
marp: true
theme: default
paginate: true
header: 'CMP-5006 · Week 1 · Threat Modeling & the Four Goals'
---

<!--
Week 1 Session A. Mini-lecture budget: 25 min. Beats: goals-as-adversary-
objectives (8) · STRIDE (10) · Kerckhoffs / why we publish attacks (7).
Lesson plan: ../../weeks/week-01.md
-->

# Information Security

## Attack · Defend · Measure

**CMP-5006** · Week 1 — Threat Modeling & the Four Goals


---

# The goals, as things an attacker wants to do

| Goal | The adversary is trying to… |
|---|---|
| **Confidentiality** | *read* what they shouldn't |
| **Integrity** | *alter* what they shouldn't |
| **Availability** | *deny* it to everyone else |
| **Authentication** | *impersonate* someone |
| **Non-repudiation** | *deny* they did something |

<!--
8 min. Reframe every goal as an ATTACKER OBJECTIVE. A control exists to deny one
objective; if you can't name the objective, you can't evaluate the control. This
is scorecard axis 1 and it runs all term.
-->

---

# A control denies one objective

> ## What does this control guarantee, against which adversary, and how do you know?

That question is the entire course. Write it on your hand.

- Not "is it secure?" — secure *against whom, doing what?*
- Every week fills in the blanks with **evidence**, not opinion.

---

# STRIDE — the systematic "what can go wrong"

| | Threat | Violates |
|---|---|---|
| **S** | Spoofing | authentication |
| **T** | Tampering | integrity |
| **R** | Repudiation | non-repudiation |
| **I** | Information disclosure | confidentiality |
| **D** | Denial of service | availability |
| **E** | Elevation of privilege | authorization |

<!--
10 min. Build a STRIDE model LIVE on a two-tier web app (browser -> server -> DB).
Draw the trust boundaries. Ask, at each boundary, which STRIDE categories apply.
-->

---

# The threat lives on the *boundary*, not in the box

```
  browser  ──┤ trust boundary ├──►  server  ──┤ boundary ├──►  DB
             (untrusted input)      (authz?)     (secrets?)
```

Students model the **boxes** and forget the **arrows**. Every arrow crossing a
trust boundary is where a threat enters.

*You will threat-model DVWA today — and attack that exact model in week 6.*

---

# Kerckhoffs's principle (1883)

> A system should be secure even if everything about it **except the key** is
> public knowledge.

- Security must **not** depend on the algorithm being secret.
- Secrecy of *design* is not security — it is a delay.

## This licenses the whole course

We can publish exactly how every attack works, because a system whose security
depended on your ignorance **was already broken**.

<!--
7 min. This is why we teach offense openly. It also sets up crypto: the KEY is
secret, the ALGORITHM is public and reviewed. Connects to open-source security.
-->

---

# The two instruments you'll use all term

## The Control Scorecard
8 axes: threat model · guarantee · coverage · **bypass** · **false-positive cost**
· operational cost · observability · failure mode.

## The Threat Model (STRIDE + an AI extension)

> A defense you have not tried to **bypass** is a defense you have not evaluated.

<!--
Briefing. Walk the scorecard axes quickly; axes 4 (bypass) and 5 (FP cost) are the
ones that make this an engineering course, not a checklist.
-->

---

# Studio: break a cipher, then model a target

1. **Break a substitution cipher** by frequency analysis — recover plaintext with
   no key. *Name the assumption that made it breakable.*
2. **STRIDE-model DVWA** — the app you attack in week 6.
3. **Give the same app to an LLM** to threat-model — find what it catches and what
   it confidently gets wrong.

> Every break is the discovery of an assumption the designer didn't know they made.

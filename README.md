# CMP-5006 — Information Security

**Attack, Defend, Measure — including the AI in the stack**

Universidad San Francisco de Quito


---

## What this course is

An information security course in which students **break things, then fix them, then measure whether the fix worked.**

Two commitments shape every session:

**1 · Nobody lectures for 80 minutes.** Each week has a Concepts day and a Studio day.

**2 · AI is in scope three ways, not one.** Modern systems increasingly depend on models, so students learn to (a) **attack and defend AI-integrated
applications**, (b) **use AI as a security tool and measure whether it actually helped**, and (c) **reason about the privacy and governance obligations** those
systems create.

> The organizing question of the course:
> **What does this control guarantee, against which adversary, and how do you know?**

Two rubrics are reused all term: the
[**Control Scorecard**](resources/control-scorecard.md) (what does this defense guarantee, and what evidence supports that?) and the [**Threat Model template**](resources/threat-model-template.md).

## ⚠️ Ethics and scope

Everything in this course runs **against targets you control, in a local sandbox.**

- Every lab target runs in Docker on the student's own machine, on an isolated network
- Attacking any system you do not own or lack written authorization for is **grounds for failing the course**, independent of any legal consequence
- Week 14 covers offensive AI capability because **defenders who do not understand it build defenses against the wrong threat**

Full policy, and the authorization-and-disclosure norms students must practise: [`resources/ethics-and-scope.md`](resources/ethics-and-scope.md).

## Setup

Everything runs on a student laptop: **no GPU, no paid API, no cloud account.**

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .
python -m seclab.doctor       # verifies the whole toolchain, including Docker
```



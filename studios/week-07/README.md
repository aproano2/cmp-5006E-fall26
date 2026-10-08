# Week 7 Studio — Blocklists Lose, Boundaries Win

**Companion to** [`../../weeks/week-07.md`](../../weeks/week-07.md) — Session 7B.
**Time budget:** Recap 5 · Lab 45 · Demos 20 · Debrief 10 (80 min total).
**Deliverables:** all provided tests pass, and a filled Control Scorecard row for
the WAF and for parameterization (across all axes).

> **Recap (5 min).** *Your WAF blocked 4/4 known attacks. Why is that not a
> security claim?*

Week 6 *attacked* the web app; this week defends it. The uncomfortable result:
the popular defense — a **WAF blocklist** — is bypassable *and* noisy, while the
boring defense — **parameterization** — makes the bug structurally impossible.
That is the whole course thread again: **negative** security raises cost;
**positive** security gives a guarantee. A blocklist enumerates *badness* (and
can never finish); a positive model enumerates or structurally enforces *good*.

## Files in this folder

| File | Purpose | You edit it? |
|---|---|---|
| [`waf.py`](waf.py) | Given: the blocklist WAF + the parameterized-login model + the detection rule + the attack/bypass sets, VERBATIM from the notebook; plus `load_benign()` and the in-process `vuln-web` bridge | no |
| [`starter.py`](starter.py) | **Tasks 1–5** — wire the coverage / bypass / false-positive measurements, verify the parameterization guarantee, and confirm a bypass on the real app | yes |
| [`test_waf.py`](test_waf.py) | Provided tests, incl. the guarantee-fail test `test_blocklist_loses_on_both_blades` | no |

The exercise is **laptop-only**: pure Python for the measurements, plus the
week-6 `vuln-web` app run **in-process** (stdlib `http.server`, a free
`127.0.0.1` port, no Docker). `start_vulnweb()` handles bring-up and teardown for
you — the same app you attacked in week 6, now with a WAF in front of its
`/login` sink. Scope stays local: see
[`../../resources/ethics-and-scope.md`](../../resources/ethics-and-scope.md).

The benign corpus is **reused, not rebuilt**: `load_benign()` reads the 26 legit
inputs already verified in
[`../../projects/duel-2-web/benign_traffic.json`](../../projects/duel-2-web/benign_traffic.json).
Don't duplicate them here.

## Task 1 — Deploy a WAF filter, confirm coverage (8 min)

Open `starter.py`, implement `measure_coverage(payloads)` → `(blocked, total)`.
On `KNOWN_ATTACKS` you get **4/4** — great coverage on the payloads you thought
of. Set the trap in your own head: coverage on *known* attacks tells you nothing
about what you didn't enumerate.

## Task 2 — Bypass it, axis 4 (12 min)

Implement `measure_bypasses(BYPASSES)` → `(through, total)`. Same intent, new
surface: `OR 'a'='a'` instead of `OR 1=1`, a case/spacing `UnIoN SeLeCt`, an
`<img onerror>` with no `<script`, a zero-width char splitting `DROP`. **3/4 get
through.** Each is a five-minute mutation; the blocklist can never be complete,
because the space of "bad" is open-ended. *Required — an un-bypass-tested defense
is unevaluated.*

## Task 3 — False positives, axis 5 (10 min)

Implement `measure_false_positives(load_benign())` → `[(input, rule), ...]`. A
rule broad enough to catch variants also blocks **legitimate** traffic:
`drop table tennis lessons for beginners` trips the DROP TABLE rule. Every false
positive is a real user turned away — a ticket, an analyst-hour — and a WAF that
blocks users gets **turned off**, at which point its coverage is zero. Report the
FP rate and name a specific legit request you blocked.

> **Both blades fail together.** Loosen the rules to cut false positives and the
> bypasses multiply; tighten them and more real users suffer. There is no setting
> that is both complete and quiet — the defining weakness of negative security,
> and exactly what `test_blocklist_loses_on_both_blades` pins.

## Task 4 — Fix it properly: the guarantee (10 min)

Implement `count_injection_successes(payloads)` → `(succeeded, total)`, sending
every attack + bypass as the username to `parameterized_login`. The answer is
**0/8**. Not "blocked by a rule" — *structurally* unable to inject, because input
is compared as a literal value and never reaches a code context. State the
guarantee out loud (axis 2): **"user input cannot alter query structure, for any
input."** The WAF could never say that.

## Task 5 — Detection + the real app (5 min)

Implement `bypass_leaks_canary(base_url)`: put the WAF in front of the **real**
`vuln-web` `/login`, send each bypass the WAF *passes*, and confirm the leak with
a **sound oracle** — the admin canary token appears in the response (a reflected
string is not a leak; the canary *is*). This is `seclab.attack` discipline: a
finding is an oracle-confirmed, reproducible effect. The WAF-blocked known attack
never reaches the app; a WAF-passed bypass does, and dumps the canary.

Then read the given `anomaly()` rule: a behaviour-based detector that flags
bypassed-but-anomalous requests for **human review** — a sensor, not a wall.
Every flag is analyst time (week 13's automation paradox), so detection is a
precision/recall tradeoff too, not a free win.

## Run the tests

```bash
python3 test_waf.py     # laptop-only; spins vuln-web up in-process, tears it down
```

All six tests must pass. The fourth —
`test_blocklist_loses_on_both_blades` — is the point of the week: it watches the
WAF fail on **both blades at once** (a bypass through *and* a legit request
blocked), while `test_parameterization_guarantee_holds` shows the boundary give
0/8 injections for any input. A test that expects a guarantee to *fail* is not a
mistake; watching negative security lose on both blades — while a boundary holds
— is how you learn the difference is real, not rhetorical.

Fast-finishing pairs: **add one rule that catches the `OR 'a'='a'` bypass without
false-positiving on "director of operations or equivalent role." Can you? State
precisely why the tradeoff has no clean setting.**

## Task 6 — Control Scorecard (in the demo)

Fill one scorecard row for the WAF and one for parameterization, across all axes.
Starting point from the notebook:

| Control | Model | Guarantee (axis 2) | Bypass (axis 4) | FP cost (axis 5) |
|---|---|---|---|---|
| WAF blocklist | negative (enumerate bad) | **none** | yes — trivial variants | high — blocks real users |
| Parameterized queries | positive (input is data) | **yes — input can't become code** | none | zero |
| WAF as detection | — | none, but **visibility** | n/a | analyst load (wk 13) |

The full rubric (all 8 axes, scoring, honesty clause) lives in
[`../../resources/control-scorecard.md`](../../resources/control-scorecard.md).

## Demos (20 min)

- Prioritize a pair whose bypass was cleverest, and a pair who measured a
  **painful false-positive rate** — the FP cost is the point students most
  underweight.
- Solicit: *did anyone's WAF-passed bypass leak the canary on the real app?* Walk
  the oracle on the board — the moment "the response changed" becomes "the canary
  leaked" is the "aha."

## Debrief (10 min)

- Blocklists lose on both blades: bypassable (axis 4) **and** noisy (axis 5).
- Parameterization / positive validation gives a *guarantee*; that's the fix.
- A WAF is a stopgap and a sensor — valuable for virtual patching and detection —
  **never** a substitute for fixing the code.
- Detection widens the net but costs analyst time (week 13's paradox, foreshadowed).

## Links

- Session 7A notebook — [`../../notebooks/week-07-web-defense.ipynb`](../../notebooks/week-07-web-defense.ipynb)
- The lab it defends — [`../../labs/vuln-web/README.md`](../../labs/vuln-web/README.md)
- Control Scorecard — [`../../resources/control-scorecard.md`](../../resources/control-scorecard.md)
- Ethics & scope — [`../../resources/ethics-and-scope.md`](../../resources/ethics-and-scope.md)
- **Duel 2 (Web Attack & Defend), due week 8** — attack, deploy a defense, *bypass
  your own defense*, measure FP cost: [`../../projects/duel-2-web/README.md`](../../projects/duel-2-web/README.md)

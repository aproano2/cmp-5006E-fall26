# Week 8 Studio — Trust the Artifact, Not the Name

**Companion to** [`../../weeks/week-08.md`](../../weeks/week-08.md) — Session 8B.
**Time budget:** Recap 5 · Lab 45 · Demos 20 · Debrief 10 (75 min total).
**Deliverables:** all provided tests pass, and a filled Control Scorecard row for
each of the three attacks.

> **Recap (5 min).** *Three attacks this week substituted an artifact behind a
> trusted name. Name the single defensive pattern that fixes all three.*

> ⚠️ **Busy assessment week.** **Duel 2 (web attack & defend) is due this week**
> and **Checkpoint 1 (weeks 1–7) is sat this week.** This studio is short and
> self-contained by design — do it before or after the checkpoint per your
> instructor's call. See the two logistics links at the bottom.

Weeks 1–7 were about breaking and pinning *primitives* — ciphers, hashes, TLS,
web inputs. This week is the one closest to how systems actually get breached
now: not by breaking crypto, but by **trusting the wrong artifact**. A package
that isn't yours. A token you didn't really sign. Each attack here substitutes an
artifact behind a *name* the victim trusted; each fix pins the *artifact* instead
of the name. That single shape is the whole studio — and it is Control Scorecard
axis 2: *only the exact vetted artifact is trusted*, a promise a name-based lookup
can never make.

## Files in this folder

| File | Purpose | You edit it? |
|---|---|---|
| [`supplychain.py`](supplychain.py) | Given: the JWT plumbing (`b64`, `make_token`) and `verify_insecure` — the header-trusting verifier you attack — verbatim from the notebook | no |
| [`data.py`](data.py) | Given: the two registries, the lockfile, the dependency graph + known-bad set, and the signing secret — same values as the notebook | no |
| [`starter.py`](starter.py) | **Tasks 1–3** — the three attacks and their three pins | yes |
| [`test_supplychain.py`](test_supplychain.py) | Provided tests, incl. the two guarantee tests (public package wins until pinned; `alg=none` accepted until pinned) | no |

`seclab` is not imported — like weeks 1–3 this is a pure-Python week: stdlib
only, no lab target, no Docker. The three demos are fully self-contained.

## Task 1 — Dependency confusion (12 min)

Open `starter.py`. Implement `resolve_highest_version(pkg)`: a naive resolver
that considers **both** your internal registry and the public one and picks the
**highest version, ignoring the source**. For `acme-auth`, your internal 1.4.2
loses to the attacker's public **9.9.9** — their code installs under your trusted
name. Nobody typo'd anything; the resolver trusted the *name* and picked by
number. This is Alex Birsan's 2021 attack that breached Apple, Microsoft, and
dozens more.

Then implement the fix, `resolve_pinned(pkg, candidate_hash, candidate_source)`:
resolve against the **lockfile** (exact version + `sha256` + source you vetted),
not by name+version. The attacker's public artifact is refused on source/hash
mismatch; only the exact vetted internal artifact installs. That's what a lockfile
with hashes (`pip --require-hashes`, `package-lock.json`) plus scoped internal
registries buys you: the name becomes irrelevant.

## Task 2 — SBOM and transitive risk (10 min)

Implement `build_sbom(root, graph)` — the sorted list of **all transitive**
dependencies, not just the direct ones — and `cve_affected(sbom, known_bad)`, the
"are we affected by CVE-X?" query. The point: `xz-utils` sits **two levels deep**
(nobody chose it; `acme-auth` pulled it in) — exactly where the 2024 backdoor
lived. Without an SBOM, "are we exposed?" is days of grepping build logs across
every repo. With one, it is an instant set-intersection. **You cannot pin, patch,
or even assess what you cannot enumerate** — inventory is the prerequisite for
every other control.

## Task 3 — `alg=none` token forgery (15 min)

Implement `forge_alg_none_admin()`: forge a JWT with header `alg=none`, payload
`role: admin`, and an **empty signature**. The given `verify_insecure` trusts the
token's own `alg` header — so it skips the signature check entirely and hands you
admin, no signing key required. Watch privilege escalation happen with zero
crypto.

Then implement `verify_secure(token, expected_alg="HS256")`: **pin the algorithm
server-side**. Reject any header whose `alg` isn't what the server expects (so
`alg=none` dies immediately), then verify the HS256 signature under `SECRET`. The
fix is the same shape as Tasks 1–2: don't trust the name/header the artifact hands
you — verify against a value *you* pinned.

**Bonus for the demo:** the weak-HMAC-secret variant. If `SECRET` were a short
dictionary word, an attacker could brute-force it offline and mint valid tokens.
Short signing keys are forgeable; that's still a top finding in leaked repos.

## Task 4 — Control Scorecard (8 min)

For each attack, fill one scorecard row — the trusted *name*, the substituted
*artifact*, the *pin* that closes it, and the guarantee the pin provides (axis 2).
Starting point from the notebook:

| Attack | Trusted name | Substituted artifact | The pin that fixes it |
|---|---|---|---|
| Dependency confusion | package name | attacker's public package | lockfile + hash + source scope |
| Transitive backdoor (XZ) | "it's just a dependency" | compromised upstream code | SBOM + provenance + pinning |
| `alg=none` JWT | the token's `alg` header | an unsigned token | server-side algorithm pinning |

The guarantee, stated once for all three (axis 2): *only the exact vetted artifact
is trusted* — under a key or list **you** control. The scorecard rubric (all 8
axes, scoring, honesty clause) lives in
[`../../resources/control-scorecard.md`](../../resources/control-scorecard.md).

## Run the tests

```bash
python3 test_supplychain.py
```

All four tests must pass. Two are **guarantee tests** and are the point of the
week: `test_dependency_confusion_public_wins_until_pinned` watches the attacker's
public package *win* the naive resolve before the lockfile pin refuses it, and
`test_alg_none_forgery_accepted_until_algorithm_pinned` watches the header-trusting
verifier *accept* an unsigned admin token before algorithm pinning rejects it. A
test that expects the attacker to succeed on the naive path is not a mistake:
watching a name-based guarantee break once is how you know it was never a
guarantee.

Fast-finishing pairs: **name a fourth place a system trusts a name where it should
pin an artifact** — container `:latest`, an OAuth redirect URI, a DNS record, a CI
cache key. State the pin.

## Demos (20 min)

- Prioritize a pair who found a name-trusts-artifact bug **beyond the three we
  covered** (container `:latest`, an OAuth redirect, a CI cache), and a pair who
  **brute-forced a weak JWT secret** to show short keys are forgeable.
- Solicit: *did the naive verifier hand anyone admin?* Walk the empty-signature
  forgery on the board — the moment the verifier reads the attacker's `alg` header
  and obeys it is the "aha."

## Debrief (10 min)

- Modern breaches target the **supply chain and auth**, not the crypto.
- ⚠️ Trusting a *name* (package, header, tag) is the shared bug; pinning the
  *artifact* (hash, algorithm, digest) under a key/list you control is the shared
  fix.
- You can't pin, patch, or assess what you can't enumerate — **SBOMs first**.
- This is one of the most transferable ideas in the course. It is the same shape
  as **week 5's trust store** (pin the CA, don't trust the name on the cert),
  returns as **week 10's tool allow-list** (least privilege for model tools), and
  anchors the **capstone's model provenance** (trust the signed artifact, not the
  model's name). Same pattern, weaker guarantees each time — carry the habit
  forward.

## Links

- Session A notebook — [`../../notebooks/week-08-systems-supplychain.ipynb`](../../notebooks/week-08-systems-supplychain.ipynb)
- Control Scorecard — [`../../resources/control-scorecard.md`](../../resources/control-scorecard.md)
- Ethics & scope — [`../../resources/ethics-and-scope.md`](../../resources/ethics-and-scope.md)
- **Duel 2 (web attack & defend) — DUE this week** — [`../../projects/duel-2-web/README.md`](../../projects/duel-2-web/README.md) · brief [`../../projects/duel-2-web.md`](../../projects/duel-2-web.md)
- **Checkpoint 1 (weeks 1–7) — sat this week** — [`../../projects/checkpoint-1-bank.md`](../../projects/checkpoint-1-bank.md)

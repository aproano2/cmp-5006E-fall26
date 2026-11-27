# AI Log — Homework 1 (Duel 1, Crypto & Protocols)
Daniel Andrade - Andrés Vega - Carlos Flores

Per [`resources/ai-policy.md`](../../../resources/ai-policy.md). All data shared with the
assistant was the course's synthetic lab material (`duel1_targets.py`, studios,
notebooks); no real secrets or personal data.

---

## Break 06 — verify_login (timing side channel)

**Date:** 2026-10-06
**Tool:** OpenCode (DeepSeek V4.1 Flash)
**What I asked:** "I need you to help me break deployments 5 and 6" following the
  format of the breaks already solved, and I wanted the code to reuse snippets from
  the week-4 class material.
**What I got:**
- `breaks/06-verify_login/verify_login.py` — `timing_attack` with the studio's
  `time_guesses` (interleaved measurements) and a `__main__` block that prints the
  artifact.
- `breaks/06-verify_login/verify_login.ipynb` — executed: recovers `83fabf35`, five
  reliability runs (5/5), and a cell with the fix using `constant_time_equal` /
  `hmac.compare_digest`.
- `breaks/06-verify_login/README.md` — assumption, misuse vs. primitive, artifact, and
  reliability (41 rounds per candidate, ~34 us of separation per byte).
- The assistant pointed out that the instructor's `--check` fails on `#6` on this
  machine (it uses sequential medians); the interleaved version recovers 5/5.
- Afterwards, at the team's request, it simplified the README language.

**What I did with it:** Reviewed the generated files and asked for wording adjustments.

**Did I understand it?** Yes — the comparison time depends on the correct prefix; with
  the interleaved measurements and the median, the signal becomes visible.

---

## Break 05 — keygen_fleet (shared RSA prime)

**Date:** 2026-10-06
**Tool:** OpenCode (DeepSeek V4.1 Flash)
**What I asked:** The same request (deployments 5 and 6, reusing class code).
**What I got:**
- `breaks/05-keygen_fleet/keygen_fleet.py` — pairwise scan with `math.gcd` and
  `factor_from_shared` from the week-4 studio (`studios/week-04/rsa_lab.py`) to recover
  `d` for both devices; a `__main__` block that prints the artifact.
- `breaks/05-keygen_fleet/keygen_fleet.ipynb` — executed: moduli → gcd → factorization
  → `d` → RSA round-trip.
- `breaks/05-keygen_fleet/README.md` — assumption, misuse vs. primitive, and artifact.
- Artifact: `p = 14723961130838400979`,
  `d(device0) = 155006092543738932355592225651672081825`,
  `d(device2) = 101591964428919489627153881052022337249`, confirmed with
  `(m^e)^d mod n == m`.

**What I did with it:** Reviewed the generated files and asked for wording adjustments.

**Did I understand it?** Yes — a gcd between the moduli reveals the shared prime, and
  the private key follows from the factorization, without attacking RSA's math.

---

## Breaks 00, 02 and 04 — `__main__` blocks

**Date:** 2026-10-06
**Tool:** OpenCode (DeepSeek V4.1 Flash)
**What I asked:** Add a `__main__` block to the existing scripts so they print the
  artifact, as the `duel-1-crypto` README asks.
**What I got:** `__main__` blocks in `00-reused_pad/reused_pad.py`,
  `02-token_mac/token_mac.py` and `04-ctr_log/ctr_log.py`; all three print their
  artifact when run. Assistant's note: in `reused_pad` and `ctr_log` the last byte
  never appears in any XOR, so the output marks it with `?` and it is inferred from
  context.
**What I did with it:** Reviewed the outputs of the five scripts.

**Did I understand it?** Yes.

---

## Break 04 — ctr_log (AES-CTR nonce reuse)

**Date:** 2026-10-06
**Tool:** Claude Code (Claude Opus 5.5), inside VS Code
**What I asked:** "Look at how `reused_pad` was implemented in
  `homework/hw1/andrade-flores-vega` and do the same for `ctr_log` and `token_mac`.
  The instructions are in `hw-1-crypto.md` and the `duel-1-crypto` README; the studios
  and notebooks that apply these are in the same repo. In the end I want them to look
  like `reused_pad`, with the 3 files."
**What I got:**
- `breaks/04-ctr_log/ctr_log.py` — the same `crib_drag` as `reused_pad.py`, plus
  `recover_entry(c_known, c_target, known_plaintext)` that computes
  `C_known ⊕ C_target ⊕ P_known`.
- `breaks/04-ctr_log/ctr_log.ipynb` — an executed notebook that crib-drags step by step
  (date → `user=admin` → `user=alice action=login` → full guess of `log0`), recovers
  `log2`, and confirms the guess by decrypting `log1` with the same `log0` guess.
- `breaks/04-ctr_log/README.md` — assumption violated, misuse vs. primitive, and the
  recovered artifact:
  `2025-03-01 12:09 user=admin action=export result=success from=10.0.0.?`
- The assistant pointed out that the last byte of `log2` (last IP digit) cannot be
  recovered: `log2` is 70 bytes and the other entries are 69, so that keystream byte
  never appears in any XOR.

**What I did with it:** Ran the notebook and review if everything is ok.

**Did I understand it?** Yes

---

## Break 02 — token_mac (length extension on `H(secret ‖ data)`)

**Date:** 2026-10-06
**Tool:** Claude Code (Claude Opus 5.5), inside VS Code
**What I asked:** Same request as above (one prompt covered both breaks).
**What I got:**
- `breaks/02-token_mac/token_mac.py` — `forge_token(data, tag, secret_len, extension)`
  (rebuilds the glue padding and resumes `_md_hash` from the observed tag, following
  the week 3 studio `forge_extension`) and `find_secret_len(...)`, which tries secret
  lengths 1–32 and uses the server's `verify_token` as an oracle.
- `breaks/02-token_mac/token_mac.ipynb` — an executed notebook showing that a naive edit
  with the old tag is rejected, then forging an accepted token:
  `data = b'user=alice&role=user\x00\x00\x00&role=admin'`, `tag = 4024164909`.
- `breaks/02-token_mac/README.md` — assumption violated, misuse vs. primitive (fix:
  HMAC), and the forged artifact.
- The assistant noted two limitations: the oracle only reveals the secret length
  mod 4 (lengths 1, 5, 9, … are all accepted), and the escalation to admin assumes
  the application parses repeated parameters as "last value wins".

**What I did with it:** Ran the notebook and review if everything is ok.

**Did I understand it?** Yes

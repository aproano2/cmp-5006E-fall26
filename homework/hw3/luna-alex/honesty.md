# Where our red team might be unfair

HW3 asks us to address at least 3. We address the 3 it names explicitly, plus
one more that showed up once we actually ran things.

## 1. Which findings are reliability-limited (worked k/5) and might not reproduce for the grader?

`<fill in once you have real numbers from results/part_a_findings.json and
results/part_b1_findings.json>`

Things to actually say here, not just acknowledge in the abstract:

- Name every attack that came back `k/5` with `0 < k < 5`, not `0/5` or `5/5`.
- For each one, say what you think is actually varying between trials — model
  sampling temperature, a timing race, wording the model happens to latch onto
  some runs and not others — rather than leaving it as an unexplained number.
- If the grader re-runs this against a fresh `ollama` pull of the same model
  name, the weights could differ slightly by pull date/quantization, and a
  3/5 finding on our machine could land anywhere from 0/5 to 5/5 on theirs.
  That's not a bug in our methodology, it's the actual property axis 9 exists
  to surface — say so plainly instead of implying our number is the ground
  truth.

## 2. Did the deterministic mock let us *demonstrate* logic you couldn't *measure*? Say where.

`<fill in after you've actually run against both backends, or confirmed you
only had the mock available>`

The honest version of this answer, concretely:

- `call_mock()` in `vulnllm_app.py` is a pure function of the input string —
  given the same message, defense level, and corpus state, it always returns
  the same thing. Any reliability number measured purely against `mock` is
  **not** a measurement of model non-determinism; it's a confirmation that a
  code path exists and is reachable. Say which of your Part A findings were
  only ever run against `mock` (if any), and don't report a `5/5` or `0/5`
  from `mock` next to a `3/5` from `ollama` as if they're the same kind of
  number — one is a logic check, the other is a measurement.
- Where we *did* have `ollama` serving `qwen2.5:3b`, say which findings
  actually used it, and reason briefly about whether a frontier model (not
  the small local one) would likely be easier or harder to land the same
  attack against, and why.

## 3. Is your least-privilege policy so narrow it breaks a legitimate task (an axis-5 false-positive cost on the containment)?

`<fill in from results/part_b2_containment.json → benign_task_check>`

We chose `LEAST_PRIVILEGE_ALLOW = ["get_faq", "lookup_balance"]` by reading
`plan_tool_calls()` and noting that no benign-looking request ever plans
`send_email` on its own — only exfil-shaped requests do. That's a real
argument for why dropping `send_email` entirely shouldn't cost anything, but
it's an argument from reading the source, not a guarantee. Report what
actually happened when the three benign requests in `b2_containment.py` were
run against the narrowed policy: `<OK / BROKEN for each, from the real
run>`. If any legitimate flow in a real deployment of this app does need
`send_email` (e.g. "email me my statement"), our allow-list would break it —
say whether that's a real gap or genuinely outside this app's benign-use
surface, rather than assuming zero cost just because our three test requests
passed.

## 4. [Bonus] Is a hand-built 5-document CORPUS a fair stand-in for a real RAG index?

`CORPUS` in `vulnllm_app.py` is five hardcoded strings with a bag-of-words
overlap retriever (`retrieve()`), not a real embedding-based vector store. Two
ways this might make our RAG findings look easier than they'd be in
production, and one way it might make them look harder:

- **Easier:** a real embedding retriever over thousands of documents has far
  more "surface area" for an attacker's question to accidentally or
  deliberately match a sensitive doc, not less — so if anything, this toy
  corpus likely *understates* the real risk, not overstates it.
- **Easier, differently:** `retrieve()`'s keyword-overlap scoring is far more
  predictable than a real embedding model's semantic similarity, which made
  it straightforward to reason out *which* question would surface
  `private-vip` or `poisoned-promo` just by reading the corpus text. A real
  attacker against a real vector store would need to probe for this instead
  of reading it off the source.
- **Harder:** there is no actual access-control layer to test here at all —
  `private-vip` isn't gated by any role check, it's just a string in the same
  dict as everything else. A real finding against a production RAG system
  would need to additionally show that the retriever ignores a role or
  tenant boundary that's supposed to exist, not just that nothing scopes
  retrieval in this toy app because nothing was ever built to.

---

*Numbers above are placeholders until the real harness/defense scripts have
been run with real payloads filled into `harness/payloads.py`. Do not submit
this file with any `<...>` still in it — every bracket here is something that
needs an actual measured answer, not a guess.*

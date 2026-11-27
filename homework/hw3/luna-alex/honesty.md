# Where our red team might be unfair

HW3 asks for at least three limitations. We address the three it names and two
additional limitations visible in the supplied target implementation.

## 1. Which findings are reliability-limited and might not reproduce for the grader?

**Measured status: PENDING RUN.** Fill this section from
`results/part_a_findings.json` and `results/part_b1_findings.json` after running
at least five trials per payload.

- List every finding with `0 < k < 5` by its exact name and ratio (for example,
  `A.1 direct injection: 3/5`). Explain that a mixed result may reflect model
  sampling, wording sensitivity, or the model's interpretation of the
  instruction/data boundary.
- Do not describe `0/5` or `5/5` from a five-trial Ollama sample as proof of
  permanent determinism. It only means no successful/failed variation was
  observed within this small sample.
- A fresh Ollama installation may use a different model build, quantization,
  or generation behavior. A grader's result can therefore differ from ours.
  Record the model name and backend from `/health` alongside the ratios.
- `/agent` is a special case: the supplied `plan_tool_calls()` is deterministic
  Python keyword logic and does not invoke the LLM. A stable A.4 result is not
  evidence that the Ollama model itself is reliably vulnerable.

## 2. Did the deterministic mock let us demonstrate logic we could not measure?

**Backend actually used: PENDING RUN.** Read `_metadata.backend` from each
results JSON and state whether it was `mock` or `ollama`.

When `/health` reports `mock`, `call_mock()` is a scripted function of the
input text. Repeating the same payload five times demonstrates whether the
application's deliberately vulnerable logic path is reachable; it does not
measure non-deterministic model behavior. A 5/5 mock result should therefore be
reported as **5/5 deterministic mock confirmations**, not as “the model leaks
with 100% reliability.” The same distinction applies to B1's block-rate and
bypass trials.

The target source defaults to `qwen2.5:1.5b` when Ollama is reachable (unless
`VULN_LLM_MODEL` overrides it). The separate `seclab.llm` helper's default
model is not the target's model setting. Record the actual target backend and
model configuration used. A larger or frontier model could be more resistant
to some prompt-injection attempts because it may better preserve instruction
hierarchy, but it could also follow complex malicious requests more effectively.
There is no reliable universal direction; it must be measured against that
model and application context.

Also note that the `/agent` endpoint does not call Ollama in this lab. It uses
`plan_tool_calls()` and a fixed dispatcher. This is useful for demonstrating
tool authorization and least-privilege enforcement, but it is not a measurement
of an LLM's tool-selection reliability.

## 3. Is the least-privilege policy so narrow that it breaks a legitimate task?

We chose `LEAST_PRIVILEGE_ALLOW = ["get_faq"]`, defining the permitted workflow
as read-only FAQ support. The same policy is used for all containment trials.

**Measured status: PENDING RUN.** Copy the three cases from
`results/part_b2_containment.json` → `benign_task_check.results`.

- “What are your support hours?” should pass through `get_faq`.
- “How do I report a lost card?” should pass through `get_faq`.
- “What's my account balance?” is denied because it requires
  `lookup_balance`, which is not in the allow-list.

This is an intentional functionality cost: the tested policy protects a
read-only FAQ workflow, not every feature a bank assistant might offer. It
would be misleading to claim that least privilege has zero false-positive
cost. A production design could split the assistant into separately authorized
workflows and require customer authentication/authorization before exposing a
balance tool, rather than broadly allowing it for every request.

## 4. Is the five-document RAG corpus a fair stand-in for production?

The supplied `CORPUS` has only five hardcoded documents and uses keyword overlap,
not an embedding-based retriever. That creates several limitations:

- **Predictable retrieval:** because the corpus and matching terms are visible
  in source, we can choose questions that predictably retrieve
  `private-vip` and `poisoned-promo`. A real vector store would require probing
  its retrieval behavior and might rank different documents.
- **No authorization layer exists to bypass:** `private-vip` is placed in the
  same dictionary as public FAQ documents. The experiment demonstrates an
  unscoped retriever, but it does not show the bypass of a real role- or
  tenant-based access-control mechanism.
- **Scale is not measured:** a larger index may create more opportunities for
  sensitive or poisoned material to be retrieved, but it may also add retrieval
  noise. Five documents are insufficient to quantify either effect. We should
  not claim that the toy corpus gives a numerical estimate of production risk.

The A.3 exfiltration oracle was deliberately strengthened to require both the
private document to be retrieved and the canary to appear in the answer. This
avoids counting retrieval metadata alone as proof that the secret was
exfiltrated.

## 5. Does the indirect-injection test exercise URL fetching?

The default harness submits a poisoned content string using the target's
explicitly supported `/summarize` `{"content": ...}` offline mode. This
exercises the indirect-instruction path, because the attacker-controlled text
is separate from the user's instruction, but it does **not** exercise HTTP URL
fetching or the SSRF behavior also present in `/summarize`. To test the fetch
path, set `INDIRECT_INJECTION_URL` to a page hosted locally and confirm that the
container can reach that host. Report which mode was actually used; do not call
an inline-content test a successful fetched-page test.

---

**Execution note:** this deliverable bundle contained the homework folder, not
the full course repository or a running target. The scripts and payloads were
reviewed against the `vulnllm_app.py` source supplied in the task description,
but no live-target trial counts are claimed here. Complete the PENDING RUN
fields from the JSON files generated on your machine before submission.

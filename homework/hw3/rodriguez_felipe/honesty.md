# Where our red team might be unfair

## C1. Reliability across models

The [saved results](evidence/results.json) record five trials per case. The
5/5 disclosure results for direct and indirect prompt injection and both RAG
cases show repeatability under the deterministic mock. The grader could see
different outcomes with a real model, a different model version, or different
generation settings. The five repetitions give us no estimate of how often
those outcomes would occur with a real model.

The tool-use results have a separate limitation. `/agent` uses the deterministic
`plan_tool_calls` function. Its 5/5 results describe what the application did
with that planner and policy. They leave open how often a model-based planner
would select the same tools.

## C2. What the mock demonstrated

The mock made it possible to observe the application's handling of external
content, retrieved documents, and generated output under fixed conditions. We
could check how the application handled disclosures and whether the tool
dispatcher enforced its configured allow-list. Because the mock follows fixed
rules, the experiment could not measure how much the prompt-level defense would
change a real model's behavior.

## C3. Least privilege and the cost to legitimate requests

The allow-list contains only `get_faq`. The support-hours request succeeded in
5/5 trials, and the dispatcher denied both restricted tools in each of the
five containment trials for the original case. The same policy would also deny
`lookup_balance` and `send_email` for legitimate requests. For example, even an
authorized customer would be unable to use the agent to check an account balance.
That loss of functionality is the false-positive cost of the policy we tested.

# Where our attack, defense, or comparison might be unfair

Homework 2 — Web Attack & Defend · Benjamín Vaca · CMP-5006E

Graded on evidence quality, not which side won. These are the places I think the
numbers in this submission could mislead a reader, written before anyone asks.

## 1. The ground truth is reused, not built from scratch by me — but it *is* tool-independent

Part C scores every tool against `duel/ground_truth.json`, which is the course's
hand-verified set (`homework/hw2/duel-2-web/ground_truth.json`), built by **reading
`vulnweb_app.py`**, not by running any scanner. That is the right kind of
independence — it was not "whatever sqlmap found" — so it does not rig the duel
toward any arm.

The honest caveat is that I did not *construct* it independently; I inherited it.
To avoid grading three tools against a set I never checked, I did two things: (a) I
re-read the three sinks and the `/safe` endpoint by eye and agree with all three
entries and the two negatives; (b) Part A **dynamically confirms** all three bugs
with sound oracles (canary leak, unescaped active markup, `injection_detected`),
so the ground truth is corroborated by live exploitation, not taken on faith.
`verify_fixtures.py` (instructor self-check) also reports *FIXTURES SOUND*.

## 2. I tuned the WAF and the semgrep rules; the LLM got a single default prompt

This is the biggest asymmetry in the comparison.

- The **WAF** (`defend/waf_blocklist.py`) is seven rules I wrote *knowing my own
  Part-A payloads*. Its 6/6 coverage is therefore partly circular — it blocks the
  attacks I thought of because I wrote it to. That is exactly why coverage is the
  weakest axis and why axes 4–5 (bypass + false positives) are the ones that
  actually tell you anything.
- The **semgrep rules** (`duel/semgrep_rules.yml`) are three rules I wrote *after
  reading the sinks*. So "semgrep misses the SQLi" is a statement about **my
  ruleset**, not semgrep's ceiling: a taint rule, or a different pattern, would
  catch the concatenated-f-string query. I disclose this rather than present
  semgrep as a fixed natural phenomenon. (The registry rule packs `p/python` /
  `p/security-audit` returned zero rules offline on this machine, so I could not
  use an untouched community pack; I say so here.)
- The **LLM** got one neutral prompt, no few-shot examples, no iteration. So if I
  "tuned the defense for an hour but used a default LLM prompt," that is precisely
  what happened. A fairer duel would either tune all three or none. Read the LLM
  numbers as *default-prompt* behaviour, not the model's best effort.

## 3. The benign corpus is adversarial and tiny, so 7.7% FP is not a production rate

The false-positive measurement (2/26) uses the provided `benign_traffic.json`,
which **deliberately** contains attack-adjacent English ("drop table tennis
lessons", "select the union option") to trip naive regexes. That is a good
teaching corpus but a bad estimate of real traffic: it is engineered to find my
WAF's worst case, and 26 inputs is far too few to put a confidence interval on.
The honest reading is "my DROP TABLE rule blocks at least these two legitimate
phrases," not "my WAF has a 7.7% false-positive rate in production." A real
estimate needs a large sample of genuine logs.

## 4. The Part-A finding I am least sure reproduces: command injection

`do_ping` **simulates** execution — it reports `injection_detected` when a shell
metacharacter reaches the command string, but never runs a shell. So my cmdi
oracle confirms the *precondition* of command injection (untrusted data reaching a
command context), not actual code execution. On a real `os.system(command)` the
same payloads would execute, but I have not demonstrated execution here, and I
should not claim I did. By contrast the SQLi (canary byte-for-byte leaked) and the
XSS (raw `<script>`/`onerror` in the response body) are confirmed on real effects.

The SQLi bypasses also lean on a quirk of *this* query's shape: they work without a
trailing `-- ` comment only because the template wraps the value in quotes and
operator precedence (`AND` binds tighter than `OR`) makes the wrong password
irrelevant. A differently-shaped query would need different payloads; these are
not universal.

## 5. "The LLM hallucinated" is model- and prompt-specific

qwen2.5:3b produced **no** hallucination and was identical across all five seeds —
if I had only run the small model I would have concluded "the LLM was perfectly
precise here," which is true but incomplete. The Broken-Access-Control
hallucination only appears on the larger llama3.1:8b, and even there only in 3 of 5
runs. So the headline "LLMs hallucinate access-control bugs" is really "a bigger
model, under a prompt that mentions access control, invented one some of the time."
I mention access control in the prompt, which arguably *invites* the hallucination —
another way the setup is not neutral.

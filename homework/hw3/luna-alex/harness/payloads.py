"""
FILL THESE IN BY HAND before running reliability_harness.py, b1_defense_and_bypass.py,
or b2_containment.py.

Each constant below must be an actual attack string you crafted and confirmed
against the live `vuln-llm` target yourself. Claude will not write prompt-
injection, RAG-poisoning, confused-deputy-abuse, or filter-bypass payload
content -- even for this local, course-authorized sandbox target -- so these
six values are the one piece of HW3 that has to come from you by hand.

Leave any of them as None (the default) and the script that needs it will
print a clear "[skip] ..." message naming exactly which payload is missing,
instead of silently pretending the attack ran, or crashing with a confusing
traceback.

Everything else -- the HTTP plumbing, the oracle logic, the reliability
measurement over N trials, the JSON output -- is already built and tested
against the real vuln-llm source in app logic terms. You only have to supply
the attack text itself.
"""

# --- Part A.1 -- direct prompt injection against /chat ---------------------
# Goal: get generate() to put SECRET in the reply.
PAYLOAD_DIRECT_INJECTION: str | None = None

# --- Part A.2 -- indirect prompt injection against /summarize --------------
# This is the CONTENT of a page the agent is asked to "summarize" -- the
# injection lives in data the agent fetches, not in what the user typed.
#   Victim  = the vuln-llm agent (and whoever relies on its summary).
#   Attacker = whoever controls the fetched page's content.
# Set PAYLOAD_INDIRECT_INJECTION to the page content directly (sent as
# {"content": ...} so you don't need to stand up a real HTTP server), OR set
# INDIRECT_INJECTION_URL to a local page you *do* serve (e.g. with
# `python -m http.server` bound to 127.0.0.1) if you want to demonstrate the
# fetch itself. Only one of the two is required.
PAYLOAD_INDIRECT_INJECTION: str | None = None
INDIRECT_INJECTION_URL: str | None = None   # e.g. "http://127.0.0.1:8899/page.html"

# --- Part A.3 -- RAG exfiltration + poisoning against /rag ------------------
# Two separate natural-language QUESTIONS (not injected content -- the
# retriever is unscoped, so an ordinary-sounding question is enough):
#   1) a question worded so retrieve() surfaces the "private-vip" doc.
#   2) a question worded so retrieve() surfaces the "poisoned-promo" doc
#      (whose own text is what carries the injected instruction).
PAYLOAD_RAG_EXFIL_QUESTION: str | None = None
PAYLOAD_RAG_POISON_QUESTION: str | None = None

# --- Part A.4 -- confused-deputy tool abuse against /agent ------------------
# A natural-language request worded so plan_tool_calls() plans
# lookup_balance + send_email to an address of your choosing. This same
# request is reused, unmodified, in b2_containment.py to prove the SAME
# attack is contained once least privilege is applied.
PAYLOAD_CONFUSED_DEPUTY_REQUEST: str | None = None

# --- Part B1.3 -- filter bypass (axis 4) ------------------------------------
# A variant of your direct-injection payload that also asks the model to
# spell out, space out, or base64-encode the secret, so the literal-string
# filter at /defense level 2 (`out.replace(SECRET, "[REDACTED]")`) can't
# pattern-match the transformed output.
PAYLOAD_FILTER_BYPASS: str | None = None

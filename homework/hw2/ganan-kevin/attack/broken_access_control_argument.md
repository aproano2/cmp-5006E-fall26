# Is Broken Access Control (OWASP 2021 #A01) reachable in `vuln-web`?

**No — and the argument for that is itself the point of this section**, per
the week-6 lesson that A01 needs application *context* to even be a
meaningful question, not just a scanner signature.

## The argument

Broken Access Control is a vulnerability **in the relationship between**
an authenticated identity, a resource, and a policy about who may act on
that resource. Concretely, it requires at least:

1. A notion of **identity** that persists across requests (a session, a
   token, a cookie — *something* that says "this request is Alice").
2. A notion of **resource ownership or role** (this row belongs to Alice;
   this action requires role=admin).
3. A **check** that compares (1) against (2) before performing an action
   — and a bug is specifically a missing, wrong, or bypassable version of
   that check.

Reading `vulnweb_app.py` end to end: there is no cookie, no session table,
no token, no `Authorization` header handling, and no role field consulted
anywhere in `Handler.do_GET` / `Handler.do_POST`. The `users` table has a
`secret` column, but nothing in the request-handling path ever asks "whose
secret is this, and is the caller allowed to see it" — `do_login`'s bug is
that the *authentication* check itself can be subverted (that's injection,
A03), not that a correctly-authenticated user can reach another user's
data through a missing *authorization* check.

**In other words: there is no access-control mechanism here to break.**
A01 is not "present but weak" in this app — it is **structurally absent**,
the same way you can't have a race condition in code with no concurrency.
This matches `ground_truth.json`'s own `not_present` entry for exactly this
reason, and it's why a tool (scanner or LLM) that reports a
"broken-access-control" finding against this app is **hallucinating a
category that has nothing to attach to**, not finding a subtle instance of
it — see `duel/score.py`'s explicit check for this trap.

## What *would* make it reachable

For contrast — because "the mechanism doesn't exist" is a different claim
from "the mechanism exists and the question is academic" — A01 would become
reachable the moment the app grew:

- a `/profile?user_id=N` endpoint that fetches another user's row by a
  caller-supplied ID with no ownership check (classic IDOR), or
- a `role` column actually consulted somewhere, with a code path that
  trusts a client-supplied value for it instead of deriving it from a
  verified session.

Neither exists in the current source. This is also the reason **SECS-style
designs** (see Homework 1) explicitly separate *authentication* (proving
who you are, via a signature) from *authorization* (what you're allowed to
do once identified) — `vuln-web` is missing the second concept entirely,
not implementing it incorrectly.

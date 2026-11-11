## Week 2 — Entropy, perfect secrecy, and the two-time-pad break

**Tool:** OpenAI Codex

**What I asked:** I asked the assistant to implement the four functions in
`starter.py`, explain the implementations, and complete the remaining written
requirements from the Week 2 README.

**What I got:** The assistant implemented the entropy/unicity calculation, the
decoy-key construction, crib-dragging, and known-plaintext recovery. It also
drafted the Task 1 answers, documented the crib chain and recovered plaintexts,
filled the one-time-pad Control Scorecard entries, stated the practical key-
distribution limitation, and added an evaluation-limitations section.

**What I did with it:** I ran the provided `python3 test_otp.py` test program and
checked the reported entropy, unicity distance, crib hits, recovered plaintexts,
and XOR reasoning against the supplied `otp.py`, `twotimepad.json`, and tests. All
four tests passed. Before submission, I will review the prose and code again and
make any changes needed so that it accurately reflects my own understanding.

**Did I understand it?** To be confirmed personally before submission. I should
be able to explain that XOR cancels identical values, that a one-use uniformly
random OTP gives every equal-length plaintext a corresponding key, that reusing
the key reveals `p1 XOR p2`, and that crib-dragging uses English redundancy to
turn that relationship into candidate plaintext fragments.

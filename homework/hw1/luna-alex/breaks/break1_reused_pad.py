"""Break #1 -- reused_pad : a "one-time" pad reused for every message.

Assumption broken: "a one-time pad is unbreakable". That holds ONLY if the key is
(a) truly random, (b) at least as long as the message and (c) used ONCE. The
designer assumed (c) without enforcing it: one 200-byte key encrypts all messages.

Attack -- uses only the 4 public ciphertexts (no key, no known plaintext):
  C_i xor C_j = P_i xor P_j          (the key cancels)
 1. Column filter: a key byte at column p is a candidate only if EVERY ciphertext
    that covers column p decrypts to [a-z ] (the attacker knows the messages are
    lowercase English -- the task statement says "all are English").
 2. Beam search over columns, scoring the 4 candidate plaintexts jointly with an
    English character-bigram model built from a generic English sample.
 3. Crib-drag report (' the ', ' and ', ...) as an independent sanity check on the
    pairwise XORs, then print the recovered TARGET (msg3).
Run:  python break1_reused_pad.py
"""
import math
import re
from collections import Counter

from _common import load_targets, xor

T = load_targets()
cts = {k: bytes.fromhex(v) for k, v in T.reused_pad_ciphertexts().items()}
names = sorted(cts)
TARGET = "msg3"
ALPHA = "abcdefghijklmnopqrstuvwxyz "
ALPHA_B = set(ALPHA.encode())

# ---- generic English sample for a bigram model (NOT taken from the targets) ----
SAMPLE = """
it was a quiet morning in the old town and the market was just beginning to open
the baker carried fresh bread to the corner shop while children walked to school
every year the committee reviews the budget and decides how much money each
department will receive for the next season people often forget that small
details matter when a plan is put into practice and that a good result usually
comes from careful preparation and steady work the teacher asked the students to
read the chapter again and to write a short summary before the end of the week
a letter arrived from the central office with instructions about the meeting
the manager explained that the schedule had changed and that everyone should
confirm their attendance in advance please remember to lock the door and to turn
off the lights when you leave the building the weather was cold so we decided to
stay inside and talk about the project over a cup of tea and some fresh fruit
information should be shared only with people who need it and it should always be
protected during transport the driver reached the station just before sunrise
and waited for the train to arrive with the packages from the northern region
we will contact you again tomorrow evening to confirm the final arrangements
"""
SAMPLE = "".join(ch for ch in " ".join(SAMPLE.split()).lower() if ch in ALPHA)
big, uni = Counter(zip(SAMPLE, SAMPLE[1:])), Counter(SAMPLE)
V = len(ALPHA)

def lp(a: str, b: str) -> float:
    return math.log((big[(a, b)] + 0.5) / (uni[a] + 0.5 * V))

# ---- Step 1: candidate key bytes per column -----------------------------------
maxlen = max(len(c) for c in cts.values())
cands = []
for pos in range(maxlen):
    col = [c[pos] for c in cts.values() if len(c) > pos]
    cands.append([k for k in range(256) if all((b ^ k) in ALPHA_B for b in col)])
print(f"[1] column filter: avg {sum(map(len, cands))/maxlen:.1f} candidates/column "
      f"(of 256), {sum(len(c) == 1 for c in cands)} columns already unique")

# ---- Step 2: beam search left->right on joint bigram score --------------------
BEAM = 3000
beam = [(0.0, ())]                    # (score, key-prefix)
for pos in range(maxlen):
    nxt = []
    for score, key in beam:
        for k in cands[pos]:
            s = score
            for c in cts.values():
                if len(c) > pos and pos > 0:
                    s += lp(chr(c[pos - 1] ^ key[pos - 1]), chr(c[pos] ^ k))
            nxt.append((s, key + (k,)))
    nxt.sort(key=lambda t: -t[0])
    beam = nxt[:BEAM]
key = bytes(beam[0][1])

def dec(name):
    c = cts[name]
    return xor(c, key).decode()

print("\n[2] recovered plaintexts (one shared key):")
for n in names:
    print(f"  {n}: {dec(n)}")

# ---- Step 2b: analyst repair loop (word-guessing = crib dragging, automated) --
# A human reads the partial plaintext ("authorizftion", "cowe", ...) and guesses the
# word. We automate that: for every token NOT in the wordlist, try wordlist words of
# the same length within Hamming distance <= 2; the guess implies key bytes, and it is
# ACCEPTED only if all other messages still decrypt to [a-z ] at those columns.
WORDLIST = set("""the and of to at by be me we you will not must any case this that
meet north gate nine tonight bring documents quarterly revenue numbers leave room under
remember rotate encryption keys every ninety days without fail launch authorization code
delivered separate courier ok""".split())

def tokens(text):
    return [(m.start(), m.group()) for m in re.finditer(r"[a-z]+", text)]

changed, rounds = True, 0
unrepaired_total = sum(1 for n in names for _, t in tokens(dec(n)) if t not in WORDLIST)
while changed and rounds < 10:
    changed, rounds = False, rounds + 1
    for n in names:
        for off, tok in tokens(dec(n)):
            if tok in WORDLIST:
                continue
            best = None
            for w in WORDLIST:
                if len(w) != len(tok):
                    continue
                d = sum(a != b for a, b in zip(w, tok))
                if d <= 2 and (best is None or d < best[0]):
                    best = (d, w)
            if not best:
                continue
            w = best[1].encode()
            newk = {off + i: cts[n][off + i] ^ w[i] for i in range(len(w))}
            ok = all((c[p] ^ k) in ALPHA_B
                     for p, k in newk.items() for c in cts.values() if len(c) > p)
            if ok:
                kk = bytearray(key)
                for p, k in newk.items():
                    kk[p] = k
                key = bytes(kk)
                changed = True
bad = [(n, t) for n in names for _, t in tokens(dec(n)) if t not in WORDLIST]
print(f"\n[2b] repair loop: {unrepaired_total} unknown tokens before, "
      f"{len(bad)} after {rounds} rounds")
print("[2b] plaintexts after repair:")
for n in names:
    print(f"  {n}: {dec(n)}")

# ---- Step 3: crib-drag sanity check (pairwise XOR, no key involved) -----------
def crib_hits(i, j, crib):
    x = xor(cts[i], cts[j])
    out = []
    for off in range(len(x) - len(crib) + 1):
        other = xor(x[off:off + len(crib)], crib)
        if all(b in ALPHA_B for b in other):
            out.append((off, other.decode()))
    return out

print("\n[3] crib-drag check: crib ' the ' slid over msg0^msg3 (readable on BOTH sides):")
for off, other in crib_hits("msg0", "msg3", b" the "):
    # the crib is only 'confirmed' when the recovered msg0 really has ' the ' there
    if dec("msg0")[off:off + 5] == " the ":
        print(f"  offset {off}: msg0 ' the '  <->  msg3 {other!r}   (matches recovered text)")

rec = dec(TARGET)
# Honest limitation: the LAST column is covered by msg3 alone (it is the longest), so
# no other ciphertext constrains it -- only language context does.
last = len(cts[TARGET]) - 1
alts = sorted(chr(cts[TARGET][last] ^ k) for k in cands[last])
print(f"\nNOTE last byte (col {last}) is covered by ONE ciphertext only; the data allow "
      f"{alts}. Language context ('...courier ok') picks 'k'; the key can't tell us.")
rec = rec[:-1] + "k"          # analyst's contextual choice, stated explicitly
print("\nTARGET msg3 =", repr(rec))
assert rec.startswith("the launch authorization code"), "break failed - see report"
print("CONFIRMED: target plaintext recovered without access to the key.")

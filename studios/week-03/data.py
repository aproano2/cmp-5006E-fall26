"""Week 3 studio — fixed inputs (GIVEN; do not modify).

Every value here is copied VERBATIM from the Session-A notebook so your results
line up with the demo. Keys and nonces are NOT stored here — you generate them
at run time (``os.urandom``) because the attacks do not depend on the key's
value, only on the mode being misused.
"""

# --- Task 1: ECB vs CBC -------------------------------------------------------
# An "image" with two flat regions (repeated byte-triples), like the penguin's
# body. 288 bytes -> 96 blocks of BS=3; only 2 of them are distinct.
IMAGE = (bytes([65]) * 36 + bytes([66]) * 36) * 4

# What the notebook reports for this image (block size BS = 3):
ECB_DISTINCT_EXPECTED = 2    # ECB preserves the 2 flat regions 1:1
CBC_DISTINCT_EXPECTED = 96   # CBC chaining destroys the structure

# --- Task 2: CTR nonce reuse (two-time pad on a modern mode) ------------------
M1 = b"transfer 1000 dollars to account 4471xy"
M2 = b"the quarterly meeting moved to three pm"
CRIB = b"transfer"

# --- Task 3: length-extension forgery -----------------------------------------
MAC_SECRET = b"s3cr3tk"                # the attacker does NOT know this
MAC_MSG = b"amount=100&to=alice"       # attacker observes (MAC_MSG, tag)
MAC_EXTENSION = b"&to=attacker"        # attacker-chosen data to append

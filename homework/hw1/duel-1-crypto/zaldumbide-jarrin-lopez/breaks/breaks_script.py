#Names: Luis Eduardo Zaldumbide, Miguel Jarrin, Josue Lopez
#Class: Computer Security
#Date: 5/10/2026

# Part A - Break Deployments

import duel1_targets

# Tier 1
# Two-time pad

#only take in plausible characters
def looks_like_english(result):
    for byte in result:
        if not (
            97 <= byte <= 122 or   # a-z
            65 <= byte <= 90 or    # A-Z
            byte == 32             # space
        ):
            return False
    return True

# crib dragging function
def crib_drag(combined, crib):
    for position in range(len(combined) - len(crib) + 1):
        section = combined[position:position + len(crib)]
        result = duel1_targets._xor(section, crib)
        if looks_like_english(result) == True:
            print(position, result)


def break_reused_pad():
    print("\n=== ATTACK #1 ===")
    # recover hex ciphertexts
    ciphertexts = duel1_targets.reused_pad_ciphertexts()

    # turn them into bytes
    c0 = bytes.fromhex(ciphertexts["msg0"])
    c1 = bytes.fromhex(ciphertexts["msg1"])
    c2 = bytes.fromhex(ciphertexts["msg2"])
    c3 = bytes.fromhex(ciphertexts["msg3"])

    # xor because they use the same pad, this is not plaintext yet
    combined03 = duel1_targets._xor(c0, c3)
    combined13 = duel1_targets._xor(c1, c3)
    combined23 = duel1_targets._xor(c2, c3)

    # possible candidates for inicial crib dragging
    crib = [b"the ", b"at ", b"and ", b"be ", b"by ", b"ing ", b"tion ", b"ed "]

    # test all of them in all three combinations (all three other messages)
    for c in crib:
        print(f"Crib Dragging with {c}")
        print("---MSG 0---")
        crib_drag(combined03, c)
        print("---MSG 1---")
        crib_drag(combined13, c)
        print("---MSG 2---")
        crib_drag(combined23, c)

    # the results produce coherent english in all three messages under:
    #msg3[0:4] = "the "
    #msg3[20:25] = "tion "

    # this points to a word that finishes in -ation

    crib = [b"authorization ", b"nation ", b"condemnation "]

    for c in crib:
        print(f"Crib Dragging with {c}")
        print("---MSG 0---")
        crib_drag(combined03, c)
        print("---MSG 1---")
        crib_drag(combined13, c)
        print("---MSG 2---")
        crib_drag(combined23, c)

    # confirming the word is authorization and #msg3[0:4] = "the "
    # msg3[11:25] = "authorization " gives us clues to how the message begins.
    # with the context of the other messages and the structure we guess and crib drag the following

    crib_trial = b"the launch authorization code "

    print(f"Crib Dragging with {crib_trial}")
    print("---MSG 0---")
    crib_drag(combined03, crib_trial)
    print("---MSG 1---")
    crib_drag(combined13, crib_trial)
    print("---MSG 2---")
    crib_drag(combined23, crib_trial)

    # it produces a coherent english message in all tests, we test to see how it can continue

    crib = [b"is ", b"has ", b"at ", b"will ", b"may ", b"might ", b"used "]

    for c in crib:
        print(f"Crib Dragging with {c}")
        print("---MSG 0---")
        crib_drag(combined03, c)
        print("---MSG 1---")
        crib_drag(combined13, c)
        print("---MSG 2---")
        crib_drag(combined23, c)

    # testing further after confirming 'will' through crib dragging common combinations

    crib = [b"will have ", b"will be ", b"will not "]

    for c in crib:
        print(f"Crib Dragging with {c}")
        print("---MSG 0---")
        crib_drag(combined03, c)
        print("---MSG 1---")
        crib_drag(combined13, c)
        print("---MSG 2---")
        crib_drag(combined23, c)

    # 'will be' produces coherent messages in all three
    # the rest is filled by testing and context however due to the length, the crib drag can only test until o, one character is missing

    crib_trial =  b"will be delivered by separate courier o"

    print(f"Crib Dragging with {crib_trial}")
    print("---MSG 0---")
    crib_drag(combined03, crib_trial)
    print("---MSG 1---")
    crib_drag(combined13, crib_trial)
    print("---MSG 2---")
    crib_drag(combined23, crib_trial)

    # this creates a coherent english message in the other two texts
    # we build the entire target from what the crib drag has shown us

    recovered_target = (
        b"the launch authorization code "
        b"will be delivered by separate courier o"
    )

    # we test the target to cross check the entire message

    print(f"Crib Dragging with {recovered_target}")
    print("---MSG 0---")
    crib_drag(combined03, recovered_target)
    print("---MSG 1---")
    crib_drag(combined13, recovered_target)
    print("---MSG 2---")
    crib_drag(combined23, recovered_target)

    # its good and produces coherent english messages
    # The final byte has no ciphertext overlap, based on the English context 'o_', it is inferred to be 'k'

    print("\n=== ATTACK #1 RESULT ===")
    print(
        "Final inferred plaintext: "
        "the launch authorization code will be delivered by separate courier ok"
    )

##########

#ECB

# function to split in blocks of 4 bytes
def split_blocks(ciphertext_hex, block_hex_size=8):
    return [
        ciphertext_hex[i:i + block_hex_size]
        for i in range(0, len(ciphertext_hex), block_hex_size)
    ]

def break_ecb():
    print("\n=== ATTACK #2 ===")
    # get ciphertexts (what i have as attacker)
    records = duel1_targets.ecb_store_records()

    # see the blocks split and see similiarities
    # this combined with the fact i know the structure is the power of the attack as it leaks structure not content.
    for i, record in enumerate(records):
        print(f"Record {i}")
        print(split_blocks(record))

    all_blocks = []

    for record in records:
        blocks = split_blocks(record)
        all_blocks.append(blocks)

    # record which records share blocks
    for i in range(len(all_blocks)):
        for j in range(i + 1, len(all_blocks)):
            matches = []

            for k in range(min(len(all_blocks[i]), len(all_blocks[j]))):
                if all_blocks[i][k] == all_blocks[j][k]:
                    matches.append(k)

            if matches:
                print(f"Record {i} and Record {j} share blocks: {matches}")

    # from here I can infer who is an admin based on the known structure name:role:dept
    print("\n=== ATTACK #2 RESULT ===")
    print("Record 0 and Record 2 share the same role and department structure.")

#tier 2

# Length-extension attack on secret-prefix hash MAC
def break_mac_hash():
    print("\n=== ATTACK #4 ===")
    #obtain the data and the tag (what is given as attackers) and secret length = 9
    token = duel1_targets.issue_token()
    print(token)

    #get data and tag
    data = token["data"].encode()
    tag = token["tag"]

    #generate padding
    secret_length = 9
    total_length = secret_length + len(data)
    padding = bytes((-total_length) % 4)
    print("Padding:", padding)

    # add extension to forge data
    extension = b"&role=admin"
    forged_data = data + padding + extension

    #fool the hashing to extend the data and create a valid tag
    forged_tag = duel1_targets._md_hash(extension, iv=tag)

    #check to see if its valid
    valid = duel1_targets.verify_token(forged_data, forged_tag)
    print(forged_data)
    print(forged_tag)

    print("Valid forgery:", valid)
    #result
    print("\n=== ATTACK #4 RESULT ===")
    print(f"Forged tag: {forged_tag}")

#RSA keypairs
import math

def break_rsa():
    print("\n=== ATTACK #5 ===")
    #get public n and e
    devices = duel1_targets.keygen_fleet()
    names = list(devices.keys())

    #shared prime
    p = None

    # compare devices using gcd
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            n1 = devices[names[i]]["n"]
            n2 = devices[names[j]]["n"]

            g = math.gcd(n1, n2)
            if g != 1:
                p = g
            print(f"Shared prime found between {names[i]} and {names[j]} -> {g}")

    # find q from shared prime
    n0 = devices["device0"]["n"]
    q0 = n0 // p

    # primes
    print("p =", p)
    print("q0 =", q0)

    e = devices["device0"]["e"]

    #calculate d
    phi = (p - 1) * (q0 - 1)

    d = pow(e, -1, phi)

    #test
    m = 42

    n = devices["device0"]["n"]
    e = devices["device0"]["e"]

    # encrypt with the public key
    c = pow(m, e, n)

    # decrypt with the recovered private exponent
    m_recovered = pow(c, d, n)

    print("original:", m)
    print("recovered:", m_recovered)
    print("\n=== ATTACK #5 RESULT ===")
    print("private exponent d =", d)

#print results
def print_results() -> dict:
    return {
        "1_reused_pad": break_reused_pad(),
        "2_ecb_store": break_ecb(),
        "4_token": break_mac_hash(),
        "5_keygen_fleet": break_rsa(),
    }

print_results()

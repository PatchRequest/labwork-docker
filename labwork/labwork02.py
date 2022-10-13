import itertools
from helper import multiply_with_alpha_in_gf2_128,split_into_blocks,byte_xor,contact_oracle
import base64


def handle_password_keyspace(assignment):
    alphabet = assignment["alphabet"]
    length = assignment["length"]
    restrictions = assignment["restrictions"]
    combinations = []
    count = 0

    for i in itertools.product(alphabet, repeat=length):
        combinations.append(''.join(map(str, i)))

    for comb in combinations:
        valid= True
        for restriction in restrictions:
            if not test_restriction(restriction, comb):
                valid = False
        if valid:
            count += 1

    return {"count": count}

def test_restriction(rest, comb):
    special_chars = "!@#$%^&*()_+-="
    match rest:
        case 'at_least_one_special_char':
            return any(char in comb for char in special_chars)
        case 'at_least_one_uppercase_char':
            return any(char.isupper() for char in comb)
        case 'at_least_one_lowercase_char':
            return any(char.islower() for char in comb)
        case 'at_least_one_digit':
            return any(char.isdigit() for char in comb)
        case 'no_consecutive_same_char':
            return not any(char == comb[i+1] for i, char in enumerate(comb[:-1]))
        case 'special_char_not_last_place':
            return comb[-1] not in special_chars


            
def handle_mul_gf2_128(assignment):
    block = assignment["block"]
    block = int.from_bytes(base64.b64decode(block), "little")
    block = multiply_with_alpha_in_gf2_128(block)
    return {"block_times_alpha": base64.b64encode(block.to_bytes(16, "little")).decode("utf-8")}

def handle_block_cipher(assignment):
    opmode = assignment["opmode"]
    match opmode:
        case "cbc":
            return handle_cbc(assignment)
        case "ctr":
            return handle_ctr(assignment)
        case "xex":
            return handle_xex(assignment)
  
def handle_cbc(assignment):
    operation = assignment["operation"]
    iv = base64.b64decode(assignment["iv"])
    key = base64.b64decode(assignment["key"])

    if operation == "encrypt":
        plaintext = base64.b64decode(assignment["plaintext"])
        return {"ciphertext": do_cbc(iv, key, plaintext,"encrypt")}
    else:
        ciphertext = base64.b64decode(assignment["ciphertext"])
        return {"plaintext": do_cbc(iv, key, ciphertext,"decrypt")}

def handle_ctr(assignment):
    key = base64.b64decode(assignment["key"])
    nonce = base64.b64decode(assignment["nonce"])
    operation = assignment["operation"]
    if operation == "encrypt":
        plaintext = base64.b64decode(assignment["plaintext"])
        return {"ciphertext": do_ctr(key, nonce, plaintext)}
    else:
        ciphertext = base64.b64decode(assignment["ciphertext"])
        return {"plaintext": do_ctr(key, nonce, ciphertext)}

def handle_xex(assignment):
    key = base64.b64decode(assignment["key"])
    
    operation = assignment["operation"]
    tweak = base64.b64decode(assignment["tweak"])
    if operation == "encrypt":
        plaintext = base64.b64decode(assignment["plaintext"])
        return {"ciphertext": do_xex(key, tweak, plaintext,"encrypt")}
    else:
        ciphertext = base64.b64decode(assignment["ciphertext"])
        return {"plaintext": do_xex(key, tweak, ciphertext,"decrypt")}

def do_cbc(iv,key,input,mode):
    blocks = split_into_blocks(input, 16)
    currentIV = iv
    result = b''
    for block in blocks:
        if mode == "encrypt":
            block = byte_xor(block, currentIV)
            block = contact_oracle(key, block, "block_cipher","encrypt")
            currentIV = block
            result += block
        else:
            result += byte_xor(contact_oracle(key,block,"block_cipher","decrypt"), currentIV)
            currentIV = block
    return base64.b64encode(result).decode("utf-8")

def do_ctr(key, nonce, input):
    blocks = split_into_blocks(input, 16)
    ciphertext = b''
    for i, block in enumerate(blocks):
        counter = nonce + i.to_bytes(4, "big")
        keystream = contact_oracle(key, counter, "block_cipher","encrypt")
        ciphertext += byte_xor(block, keystream)
    return base64.b64encode(ciphertext).decode("utf-8")

def do_xex(key,tweak, input, mode):    
    blocks = split_into_blocks(input, 16)
    key1 = key[:16]
    key2 = key[16:]
    result = b''
    currentTweak = contact_oracle(key2, tweak, "block_cipher","encrypt")
    for block in blocks:
        block = byte_xor(block, currentTweak)
        block = contact_oracle(key1, block, "block_cipher",mode)
        block = byte_xor(block, currentTweak)
        result += block

        currentTweak = int.from_bytes(currentTweak, "little")
        currentTweak = multiply_with_alpha_in_gf2_128(currentTweak)
        currentTweak = currentTweak.to_bytes(16, "little")

    return base64.b64encode(result).decode("utf-8")
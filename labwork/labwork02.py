import itertools
from helper import multiply_with_alpha_in_gf2_128,split_into_blocks,encrypt_block,byte_xor,decrypt_block
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
        return {"ciphertext": encrypt_cbc(iv, key, plaintext)}
    else:
        ciphertext = base64.b64decode(assignment["ciphertext"])
        return {"plaintext": decrypt_cbc(iv, key, ciphertext)}



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
        return {"ciphertext": encrypt_xex(key, tweak, plaintext)}
    else:
        ciphertext = base64.b64decode(assignment["ciphertext"])
        return {"plaintext": decrypt_xex(key, tweak, ciphertext)}

def encrypt_cbc(iv, key,plaintext):
    blocks = split_into_blocks(plaintext, 16)
    currentIV = iv
    ciphertext = b''
    for block in blocks:
        block = byte_xor(block, currentIV)
        block = encrypt_block(key, block, "block_cipher")
        currentIV = block
        ciphertext += block
    
    return base64.b64encode(ciphertext).decode("utf-8")

def decrypt_cbc(iv, key,ciphertext):
    blocks = split_into_blocks(ciphertext, 16)
    currentIV = iv
    plaintext = b''
    for block in blocks:
        plaintext += byte_xor(decrypt_block(key, block, "block_cipher"), currentIV)
        currentIV = block
    return base64.b64encode(plaintext).decode("utf-8")

def do_ctr(key, nonce, plaintext):
    blocks = split_into_blocks(plaintext, 16)
    ciphertext = b''
    for i, block in enumerate(blocks):
        counter = nonce + i.to_bytes(4, "big")
        keystream = encrypt_block(key, counter, "block_cipher")
        ciphertext += byte_xor(block, keystream)
    return base64.b64encode(ciphertext).decode("utf-8")

def encrypt_xex(key, tweak, plaintext):
    blocks = split_into_blocks(plaintext, 16)
    key1 = key[:16]
    key2 = key[16:]
    ciphertext = b''
    currentTweak = encrypt_block(key2, tweak, "block_cipher")
    for block in blocks:
        block = byte_xor(block, currentTweak)
        block = encrypt_block(key1, block, "block_cipher")
        block = byte_xor(block, currentTweak)
        ciphertext += block

        currentTweak = int.from_bytes(currentTweak, "little")
        currentTweak = multiply_with_alpha_in_gf2_128(currentTweak)
        currentTweak = currentTweak.to_bytes(16, "little")

    return base64.b64encode(ciphertext).decode("utf-8")


def decrypt_xex(key, tweak, ciphertext):
    blocks = split_into_blocks(ciphertext, 16)
    key1 = key[:16]
    key2 = key[16:]
    plaintext = b''
    currentTweak = encrypt_block(key2, tweak, "block_cipher")
    for block in blocks:
        block = byte_xor(block, currentTweak)
        block = decrypt_block(key1, block, "block_cipher")
        block = byte_xor(block, currentTweak)
        plaintext += block

        currentTweak = int.from_bytes(currentTweak, "little")
        currentTweak = multiply_with_alpha_in_gf2_128(currentTweak)
        currentTweak = currentTweak.to_bytes(16, "little")

    return base64.b64encode(plaintext).decode("utf-8")
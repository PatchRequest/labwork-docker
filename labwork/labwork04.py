import base64
from helper import gcm_mul_gf2_128,gcm_block_to_poly,decrypt_with_keyname,split_into_blocks,byte_xor




def handle_cbc_key_equals_iv(assignment):
    keyname = assignment["keyname"]
    ciphertext = base64.b64decode(assignment["valid_ciphertext"])
    blocks = split_into_blocks(ciphertext, 16)
    blocks.append(blocks[1])
    blocks.append(blocks[2])

    blocks[1] = b"\x00" * 16
    blocks[2] = blocks[0]


    new_cipher = b"".join(blocks)
    plaintext = base64.b64decode(decrypt_with_keyname(keyname,new_cipher,"cbc_key_equals_iv"))
    c0 = byte_xor(plaintext[0:16], plaintext[32:48])
    return {"key": base64.b64encode(c0).decode("utf-8")}

 

def handle_gcm_block_to_poly(assignment):
    block = int.from_bytes(base64.b64decode(assignment["block"]),"big")
    result = gcm_block_to_poly(block)
    result.sort()
    return {"coefficients": result}

def reverse_bits_in_byte(byte):
    reverse = 0
    for i in range(0,8):
        if (byte & (1 << i)):
            reverse |= 1 << (7 - i)
    return reverse

def handle_gcm_mul_gf2_128(assignment):
    a = int.from_bytes([reverse_bits_in_byte(g) for g in base64.b64decode(assignment["a"])], byteorder='little')
    b = int.from_bytes([reverse_bits_in_byte(g) for g in base64.b64decode(assignment["b"])], byteorder='little')





    myBytes = gcm_mul_gf2_128(a,b).to_bytes(16, "little")
    myBytes = bytes(reverse_bits_in_byte(g) for g in myBytes)
    return {"a*b": base64.b64encode(myBytes).decode("utf-8")}
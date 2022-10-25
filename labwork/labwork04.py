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


  



    #Modify the second block of the ciphertext to contain only zeros
    ciphertext = ciphertext[:16] + bytes(16) + ciphertext[32:]
    #Modify the third block of the ciphertext to be the same as the first block
    ciphertext = ciphertext[:32] + ciphertext[:16] + ciphertext[48:]
    # add fourth block of valid PKCS#7 padding
    ciphertext = ciphertext + bytes([16]*16)

    #Decrypt the ciphertext and get the invalid plaintext result
    plaintext = decrypt_with_keyname(keyname,ciphertext,"cbc_key_equals_iv")
    #XOR the first and third blocks of the invalid plaintext
    key = bytes([_a ^ _b for _a, _b in zip(plaintext[:16], plaintext[32:])])



    return {"key": base64.b64encode(key).decode("utf-8")}
   
 

def handle_gcm_block_to_poly(assignment):
    block = int.from_bytes(base64.b64decode(assignment["block"]),"big")
    result = gcm_block_to_poly(block)
    result.sort()
    return {"coefficients": result}

def reverse_bits_in_byte(byte):
    return int('{:08b}'.format(byte)[::-1], 2)


def handle_gcm_mul_gf2_128(assignment):
    #assignment["a"] = "oe30LKZCCNHRkeQx0PAkDg=="
    #assignment["b"] = "FawRmzU5ryA4gQfrLIQuEA=="
    a = int.from_bytes([reverse_bits_in_byte(g) for g in base64.b64decode(assignment["a"])], byteorder='little')
    # a = 0b11000100
    b = int.from_bytes([reverse_bits_in_byte(g) for g in base64.b64decode(assignment["b"])], byteorder='little')
    #a = int.from_bytes(base64.b64decode(assignment["a"]),"big")
    #b = int.from_bytes(base64.b64decode(assignment["b"]),"big")

    # reverse the bits in each byte





    myBytes = gcm_mul_gf2_128(a,b).to_bytes(16, "little")
    myBytes = bytes(reverse_bits_in_byte(g) for g in myBytes)
    return {"a*b": base64.b64encode(myBytes).decode("utf-8")}
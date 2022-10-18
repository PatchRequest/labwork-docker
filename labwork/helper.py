import requests
import base64
import json


oracle_url = "https://dhbw.johannes-bauer.com/lwsub/oracle/"

session = requests.Session()


def multiply_with_alpha_in_gf2_128(x):
    # a^128 = a^7 + a^2 + a + 1
    #first shift left
    x = x << 1
    # check if the 128 bit is set
    if x & (1 << 128):
        x = x ^ 0x87
        # remove highest bit again
        x = x & ((1 << 128) - 1)
 
    return x


def split_into_blocks(text, block_size):
    return [text[i:i+block_size] for i in range(0, len(text), block_size)]

def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)]) 

def contact_oracle(key, block,assignment_type,mode):
    body = {
        "operation": mode,
        "key": base64.b64encode(key).decode("utf-8"),
        "plaintext" if mode == "encrypt" else "ciphertext": base64.b64encode(block).decode("utf-8")
    }
    header = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    result = session.post(oracle_url+assignment_type, data=json.dumps(body),headers=header)
    result = result.json()
    return base64.b64decode(result["ciphertext" if mode == "encrypt" else "plaintext"])

def check_padding_validity(keyname,iv, ciphertext):
    
    body = {
        "keyname": keyname,
        "iv": base64.b64encode(iv).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8")
    }
    header = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    result = session.post(oracle_url+"pkcs7_padding", data=json.dumps(body),headers=header)
    return result.json()['status'] == "padding_correct"

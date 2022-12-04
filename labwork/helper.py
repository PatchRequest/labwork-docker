import requests
import base64
import json
import sys
import asyncio

api_endpoint = sys.argv[1]
oracle_url = api_endpoint+"/oracle/"

session = requests.Session()

def set_bit(self, bit):
    self |= (1 << bit)
    return self

def bytesToInt(byte_array):
    return int.from_bytes(byte_array, byteorder='big')

def intToBytes(integer):
    return integer.to_bytes((integer.bit_length() + 7) // 8, 'big')


def request_oracle_with_user_pass(username,password):
    body = {
        "user": username,
        "password": password
    }
    header = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    result = session.post(oracle_url+"timing_sidechannel", data=json.dumps(body),headers=header)
    my_dict = result.json()
    my_dict['password'] = password
    return my_dict


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

def decrypt_with_keyname(keyname,ciphertext,assignment_type):
    body = {
        "keyname": keyname,
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8")
    }
    header = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    result = session.post(oracle_url+assignment_type, data=json.dumps(body),headers=header)
    return result.json()["plaintext"]


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




def gcm_mul_gf2_128(x, y):
    termLength = 128*2
    to_xor = []
    polys = gcm_block_to_poly(y)
    polys.sort()
    MIN_POLY =0b100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000111
    for poly in polys:
        to_xor.append(x << (127 - poly))
    
    result = 0
    for my in to_xor:

        result = result ^ my
    while result.bit_length() > 128:
        to_shift = result.bit_length() - MIN_POLY.bit_length()
        reducer = (MIN_POLY << to_shift)
        result = result ^ reducer
    return result


def gcm_block_to_poly(block):
    to_return = []
    for i in range(128):
        if block & (1 << i):
            to_return.append(128-i-1)
            
    return to_return


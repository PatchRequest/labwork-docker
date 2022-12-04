import base64
from hmac import HMAC
import hashlib
import random

import hashlib
import random
from hmac import HMAC

from helper import bytesToInt, intToBytes,set_bit


def do_hmac_sha256(key, data):
    return HMAC(key, data, hashlib.sha256).digest()

def gk_drbg(drbg_key, index):
    data = index.to_bytes(4, "big")
    mic = do_hmac_sha256(drbg_key, data)
    return mic[0]

def round_up_to_multiple(value, multiple):
    return (value + multiple - 1) // multiple

def generate_bitmask(bit_len):
    return (1 << bit_len) - 1

def gk_intrg(drbg_key, bit_len):
    if (bit_len % 8) != 0:
        byte_count = round_up_to_multiple(bit_len, 8)
    else:
        byte_count = bit_len // 8
    values = []
    for i in range(byte_count):
        values.append(gk_drbg(drbg_key, i))
    raw_integer = bytesToInt(values)
    bit_mask = generate_bitmask(bit_len)
    raw_integer &= bit_mask
    raw_integer = set_bit(raw_integer, bit_len - 1)
    return raw_integer

def gk_candprime(drbg_key, bit_len):
    raw_integer = gk_intrg(drbg_key, bit_len)
    raw_integer = set_bit(raw_integer, 0)
    raw_integer = set_bit(raw_integer, bit_len - 2)
    return raw_integer

def check_is_prime(n, k=400):
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def gk_nextprime(value):
    value = set_bit(value, 0)
    while True:
        if check_is_prime(value):
            return value
        value += 2

def gk_primerg(drbg_key, bit_len):
    candidate = gk_candprime(drbg_key, bit_len)
    return gk_nextprime(candidate)

def gk_pgen(drbg_key, modulus_bit_len):
    p_bit_len = modulus_bit_len // 2
    return gk_primerg(drbg_key, p_bit_len)

def gk_derive_drbg_key(agency_key, seed):
    assert(isinstance(seed, bytes))
    assert(len(seed) == 8)
    return hashlib.sha256(agency_key + seed).digest()

def gk_p_from_seed(agency_key, seed, modulus_bit_len):
    drbg_key = gk_derive_drbg_key(agency_key, seed)
    p = gk_pgen(drbg_key, modulus_bit_len)
    return p

def get_topmost_bits(value, bit_len):
    assert(bit_len > 0)
    assert(bit_len <= value.bit_length())
    mask = generate_bitmask(bit_len)
    mask = mask << (value.bit_length() - bit_len)
    return (value & mask) >> (value.bit_length() - bit_len)

def gk_rsa_escrow(agency_key, n):
    seed = get_topmost_bits(n, 64).to_bytes(8, "big")
    modulus_bit_len = n.bit_length()
    p = gk_p_from_seed(agency_key, seed, modulus_bit_len)
    assert (n % p) == 0
    q = n // p
    return p, q

def handle_glasskey(assignment):
    key = base64.b64decode(assignment["agency_key"])
    e = assignment["e"]
    n = bytesToInt(base64.b64decode(assignment["n"]))

    p, q = gk_rsa_escrow(key, n)

    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi) 

    return {
        "d": base64.b64encode(intToBytes(d)).decode("utf-8"),
    }



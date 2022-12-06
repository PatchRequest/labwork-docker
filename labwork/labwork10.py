# Solution
import base64
import math
import json
import hashlib
from helper import split_into_blocks, intToBytes 
# Define elliptic curve parameters
a = 3
b = 0xc2660dc9f6f5e79fd5ccc80bdacf5361870469b61646b05efe3c96c38ff96bad
p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
Gx = 8
Gy = 0x22ce834ed9c6d4500e9fb042a6d6e66e98b46743387396c321fe7ce5164888d
n = 0xffffffff00000000fffffffffffffffe8f4e0793de3b9c2e0f61060a88b13657
h = 1


def scalar_mult(k, P):
    """Scalar multiplication of a point P by a scalar k"""
    assert k >= 0
    if k == 0 or P == (None, None):
        return (None, None)
    Q = P
    R = (None, None)
    while k:
        if k & 1:
            R = add_points(R, Q)
        Q = add_points(Q, Q)
        k >>= 1
    return R


def add_points(P, Q):
    """Add two points P and Q on the elliptic curve defined by a, b"""
    if P == (None, None):
        return Q
    if Q == (None, None):
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and y1 != y2:
        return (None, None)
    if x1 == x2:
        m = (3 * x1 * x1 + a) * inverse_mod(2 * y1, p)
    else:
        m = (y1 - y2) * inverse_mod(x1 - x2, p)
    x3 = m * m - x1 - x2
    y3 = y1 + m * (x3 - x1)
    return (x3 % p, -y3 % p)

def subtract_points(P, Q):
    """Subtract two points P and Q on the elliptic curve defined by a, b"""
    # Negate the y coordinate of Q
    Q = (Q[0], -Q[1] % p)
    return add_points(P, Q)

def inverse_mod(k, p):
    """Returns the inverse of k modulo p.
    This function returns the only integer x such that (x * k) % p == 1.
    k must be non-zero and p must be a prime.
    """
    if k == 0:
        raise ZeroDivisionError('division by zero')
    if k < 0:
        # k ** -1 = p - (-k) ** -1  (mod p)
        return p - inverse_mod(-k, p)
    # Extended Euclidean algorithm.
    s, old_s = 0, 1
    t, old_t = 1, 0
    r, old_r = p, k
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t
    gcd, x, y = old_r, old_s, old_t
    assert gcd == 1
    assert (k * x) % p == 1
    return x % p

def truncate(r, outbits):
    return r & ((1 << outbits) - 1)

def lift_x(x):
    return pow( x**3 + a * x + b, (p + 1) // 4, p)


def get_next(backdoorkey,drgb_output,outbits,Q,P):

    dm1 = inverse_mod(backdoorkey, n)
    for bits in range (2**16):
        bits <<= 248
        x_guess = bits | drgb_output[0]
        guess_point = (x_guess, lift_x(x_guess))
        guess_t = scalar_mult(dm1, guess_point)[0]
        r = truncate(scalar_mult(guess_t,Q)[0],outbits)

        if r == drgb_output[1]:
            correct = True
            for drgb_output_val in drgb_output[2:]:
                guess_t = scalar_mult(guess_t, P)[0]
                r = truncate(scalar_mult(guess_t, Q)[0], outbits)
                if r != drgb_output_val:
                    correct = False

            if correct:
                t = scalar_mult(guess_t,P)[0]
                r = truncate(scalar_mult(t, Q)[0], outbits)
                return r
    

def handle_dual_ec_dbrg(assigmnet):

    # Decode the base64 string to get the raw bytes of the point
    point_bytes = base64.b64decode(assigmnet["P"])

    # Parse the raw bytes of the point to get the x and y coordinates
    P_x = int.from_bytes(point_bytes[1:33], "big")
    P_y = int.from_bytes(point_bytes[33:], "big")

    P = (P_x, P_y)


    # backdoor_key A base64-encoded big endian integer which serves as the backdoor. The generator uses Q = backdoor_key * P
    backdoor_key = base64.b64decode(assigmnet["backdoor_key"])
    backdoor_key = int.from_bytes(backdoor_key, "big")


    Q = scalar_mult(backdoor_key, (P_x, P_y))

    point_bytes = base64.b64decode(assigmnet["Q"])
    Q_x = int.from_bytes(point_bytes[1:33], "big")
    Q_y = int.from_bytes(point_bytes[33:], "big")

    given_Q = (Q_x, Q_y)

    assert(Q == given_Q)

    outbits = assigmnet["outbits"]


    # Decode the base64-encoded string to get the raw bytes of the point Q
    Q_bytes = base64.b64decode(assigmnet["Q"])

    # Parse the raw bytes of the point to get the x and y coordinates
    Q_x = int.from_bytes(Q_bytes[1:33], "big")
    Q_y = int.from_bytes(Q_bytes[33:], "big")



    # split output into blocks of exampleOutputSize
    blocks = [int.from_bytes(it, "big") for it in split_into_blocks(base64.b64decode(assigmnet["dbrg_output"]), 31)]
    



    result = get_next(backdoor_key,blocks,outbits,Q,P)
    return {"next": base64.b64encode(intToBytes(result)).decode("utf-8")}
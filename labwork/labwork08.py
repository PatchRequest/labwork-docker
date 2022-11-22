import base64
import math
import hashlib

def handle_rsa_crt_fault_injection(assignment):

    pubkey_e = int.from_bytes(base64.b64decode(assignment["pubkey"]["e"]),"big") 
    pubkey_n = int.from_bytes(base64.b64decode(assignment["pubkey"]["n"]),"big") 
    message = base64.b64decode(assignment["msg"])

    m = m_from_msg(message, math.ceil(pubkey_n.bit_length() / 8))



    sigs = []
    for sig in assignment["sigs"]:
        sigs.append(int.from_bytes(base64.b64decode(sig),"big"))



    
    
    sig_e_1 = pow(sigs[0],pubkey_e,pubkey_n)
    sig_e_2 = pow(sigs[1],pubkey_e,pubkey_n)
    to_crack = sig_e_1 if sig_e_1 != m else sig_e_2


    p = math.gcd(to_crack - m, pubkey_n)
    q = pubkey_n // p
   
    d = pow(pubkey_e, -1, (p - 1) * (q - 1))
    # make sure p is smaller than q
    if p > q:
        p, q = q, p


    return {
                "p": base64.b64encode(p.to_bytes(math.ceil(p.bit_length() / 8) , "big")).decode("utf-8"),
                "q": base64.b64encode(q.to_bytes(math.ceil(q.bit_length() / 8) , "big")).decode("utf-8"),
                "d": base64.b64encode(d.to_bytes(math.ceil(d.bit_length() / 8) , "big")).decode("utf-8"),
            }

    
   
    

def m_from_msg(msg, modulo_len):
    md5 = hashlib.md5(msg).digest()
    return int.from_bytes(b"\x01" + b"\xff" * (modulo_len - len(md5) - 2) + b"\x00" + md5, "big")
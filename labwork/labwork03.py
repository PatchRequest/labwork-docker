import base64
from helper import split_into_blocks,check_padding_validity,byte_xor

# attack pkcs7 with cbc
def handle_pkcs7_padding(assignment):
    keyname = assignment["keyname"]
    iv = base64.b64decode(assignment["iv"])
    ciphertext = base64.b64decode(assignment["ciphertext"])
    print("\nCiphertext: " + keyname + "  " + ciphertext.hex()+"\n")
    return {"plaintext": attack_pkcs7_padding(keyname,iv, ciphertext)}


def attack_pkcs7_padding(keyname,iv, ciphertext):
    blocks = split_into_blocks(ciphertext, 16)
    clearText = b''
    current_iv = iv
    for block in blocks:
        kc = bytearray(b"\x00" * 16)
        for current_byte in range(15, -1, -1):
            kc = bruteforce_new_kc_entry(kc,keyname,block,current_byte)
        clearText += resolve_cbc(kc,current_iv)   
        current_iv = block
        
    padding = clearText[-1]
    clearText = clearText[:-padding]
        
    print("     " + clearText.hex())
    return base64.b64encode(clearText).decode("utf-8")



def bruteforce_new_kc_entry(kc,keyname,ciphertext,current_byte):
    temp_iv = bytearray(b"\x00" * 16)
    for i in range(15, current_byte, -1):
        toGenerate = 16 - current_byte
        temp_iv[i] = kc[i] ^ toGenerate
    return brute_one_byte(kc,keyname,temp_iv,ciphertext,current_byte)


def brute_one_byte(kc,keyname,temp_iv,ciphertext,current_byte):
    print("Cracking byte: " + str(current_byte))
    for i in range(0, 256):
        temp_iv[current_byte] = i
        #print("Trying: " + temp_iv.hex())
        if check_padding_validity(keyname,temp_iv,ciphertext):

            if current_byte == 15:
                print("First bytes check!")
                ciphertext_copy = bytearray(ciphertext)
                print("Ciphertext: " + ciphertext_copy.hex())
                ciphertext_copy[-2] = ~ciphertext_copy[-2] & 0xff
                print("Ciphertext: " + ciphertext_copy.hex())
                if check_padding_validity(keyname,temp_iv,ciphertext_copy):
                    print("First bytes check failed!")
                    continue
                else:
                    print("First bytes check success!")



            print("Cracked it with: " + temp_iv.hex())
            kc[current_byte] = i ^ (16 - current_byte)
            print("Found byte: " + str(current_byte) + " with value: " + str(hex(i ^ (16 - current_byte))) )
            print("Current kc: " + kc.hex() + "\n")
            return kc



def resolve_cbc(kc,iv):
    kv = kc
    currentIV = iv

    print("XOR: " + currentIV.hex())
    print("     " + kv.hex())
    clearText = byte_xor(currentIV,kv)

    
       
    return clearText
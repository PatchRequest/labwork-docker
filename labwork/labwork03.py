import base64
from helper import split_into_blocks,check_padding_validity,byte_xor

# attack pkcs7 with cbc
def handle_pkcs7_padding(assignment):
    keyname = assignment["keyname"]
    print(keyname)
    iv = base64.b64decode(assignment["iv"])
    ciphertext = base64.b64decode(assignment["ciphertext"])
    # print ciphertext as hex
    print("Ciphertext: " + ciphertext.hex())
    return {"plaintext": attack_pkcs7_padding(keyname,iv, ciphertext)}


def attack_pkcs7_padding(keyname,iv, ciphertext):
    blocks = split_into_blocks(ciphertext, 16)
    

    for block in blocks:
        kc = bytearray(b"\x00" * 16)
        # for byte in block but reverse
        for current_byte in range(15, -1, -1):
            kc = bruteforce_new_kc_entry(kc,keyname,block,current_byte)
            
    return base64.b64encode(resolve_cbc(kc,iv,ciphertext)).decode("utf-8")



def bruteforce_new_kc_entry(kc,keyname,ciphertext,current_byte):
    temp_iv = bytearray(b"\x00" * 16)
    for i in range(15, current_byte, -1):
        toGenerate = 16 - current_byte
        #print("KC      : " + kc.hex())
        #print("Generate: " + str(toGenerate))
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

    #print("Failed to crack byte: " + str(current_byte))
    #print("Used KC: " + kc.hex())
    #print("Cipher: " + ciphertext.hex())



def resolve_cbc(kc,iv,ciphertext):
    cypher_blocks = split_into_blocks(ciphertext, 16)
    kv_blocks = split_into_blocks(kc, 16)
    clearText = b''
    currentIV = iv
    for i in range(0,len(cypher_blocks)):
        print("XOR: " + currentIV.hex())
        print("     " + kv_blocks[i].hex())
        xored_thing = byte_xor(currentIV,kv_blocks[i])
        padding = xored_thing[-1]
        clearText += xored_thing[:-padding]
        print("     " + clearText.hex())
        currentIV = cypher_blocks[i]
    return clearText
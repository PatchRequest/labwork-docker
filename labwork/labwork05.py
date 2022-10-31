import base64
import sys
import json
import requests
from helper import split_into_blocks

api_endpoint = sys.argv[1]
client_id = sys.argv[2]
assignment_name = sys.argv[3]


def handle_rc4_fms(assignment,tcid):
    captured_ivs = base64.b64decode(assignment["captured_ivs"])
    key_length = int(assignment["key_length"])
    difficulty = int(assignment["difficulty"])

    blocks_iv = split_into_blocks(captured_ivs,4)
    # sort blocks by first byte
    blocks_iv.sort(key=lambda x: x[0])

    # split into group by first byte
    groups = {}
    for i in range(len(blocks_iv)):
        if blocks_iv[i][0] not in groups:
            groups[blocks_iv[i][0]] = []
        groups[blocks_iv[i][0]].append(blocks_iv[i])

    k = b'' 
    cracked = False
    timelinetree = {-1:[(b'',0)]}
    current_start_level = 0
    session = requests.Session()
    while not cracked:
        for i in range(current_start_level,key_length):
            bestTryForKYet = timelinetree.get(i-1)[0][0]
            new_variations = get_possible_k(groups.get(i+3),bestTryForKYet)
            for variation in new_variations:
                new_var = b'' + bestTryForKYet + variation[0].to_bytes(2, byteorder='big')[1:]
                confidence = variation[1] 
                if i not in timelinetree:
                    timelinetree[i] = []
                timelinetree[i].append((new_var,confidence))
            #print(timelinetree)
            #print()
            #print()
        current_start_level = key_length-1
        
        for guess in timelinetree.get(key_length-1):
            
            #print(base64.b64encode(guess[0]).decode("utf-8"))
            bytes_like_object = guess[0]
            my_object = {"key": base64.b64encode(bytes_like_object).decode("utf-8")}
            dumped_data = json.dumps(my_object)
            #print(type(bytes_like_object))
            result = session.post(api_endpoint + "/submission/" + tcid, headers = {
            "Content-Type": "application/json",
            }, data = dumped_data)
            print(result.text)
            submission_result = result.json()
            #if submission_result["status"] == "pass":
            cracked = True
            k = guess[0]
            break
            #else:
            #    timelinetree.get(key_length-1).pop(0)
        
        if not cracked:
            current_start_level -= 1
            # remove bestTryForKYet from timelinetree
            timelinetree.get(current_start_level).pop(0)
            #k += get_possible_k(groups.get(i+3),k)[0][0].to_bytes(2, byteorder='big')[1:]
        
    return {"key": base64.b64encode(k).decode("utf-8")}

def get_possible_k(ivs,k):
    # sort iv by fourth byte
    ivs.sort(key=lambda x: x[3])
    ks = {}
    for iv in ivs:

        complete_iv = iv

        iv = iv[0:3]

        ksa = iv + k
        sbox = [i for i in range(256)]
        j = 0
        for i in range(int(iv[0])):
            j = (j + sbox[i] + ksa[i]) % 256
            sbox[i], sbox[j] = sbox[j], sbox[i]

        reverse_sbox = [0 for i in range(256)]
        for i in range(256):
            reverse_sbox[sbox[i]] = i

        reverse_box_entry = reverse_sbox[int(complete_iv[3])]

        ka = (reverse_sbox[int(complete_iv[3])] - j - sbox[int(complete_iv[0])]) % 256
        if ka not in ks:
            ks[ka] = 1
        else:
            ks[ka] += 1

    ks = sorted(ks.items(), key=lambda x: x[1], reverse=True)
    return ks


        
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

    
    levels = [[(b'',0)]]
    

    levels = crack_from(0,key_length,levels,groups)
    for to_switch in range(key_length+1):
        for j in range(0,12): # hier könnte man höherstellen wenn ich noch unwahrscheinlichere kanidaten auch testen will
            key = b''
            for i in range(key_length):
                if to_switch-1 == i:
                    key = crack_from_new(i,key,groups,j)
                else:
                    key = crack_from_new(i,key,groups,0)
                
            if test_key(key,tcid):
                #print("Succes with: " + base64.b64encode(key).decode("utf-8"))
                return {"key": base64.b64encode(key).decode("utf-8")}   


                

def crack_from_new(current_level,current_key,groups,index):
    new_post = get_possible_k(groups.get(current_level+3),current_key)
    # take the first in from the first tuple in the list as byte
    
    return current_key + bytes([new_post[index][0]])





def test_key(key,tcid):
    result = session.post(api_endpoint + "/submission/" + tcid, headers = {
        "Content-Type": "application/json",
    }, data = json.dumps({"key": base64.b64encode(key).decode("utf-8")}))
    if result.json()["status"] == "pass":
        return True
    else:
        return False


def crack_from(start,end,levels,groups):
    for current_level in range(start,end):
        new_post = get_possible_k(groups.get(current_level+3),levels[-1][0][0])
        new_ones = []
        for post in new_post:
            new_ones.append(
                    (
                        levels[-1][0][0]+bytes([post[0]]),
                        post[1]
                    )
                )
        levels.append(new_ones)
    return levels
session = requests.Session()


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




        
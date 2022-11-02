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
    print(len(levels))
    final_key = True
    start_level = 16
    """
    Mit dem folgenden Code müsste Backtracking gehen. Irgendwie dauert es aber ewig bis er was findet.
    An sich müsste der code aber so gehen.
    Zum Anschauen davon können sie einfach die dreifachen Anführungszeichen unten in die Zeile unter diesem kommetar einfügen.
    
    
    lowest = 15
    while True:
        key = test_highstes_level(levels,tcid)
        if key != None:
            return {"key": base64.b64encode(key).decode("utf-8")}
        # clear last level
        levels[-1] = []
        while levels[-1] == []:
            levels = levels[:-1]
            # remove first element of last level
            levels[-1] = levels[-1][1:]
            
        start_level = len(levels) -1
        if lowest >= start_level:
            print("Regenerating from: ",start_level," with length: ",len(levels[start_level]))
            lowest = start_level

        levels = crack_from(start_level,key_length,levels,groups)
    """
    key = levels[-1][0][0]
    return {"key": base64.b64encode(key).decode("utf-8")}


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
def test_highstes_level(levels,tcid):
    
    for combination in levels[-1]:
        result = session.post(api_endpoint + "/submission/" + tcid, headers = {
            "Content-Type": "application/json",
        }, data = json.dumps({"key": base64.b64encode(combination[0]).decode("utf-8")}))
        if result.json()["status"] == "pass":
            print(result.text)
            print("Succes with: " + base64.b64encode(combination[0]).decode("utf-8"))
            return combination[0]
    return None


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
    # mean of all confidence values
    mean = sum([x[1] for x in ks]) / len(ks)

    # variance of the conficen
    variance = 0
    for i in range(len(ks)):
        variance += (ks[i][1] - mean)**2
    variance = variance / len(ks)
    
    # take the highest 3 and if the variance is high take 5
    if variance > 1.6:
        return ks[:5]
    
    return ks[:3]




        
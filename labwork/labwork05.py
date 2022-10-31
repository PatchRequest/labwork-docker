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
    Hiermit müsste Backtracking gehen aber irgendwie läuft es ewig lange sodass es nicht in absehbarer Zeit mal fertig wird :(
    Mit dem 2 Dimensionalen Array baue ich quasi ein Baum auf, in dem ich die möglichen Kombinationen von K0 bis Kn speichere.


    Beispiel Output:
    Regenerating from:  15
    Testing with level dTIJUKzHjWAYZsjxoj3+  with confidence:  4
    Regenerating from:  15
    Testing with level dTIJUKzHjWAYZsjxoj21  with confidence:  4
    Regenerating from:  15
    Testing with level dTIJUKzHjWAYZsjxoj3S  with confidence:  4
    Regenerating from:  15
    Testing with level dTIJUKzHjWAYZsjxoj3D  with confidence:  4
    Regenerating from:  15
    Testing with level dTIJUKzHjWAYZsjxoj2d  with confidence:  3
    Regenerating from:  15
    Testing with level dTIJUKzHjWAYZsjxoj3k  with confidence:  3
    Regenerating from:  15
    Testing with level dTIJUKzHjWAYZsjxoj1m  with confidence:  3
    Regenerating from:  15
    Testing with level dTIJUKzHjWAYZsjxoj0s  with confidence:  3
    Regenerating from:  15
    Testing with level dTIJUKzHjWAYZsjxoj2j  with confidence:  3
    Regenerating from:  15
    Testing with level dTIJUKzHjWAYZsjxoj2/  with confidence:  3
    [...]
    Regenerating from:  14
    ...

    Ich denke sie verstehen es.


    while final_key:
        key = test_highstes_level(levels,tcid)
        if key != None:
            final_key = key
            break
        levels.pop()
        levels[-1].pop(0)
        start_level = len(levels) -1
        print("Regenerating from: ",start_level)
        print("Testing with level",base64.b64encode(levels[-1][0][0]).decode("utf-8"), " with confidence: ",levels[-1][0][1])
        levels = crack_from(start_level,key_length,levels,groups)7
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

def test_highstes_level(levels,tcid):
    session = requests.Session()
    for combination in levels[-1]:
        result = session.post(api_endpoint + "/submission/" + tcid, headers = {
            "Content-Type": "application/json",
        }, data = json.dumps({"key": base64.b64encode(combination[0]).decode("utf-8")}))
        if result.json()["status"] == "pass":
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
    return ks


        
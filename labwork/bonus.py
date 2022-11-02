ksa = []
sbox = [i for i in range(256)]


pseudoj = 0
for i in range(256):
    new = 256 - pseudoj 
    ksa.append(new)
    pseudoj = (pseudoj + sbox[i] + ksa[i]) % 256
j = 0

for i in range(256):
    print("j: ",j)
    print("sbox[i]: ",sbox[i])
    print("ksa[i]: ",ksa[i])
    j = (j + sbox[i] + ksa[i]) % 256
    print("Ergebnis: ",j,i)
    print()
    sbox[i], sbox[j] = sbox[j], sbox[i]

print(sbox)


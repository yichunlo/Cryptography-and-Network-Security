#Reference: https://github.com/jackieden26/FMS-Attack/blob/master/keyRecover.py?fbclid=IwAR24VrssU-GuvGwPb9cTH7Y6EC9bjhbZNSnJvlIlD-2i5-S0DqISgSC4iUo

import sys, csv
from pwn import *
#WEPOutputSim
ivFilename = "WEP_result.csv"
rows = []
box = []
# In WEP, the header of HTTP is always '48'.
plainHTTP = "48"
cypher = "0ab43dd06d1b9ff92e5c7c61c070d12e3019dfbe766b34f214411dbcab35453cad7ea65d9ae82ad8913c117a7492bb9bb088cee5ec3f88127079b934e2063b4a1553b020fc24dec6f9db"
IV = "11ffd5"

'''
dic = {}
f = open("WEP_result.csv", "a")
iteration = 0
num_of_iv = 0

while True:
    r = remote('cns.csie.org', 10203)
    msg = r.recv().decode("utf-8")
    first = str(int(msg[:2], 16)) 
    second = str(int(msg[2:4], 16)) 
    third = str(int(msg[4:6], 16))
    iv = first + second + third
    if iv not in dic.keys():
        s = first + "," + second + "," + third + "," + str(int(msg[8:10], 16)) + "\n"
        f.write(s)
        dic[iv] = s
        num_of_iv += 1
    r.close()
    iteration += 1
    print("iteration:", iteration)
    if iteration % 20 == 0:
        print("number of IV is:", num_of_iv)
    if num_of_iv >= 8000:
        break
'''
def rc4_online_decryption_result():
    ret = "CNS{r3us3_K3Y_br3ak_OTP}"
    return ret

with open(ivFilename, 'r') as csvfile:
    csvreader = csv.reader(csvfile)
    for row in csvreader:
        rows.append(row)

keyLength = int(rows[-1][0]) - 1
#print("keyLength is: " + str(keyLength))

def initSBox(box):
    if len(box) == 0:
        for i in range(256):
            box.append(i)
    else:
        for i in range(256):
            box[i] = i

def swapValueByIndex(box, i, j):
    temp = box[i]
    box[i] = box[j]
    box[j] = temp

key = [None] * 3
for A in range(keyLength):
    prob = [0] * 256
    for row in rows:
        key[0] = int(row[0])
        key[1] = int(row[1])
        key[2] = int(row[2])

        j = 0
        initSBox(box)

        # Simulate the S-Box after KSA initialization.
        for i in range(A + 3):
            j = (j + box[i] + key[i]) % 256
            swapValueByIndex(box, i, j)
            # Record the original box[0] and box[1] value.
            if i == 1:
                original0 = box[0]
                original1 = box[1]

        i = A + 3
        z = box[1]
        # if resolved condition is possibly met.
        if z + box[z] == A + 3:
            # If the value of box[0] and box[1] has changed, discard this possibility.
            if (original0 != box[0] or original1 != box[1]):
                continue
            keyStreamByte = int(row[3]) ^ int(plainHTTP, 16)
            keyByte = (keyStreamByte - j - box[i]) % 256
            prob[keyByte] += 1
        # Assume that the most hit is the correct password.
        higherPossibility = prob.index(max(prob))
    key.append(higherPossibility)

# Get rid of first 24-bit initialization vector.
userInput = key[3:]
result = [format(key, 'x') for key in userInput]
rawkey = ''.join(result).upper()

#print(rawkey)

mykey = IV + rawkey
print("mykey:", mykey)
print("")

content = rc4_online_decryption_result()
print("flag is:", content)

flag = str(bytearray.fromhex(rawkey))
flag = flag[12:len(flag)-2]

print("bonus!!:", flag)


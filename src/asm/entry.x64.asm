[BITS 64]

DEFAULT REL

EXTERN entry
GLOBAL Crypto
GLOBAL RipEntry

[SECTION .text$A]
    Crypto:
        push rbp
        mov  rbp, rsp
        and  rsp, 0FFFFFFFFFFFFFFF0h
        sub  rsp, 32
        call entry
        mov  rsp, rbp
        pop  rbp
    ret

    RipEntry:
        call .get_rip
        sub  rax, 5
    ret

    .get_rip:
        mov rax, [rsp]
    ret
[BITS 64]

DEFAULT REL

GLOBAL RipData

[SECTION .text$C]
    RipData:
        call .get_rip_data
        sub  rax, 5
    ret

    .get_rip_data:
        mov rax, [rsp]
    ret


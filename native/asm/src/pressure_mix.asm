; CrystalSentinel-ARC ASM weighted pressure mixer

global sentinel_asm_weighted_mix

section .text
sentinel_asm_weighted_mix:
    ; rcx=a, rdx=b, r8=c
    movzx rax, cx
    lea rax, [rax + rax*2]     ; a * 3
    movzx r9, dx
    lea r9, [r9 + r9*1]        ; b * 2
    add rax, r9
    movzx r9, r8w
    add rax, r9                ; + c
    ret

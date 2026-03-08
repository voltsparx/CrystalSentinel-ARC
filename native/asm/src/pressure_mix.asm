; CrystalSentinel-ARC ASM weighted pressure mixer

global sentinel_asm_weighted_mix
global sentinel_asm_weighted_mix4

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

sentinel_asm_weighted_mix4:
    ; rcx=a, rdx=b, r8=c, r9=d
    movzx rax, cx
    lea rax, [rax + rax*2]     ; a * 3
    movzx r10, dx
    add rax, r10               ; + b
    movzx r10, r8w
    add rax, r10               ; + c
    movzx r10, r9w
    lea r10, [r10 + r10*1]     ; d * 2
    add rax, r10
    ret

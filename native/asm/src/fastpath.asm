; CrystalSentinel-ARC ASM timing primitive

global sentinel_asm_cycle_stamp

section .text
sentinel_asm_cycle_stamp:
    rdtsc
    shl rdx, 32
    or rax, rdx
    ret

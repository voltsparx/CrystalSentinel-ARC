; CrystalSentinel-ARC ASM directive helpers
; mode values:
; 0 = standby
; 1 = decoy-capture
; 2 = containment-guard
; 3 = zen-recovery

global sentinel_asm_pressure_mode
global sentinel_asm_observation_window
global sentinel_asm_decoy_budget

section .text

sentinel_asm_pressure_mode:
    ; rcx=scan_score, rdx=intrusion_score, r8=ddos_score
    ; r9b=cpu_load_pct, [rsp+40]=memory_load_pct, [rsp+48]=thermal_c
    movzx eax, r9b
    cmp eax, 92
    jae .zen
    movzx eax, byte [rsp+40]
    cmp eax, 92
    jae .zen
    movzx eax, byte [rsp+48]
    cmp eax, 88
    jae .zen

    movzx r10, cx
    movzx r11, dx
    movzx rax, r8w

    cmp rax, r11
    ja .ddos
    cmp r11, r10
    ja .intrusion
    cmp r10, 0
    jne .scan
    xor eax, eax
    ret

.ddos:
    mov eax, 2
    ret

.intrusion:
    mov eax, 2
    ret

.scan:
    mov eax, 1
    ret

.zen:
    mov eax, 3
    ret

sentinel_asm_observation_window:
    ; rcx=mode, rdx=cpu_load_pct, r8=memory_load_pct, r9=thermal_c
    xor eax, eax
    cmp ecx, 3
    je .zen_window
    cmp ecx, 2
    je .contain_window
    cmp ecx, 1
    je .decoy_window
    ret

.decoy_window:
    mov eax, 180
    jmp .cap

.contain_window:
    mov eax, 140
    jmp .cap

.zen_window:
    mov eax, 90
    ret

.cap:
    movzx r10d, dl
    cmp r10d, 80
    jae .tight
    movzx r10d, r8b
    cmp r10d, 80
    jae .tight
    movzx r10d, r9b
    cmp r10d, 82
    jae .tight
    ret

.tight:
    cmp eax, 110
    jbe .done
    mov eax, 110
.done:
    ret

sentinel_asm_decoy_budget:
    ; rcx=mode, rdx=cpu_load_pct, r8=memory_load_pct, r9=thermal_c
    xor eax, eax
    cmp ecx, 1
    je .decoy_budget
    cmp ecx, 2
    je .contain_budget
    cmp ecx, 3
    je .done
    ret

.decoy_budget:
    mov eax, 3
    jmp .cap_budget

.contain_budget:
    mov eax, 1
    jmp .cap_budget

.cap_budget:
    movzx r10d, dl
    cmp r10d, 80
    jae .reduce_budget
    movzx r10d, r8b
    cmp r10d, 80
    jae .reduce_budget
    movzx r10d, r9b
    cmp r10d, 82
    jae .reduce_budget
    ret

.reduce_budget:
    cmp eax, 1
    jbe .done
    mov eax, 1
.done:
    ret

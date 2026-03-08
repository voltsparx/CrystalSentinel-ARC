; CrystalSentinel-ARC ASM directive helpers
; mode values:
; 0 = standby
; 1 = decoy-capture
; 2 = containment-guard
; 3 = zen-recovery

global sentinel_asm_pressure_mode
global sentinel_asm_observation_window
global sentinel_asm_decoy_budget
global sentinel_asm_evidence_budget
global sentinel_asm_phantom_jitter
global sentinel_asm_guard_bias
global sentinel_asm_load_balance_intensity
global sentinel_asm_micro_pacing_gap
global sentinel_asm_heartbeat_guard_mode
global sentinel_asm_guardian_mode
global sentinel_asm_mesh_gossip_ttl

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

sentinel_asm_evidence_budget:
    ; rcx=mode, rdx=overall_score, r8=dominance_margin, r9=kinetic_score
    xor eax, eax
    cmp ecx, 1
    je .scan_evidence
    cmp ecx, 2
    je .contain_evidence
    ret

.scan_evidence:
    mov eax, 4
    cmp r8b, 40
    jb .check_scan_kinetic
    mov eax, 5
.check_scan_kinetic:
    cmp r9b, 80
    jb .evidence_done
    mov eax, 5
    ret

.contain_evidence:
    mov eax, 2
    cmp dl, 95
    jb .evidence_done
    mov eax, 3

.evidence_done:
    ret

sentinel_asm_phantom_jitter:
    ; rcx=mode, rdx=kinetic_score, r8=dominance_margin, r9=resource_pressure
    xor eax, eax
    cmp ecx, 1
    jne .jitter_done
    mov eax, 12
    cmp r9b, 0
    je .check_kinetic
    mov eax, 6
    ret
.check_kinetic:
    cmp dl, 80
    jb .check_margin
    mov eax, 8
    ret
.check_margin:
    cmp r8b, 40
    jb .jitter_done
    mov eax, 8
.jitter_done:
    ret

sentinel_asm_guard_bias:
    ; rcx=mode, rdx=overall_score, r8=dominance_margin, r9=criticality
    xor eax, eax
    cmp ecx, 3
    je .zen_bias
    cmp ecx, 2
    je .contain_bias
    cmp ecx, 1
    je .scan_bias
    mov eax, 10
    ret

.scan_bias:
    mov eax, 45
    cmp r8b, 40
    jb .bias_done
    mov eax, 55
    ret

.contain_bias:
    mov eax, 60
    cmp r9b, 0
    je .check_contain_score
    mov eax, 82
    ret
.check_contain_score:
    cmp dl, 95
    jb .bias_done
    mov eax, 68
    ret

.zen_bias:
    mov eax, 20
    ret

.bias_done:
    ret

sentinel_asm_load_balance_intensity:
    ; rcx=cpu_load_pct, rdx=gpu_load_pct, r8=link_pressure_pct, r9=queue_fill_pct
    mov eax, 100
    movzx r10d, cl
    cmp r10d, 90
    jae .load_balance_min
    movzx r10d, dl
    cmp r10d, 90
    jae .load_balance_min
    movzx r10d, r8b
    cmp r10d, 90
    jae .load_balance_min
    movzx r10d, r9b
    cmp r10d, 90
    jae .load_balance_min

    movzx r10d, cl
    cmp r10d, 80
    jae .load_balance_guarded
    movzx r10d, dl
    cmp r10d, 80
    jae .load_balance_guarded
    movzx r10d, r8b
    cmp r10d, 80
    jae .load_balance_guarded
    movzx r10d, r9b
    cmp r10d, 80
    jae .load_balance_guarded

    movzx r10d, cl
    cmp r10d, 70
    jae .load_balance_recoil
    movzx r10d, dl
    cmp r10d, 70
    jae .load_balance_recoil
    movzx r10d, r8b
    cmp r10d, 70
    jae .load_balance_recoil
    movzx r10d, r9b
    cmp r10d, 70
    jae .load_balance_recoil
    ret

.load_balance_recoil:
    mov eax, 40
    ret

.load_balance_guarded:
    mov eax, 20
    ret

.load_balance_min:
    mov eax, 5
    ret

sentinel_asm_micro_pacing_gap:
    ; rcx=fragility, rdx=queue_fill_pct, r8=link_pressure_pct, r9=passive_only
    mov eax, 40
    cmp r9b, 0
    jne .micro_passive
    cmp ecx, 2
    je .micro_critical
    cmp ecx, 1
    je .micro_sensitive
    jmp .micro_network

.micro_passive:
    mov eax, 900
    ret

.micro_critical:
    mov eax, 700
    jmp .micro_network

.micro_sensitive:
    mov eax, 400

.micro_network:
    movzx r10d, dl
    cmp r10d, 95
    jae .micro_queue_critical
    cmp r10d, 85
    jae .micro_queue_high
    movzx r10d, r8b
    cmp r10d, 90
    jae .micro_link_critical
    cmp r10d, 80
    jae .micro_link_high
    ret

.micro_queue_high:
    cmp eax, 450
    jae .micro_done
    mov eax, 450
    ret

.micro_queue_critical:
    cmp eax, 800
    jae .micro_done
    mov eax, 800
    ret

.micro_link_high:
    cmp eax, 500
    jae .micro_done
    mov eax, 500
    ret

.micro_link_critical:
    cmp eax, 750
    jae .micro_done
    mov eax, 750

.micro_done:
    ret

sentinel_asm_heartbeat_guard_mode:
    ; rcx=missing_peers, rdx=malformed_peers, r8=jitter_us, r9=passive_only
    ; return: 0=steady, 1=tighten-trust, 2=shift-coverage, 3=quarantine
    xor eax, eax
    cmp dl, 0
    jne .heartbeat_quarantine
    cmp r8w, 10
    ja .heartbeat_quarantine
    cmp cl, 0
    jne .heartbeat_shift
    cmp r8w, 2
    ja .heartbeat_tighten
    cmp r9b, 0
    jne .heartbeat_tighten
    ret

.heartbeat_tighten:
    mov eax, 1
    ret

.heartbeat_shift:
    mov eax, 2
    ret

.heartbeat_quarantine:
    mov eax, 3
    ret

sentinel_asm_guardian_mode:
    ; rcx=protected_nodes, rdx=gentle_nodes, r8=cpu_load_pct, r9=passive_only
    ; return: 0=local, 1=adopt, 2=shared, 3=shadow-gateway
    xor eax, eax
    cmp r9b, 0
    jne .guardian_shadow
    cmp r8b, 88
    jae .guardian_shadow
    cmp cx, 0
    jne .guardian_adopt
    cmp dx, 0
    jne .guardian_adopt
    cmp r8b, 60
    jae .guardian_shared
    ret

.guardian_adopt:
    mov eax, 1
    ret

.guardian_shared:
    mov eax, 2
    ret

.guardian_shadow:
    mov eax, 3
    ret

sentinel_asm_mesh_gossip_ttl:
    ; rcx=confidence, rdx=integrity_event, r8=mesh_pressure, r9=shadow_gateway
    mov eax, 0
    cmp r9b, 0
    jne .ttl_shadow
    cmp dl, 0
    jne .ttl_integrity
    cmp cl, 90
    jae .ttl_high_confidence
    cmp r8b, 0
    jne .ttl_mesh_pressure
    ret

.ttl_shadow:
    mov eax, 120
    ret

.ttl_integrity:
    mov eax, 140
    ret

.ttl_high_confidence:
    mov eax, 220
    ret

.ttl_mesh_pressure:
    mov eax, 160
    ret

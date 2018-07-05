;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;	
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; Trampoline_ASM_x86
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
.386
.model flat, c
.code

public Trampoline_ASM_x86@0

Trampoline_ASM_x86@0 PROC

; Handle:       1A2B3C05h
; NETEntry:     1A2B3C03h
; OldProc:      1A2B3C01h
; NewProc:      1A2B3C00h
; NETOutro:     1A2B3C06h
; IsExecuted:   1A2B3C02h
; RetAddr:      1A2B3C04h
; Ptr:NewProc:  1A2B3C07h

	mov eax, esp
	push ecx ; both are fastcall parameters, ECX is also used as "this"-pointer
	push edx
	mov ecx, eax; InitialRSP value for NETIntro()...
	
	mov eax, 1A2B3C02h
	db 0F0h ; interlocked increment execution counter
	inc dword ptr [eax]
	
; is a user handler available?
	mov eax, 1A2B3C07h
	cmp dword ptr[eax], 0
	
	db 3Eh ; branch usually taken
	jne CALL_NET_ENTRY
	
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; call original method
		mov eax, 1A2B3C02h
		db 0F0h ; interlocked decrement execution counter
		dec dword ptr [eax]
		mov eax, 1A2B3C01h
		jmp TRAMPOLINE_EXIT

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; call hook handler or original method...
CALL_NET_ENTRY:	
	
; call NET intro
	push ecx
	push dword ptr [esp + 12] ; push return address
	push 1A2B3C05h ; Hook handle
	mov eax, 1A2B3C03h
	call eax ; Hook->NETIntro(Hook, RetAddr);
	
; should call original method?
	test eax, eax
	
	db 3Eh ; branch usually taken
	jne CALL_HOOK_HANDLER
	
	; call original method
		mov eax, 1A2B3C02h
		db 0F0h ; interlocked decrement execution counter
		dec dword ptr [eax]
		mov eax, 1A2B3C01h
		jmp TRAMPOLINE_EXIT
		
CALL_HOOK_HANDLER:
; adjust return address --- ATTENTION: this offset "83h" will also change if CALL_NET_OUTRO moves due to changes...
	mov dword ptr [esp + 8], 1A2B3C04h

; call hook handler
	mov eax, 1A2B3C00h
	jmp TRAMPOLINE_EXIT 

CALL_NET_OUTRO: ; this is where the handler returns...

; call NET outro --- ATTENTION: Never change EAX/EDX from now on!
	push 0 ; space for return address
	push eax
	push edx
	
	lea eax, [esp + 8]
	push eax ; Param 2: Address of return address
	push 1A2B3C05h ; Param 1: Hook handle
	mov eax, 1A2B3C06h
	call eax ; Hook->NETOutro(Hook);
	
	mov eax, 1A2B3C02h
	db 0F0h ; interlocked decrement execution counter
	dec dword ptr [eax]
	
	pop edx ; restore return value of user handler...
	pop eax
	
; finally return to saved return address - the caller of this trampoline...
	ret
	
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; generic outro for both cases...
TRAMPOLINE_EXIT:

	pop edx
	pop ecx
	
	jmp eax ; ATTENTION: In case of hook handler we will return to CALL_NET_OUTRO, otherwise to the caller...
	
; outro signature, to automatically determine code size
	db 78h
	db 56h
	db 34h
	db 12h

Trampoline_ASM_x86@0 ENDP

END
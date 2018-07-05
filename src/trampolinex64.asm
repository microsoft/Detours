;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;	
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; Trampoline_ASM_x64
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; This method is highly optimized and executes within 78 nanoseconds
; including the intro, outro and return...
; "IsExecuted" has to be within the next code subpage to prevent the
; Self-Modifing-Code-Condition to apply which would reduce performance 
; about 200 ns.

; Only for comparsion: The first proof of concept was unoptimized and
; did execute within 10000 nanoseconds... This optimized version just
; uses RIP relative addressing instead of register relative addressing,
; prevents the SMC condition and uses RIP relative jumps...


public Trampoline_ASM_x64

_TEXT SEGMENT

Trampoline_ASM_x64 PROC

NETIntro:
	;void*			NETEntry; // fixed 0 (0) 
	db 0
	db 0
	db 0
	db 0
	db 0
	db 0
	db 0
	db 0
	
OldProc:
	;BYTE*			OldProc; // fixed 4 (8)  
	db 0
	db 0
	db 0
	db 0
	db 0
	db 0
	db 0
	db 0
	
NewProc:
	;BYTE*			NewProc; // fixed 8 (16) 
	db 0
	db 0
	db 0
	db 0
	db 0
	db 0
	db 0
	db 0
	
NETOutro:
	;void*			NETOutro; // fixed 12 (24) 
	db 0
	db 0
	db 0
	db 0
	db 0
	db 0
	db 0
	db 0
	
IsExecutedPtr:
	;size_t*		IsExecutedPtr; // fixed 16 (32) 
	db 0
	db 0
	db 0
	db 0
	db 0
	db 0
	db 0
	db 0
	
; ATTENTION: 64-Bit requires stack alignment (RSP) of 16 bytes!!
	; Apply alignment trick: https://stackoverflow.com/a/9600102
	push rsp
	push [rsp]
	and rsp, 0FFFFFFFFFFFFFFF0H
	
	mov rax, rsp
	push rcx ; save not sanitized registers...
	push rdx
	push r8
	push r9
	
	sub rsp, 4 * 16 ; space for SSE registers
	
	movups [rsp + 3 * 16], xmm0
	movups [rsp + 2 * 16], xmm1
	movups [rsp + 1 * 16], xmm2
	movups [rsp + 0 * 16], xmm3
	
	sub rsp, 32; shadow space for method calls
	
	lea rax, [IsExecutedPtr]
	mov rax, [rax]
	db 0F0h ; interlocked increment execution counter
	inc qword ptr [rax]
	
; is a user handler available?
	cmp qword ptr[NewProc], 0
	
	db 3Eh ; branch usually taken
	jne CALL_NET_ENTRY
	
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; call original method
		lea rax, [IsExecutedPtr]
		mov rax, [rax]
		db 0F0h ; interlocked decrement execution counter
		dec qword ptr [rax]
		
		lea rax, [OldProc]
		jmp TRAMPOLINE_EXIT

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; call hook handler or original method...
CALL_NET_ENTRY:	

	
; call NET intro
	lea rcx, [IsExecutedPtr + 8] ; Hook handle (only a position hint)
	; Here we are under the alignment trick.
	mov r8, [rsp + 32 + 4 * 16 + 4 * 8 + 8] ; r8 = original rsp (address of return address)
	mov rdx, [r8] ; return address (value stored in original rsp)
	call qword ptr [NETIntro] ; Hook->NETIntro(Hook, RetAddr, InitialRSP);
	
; should call original method?
	test rax, rax
	
	db 3Eh ; branch usually taken
	jne CALL_HOOK_HANDLER
	
	; call original method
		lea rax, [IsExecutedPtr]
		mov rax, [rax]
		db 0F0h ; interlocked decrement execution counter
		dec qword ptr [rax]
	
		lea rax, [OldProc]
		jmp TRAMPOLINE_EXIT
		
CALL_HOOK_HANDLER:
; adjust return address
	lea rax, [CALL_NET_OUTRO]
	; Here we are under the alignment trick.
	mov r9, [rsp + 32 + 4 * 16 + 4 * 8 + 8] ; r9 = original rsp
	mov qword ptr [r9], rax

; call hook handler
	lea rax, [NewProc]
	jmp TRAMPOLINE_EXIT 

CALL_NET_OUTRO: ; this is where the handler returns...

; call NET outro
	; Here we are NOT under the alignment trick.
	
	push 0 ; space for return address
	push rax
	
	sub rsp, 32 + 16; shadow space for method calls and SSE registers
	movups [rsp + 32], xmm0
	
	lea rcx, [IsExecutedPtr + 8]  ; Param 1: Hook handle hint
	lea rdx, [rsp + 56] ; Param 2: Address of return address
	call qword ptr [NETOutro] ; Hook->NETOutro(Hook);
	
	lea rax, [IsExecutedPtr]
	mov rax, [rax]
	db 0F0h ; interlocked decrement execution counter
	dec qword ptr [rax]
	
	add rsp, 32 + 16
	movups xmm0, [rsp - 16]
	
	pop rax ; restore return value of user handler...
	
; finally return to saved return address - the caller of this trampoline...
	ret
	
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; generic outro for both cases...
TRAMPOLINE_EXIT:

	add rsp, 32 + 16 * 4

	movups xmm3, [rsp - 4 * 16]
	movups xmm2, [rsp - 3 * 16]
	movups xmm1, [rsp - 2 * 16]
	movups xmm0, [rsp - 1 * 16]
	
	pop r9
	pop r8
	pop rdx
	pop rcx
	
	; Remove alignment trick: https://stackoverflow.com/a/9600102
	mov rsp, [rsp + 8]
	
	jmp qword ptr[rax] ; ATTENTION: In case of hook handler we will return to CALL_NET_OUTRO, otherwise to the caller...
	
	
; outro signature, to automatically determine code size
	db 78h
	db 56h
	db 34h
	db 12h

Trampoline_ASM_x64 ENDP

_TEXT    ENDS

END
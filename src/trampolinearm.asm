        AREA     Pointers2, DATA, READWRITE

NETIntro       DCD 0 ; .NET Barrier Intro Function
OldProc        DCD 0 ; Original Replaced Function
NewProc        DCD 0 ; Detour Function
NETOutro       DCD 0 ; .NET Barrier Outro Function
IsExecutedPtr  DCD 0 ; Count of times trampoline was executed

        AREA     .text, CODE, THUMB, READONLY
                           
Trampoline_ASM_ARM FUNCTION

        EXPORT  Trampoline_ASM_ARM 
         
start     
        PUSH    {r0, r1, r2, r3, r4, lr}
        VPUSH    {d0-d7}
        LDR     r5, =IsExecutedPtr
try_lock        
        MOV     r1, #0x1
        LDREX   r0, [r5]
        CMP     r0, #0
        STREX   r1, r0, [r5]
        CMPEQ   r0, #0
        BNE     try_lock
        LDR     r1, =NewProc
        LDR     r2, [r1]
        CMPEQ   r2, #0
        BNE     CALL_NET_ENTRY
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; call original method
		

        LDR     pc, [pc, #-8]
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; call hook handler or original method...
CALL_NET_ENTRY

; call NET intro

        LDR     r0, =IsExecutedPtr
        ADD     r0, r0, #4
        LDR     r0, [r0]

        LDR     r4, =NETIntro ;LDR     pc, [r4]
        LDR     r5, [r4]
        BLX     r4
; should call original method?              
        CMP     r0, #0
        BNE     CALL_HOOK_HANDLER

; call original method
        LDR     r5, =OldProc
        LDR     r6, [r5]
        BNE     TRAMPOLINE_EXIT

CALL_HOOK_HANDLER
; adjust return address
        LDR     r4, CALL_NET_OUTRO
        ;LDR     pc, [r4]
        STR     r4, [sp] ; store outro return to stack after hook handler is called 

; call hook handler        
        LDR     r5, =NewProc
        B       TRAMPOLINE_EXIT

CALL_NET_OUTRO
        PUSH    {r0} ; save return handler
        LDR     r0, =IsExecutedPtr
        ADD     r0, r0, #4
        LDR     r0, [r0] ; get address of next Hook struct pointer

        LDR     r5, =NETOutro
        ;LDR     pc, [r5]
        LDR     r6, [r5]
        BLX     r5

        POP     {r0} ; restore return value of user handler...
; finally return to saved return address - the caller of this trampoline...        
        BX      lr

TRAMPOLINE_EXIT
        
        VPOP   {d0-d7}        
        POP    {r0, r1, r2, r3, r4, lr}

        LDR     r6, [r5] 
        BX      r5
        ENDFUNC

        END                     

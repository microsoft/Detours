        AREA     .text, CODE, THUMB, READONLY
                     
Trampoline_ASM_ARM FUNCTION

        EXPORT  Trampoline_ASM_ARM 

        DCB 0   ; help with alignment
        DCB 0
        DCB 0
    
       
NETIntro        ; .NET Barrier Intro Function
        DCB 0
        DCB 0
        DCB 0
        DCB 0
OldProc        ; Original Replaced Function
        DCB 0
        DCB 0
        DCB 0
        DCB 0
NewProc        ; Detour Function
        DCB 0
        DCB 0
        DCB 0
        DCB 0
NETOutro       ; .NET Barrier Outro Function
        DCB 0
        DCB 0
        DCB 0
        DCB 0
IsExecutedPtr  ; Count of times trampoline was executed
        DCB 0
        DCB 0
        DCB 0
        DCB 0

        ;
      
start     
        PUSH    {r0, r1, r2, r3, r4, lr}
        PUSH    {r5, r6, r7, r8, r10, r11}        
        VPUSH   {d8-d15}
        LDR     r5, =IsExecutedPtr
        LDR     r5, [r5]
        MOV     r1, #0x0               
        DMB     ish
try_inc_lock        
        LDREX   r0, [r5]
        ADDS    r0, r0, #1 ;CMP     r0, #0
        STREX   r1, r0, [r5]
        CMP     r1, #0
        BNE     try_inc_lock
        DMB     ish
        LDR     r1, =NewProc
        LDR     r2, [r1]
        CMPEQ   r2, #0
        BNE     CALL_NET_ENTRY
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; call original method      
        DMB     ish
try_dec_lock        
        LDREX   r0, [r5]
        SUBS    r0, r0, #1
        STREX   r1, r0, [r5]
        CMP     r1, #0
        BNE     try_dec_lock
        DMB     ish		

        LDR   r5, =OldProc
        LDR   r5, [r5]        
        B     TRAMPOLINE_EXIT
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; call hook handler or original method...
CALL_NET_ENTRY

; call NET intro

        LDR     r0, =IsExecutedPtr
        ADD     r0, r0, #4 ; Hook handle (only a position hint)
        ADDS    r2, sp, #0x6C ; original sp (address of return address)
        LDR     r1, [sp, #0x6C] ; return address (value stored in original sp)
        LDR     r4, =NETIntro
        LDR     r4, [r4]
        BLX     r4 ; Hook->NETIntro(Hook, RetAddr, InitialSP);
; should call original method?              
        CMP     r0, #0
        BNE     CALL_HOOK_HANDLER

; call original method
        LDR     r5, =IsExecutedPtr
        LDR     r5, [r5]        
        DMB     ish
try_dec_lock2        
        LDREX   r0, [r5]
        SUBS    r0, r0, #1
        STREX   r1, r0, [r5]
        CMP     r1, #0
        BNE     try_dec_lock2
        DMB     ish

        LDR     r5, =OldProc
        LDR     r5, [r5]
        B       TRAMPOLINE_EXIT

CALL_HOOK_HANDLER

; call hook handler        
        LDR     r5, =NewProc
        LDR     r5, [r5]
        LDR     r4, =CALL_NET_OUTRO ; adjust return address
        STR     r4, [sp, #0x6C] ; store outro return to stack after hook handler is called         
        B       TRAMPOLINE_EXIT
 ; this is where the handler returns...
CALL_NET_OUTRO
        MOV     r3, 0
        PUSH    r3
        ADDS    r1, sp, #0
        PUSH    {r0, r1, r2} ; save return handler
        LDR     r0, =IsExecutedPtr
        ADD     r0, r0, #4 ; get address of next Hook struct pointer
        ; Param 2: Address of return address
        LDR     r5, =NETOutro
        LDR     r5, [r5]
        BLX     r5       ; Hook->NETOutro(Hook, InAddrOfRetAddr);

        LDR     r5, =IsExecutedPtr
        LDR     r5, [r5]
        DMB     ish        
try_dec_lock3        
        LDREX   r0, [r5]
        SUBS    r0, r0, #1
        STREX   r1, r0, [r5]
        CMP     r1, #0
        BNE     try_dec_lock3
        DMB     ish

        POP     {r0, r1, r2, lr} ; restore return value of user handler...
; finally return to saved return address - the caller of this trampoline...        
        BX      lr

TRAMPOLINE_EXIT
        MOV     r9, r5
        VPOP   {d8-d15}    
        POP    {r5, r6, r7, r8, r10, r11}            
        POP    {r0, r1, r2, r3, r4, lr}
        
        BX      r9 ; MOV     pc, r9

; outro signature, to automatically determine code size        
        DCB     0x78
        DCB     0x56
        DCB     0x34
        DCB     0x12  
      
        ENDFUNC

        END                     

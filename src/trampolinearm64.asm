   AREA     .text, CODE, THUMB
                           
Trampoline_ASM_ARM64 FUNCTION

        EXPORT  Trampoline_ASM_ARM64 
         
start                           
        MOV      r0, #10
        MOV      r1, #3
        ADD      r0, r0, r1
stop
        MOV      r0, #0x18

        ENDFUNC
        END                     

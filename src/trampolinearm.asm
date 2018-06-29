        AREA     .text, CODE, THUMB, READONLY
                           
Trampoline_ASM_ARM FUNCTION

        EXPORT  Trampoline_ASM_ARM 
         
start                           
        MOV      r0, #10
        MOV      r1, #3
        ADD      r0, r0, r1
stop
        MOV      r0, #0x18

        ENDFUNC
        END                     

# Detours Contributor Credits

The following individuals have helped identify specific bugs and improvements
in Detours. The entire Detours community has benefited from their help.

* Jay Krell:          Identified error in DetourFindPayload that caused a
                      incorrect failure when pcbData is NULL. (Build_342)

* Jay Krell:          Identified issue with VirtualSize == 0 files created in
                      NT 3.1 images. (Build_339)

* Igor Odnovorov:     Identified an issue with the placement of the trampoline
                      region when a function is detoured twice and the second
                      trampoline region is outside of the +/- 2GB range of
                      the target. (Build_337)

* Jay Krell:          Identified need for some programs to enumerate the
                      address of IAT entries. (Build_336)

* Calvin Hsia:        Identified need for some program to change the excluded
                      system region. (Build_336)

* Adam Smith:         Identified error in failure handling when VirtualProect
                      cannot make pages executable because the Prohibit
                      Dynamic Code Generation mitigation policy has been
                      applied to a process. (Build_335)

* Ben Faull:          Identified fix to detour_alloc_region_from_lo and
                      detour_alloc_region_from_hi that preserves ASLR entropy.
                      (Build_334)

* Shaoxiang Su:       Reported errors building with Visual Studio 2015.
                      (Build_332)

* Jay Krell:          Identified and resolved significant gaps in the X86, X64
                      and IA64 disassemblers for instruction found in code,
                      but seldom found in function prologues. (Build_331)

* Allan Murphy:       Identify error in rep and jmp ds: encodings. (Build_331)

* Philip Bacon:       Identified incorrect entry point return for pure
                      resource-only binaries. (Build_330)

* Jay Krell:          Identified failure in DetourAttachEx to update nAlign.
                      (Build_330)

* Sumit Sarin:        Helped debug error with packed binaries.
                      (Build_329)

* Nitya Kumar Sharma: Reported bug in DetourAfterWithDll for 32/64 agnostic
                      EXEs.
                      (Build_327)

* Richard Black:      Identified a large number of typos in documentation.
                      (Build_326)

* Michael Bilodeau:   Identified bug in DetourUpdateProcessWithDll when the
                      target process contains a Detours payload *after* all
                      valid PE binaries.
                      (Build_324)

* Meera Jindal:       Reported bug in identification of target address in
                      DetourCopyInstruction for jmp[] and call[] on x86 & x64,
                      the ff15 and ff25 opcodes.
                      (Build_323)

* Ken Johnson:        Assistance with SAL 2.0 annotations.
                      (Build_319)

* Nick Wood:          Identified bug in DetourFindFunction on ARM.
                      (Build_314)

* Mark Russinovich:   Helped debug DetourCreateProcessWithDllEx.
                      (Build_314)

* John Lin:           Implementation idea for DetoursCreateProcessWithDllEx.
                      (Build_314)

* Andrew Zawadowskiy  Reported an improper memory page permissions
                      vulnerability in Detours 2.1.  (Vulnerability does not
                      exist in versions later than Detours 2.1.)
                      (Build_223)

* Nightxie:           Identified bug in detour_alloc_round_up_to_region.
                      (Build_310)

* Diana Milirud:      Identified bug in B* instructions on ARM.
                      (Build_309)

* Juan Carlos         Identified correct MSIL entry point for unsigned MSIL.
  Luciani:            (Build_308)

* Lee Hunt            Suggested improvements in algorithm for allocation of
  Lawrence Landauer   trampoline regions on x64 to avoid collisions with
  Joe Laughlin:       system DLLs.
                      (Build_307)

* Tyler Sims          Identified bug in handling of "anycpu" MSIL binaries
  Darren Kennedy:     on x64.
                      (Build_307)

* Andre Vachon:       Help with optimized binaries.
                      (Build 301)

* Chris Mann:         Identified fix not forward ported from 2.2 to 3.0.
                      (Build_301)

* Mark Irving:        Identified bug with EXEs missing second import table.
                      (Build_300)

* Ben Schwarz:        Identified bug in handling of multi-byte NOPs.
                      (Build_300)

* Aaron Giles         Coded initial ARM/Thumb2 disassembler.
  Jared Henderson:    (Build_300)

* Doug Brubacher:     Coded initial x86 disassembler.
                      (Build_100)

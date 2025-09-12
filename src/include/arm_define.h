#ifndef __ARM_DEFINE__
#define __ARM_DEFINE__

#define ARM_R0 1
#define ARM_R1 2
#define ARM_R2 3
#define ARM_R3 4
#define ARM_R4 5
#define ARM_R5 6
#define ARM_R6 7
#define ARM_R7 8
#define ARM_R8 9
#define ARM_R9 10
#define ARM_R10 11
#define ARM_R11 12
#define ARM_R12 13
// not sure whether to reorder LR PC SP to correct r13 r14 r15 mapping
#define ARM_LR 14
#define ARM_PC 15
#define ARM_SP 16
// arm32 bit uses CPSR instead of XPSR
// not used anyway
#define ARM_CPSR 17

#define MEM_WRITE 17
#define MEM_READ_AFTER 25
#endif
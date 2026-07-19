//go:build amd64 && !purego && !noasm

#include "go_asm.h"
#include "textflag.h"

DATA snowViAMDForward<>+0(SB)/8, $0x4a6d4a6d4a6d4a6d
DATA snowViAMDForward<>+8(SB)/8, $0x4a6d4a6d4a6d4a6d
DATA snowViAMDForward<>+16(SB)/8, $0xcc87cc87cc87cc87
DATA snowViAMDForward<>+24(SB)/8, $0xcc87cc87cc87cc87
GLOBL snowViAMDForward<>(SB), (NOPTR+RODATA), $32
DATA snowViAMDSigma<>+0(SB)/8, $0x0d0905010c080400
DATA snowViAMDSigma<>+8(SB)/8, $0x0f0b07030e0a0602
GLOBL snowViAMDSigma<>(SB), (NOPTR+RODATA), $16

// X0=A0, X1=B0, X2=A1, X3=B1, X4=R1, X5=R2,
// X6=(canonical R3 xor A1), X7=output, X8-X14=secret temporaries,
// and X15=zero. General registers contain only public pointers and counts.
#define SNOWVI_XMM_STEP_BEGIN \
	MOVOU X3, X7; \
	PADDD X4, X7; \
	PXOR X5, X7; \
	MOVOU X6, X8; \
	PADDD X5, X8; \
	PSHUFB snowViAMDSigma<>(SB), X8; \
	MOVOU X4, X13; \
	MOVOU X5, X14; \
	MOVOU X0, X11; \
	PSLLW $1, X11; \
	MOVOU X0, X9; \
	PSRAW $15, X9; \
	PAND snowViAMDForward<>(SB), X9; \
	PXOR X9, X11; \
	MOVOU X2, X9; \
	PALIGNR $14, X0, X9; \
	PXOR X9, X11; \
	PXOR X1, X11; \
	MOVOU X1, X12; \
	PSLLW $1, X12; \
	MOVOU X1, X9; \
	PSRAW $15, X9; \
	PAND snowViAMDForward<>+16(SB), X9; \
	PXOR X9, X12; \
	PXOR X0, X12; \
	PXOR X3, X12

#define SNOWVI_XMM_STEP_FINISH \
	AESENC X15, X13; \
	AESENC X11, X14; \
	MOVOU X2, X0; \
	MOVOU X3, X1; \
	MOVOU X11, X2; \
	MOVOU X12, X3; \
	MOVOU X8, X4; \
	MOVOU X13, X5; \
	MOVOU X14, X6

#define SNOWVI_XMM_STEP \
	SNOWVI_XMM_STEP_BEGIN; \
	SNOWVI_XMM_STEP_FINISH

#define SNOWVI_XMM_INIT_STEP \
	SNOWVI_XMM_STEP_BEGIN; \
	PXOR X7, X11; \
	SNOWVI_XMM_STEP_FINISH

#define LOAD_SNOWVI_XMM_STATE \
	MOVOU snowVState_lo(AX), X0; \
	MOVOU snowVState_lo+16(AX), X1; \
	MOVOU snowVState_hi(AX), X2; \
	MOVOU snowVState_hi+16(AX), X3; \
	MOVOU snowVState_r1(AX), X4; \
	MOVOU snowVState_r2(AX), X5; \
	MOVOU snowVState_r3(AX), X6; \
	PXOR X2, X6

#define STORE_SNOWVI_XMM_STATE \
	MOVOU X0, snowVState_lo(AX); \
	MOVOU X1, snowVState_lo+16(AX); \
	MOVOU X2, snowVState_hi(AX); \
	MOVOU X3, snowVState_hi+16(AX); \
	MOVOU X4, snowVState_r1(AX); \
	MOVOU X5, snowVState_r2(AX); \
	PXOR X2, X6; \
	MOVOU X6, snowVState_r3(AX)

#define WIPE_SNOWVI_XMM \
	PXOR X0, X0; \
	PXOR X1, X1; \
	PXOR X2, X2; \
	PXOR X3, X3; \
	PXOR X4, X4; \
	PXOR X5, X5; \
	PXOR X6, X6; \
	PXOR X7, X7; \
	PXOR X8, X8; \
	PXOR X9, X9; \
	PXOR X10, X10; \
	PXOR X11, X11; \
	PXOR X12, X12; \
	PXOR X13, X13; \
	PXOR X14, X14; \
	PXOR X15, X15

// Y0/Y1 hold memory-compatible lo=(B0|A0) and hi=(B1|A1).
// In bank A, X2-X4 are R1/R2/(R3 xor A1); in bank B, X12/X10/X11
// hold those values. X5 is output; Y6-Y9 are secret LFSR/input
// temporaries; Y13 is the reduction vector and Y15 is zero.
#define LOAD_SNOWVI_AVX2_CONSTANTS \
	VMOVDQU snowViAMDForward<>(SB), Y13; \
	VPXOR Y15, Y15, Y15

#define SNOWVI_AVX2_LFSR_A \
	VPSLLW $1, Y0, Y6; \
	VPSRAW $15, Y0, Y7; \
	VPAND Y13, Y7, Y7; \
	VPXOR Y7, Y6, Y6; \
	VPALIGNR $14, Y0, Y1, Y7; \
	VPBLENDD $0xf0, Y1, Y7, Y7; \
	VPERM2I128 $0x01, Y0, Y0, Y9; \
	VPXOR Y9, Y7, Y7; \
	VPXOR Y7, Y6, Y0

#define SNOWVI_AVX2_LFSR_B \
	VPSLLW $1, Y1, Y6; \
	VPSRAW $15, Y1, Y7; \
	VPAND Y13, Y7, Y7; \
	VPXOR Y7, Y6, Y6; \
	VPALIGNR $14, Y1, Y0, Y7; \
	VPBLENDD $0xf0, Y0, Y7, Y7; \
	VPERM2I128 $0x01, Y1, Y1, Y9; \
	VPXOR Y9, Y7, Y7; \
	VPXOR Y7, Y6, Y1

#define SNOWVI_AVX2_STEP_A \
	VEXTRACTI128 $1, Y1, X5; \
	VPADDD X5, X2, X5; \
	VPXOR X3, X5, X5; \
	VPADDD X4, X3, X12; \
	VPSHUFB snowViAMDSigma<>(SB), X12, X12; \
	VAESENC X15, X2, X10; \
	SNOWVI_AVX2_LFSR_A; \
	VAESENC X0, X3, X11

#define SNOWVI_AVX2_STEP_B \
	VEXTRACTI128 $1, Y0, X5; \
	VPADDD X5, X12, X5; \
	VPXOR X10, X5, X5; \
	VPADDD X11, X10, X2; \
	VPSHUFB snowViAMDSigma<>(SB), X2, X2; \
	VAESENC X15, X12, X3; \
	SNOWVI_AVX2_LFSR_B; \
	VAESENC X1, X10, X4

#define SNOWVI_AVX2_INIT_STEP_A \
	VEXTRACTI128 $1, Y1, X5; \
	VPADDD X5, X2, X5; \
	VPXOR X3, X5, X5; \
	VPADDD X4, X3, X12; \
	VPSHUFB snowViAMDSigma<>(SB), X12, X12; \
	VAESENC X15, X2, X10; \
	SNOWVI_AVX2_LFSR_A; \
	VPXOR X5, X0, X6; \
	VINSERTI128 $0, X6, Y0, Y0; \
	VAESENC X0, X3, X11

#define SNOWVI_AVX2_INIT_STEP_B \
	VEXTRACTI128 $1, Y0, X5; \
	VPADDD X5, X12, X5; \
	VPXOR X10, X5, X5; \
	VPADDD X11, X10, X2; \
	VPSHUFB snowViAMDSigma<>(SB), X2, X2; \
	VAESENC X15, X12, X3; \
	SNOWVI_AVX2_LFSR_B; \
	VPXOR X5, X1, X6; \
	VINSERTI128 $0, X6, Y1, Y1; \
	VAESENC X1, X10, X4

#define LOAD_SNOWVI_AVX2_STATE \
	VMOVDQU snowVState_lo(AX), Y0; \
	VMOVDQU snowVState_hi(AX), Y1; \
	VMOVDQU snowVState_r1(AX), X2; \
	VMOVDQU snowVState_r2(AX), X3; \
	VMOVDQU snowVState_r3(AX), X4; \
	VPXOR X1, X4, X4

#define STORE_SNOWVI_AVX2_STATE \
	VMOVDQU Y0, snowVState_lo(AX); \
	VMOVDQU Y1, snowVState_hi(AX); \
	VMOVDQU X2, snowVState_r1(AX); \
	VMOVDQU X3, snowVState_r2(AX); \
	VPXOR X1, X4, X6; \
	VMOVDQU X6, snowVState_r3(AX)

#define WIPE_SNOWVI_YMM \
	VPXOR Y0, Y0, Y0; \
	VPXOR Y1, Y1, Y1; \
	VPXOR Y2, Y2, Y2; \
	VPXOR Y3, Y3, Y3; \
	VPXOR Y4, Y4, Y4; \
	VPXOR Y5, Y5, Y5; \
	VPXOR Y6, Y6, Y6; \
	VPXOR Y7, Y7, Y7; \
	VPXOR Y8, Y8, Y8; \
	VPXOR Y9, Y9, Y9; \
	VPXOR Y10, Y10, Y10; \
	VPXOR Y11, Y11, Y11; \
	VPXOR Y12, Y12, Y12; \
	VPXOR Y13, Y13, Y13; \
	VPXOR Y14, Y14, Y14; \
	VPXOR Y15, Y15, Y15; \
	VZEROUPPER

// func initStateViXMM(state *snowVState, key, iv *byte)
// The complete secret register map is above; all XMM registers are cleared on return.
TEXT ·initStateViXMM(SB), NOSPLIT, $0-24
	MOVQ state+0(FP), AX
	MOVQ key+8(FP), CX
	MOVQ iv+16(FP), DX
	MOVOU (DX), X0
	PXOR X1, X1
	MOVOU (CX), X2
	MOVOU 16(CX), X3
	PXOR X4, X4
	PXOR X5, X5
	MOVOU X2, X6
	PXOR X15, X15
	MOVQ $14, BX
initViXMMLoop14:
	SNOWVI_XMM_INIT_STEP
	DECQ BX
	JNZ initViXMMLoop14
	SNOWVI_XMM_INIT_STEP
	MOVOU (CX), X9
	PXOR X9, X4
	SNOWVI_XMM_INIT_STEP
	MOVOU 16(CX), X9
	PXOR X9, X4
	STORE_SNOWVI_XMM_STATE
	WIPE_SNOWVI_XMM
	RET

// func xorBlocksViXMM(state *snowVState, dst, src *byte, blocks uintptr)
// Caller memory is loaded with MOVOU before arithmetic. Branches use only blocks.
TEXT ·xorBlocksViXMM(SB), NOSPLIT, $0-32
	MOVQ state+0(FP), AX
	MOVQ dst+8(FP), DI
	MOVQ src+16(FP), SI
	MOVQ blocks+24(FP), CX
	LOAD_SNOWVI_XMM_STATE
	PXOR X15, X15
	CMPQ CX, $4
	JB streamViXMMRemainder
streamViXMMLoop4:
	SNOWVI_XMM_STEP
	MOVOU (SI), X11
	PXOR X7, X11
	MOVOU X11, (DI)
	ADDQ $16, SI
	ADDQ $16, DI
	SNOWVI_XMM_STEP
	MOVOU (SI), X11
	PXOR X7, X11
	MOVOU X11, (DI)
	ADDQ $16, SI
	ADDQ $16, DI
	SNOWVI_XMM_STEP
	MOVOU (SI), X11
	PXOR X7, X11
	MOVOU X11, (DI)
	ADDQ $16, SI
	ADDQ $16, DI
	SNOWVI_XMM_STEP
	MOVOU (SI), X11
	PXOR X7, X11
	MOVOU X11, (DI)
	ADDQ $16, SI
	ADDQ $16, DI
	SUBQ $4, CX
	CMPQ CX, $4
	JAE streamViXMMLoop4
streamViXMMRemainder:
	TESTQ CX, CX
	JZ streamViXMMDone
streamViXMMRemainderLoop:
	SNOWVI_XMM_STEP
	MOVOU (SI), X11
	PXOR X7, X11
	MOVOU X11, (DI)
	ADDQ $16, SI
	ADDQ $16, DI
	DECQ CX
	JNZ streamViXMMRemainderLoop
streamViXMMDone:
	STORE_SNOWVI_XMM_STATE
	WIPE_SNOWVI_XMM
	RET

// func initStateViAVX2(state *snowVState, key, iv *byte)
// The complete secret register map is above; all YMM registers are cleared on return.
TEXT ·initStateViAVX2(SB), NOSPLIT, $0-24
	MOVQ state+0(FP), AX
	MOVQ key+8(FP), CX
	MOVQ iv+16(FP), DX
	LOAD_SNOWVI_AVX2_CONSTANTS
	VMOVDQU (DX), X0
	VINSERTI128 $1, X15, Y0, Y0
	VMOVDQU (CX), Y1
	VPXOR X2, X2, X2
	VPXOR X3, X3, X3
	VMOVDQU X1, X4
	MOVQ $7, BX
initViAVX2Loop14:
	SNOWVI_AVX2_INIT_STEP_A
	SNOWVI_AVX2_INIT_STEP_B
	DECQ BX
	JNZ initViAVX2Loop14
	SNOWVI_AVX2_INIT_STEP_A
	VMOVDQU (CX), X6
	VPXOR X6, X12, X12
	SNOWVI_AVX2_INIT_STEP_B
	VMOVDQU 16(CX), X6
	VPXOR X6, X2, X2
	STORE_SNOWVI_AVX2_STATE
	WIPE_SNOWVI_YMM
	RET

// func xorBlocksViAVX2(state *snowVState, dst, src *byte, blocks uintptr)
// VMOVDQU handles all caller alignments; exact alias and disjoint buffers are supported.
TEXT ·xorBlocksViAVX2(SB), NOSPLIT, $0-32
	MOVQ state+0(FP), AX
	MOVQ dst+8(FP), DI
	MOVQ src+16(FP), SI
	MOVQ blocks+24(FP), CX
	LOAD_SNOWVI_AVX2_CONSTANTS
	LOAD_SNOWVI_AVX2_STATE
	CMPQ CX, $2
	JB streamViAVX2Remainder
streamViAVX2Loop2:
	SNOWVI_AVX2_STEP_A
	VMOVDQU (SI), X9
	VPXOR X5, X9, X9
	VMOVDQU X9, (DI)
	SNOWVI_AVX2_STEP_B
	VMOVDQU 16(SI), X9
	VPXOR X5, X9, X9
	VMOVDQU X9, 16(DI)
	ADDQ $32, SI
	ADDQ $32, DI
	SUBQ $2, CX
	CMPQ CX, $2
	JAE streamViAVX2Loop2
streamViAVX2Remainder:
	TESTQ CX, CX
	JZ streamViAVX2Done
	SNOWVI_AVX2_STEP_A
	VMOVDQU (SI), X9
	VPXOR X5, X9, X9
	VMOVDQU X9, (DI)
	VMOVDQU Y0, Y6
	VMOVDQU Y1, Y0
	VMOVDQU Y6, Y1
	VMOVDQU X12, X2
	VMOVDQU X10, X3
	VMOVDQU X11, X4
streamViAVX2Done:
	STORE_SNOWVI_AVX2_STATE
	WIPE_SNOWVI_YMM
	RET

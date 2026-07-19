//go:build amd64 && !purego && !noasm

#include "go_asm.h"
#include "textflag.h"

DATA amdForward<>+0(SB)/8, $0x990f990f990f990f
DATA amdForward<>+8(SB)/8, $0x990f990f990f990f
DATA amdForward<>+16(SB)/8, $0xc963c963c963c963
DATA amdForward<>+24(SB)/8, $0xc963c963c963c963
GLOBL amdForward<>(SB), (NOPTR+RODATA), $32
DATA amdInverse<>+0(SB)/8, $0xcc87cc87cc87cc87
DATA amdInverse<>+8(SB)/8, $0xcc87cc87cc87cc87
DATA amdInverse<>+16(SB)/8, $0xe4b1e4b1e4b1e4b1
DATA amdInverse<>+24(SB)/8, $0xe4b1e4b1e4b1e4b1
GLOBL amdInverse<>(SB), (NOPTR+RODATA), $32
DATA amdNegativeInverse<>+0(SB)/8, $0x3379337933793379
DATA amdNegativeInverse<>+8(SB)/8, $0x3379337933793379
DATA amdNegativeInverse<>+16(SB)/8, $0x1b4f1b4f1b4f1b4f
DATA amdNegativeInverse<>+24(SB)/8, $0x1b4f1b4f1b4f1b4f
GLOBL amdNegativeInverse<>(SB), (NOPTR+RODATA), $32
DATA amdSigma<>+0(SB)/8, $0x0d0905010c080400
DATA amdSigma<>+8(SB)/8, $0x0f0b07030e0a0602
GLOBL amdSigma<>(SB), (NOPTR+RODATA), $16

// Y0/Y1: lo/hi LFSR; X2-X4: R1-R3; X5: output; Y6-Y9:
// secret LFSR and input temporaries. X10/X11 are the next R2/R3 and X12 is
// next R1. Y13/Y14: public field constants; Y15: zero. General registers
// contain only public pointers and counts.
#define SNOWV_AVX2_STEP \
	VEXTRACTI128 $1, Y1, X5; \
	VPADDD X5, X2, X5; \
	VPXOR X3, X5, X5; \
	VAESENC X15, X2, X10; \
	VAESENC X15, X3, X11; \
	VPXOR X0, X4, X6; \
	VPADDD X6, X3, X12; \
	VPSHUFB amdSigma<>(SB), X12, X12; \
	VPSLLW $1, Y0, Y6; \
	VPSRAW $15, Y0, Y7; \
	VPAND Y13, Y7, Y7; \
	VPXOR Y7, Y6, Y6; \
	VPSRLW $1, Y1, Y8; \
	VPSLLW $15, Y1, Y7; \
	VPSIGNW Y7, Y14, Y7; \
	VPXOR Y7, Y8, Y8; \
	VPALIGNR $2, Y0, Y1, Y7; \
	VPALIGNR $6, Y0, Y1, Y9; \
	VPBLENDD $0xf0, Y9, Y7, Y7; \
	VPERM2I128 $0x01, Y0, Y0, Y9; \
	VPXOR Y9, Y7, Y7; \
	VPXOR Y8, Y6, Y6; \
	VPXOR Y7, Y6, Y6; \
	VMOVDQU Y1, Y0; \
	VMOVDQU Y6, Y1; \
	VMOVDQU X12, X2; \
	VMOVDQU X10, X3; \
	VMOVDQU X11, X4

// The rotating stream steps leave the LFSR and FSM state in alternating
// physical banks. A uses canonical Y0/Y1 and X2-X4; B uses Y1/Y0 and
// X12/X10/X11. B returns all registers to canonical mapping. Y6-Y9 hold
// independent LFSR terms until a balanced XOR tree overwrites the dead old LO.
#define SNOWV_AVX2_STEP_ROT_A \
	VAESENC X15, X2, X10; \
	VAESENC X15, X3, X11; \
	VPXOR X0, X4, X12; \
	VPADDD X12, X3, X12; \
	VPSHUFB amdSigma<>(SB), X12, X12; \
	VPSLLW $1, Y0, Y6; \
	VPSRAW $15, Y0, Y7; \
	VPAND Y13, Y7, Y7; \
	VPXOR Y7, Y6, Y6; \
	VPSRLW $1, Y1, Y8; \
	VPSLLW $15, Y1, Y7; \
	VPSIGNW Y7, Y14, Y7; \
	VPXOR Y7, Y8, Y8; \
	VPALIGNR $2, Y0, Y1, Y7; \
	VPALIGNR $6, Y0, Y1, Y9; \
	VPBLENDD $0xf0, Y9, Y7, Y7; \
	VPERM2I128 $0x01, Y0, Y0, Y9; \
	VPXOR Y9, Y7, Y7; \
	VPXOR Y8, Y6, Y6; \
	VPXOR Y7, Y6, Y0

#define SNOWV_AVX2_STEP_ROT_B \
	VAESENC X15, X12, X3; \
	VAESENC X15, X10, X4; \
	VPXOR X1, X11, X2; \
	VPADDD X2, X10, X2; \
	VPSHUFB amdSigma<>(SB), X2, X2; \
	VPSLLW $1, Y1, Y6; \
	VPSRAW $15, Y1, Y7; \
	VPAND Y13, Y7, Y7; \
	VPXOR Y7, Y6, Y6; \
	VPSRLW $1, Y0, Y8; \
	VPSLLW $15, Y0, Y7; \
	VPSIGNW Y7, Y14, Y7; \
	VPXOR Y7, Y8, Y8; \
	VPALIGNR $2, Y1, Y0, Y7; \
	VPALIGNR $6, Y1, Y0, Y9; \
	VPBLENDD $0xf0, Y9, Y7, Y7; \
	VPERM2I128 $0x01, Y1, Y1, Y9; \
	VPXOR Y9, Y7, Y7; \
	VPXOR Y8, Y6, Y6; \
	VPXOR Y7, Y6, Y1; \

#define SNOWV_AVX2_PACK_OUTPUT_PAIR \
	VINSERTI128 $1, X12, Y2, Y5; \
	VINSERTI128 $1, X10, Y3, Y6; \
	VPERM2I128 $0x31, Y0, Y1, Y7; \
	VPADDD Y7, Y5, Y5; \
	VPXOR Y6, Y5, Y5

#define LOAD_AVX2_CONSTANTS \
	VMOVDQU amdForward<>(SB), Y13; \
	VMOVDQU amdNegativeInverse<>(SB), Y14; \
	VPXOR Y15, Y15, Y15

#define LOAD_AVX2_STATE \
	VMOVDQU snowVState_lo(AX), Y0; \
	VMOVDQU snowVState_hi(AX), Y1; \
	VMOVDQU snowVState_r1(AX), X2; \
	VMOVDQU snowVState_r2(AX), X3; \
	VMOVDQU snowVState_r3(AX), X4

#define STORE_AVX2_STATE \
	VMOVDQU Y0, snowVState_lo(AX); \
	VMOVDQU Y1, snowVState_hi(AX); \
	VMOVDQU X2, snowVState_r1(AX); \
	VMOVDQU X3, snowVState_r2(AX); \
	VMOVDQU X4, snowVState_r3(AX)

#define WIPE_YMM \
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

// X0-X3: loA/loB/hiA/hiB; X4-X6: R1-R3; X7: output; X8-X12:
// next FSM state and LFSR temporaries. X13/X14 hold AESR(R1/R2), and X15
// is a persistent zero AES round key. General registers contain only public
// pointers and counts.
#define SNOWV_XMM_STEP \
	MOVOU X3, X7; \
	PADDD X4, X7; \
	PXOR X5, X7; \
	MOVOU X6, X8; \
	PXOR X0, X8; \
	PADDD X5, X8; \
	PSHUFB amdSigma<>(SB), X8; \
	MOVOU X4, X13; \
	MOVOU X5, X14; \
	AESENC X15, X13; \
	AESENC X15, X14; \
	MOVOU X0, X11; \
	PSLLW $1, X11; \
	MOVOU X0, X9; \
	PSRAW $15, X9; \
	PAND amdForward<>(SB), X9; \
	PXOR X9, X11; \
	MOVOU X2, X9; \
	PALIGNR $2, X0, X9; \
	PXOR X9, X11; \
	MOVOU X2, X9; \
	PSRLW $1, X9; \
	MOVOU X2, X10; \
	PSLLW $15, X10; \
	PSRAW $15, X10; \
	PAND amdInverse<>(SB), X10; \
	PXOR X10, X9; \
	PXOR X9, X11; \
	PXOR X1, X11; \
	MOVOU X1, X12; \
	PSLLW $1, X12; \
	MOVOU X1, X9; \
	PSRAW $15, X9; \
	PAND amdForward<>+16(SB), X9; \
	PXOR X9, X12; \
	MOVOU X3, X9; \
	PALIGNR $6, X1, X9; \
	PXOR X9, X12; \
	MOVOU X3, X9; \
	PSRLW $1, X9; \
	MOVOU X3, X10; \
	PSLLW $15, X10; \
	PSRAW $15, X10; \
	PAND amdInverse<>+16(SB), X10; \
	PXOR X10, X9; \
	PXOR X9, X12; \
	PXOR X0, X12; \
	MOVOU X2, X0; \
	MOVOU X3, X1; \
	MOVOU X11, X2; \
	MOVOU X12, X3; \
	MOVOU X8, X4; \
	MOVOU X13, X5; \
	MOVOU X14, X6

#define LOAD_XMM_STATE \
	MOVOU snowVState_lo(AX), X0; \
	MOVOU snowVState_lo+16(AX), X1; \
	MOVOU snowVState_hi(AX), X2; \
	MOVOU snowVState_hi+16(AX), X3; \
	MOVOU snowVState_r1(AX), X4; \
	MOVOU snowVState_r2(AX), X5; \
	MOVOU snowVState_r3(AX), X6

#define STORE_XMM_STATE \
	MOVOU X0, snowVState_lo(AX); \
	MOVOU X1, snowVState_lo+16(AX); \
	MOVOU X2, snowVState_hi(AX); \
	MOVOU X3, snowVState_hi+16(AX); \
	MOVOU X4, snowVState_r1(AX); \
	MOVOU X5, snowVState_r2(AX); \
	MOVOU X6, snowVState_r3(AX)

#define WIPE_XMM \
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

// func hasVAESCPUIDAMD64() bool
// cpu.X86.HasAVX2 has already established OS AVX state support; this routine
// supplies the architectural VAES CPUID leaf 7 ECX bit 9 predicate.
TEXT ·hasVAESCPUIDAMD64(SB), NOSPLIT, $0-1
	XORL AX, AX
	CPUID
	CMPL AX, $7
	JL noVAES
	MOVL $7, AX
	XORL CX, CX
	CPUID
	BTL $9, CX
	SETCS ret+0(FP)
	RET
noVAES:
	MOVB $0, ret+0(FP)
	RET

// func initStateXMM(state *snowVState, key, iv *byte)
// The XMM map above lists all secret-bearing registers; WIPE_XMM clears all
// of them before returning.
TEXT ·initStateXMM(SB), NOSPLIT, $0-24
	MOVQ state+0(FP), AX
	MOVQ key+8(FP), CX
	MOVQ iv+16(FP), DX
	MOVOU (DX), X0
	PXOR X1, X1
	MOVOU (CX), X2
	MOVOU 16(CX), X3
	PXOR X4, X4
	PXOR X5, X5
	PXOR X6, X6
	PXOR X15, X15
	MOVQ $14, BX
initXMMLoop14:
	SNOWV_XMM_STEP
	PXOR X7, X2
	DECQ BX
	JNZ initXMMLoop14
	SNOWV_XMM_STEP
	PXOR X7, X2
	MOVOU (CX), X8
	PXOR X8, X4
	SNOWV_XMM_STEP
	PXOR X7, X2
	MOVOU 16(CX), X8
	PXOR X8, X4
	STORE_XMM_STATE
	WIPE_XMM
	RET

// func xorBlocksXMM(state *snowVState, dst, src *byte, blocks uintptr)
// The XMM map above lists all secret-bearing registers; source is loaded
// before destination store for exact in-place use. Branches use only blocks.
TEXT ·xorBlocksXMM(SB), NOSPLIT, $0-32
	MOVQ state+0(FP), AX
	MOVQ dst+8(FP), DI
	MOVQ src+16(FP), SI
	MOVQ blocks+24(FP), CX
	LOAD_XMM_STATE
	PXOR X15, X15
	CMPQ CX, $4
	JB streamXMMRemainder
streamXMMLoop4:
	SNOWV_XMM_STEP
	MOVOU (SI), X11
	PXOR X7, X11
	MOVOU X11, (DI)
	ADDQ $16, SI
	ADDQ $16, DI
	SNOWV_XMM_STEP
	MOVOU (SI), X11
	PXOR X7, X11
	MOVOU X11, (DI)
	ADDQ $16, SI
	ADDQ $16, DI
	SNOWV_XMM_STEP
	MOVOU (SI), X11
	PXOR X7, X11
	MOVOU X11, (DI)
	ADDQ $16, SI
	ADDQ $16, DI
	SNOWV_XMM_STEP
	MOVOU (SI), X11
	PXOR X7, X11
	MOVOU X11, (DI)
	ADDQ $16, SI
	ADDQ $16, DI
	SUBQ $4, CX
	CMPQ CX, $4
	JAE streamXMMLoop4
streamXMMRemainder:
	TESTQ CX, CX
	JZ streamXMMDone
streamXMMRemainderLoop:
	SNOWV_XMM_STEP
	MOVOU (SI), X11
	PXOR X7, X11
	MOVOU X11, (DI)
	ADDQ $16, SI
	ADDQ $16, DI
	DECQ CX
	JNZ streamXMMRemainderLoop
streamXMMDone:
	STORE_XMM_STATE
	WIPE_XMM
	RET

// func initStateAVX2(state *snowVState, key, iv *byte)
// Secret-bearing vector map is documented above. Every YMM register is
// explicitly cleared before VZEROUPPER and return.
TEXT ·initStateAVX2(SB), NOSPLIT, $0-24
	MOVQ state+0(FP), AX
	MOVQ key+8(FP), CX
	MOVQ iv+16(FP), DX
	LOAD_AVX2_CONSTANTS
	VMOVDQU (DX), X0
	VINSERTI128 $1, X15, Y0, Y0
	VMOVDQU (CX), Y1
	VPXOR X2, X2, X2
	VPXOR X3, X3, X3
	VPXOR X4, X4, X4
	MOVQ $14, BX
initAVX2Loop14:
	SNOWV_AVX2_STEP
	VPXOR X5, X1, X9
	VINSERTI128 $0, X9, Y1, Y1
	DECQ BX
	JNZ initAVX2Loop14
	SNOWV_AVX2_STEP
	VPXOR X5, X1, X9
	VINSERTI128 $0, X9, Y1, Y1
	VPXOR (CX), X2, X2
	SNOWV_AVX2_STEP
	VPXOR X5, X1, X9
	VINSERTI128 $0, X9, Y1, Y1
	VPXOR 16(CX), X2, X2
	STORE_AVX2_STATE
	WIPE_YMM
	RET

// func xorBlocksAVX2(state *snowVState, dst, src *byte, blocks uintptr)
// Secret-bearing vector map is documented above. Every YMM register is
// explicitly cleared before VZEROUPPER and return.
TEXT ·xorBlocksAVX2(SB), NOSPLIT, $0-32
	MOVQ state+0(FP), AX
	MOVQ dst+8(FP), DI
	MOVQ src+16(FP), SI
	MOVQ blocks+24(FP), CX
	LOAD_AVX2_CONSTANTS
	LOAD_AVX2_STATE
	CMPQ CX, $16
	JB streamAVX2Remainder
	SUBQ $16, CX
	PCALIGN $32
streamAVX2Loop16:
	SNOWV_AVX2_STEP_ROT_A
	SNOWV_AVX2_PACK_OUTPUT_PAIR
	SNOWV_AVX2_STEP_ROT_B
	VPXOR (SI), Y5, Y5
	VMOVDQU Y5, (DI)
	SNOWV_AVX2_STEP_ROT_A
	SNOWV_AVX2_PACK_OUTPUT_PAIR
	SNOWV_AVX2_STEP_ROT_B
	VPXOR 32(SI), Y5, Y5
	VMOVDQU Y5, 32(DI)
	SNOWV_AVX2_STEP_ROT_A
	SNOWV_AVX2_PACK_OUTPUT_PAIR
	SNOWV_AVX2_STEP_ROT_B
	VPXOR 64(SI), Y5, Y5
	VMOVDQU Y5, 64(DI)
	SNOWV_AVX2_STEP_ROT_A
	SNOWV_AVX2_PACK_OUTPUT_PAIR
	SNOWV_AVX2_STEP_ROT_B
	VPXOR 96(SI), Y5, Y5
	VMOVDQU Y5, 96(DI)
	SNOWV_AVX2_STEP_ROT_A
	SNOWV_AVX2_PACK_OUTPUT_PAIR
	SNOWV_AVX2_STEP_ROT_B
	VPXOR 128(SI), Y5, Y5
	VMOVDQU Y5, 128(DI)
	SNOWV_AVX2_STEP_ROT_A
	SNOWV_AVX2_PACK_OUTPUT_PAIR
	SNOWV_AVX2_STEP_ROT_B
	VPXOR 160(SI), Y5, Y5
	VMOVDQU Y5, 160(DI)
	SNOWV_AVX2_STEP_ROT_A
	SNOWV_AVX2_PACK_OUTPUT_PAIR
	SNOWV_AVX2_STEP_ROT_B
	VPXOR 192(SI), Y5, Y5
	VMOVDQU Y5, 192(DI)
	SNOWV_AVX2_STEP_ROT_A
	SNOWV_AVX2_PACK_OUTPUT_PAIR
	SNOWV_AVX2_STEP_ROT_B
	VPXOR 224(SI), Y5, Y5
	VMOVDQU Y5, 224(DI)
	ADDQ $256, SI
	ADDQ $256, DI
	SUBQ $16, CX
	JAE streamAVX2Loop16
	ADDQ $16, CX
streamAVX2Remainder:
	TESTQ CX, CX
	JZ streamAVX2Done
streamAVX2RemainderLoop:
	SNOWV_AVX2_STEP
	VPXOR (SI), X5, X5
	VMOVDQU X5, (DI)
	ADDQ $16, SI
	ADDQ $16, DI
	DECQ CX
	JNZ streamAVX2RemainderLoop
streamAVX2Done:
	STORE_AVX2_STATE
	WIPE_YMM
	RET

// func aesRoundPairAES(dstR2, dstR3, srcR1, srcR2 *[4]uint32)
// X0/X1 hold source and result state; X2 is the zero round key. Sources are
// loaded before either destination is stored so destination/source aliasing is safe.
TEXT ·aesRoundPairAES(SB), NOSPLIT, $0-32
	MOVQ dstR2+0(FP), AX
	MOVQ dstR3+8(FP), BX
	MOVQ srcR1+16(FP), CX
	MOVQ srcR2+24(FP), DX
	MOVUPS (CX), X0
	MOVUPS (DX), X1
	PXOR X2, X2
	AESENC X2, X0
	AESENC X2, X1
	MOVUPS X0, (AX)
	MOVUPS X1, (BX)
	PXOR X0, X0
	PXOR X1, X1
	PXOR X2, X2
	RET

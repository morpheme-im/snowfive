//go:build arm64 && !purego && !noasm

#include "go_asm.h"
#include "textflag.h"

DATA armConstants<>+0(SB)/8, $0x990f990f990f990f
DATA armConstants<>+8(SB)/8, $0x990f990f990f990f
DATA armConstants<>+16(SB)/8, $0xc963c963c963c963
DATA armConstants<>+24(SB)/8, $0xc963c963c963c963
DATA armConstants<>+32(SB)/8, $0xcc87cc87cc87cc87
DATA armConstants<>+40(SB)/8, $0xcc87cc87cc87cc87
DATA armConstants<>+48(SB)/8, $0xe4b1e4b1e4b1e4b1
DATA armConstants<>+56(SB)/8, $0xe4b1e4b1e4b1e4b1
DATA armConstants<>+64(SB)/8, $0x0d0905010c080400
DATA armConstants<>+72(SB)/8, $0x0f0b07030e0a0602
DATA armConstants<>+80(SB)/8, $0x0001000100010001
DATA armConstants<>+88(SB)/8, $0x0001000100010001
DATA armConstants<>+96(SB)/8, $0x8000800080008000
DATA armConstants<>+104(SB)/8, $0x8000800080008000
GLOBL armConstants<>(SB), (NOPTR+RODATA), $112

// Bitwise-complemented reduction constants let BCAX apply each polynomial
// under the all-ones mask produced by VCMTST.
DATA armSHA3Constants<>+0(SB)/8, $0x66f066f066f066f0
DATA armSHA3Constants<>+8(SB)/8, $0x66f066f066f066f0
DATA armSHA3Constants<>+16(SB)/8, $0x369c369c369c369c
DATA armSHA3Constants<>+24(SB)/8, $0x369c369c369c369c
DATA armSHA3Constants<>+32(SB)/8, $0x3378337833783378
DATA armSHA3Constants<>+40(SB)/8, $0x3378337833783378
DATA armSHA3Constants<>+48(SB)/8, $0x1b4e1b4e1b4e1b4e
DATA armSHA3Constants<>+56(SB)/8, $0x1b4e1b4e1b4e1b4e
GLOBL armSHA3Constants<>(SB), (NOPTR+RODATA), $64

// V0/V1: loA/loB; V2/V3: hiA/hiB; V4-V6: R1-R3.
// V7: output; V8-V23: secret state, AES, tap, and input temporaries.
// V24-V30: public constants; V31: zero. General registers hold only public
// pointers and counts.
#define SNOWV_CORE_STEP \
	VADD V3.S4, V4.S4, V7.S4; \
	VEOR V5.B16, V7.B16, V7.B16; \
	VEOR V0.B16, V6.B16, V8.B16; \
	VADD V8.S4, V5.S4, V8.S4; \
	VTBL V28.B16, [V8.B16], V9.B16; \
	AESE V31.B16, V4.B16; \
	AESMC V4.B16, V4.B16; \
	AESE V31.B16, V5.B16; \
	AESMC V5.B16, V5.B16; \
	VEXT $2, V2.B16, V0.B16, V10.B16; \
	VEXT $6, V3.B16, V1.B16, V11.B16; \
	VEOR V1.B16, V10.B16, V10.B16; \
	VEOR V0.B16, V11.B16, V11.B16; \
	VSHL $1, V0.H8, V12.H8; \
	VSHL $1, V1.H8, V13.H8; \
	VCMTST V30.H8, V0.H8, V16.H8; \
	VCMTST V30.H8, V1.H8, V17.H8; \
	VAND V24.B16, V16.B16, V16.B16; \
	VAND V25.B16, V17.B16, V17.B16; \
	VEOR V16.B16, V12.B16, V12.B16; \
	VEOR V17.B16, V13.B16, V13.B16; \
	VUSHR $1, V2.H8, V14.H8; \
	VUSHR $1, V3.H8, V15.H8; \
	VCMTST V29.H8, V2.H8, V16.H8; \
	VCMTST V29.H8, V3.H8, V17.H8; \
	VAND V26.B16, V16.B16, V16.B16; \
	VAND V27.B16, V17.B16, V17.B16; \
	VEOR V16.B16, V14.B16, V14.B16; \
	VEOR V17.B16, V15.B16, V15.B16; \
	VEOR V14.B16, V12.B16, V12.B16; \
	VEOR V15.B16, V13.B16, V13.B16; \
	VEOR V10.B16, V12.B16, V12.B16; \
	VEOR V11.B16, V13.B16, V13.B16; \
	VMOV V2.B16, V0.B16; \
	VMOV V3.B16, V1.B16; \
	VMOV V12.B16, V2.B16; \
	VMOV V13.B16, V3.B16; \
	VMOV V5.B16, V6.B16; \
	VMOV V4.B16, V5.B16; \
	VMOV V9.B16, V4.B16

#define SNOWV_LFSR_STEP_SHA3 \
	VEXT $2, V2.B16, V0.B16, V10.B16; \
	VEXT $6, V3.B16, V1.B16, V11.B16; \
	VEOR V1.B16, V10.B16, V10.B16; \
	VEOR V0.B16, V11.B16, V11.B16; \
	VSHL $1, V0.H8, V12.H8; \
	VSHL $1, V1.H8, V13.H8; \
	VCMTST V30.H8, V0.H8, V16.H8; \
	VCMTST V30.H8, V1.H8, V17.H8; \
	VBCAX V24.B16, V16.B16, V12.B16, V12.B16; \
	VBCAX V25.B16, V17.B16, V13.B16, V13.B16; \
	VUSHR $1, V2.H8, V14.H8; \
	VUSHR $1, V3.H8, V15.H8; \
	VCMTST V29.H8, V2.H8, V16.H8; \
	VCMTST V29.H8, V3.H8, V17.H8; \
	VBCAX V26.B16, V16.B16, V14.B16, V14.B16; \
	VBCAX V27.B16, V17.B16, V15.B16, V15.B16; \
	VEOR3 V10.B16, V14.B16, V12.B16, V12.B16; \
	VEOR3 V11.B16, V15.B16, V13.B16, V13.B16; \
	VMOV V2.B16, V0.B16; \
	VMOV V3.B16, V1.B16; \
	VMOV V12.B16, V2.B16; \
	VMOV V13.B16, V3.B16

// FEAT_SHA3 folds source XOR into EOR3, shortens the LFSR XOR tree, and uses
// BCAX with complemented constants for each conditional polynomial reduction.
#define SNOWV_CORE_STEP_SHA3(SRC) \
	VADD V3.S4, V4.S4, V7.S4; \
	VEOR3 V5.B16, V7.B16, SRC.B16, SRC.B16; \
	VEOR V0.B16, V6.B16, V8.B16; \
	VADD V8.S4, V5.S4, V8.S4; \
	AESE V31.B16, V4.B16; \
	AESMC V4.B16, V4.B16; \
	AESE V31.B16, V5.B16; \
	AESMC V5.B16, V5.B16; \
	VTBL V28.B16, [V8.B16], V9.B16; \
	SNOWV_LFSR_STEP_SHA3; \
	VMOV V5.B16, V6.B16; \
	VMOV V4.B16, V5.B16; \
	VMOV V9.B16, V4.B16

// Three consecutive stream clocks rotate the FSM register roles without
// copies. Each AES result stays in place and the dead old-R3 register receives
// the next R1; A/B/C restores the canonical V4/V5/V6 map.
#define SNOWV_CORE_STEP_SHA3_FSM_ROT(SRC, F1, F2, F3) \
	VADD V3.S4, F1.S4, V7.S4; \
	VEOR3 F2.B16, V7.B16, SRC.B16, SRC.B16; \
	VEOR V0.B16, F3.B16, V8.B16; \
	VADD V8.S4, F2.S4, V8.S4; \
	AESE V31.B16, F1.B16; \
	AESMC F1.B16, F1.B16; \
	AESE V31.B16, F2.B16; \
	AESMC F2.B16, F2.B16; \
	VTBL V28.B16, [V8.B16], F3.B16; \
	SNOWV_LFSR_STEP_SHA3

#define SNOWV_CORE_STEP_SHA3_FSM_A(SRC) \
	SNOWV_CORE_STEP_SHA3_FSM_ROT(SRC, V4, V5, V6)

#define SNOWV_CORE_STEP_SHA3_FSM_B(SRC) \
	SNOWV_CORE_STEP_SHA3_FSM_ROT(SRC, V6, V4, V5)

#define SNOWV_CORE_STEP_SHA3_FSM_C(SRC) \
	SNOWV_CORE_STEP_SHA3_FSM_ROT(SRC, V5, V6, V4)


#define LOAD_CONSTANTS \
	MOVD $armConstants<>(SB), R4; \
	VLD1.P 64(R4), [V24.B16, V25.B16, V26.B16, V27.B16]; \
	VLD1.P 16(R4), [V28.B16]; \
	VLD1.P 16(R4), [V29.B16]; \
	VLD1 (R4), [V30.B16]; \
	VEOR V31.B16, V31.B16, V31.B16

#define LOAD_CONSTANTS_SHA3 \
	MOVD $armSHA3Constants<>(SB), R4; \
	VLD1.P 64(R4), [V24.B16, V25.B16, V26.B16, V27.B16]; \
	MOVD $armConstants<>+64(SB), R4; \
	VLD1.P 16(R4), [V28.B16]; \
	VLD1.P 16(R4), [V29.B16]; \
	VLD1 (R4), [V30.B16]; \
	VEOR V31.B16, V31.B16, V31.B16

#define LOAD_STATE \
	VLD1 (R0), [V0.B16, V1.B16, V2.B16, V3.B16]; \
	ADD $snowVState_r1, R0, R5; \
	VLD1 (R5), [V4.B16, V5.B16, V6.B16]

#define STORE_STATE \
	VST1 [V0.B16, V1.B16, V2.B16, V3.B16], (R0); \
	ADD $snowVState_r1, R0, R5; \
	VST1 [V4.B16, V5.B16, V6.B16], (R5)

#define WIPE_VECTORS \
	VEOR V0.B16, V0.B16, V0.B16; \
	VEOR V1.B16, V1.B16, V1.B16; \
	VEOR V2.B16, V2.B16, V2.B16; \
	VEOR V3.B16, V3.B16, V3.B16; \
	VEOR V4.B16, V4.B16, V4.B16; \
	VEOR V5.B16, V5.B16, V5.B16; \
	VEOR V6.B16, V6.B16, V6.B16; \
	VEOR V7.B16, V7.B16, V7.B16; \
	VEOR V8.B16, V8.B16, V8.B16; \
	VEOR V9.B16, V9.B16, V9.B16; \
	VEOR V10.B16, V10.B16, V10.B16; \
	VEOR V11.B16, V11.B16, V11.B16; \
	VEOR V12.B16, V12.B16, V12.B16; \
	VEOR V13.B16, V13.B16, V13.B16; \
	VEOR V14.B16, V14.B16, V14.B16; \
	VEOR V15.B16, V15.B16, V15.B16; \
	VEOR V16.B16, V16.B16, V16.B16; \
	VEOR V17.B16, V17.B16, V17.B16; \
	VEOR V18.B16, V18.B16, V18.B16; \
	VEOR V19.B16, V19.B16, V19.B16; \
	VEOR V20.B16, V20.B16, V20.B16; \
	VEOR V21.B16, V21.B16, V21.B16; \
	VEOR V22.B16, V22.B16, V22.B16; \
	VEOR V23.B16, V23.B16, V23.B16; \
	VEOR V24.B16, V24.B16, V24.B16; \
	VEOR V25.B16, V25.B16, V25.B16; \
	VEOR V26.B16, V26.B16, V26.B16; \
	VEOR V27.B16, V27.B16, V27.B16; \
	VEOR V28.B16, V28.B16, V28.B16; \
	VEOR V29.B16, V29.B16, V29.B16; \
	VEOR V30.B16, V30.B16, V30.B16; \
	VEOR V31.B16, V31.B16, V31.B16

// func initStateARM64(state *snowVState, key, iv *byte)
// Secret-bearing vector map is documented above; R0-R4 contain public
// addresses/counts only. Every vector register is cleared before return.
TEXT ·initStateARM64(SB), NOSPLIT, $0
	MOVD state+0(FP), R0
	MOVD key+8(FP), R1
	MOVD iv+16(FP), R2
	LOAD_CONSTANTS
	VLD1 (R2), [V0.B16]
	VEOR V1.B16, V1.B16, V1.B16
	VLD1 (R1), [V2.B16, V3.B16]
	VEOR V4.B16, V4.B16, V4.B16
	VEOR V5.B16, V5.B16, V5.B16
	VEOR V6.B16, V6.B16, V6.B16
	MOVD $14, R3
initLoop14:
	SNOWV_CORE_STEP
	VEOR V7.B16, V2.B16, V2.B16
	SUBS $1, R3
	BNE initLoop14
	SNOWV_CORE_STEP
	VEOR V7.B16, V2.B16, V2.B16
	VLD1 (R1), [V23.B16]
	VEOR V23.B16, V4.B16, V4.B16
	SNOWV_CORE_STEP
	VEOR V7.B16, V2.B16, V2.B16
	ADD $16, R1, R5
	VLD1 (R5), [V23.B16]
	VEOR V23.B16, V4.B16, V4.B16
	STORE_STATE
	WIPE_VECTORS
	RET

// func xorBlocksARM64(state *snowVState, dst, src *byte, blocks uintptr)
// Secret-bearing vector map is documented above; R0-R4 contain public
// addresses/counts only. Every vector register is cleared before return.
TEXT ·xorBlocksARM64(SB), NOSPLIT, $0
	MOVD state+0(FP), R0
	MOVD dst+8(FP), R1
	MOVD src+16(FP), R2
	MOVD blocks+24(FP), R3
	LOAD_CONSTANTS
	LOAD_STATE
	CMP $4, R3
	BLT streamRemainder
streamLoop4:
	VLD1.P 64(R2), [V20.B16, V21.B16, V22.B16, V23.B16]
	SNOWV_CORE_STEP
	VEOR V20.B16, V7.B16, V20.B16
	SNOWV_CORE_STEP
	VEOR V21.B16, V7.B16, V21.B16
	SNOWV_CORE_STEP
	VEOR V22.B16, V7.B16, V22.B16
	SNOWV_CORE_STEP
	VEOR V23.B16, V7.B16, V23.B16
	VST1.P [V20.B16, V21.B16, V22.B16, V23.B16], 64(R1)
	SUB $4, R3
	CMP $4, R3
	BGE streamLoop4
streamRemainder:
	CBZ R3, streamDone
streamRemainderLoop:
	VLD1.P 16(R2), [V23.B16]
	SNOWV_CORE_STEP
	VEOR V23.B16, V7.B16, V7.B16
	VST1.P [V7.B16], 16(R1)
	SUBS $1, R3
	BNE streamRemainderLoop
streamDone:
	STORE_STATE
	WIPE_VECTORS
	RET

// func xorBlocksARM64SHA3(state *snowVState, dst, src *byte, blocks uintptr)
// The caller gates this entry point on FEAT_SHA3. State remains canonical, so
// initialization and stream calls may use different ARM64 implementations.
TEXT ·xorBlocksARM64SHA3(SB), NOSPLIT, $0
	MOVD state+0(FP), R0
	MOVD dst+8(FP), R1
	MOVD src+16(FP), R2
	MOVD blocks+24(FP), R3
	LOAD_CONSTANTS_SHA3
	LOAD_STATE
	CMP $4, R3
	BLT streamSHA3Remainder
streamSHA3Loop4:
	VLD1.P 64(R2), [V20.B16, V21.B16, V22.B16, V23.B16]
	SNOWV_CORE_STEP_SHA3_FSM_A(V20)
	SNOWV_CORE_STEP_SHA3_FSM_B(V21)
	SNOWV_CORE_STEP_SHA3_FSM_C(V22)
	SNOWV_CORE_STEP_SHA3(V23)
	VST1.P [V20.B16, V21.B16, V22.B16, V23.B16], 64(R1)
	SUB $4, R3
	CMP $4, R3
	BGE streamSHA3Loop4
streamSHA3Remainder:
	CBZ R3, streamSHA3Done
streamSHA3RemainderLoop:
	VLD1.P 16(R2), [V23.B16]
	SNOWV_CORE_STEP_SHA3(V23)
	VST1.P [V23.B16], 16(R1)
	SUBS $1, R3
	BNE streamSHA3RemainderLoop
streamSHA3Done:
	STORE_STATE
	WIPE_VECTORS
	RET

/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2016-2017 René van Dorst <opensource@vdorst.com>. All Rights Reserved.
 * Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#define X0  $v0
#define X1  $v1
#define X2  $ra
#define X3  $fp
#define X4  $s0
#define X5  $s1
#define X6  $s2
#define X7  $s3
#define X8  $s4
#define X9  $s5
#define X10 $s6
#define X11 $s7
#define X12 $t0
#define X13 $t1
#define X14 $t2
#define X15 $t3
#define T0  $t4
#define T1  $t5
#define T2  $t6
#define T3  $t7
#define T4  $t8
#define T5  $t9
#define T6  $at
#define T(n) T ## n
#define X(n) X ## n

#define AXR(A, B, C, D,  K, L, M, N,  V, W, Y, Z,  S) \
	addu X(A), X(K); \
	addu X(B), X(L); \
	addu X(C), X(M); \
	addu X(D), X(N); \
	xor  X(V), X(A); \
	xor  X(W), X(B); \
	xor  X(Y), X(C); \
	xor  X(Z), X(D); \
	rotl X(V), S;    \
	rotl X(W), S;    \
	rotl X(Y), S;    \
	rotl X(Z), S;

#define CHACHA20_BLOCK_SIZE 64
#define STACK_SIZE	96
#define OUT		$a0
#define IN		$a1
#define BYTES		$a2
#define KEY		$a3
#define ROUND_INDEX	T6
#define COUNTER		T4
#define COUNTER_0	T5
#define LAST_BLOCK	T6

#define CONSTANT_1	0x61707865
#define CONSTANT_2	0x3320646e
#define CONSTANT_3	0x79622d32
#define CONSTANT_4	0x6b206574

#define U32_HI_PART(x)	((x & 0xFFFF0000) >> 16)
#define U32_LO_PART(x)	(x & 0x0000FFFF)

#define TEMP_XOR_OFFSET 40

// chacha20_mips(u8 *out, const u8 *in, size_t len, const u32 key[8], const u32 counter[4]);
.align 4
.set reorder
.set noat
.globl chacha20_mips
.ent   chacha20_mips
chacha20_mips:
	// this is in the fifth argument
	lw COUNTER, 16($sp)

	addiu $sp, -(STACK_SIZE)

	// Return if no bytes
	beqz BYTES, .Lchacha20_mips_end
	nop

	sw $ra,  0($sp)
	sw $fp,  4($sp)
	sw $s0,  8($sp)
	sw $s1, 12($sp)
	sw $s2, 16($sp)
	sw $s3, 20($sp)
	sw $s4, 24($sp)
	sw $s5, 28($sp)
	sw $s6, 32($sp)
	sw $s7, 36($sp)

	lw COUNTER_0, 0(COUNTER)

.Loop_chacha:
	lui X0, U32_HI_PART(CONSTANT_1)
	lui X1, U32_HI_PART(CONSTANT_2)
	lui X2, U32_HI_PART(CONSTANT_3)
	lui X3, U32_HI_PART(CONSTANT_4)
	ori X0, U32_LO_PART(CONSTANT_1)
	ori X1, U32_LO_PART(CONSTANT_2)
	ori X2, U32_LO_PART(CONSTANT_3)
	ori X3, U32_LO_PART(CONSTANT_4)
	lw X4,   0(KEY)
	lw X5,   4(KEY)
	lw X6,   8(KEY)
	lw X7,  12(KEY)
	lw X8,  16(KEY)
	lw X9,  20(KEY)
	lw X10, 24(KEY)
	lw X11, 28(KEY)
	move X12, COUNTER_0
	lw X13,  4(COUNTER)
	lw X14,  8(COUNTER)
	lw X15, 12(COUNTER)

	li	ROUND_INDEX, 9
.Loop_chacha_xor_rounds:
	AXR( 0, 1, 2, 3,  4, 5, 6, 7, 12,13,14,15, 16);
	AXR( 8, 9,10,11, 12,13,14,15,  4, 5, 6, 7, 12);
	AXR( 0, 1, 2, 3,  4, 5, 6, 7, 12,13,14,15,  8);
	AXR( 8, 9,10,11, 12,13,14,15,  4, 5, 6, 7,  7);
	AXR( 0, 1, 2, 3,  5, 6, 7, 4, 15,12,13,14, 16);
	AXR(10,11, 8, 9, 15,12,13,14,  5, 6, 7, 4, 12);
	AXR( 0, 1, 2, 3,  5, 6, 7, 4, 15,12,13,14,  8);
	AXR(10,11, 8, 9, 15,12,13,14,  5, 6, 7, 4,  7);

	.set noreorder
	bnez ROUND_INDEX, .Loop_chacha_xor_rounds
	subu ROUND_INDEX, 1
	.set reorder

	lui T0, U32_HI_PART(CONSTANT_1)
	lui T1, U32_HI_PART(CONSTANT_2)
	lui T2, U32_HI_PART(CONSTANT_3)
	lui T3, U32_HI_PART(CONSTANT_4)
	ori T0, U32_LO_PART(CONSTANT_1)
	ori T1, U32_LO_PART(CONSTANT_2)
	ori T2, U32_LO_PART(CONSTANT_3)
	ori T3, U32_LO_PART(CONSTANT_4)
	addu X0, T0
	addu X1, T1
	addu X2, T2
	addu X3, T3
	lw T0, 0(KEY)
	lw T1, 4(KEY)
	lw T2, 8(KEY)
	lw T3, 12(KEY)

	// Set LAST_BLOCK if bytes left is less then CHACHA20_BLOCK_SIZE
	sltiu LAST_BLOCK, BYTES, CHACHA20_BLOCK_SIZE

	addu X4, T0
	addu X5, T1
	addu X6, T2
	addu X7, T3
	lw T0, 16(KEY)
	lw T1, 20(KEY)
	lw T2, 24(KEY)
	lw T3, 28(KEY)
	addu X8, T0
	addu X9, T1
	addu X10, T2
	addu X11, T3
	lw T1, 4(COUNTER)
	lw T2, 8(COUNTER)
	lw T3, 12(COUNTER)
	addu X12, COUNTER_0
	addu X13, T1
	addu X14, T2
	addu X15, T3

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	wsbh 	X0
	wsbh 	X1
	wsbh 	X2
	wsbh 	X3
	wsbh 	X4
	wsbh 	X5
	wsbh 	X6
	wsbh 	X7
	wsbh 	X8
	wsbh 	X9
	wsbh 	X10
	wsbh 	X11
	wsbh 	X12
	wsbh 	X13
	wsbh 	X14
	wsbh 	X15
	rotr 	X0, 16
	rotr 	X1, 16
	rotr 	X2, 16
	rotr 	X3, 16
	rotr 	X4, 16
	rotr 	X5, 16
	rotr 	X6, 16
	rotr 	X7, 16
	rotr 	X8, 16
	rotr 	X9, 16
	rotr 	X10, 16
	rotr 	X11, 16
	rotr 	X12, 16
	rotr 	X13, 16
	rotr 	X14, 16
	rotr 	X15, 16
#endif

	// XOR last bytes
	bnez LAST_BLOCK, .Lchacha20_mips_last_bytes
	nop

	lw T0, 0(IN)
	lw T1, 4(IN)
	lw T2, 8(IN)
	lw T3, 12(IN)
	xor X0, T0
	xor X1, T1
	xor X2, T2
	xor X3, T3

	lw T0, 16(IN)
	lw T1, 20(IN)
	lw T2, 24(IN)
	lw T3, 28(IN)
	xor X4, T0
	xor X5, T1
	xor X6, T2
	xor X7, T3

	lw T0, 32(IN)
	lw T1, 36(IN)
	lw T2, 40(IN)
	lw T3, 44(IN)
	xor X8, T0
	xor X9, T1
	xor X10, T2
	xor X11, T3

	lw T0, 48(IN)
	lw T1, 52(IN)
	lw T2, 56(IN)
	lw T3, 60(IN)
	xor X12, T0
	xor X13, T1
	xor X14, T2
	xor X15, T3

	addiu BYTES, -(CHACHA20_BLOCK_SIZE)

	sw X0,   0(OUT)
	sw X1,   4(OUT)
	sw X2,   8(OUT)
	sw X3,  12(OUT)
	sw X4,  16(OUT)
	sw X5,  20(OUT)
	sw X6,  24(OUT)
	sw X7,  28(OUT)
	sw X8,  32(OUT)
	sw X9,  36(OUT)
	sw X10, 40(OUT)
	sw X11, 44(OUT)
	sw X12, 48(OUT)
	sw X13, 52(OUT)
	sw X14, 56(OUT)
	sw X15, 60(OUT)

	// update pointers
	addiu IN,  CHACHA20_BLOCK_SIZE
	addiu OUT, CHACHA20_BLOCK_SIZE

.set noreorder
	// bytes left?
	bnez BYTES, .Loop_chacha
	addiu COUNTER_0, 1
.set reorder

	b .Lchacha20_mips_done
	nop

.Lchacha20_mips_last_bytes:
	addiu T3, $sp, TEMP_XOR_OFFSET
	sltiu	LAST_BLOCK, BYTES, 4
	// Store block on stack so we can easely access them with a pointer.
	sw X0,   0(T3)
	sw X1,   4(T3)
	sw X2,   8(T3)
	sw X3,  12(T3)
	sw X4,  16(T3)
	sw X5,  20(T3)
	sw X6,  24(T3)
	sw X7,  28(T3)
	sw X8,  32(T3)
	sw X9,  36(T3)
	sw X10, 40(T3)
	sw X11, 44(T3)
	sw X12, 48(T3)
	sw X13, 52(T3)
	sw X14, 56(T3)
	sw X15, 60(T3)

	bnez	LAST_BLOCK, .Loop_xor_byte
	nop

.Loop_xor_word:
	addiu	BYTES, -4
	lw	T0, 0(IN)
	addiu	IN, 4
	lw	T1, 0(T3)
	sltiu	LAST_BLOCK, BYTES, 4
	addiu	T3, 4
	xor	T0, T1
	sw	T0, 0(OUT)
	addiu	OUT, 4
	.set noreorder
	beqz	LAST_BLOCK, .Loop_xor_word
	nop
	.set reorder

	beqz	BYTES, .Lchacha20_mips_done
	nop

.Loop_xor_byte:
	addiu	BYTES, -1
	lbu	T0, 0(IN)
	addiu	IN, 1
	lbu	T1, 0(T3)
	addiu	T3, 1
	xor	T0, T1
	sb	T0, 0(OUT)
	.set noreorder
	bnez	BYTES, .Loop_xor_byte
	addiu	OUT, 1
	.set reorder

.Lchacha20_mips_done:
	lw $ra,  0($sp)
	lw $fp,  4($sp)
	lw $s0,  8($sp)
	lw $s1, 12($sp)
	lw $s2, 16($sp)
	lw $s3, 20($sp)
	lw $s4, 24($sp)
	lw $s5, 28($sp)
	lw $s6, 32($sp)
	lw $s7, 36($sp)

.Lchacha20_mips_end:
	.set noreorder
	jr	$ra
	addiu	$sp, STACK_SIZE
	.set reorder
	.set at
.end chacha20_mips

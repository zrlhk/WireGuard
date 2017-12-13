/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2016-2017 René van Dorst <opensource@vdorst.com>. All Rights Reserved.
 * Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#define X0  $t0
#define X1  $t1
#define X2  $t2
#define X3  $t3
#define X4  $t4
#define X5  $t5
#define X6  $t6
#define X7  $t7
#define X8  $t8
#define X9  $t9
#define X10 $s0
#define X11 $s1
#define X12 $s2
#define X13 $s3
#define X14 $s4
#define X15 $s5
#define T0  $s6
#define T1  $s7
#define T2  $v0
#define T3  $v1
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

#define STACK_SIZE	32
#define OUT		$a0
#define IN		$a1
#define KEY		$a3
#define COUNTER		$a2
#define ROUND_INDEX	T0

#define CONSTANT_1	0x61707865
#define CONSTANT_2	0x3320646e
#define CONSTANT_3	0x79622d32
#define CONSTANT_4	0x6b206574

// TODO: this should actually do a loop, rather than only computing one block, taking into account partial blocks

// chacha20_mips(u8 *out, const u8 *in, size_t len, const u32 key[8], const u32 counter[4]);
.align 4
.set reorder
.globl chacha20_mips
.ent   chacha20_mips
chacha20_mips:
	// this is in the fifth argument
	lw COUNTER, 16($sp)

	addiu $sp, -(STACK_SIZE)
	sw $s0, 0($sp)
	sw $s1, 4($sp)
	sw $s2, 8($sp)
	sw $s3, 12($sp)
	sw $s4, 16($sp)
	sw $s5, 20($sp)
	sw $s6, 24($sp)
	sw $s7, 28($sp)

	li X0, CONSTANT_1
	li X1, CONSTANT_2
	li X2, CONSTANT_3
	li X3, CONSTANT_4
	lw X4, 0(KEY)
	lw X5, 4(KEY)
	lw X6, 8(KEY)
	lw X7, 12(KEY)
	lw X8, 16(KEY)
	lw X9, 20(KEY)
	lw X10, 24(KEY)
	lw X11, 28(KEY)
	lw X12, 0(COUNTER)
	lw X13, 4(COUNTER)
	lw X14, 8(COUNTER)
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
	bnez	ROUND_INDEX, .Loop_chacha_xor_rounds
	subu	ROUND_INDEX, 1
	.set reorder

	addu X0, CONSTANT_1
	addu X1, CONSTANT_2
	addu X2, CONSTANT_3
	addu X3, CONSTANT_4
	lw T0, 0(KEY)
	lw T1, 4(KEY)
	lw T2, 8(KEY)
	lw T3, 12(KEY)
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
	lw T0, 0(COUNTER)
	lw T1, 4(COUNTER)
	lw T2, 8(COUNTER)
	lw T3, 12(COUNTER)
	addu X12, T0
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

	sw X0, 0(OUT)
	sw X1, 4(OUT)
	sw X2, 8(OUT)
	sw X3, 12(OUT)
	sw X4, 16(OUT)
	sw X5, 20(OUT)
	sw X6, 24(OUT)
	sw X7, 28(OUT)
	sw X8, 32(OUT)
	sw X9, 36(OUT)
	sw X10, 40(OUT)
	sw X11, 44(OUT)
	sw X12, 48(OUT)
	sw X13, 52(OUT)
	sw X14, 56(OUT)
	sw X15, 60(OUT)

	lw $s0, 0($sp)
	lw $s1, 4($sp)
	lw $s2, 8($sp)
	lw $s3, 12($sp)
	lw $s4, 16($sp)
	lw $s5, 20($sp)
	lw $s6, 24($sp)
	lw $s7, 28($sp)
	.set noreorder
	jr	$ra
	addiu	$sp, STACK_SIZE
	.set reorder
.end chacha20_mips

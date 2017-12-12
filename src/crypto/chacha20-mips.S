/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2016-2017 René van Dorst <opensource@vdorst.com>. All Rights Reserved.
 */

#include <linux/linkage.h>

#define CHACHA20_BLOCK_SIZE 64
#define CHACHA20_CTX_STATE_OFFSET 0
#define CHACHA20_CTX_STREAM_OFFSET (CHACHA20_BLOCK_SIZE)

#ifndef ENTRY
#define ENTRY(x) .ent(x)
#endif
#ifndef END
#define END(x) .end(x)
#endif

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
#define T2  $a2
#define T3  $a3

#define T(n) T ## n
#define X(n) X ## n
#define __in_ctx_p	$a0
#define __in_dst_p	$a1

#define stack_size (24*4)

#define AXR( A, B, C, D,  K, L, M, N,  V, W, Y, Z,  S) \
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

#define PTR_CHACHA20_STATE(x)	(CHACHA20_CTX_STATE_OFFSET + (x*4)) ## (__in_ctx_p)
#define PTR_CHACHA20_STREAM(x)	(CHACHA20_CTX_STREAM_OFFSET + (x*4)) ## (__in_ctx_p)

#define LOAD_ctx(R)		lw X(R),  PTR_CHACHA20_STATE(R);
#define STORE_ctx(R)		sw X(R),  PTR_CHACHA20_STATE(R);
#define STORE_stream(R)		sw X(R),  PTR_CHACHA20_STREAM(R);
#define LOAD_ctx_TMP(R, TR)	lw T(TR), PTR_CHACHA20_STATE(R);
#define loop_cnt T(3)

#define PTR_CHACHA20_DATA_DST(x)	(x*4) ## (__in_dst_p)

#define LOAD_data_TMP(RZ,RT)		lw T(RT), PTR_CHACHA20_DATA_DST(RZ);
#define STORE_xordata(RZ)		sw X(RZ), PTR_CHACHA20_DATA_DST(RZ);

.align 4
.set noat
.set noreorder
.globl chacha20_block_xor_mips
.ent   chacha20_block_xor_mips
chacha20_block_xor_mips:
	// store the used save registers.
	addiu	$sp, -(stack_size)
	// Load all chacha settings.
	LOAD_ctx(0)
	LOAD_ctx(1)
	LOAD_ctx(2)
	LOAD_ctx(3)
	LOAD_ctx(4)
	LOAD_ctx(5)
	LOAD_ctx(6)
	LOAD_ctx(7)
	// store the used save registers.
	sw  $s0, 0($sp)
	sw  $s1, 4($sp)
	sw  $s2, 8($sp)
	sw  $s3, 12($sp)
	sw  $s4, 16($sp)
	sw  $s5, 20($sp)
	sw  $s6, 24($sp)
	sw  $s7, 28($sp)
	// Load all chacha settings.
	LOAD_ctx(8)
	LOAD_ctx(9)
	LOAD_ctx(10)
	LOAD_ctx(11)
	LOAD_ctx(12)
	LOAD_ctx(13)
	LOAD_ctx(14)
	LOAD_ctx(15)
	// set loop counter.
	li	loop_cnt, 18
.Loop_chacha_xor_rounds:
	// do row shuffle
	AXR( 0, 1, 2, 3,  4, 5, 6, 7, 12,13,14,15, 16);
	AXR( 8, 9,10,11, 12,13,14,15,  4, 5, 6, 7, 12);
	AXR( 0, 1, 2, 3,  4, 5, 6, 7, 12,13,14,15,  8);
	AXR( 8, 9,10,11, 12,13,14,15,  4, 5, 6, 7,  7);
	AXR( 0, 1, 2, 3,  5, 6, 7, 4, 15,12,13,14, 16);
	AXR(10,11, 8, 9, 15,12,13,14,  5, 6, 7, 4, 12);
	AXR( 0, 1, 2, 3,  5, 6, 7, 4, 15,12,13,14,  8);
	AXR(10,11, 8, 9, 15,12,13,14,  5, 6, 7, 4,  7);
.set noreorder
	// loop_cnt if T(0) != 0
	bnez	loop_cnt, .Loop_chacha_xor_rounds
	// decrease loop counter, make use of delay slot.
	addiu	loop_cnt, -2
.set reorder
	
	LOAD_ctx_TMP(0,0)
	LOAD_ctx_TMP(1,1)
	LOAD_ctx_TMP(2,2)
	LOAD_ctx_TMP(3,3)
	addu X(0), T(0)
	addu X(1), T(1)
	addu X(2), T(2)
	addu X(3), T(3)
	LOAD_ctx_TMP(4,0)
	LOAD_ctx_TMP(5,1)
	LOAD_ctx_TMP(6,2)
	LOAD_ctx_TMP(7,3)
	addu X(4), T(0)
	addu X(5), T(1)
	addu X(6), T(2)
	addu X(7), T(3)
	LOAD_ctx_TMP(8,0)
	LOAD_ctx_TMP(9,1)
	LOAD_ctx_TMP(10,2)
	LOAD_ctx_TMP(11,3)
	addu X(8), T(0)
	addu X(9), T(1)
	addu X(10), T(2)
	addu X(11), T(3)
	LOAD_ctx_TMP(12,0)
	LOAD_ctx_TMP(13,1)
	LOAD_ctx_TMP(14,2)
	LOAD_ctx_TMP(15,3)
	addu X(12), T(0)
	addiu T(0), 1
	addu X(13), T(1)
	addu X(14), T(2)
	addu X(15), T(3)
	sw T(0), PTR_CHACHA20_STATE(12)
	// Convert to Litte endian and Save all to stream.
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	wsbh 	X(0)
	wsbh 	X(1)
	wsbh 	X(2)
	wsbh 	X(3)
	wsbh 	X(4)
	wsbh 	X(5)
	wsbh 	X(6)
	wsbh 	X(7)
	wsbh 	X(8)
	wsbh 	X(9)
	wsbh 	X(10)
	wsbh 	X(11)
	wsbh 	X(12)
	wsbh 	X(13)
	wsbh 	X(14)
	wsbh 	X(15)
	rotr 	X(0), 16
	rotr 	X(1), 16
	rotr 	X(2), 16
	rotr 	X(3), 16
	rotr 	X(4), 16
	rotr 	X(5), 16
	rotr 	X(6), 16
	rotr 	X(7), 16
	rotr 	X(8), 16
	rotr 	X(9), 16
	rotr 	X(10), 16
	rotr 	X(11), 16
	rotr 	X(12), 16
	rotr 	X(13), 16
	rotr 	X(14), 16
	rotr 	X(15), 16
#endif

	/* Temp for debugging */
#if defined(CONFIG_WIREGUARD_DEBUG)
	STORE_stream(0)
	STORE_stream(1)
	STORE_stream(2)
	STORE_stream(3)
	STORE_stream(4)
	STORE_stream(5)
	STORE_stream(6)
	STORE_stream(7)
	STORE_stream(8)
	STORE_stream(9)
	STORE_stream(10)
	STORE_stream(11)
	STORE_stream(12)
	STORE_stream(13)
	STORE_stream(14)
	STORE_stream(15)
#endif

	LOAD_data_TMP(0,0)
	LOAD_data_TMP(1,1)
	LOAD_data_TMP(2,2)
	LOAD_data_TMP(3,3)
	xor  X0, T0
	xor  X1, T1
	xor  X2, T2
	xor  X3, T3
	LOAD_data_TMP(4,0)
	LOAD_data_TMP(5,1)
	LOAD_data_TMP(6,2)
	LOAD_data_TMP(7,3)
	xor  X4, T0
	xor  X5, T1
	xor  X6, T2
	xor  X7, T3
	LOAD_data_TMP(8,0)
	LOAD_data_TMP(9,1)
	LOAD_data_TMP(10,2)
	LOAD_data_TMP(11,3)
	xor  X8, T0
	xor  X9, T1
	xor  X10, T2
	xor  X11, T3
	LOAD_data_TMP(12,0)
	LOAD_data_TMP(13,1)
	LOAD_data_TMP(14,2)
	LOAD_data_TMP(15,3)
	xor  X12, T0
	xor  X13, T1
	xor  X14, T2
	xor  X15, T3

	STORE_xordata(0)
	STORE_xordata(1)
	STORE_xordata(2)
	STORE_xordata(3)
	STORE_xordata(4)
	STORE_xordata(5)
	STORE_xordata(6)
	STORE_xordata(7)
	STORE_xordata(8)
	STORE_xordata(9)
	STORE_xordata(10)
	STORE_xordata(11)
	STORE_xordata(12)
	STORE_xordata(13)
	STORE_xordata(14)
	STORE_xordata(15)
	
	// restore the used save registers.
	lw  $s0, 0($sp)
	lw  $s1, 4($sp)
	lw  $s2, 8($sp)
	lw  $s3, 12($sp)
	lw  $s4, 16($sp)
	lw  $s5, 20($sp)
	lw  $s6, 24($sp)
	lw  $s7, 28($sp)
	addiu	$sp, stack_size
	// Jump Back
	jr	$ra
	nop
.end chacha20_block_xor_mips
.set at
.set reorder

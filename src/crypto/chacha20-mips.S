/* SPDX-License-Identifier: (GPL-2.0)
 *
 * Copyright (C) 2016-2017 René van Dorst <opensource@vdorst.com>. All Rights Reserved.
 * Based on the C code.
 */

#include <linux/linkage.h>

#define CHACHA20_BLOCK_SIZE 64
#define CHACHA20_CTX_STATE_OFFSET 0
#define CHACHA20_CTX_STREAM_OFFSET (CHACHA20_BLOCK_SIZE)

#ifndef CONFIG_32BIT
#error Only 32-bits
#endif
#ifndef CONFIG_CPU_MIPS32_R2
#error Only MIPS32R2
#endif
#ifndef ENTRY
#define ENTRY(x) .ent(x)
#endif
#ifndef END
#define END(x) .end(x)
#endif

// asmlinkage void chacha20_keysetup(struct chacha20_ctx *ctx, const u8 key[static 32], const u8 nonce[static 8]);

	.align 4
	.text
	.set reorder
	.globl chacha20_keysetup
	.ent chacha20_keysetup
chacha20_keysetup:
    // Load upper part of Constant
    lui		$t0, 0x6170
    lui		$t1, 0x3320
    lui		$t2, 0x7962
    lui		$t3, 0x6b20
    // Load first part of key data
    lw 		$t4, 0($a1)
    lw 		$t5, 4($a1)
    lw 		$t6, 8($a1)
    lw 		$t7, 12($a1)
    lw 		$t8, 16($a1)
    lw 		$t9, 20($a1)
    // Load lower part of Constant
    ori		$t0, 0x7865
    ori		$t1, 0x646e
    ori		$t2, 0x2d32
    ori		$t3, 0x6574
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    // Convert to Little Endian
    wsbh 	$t4
    wsbh 	$t5
    wsbh 	$t6
    wsbh 	$t7
    wsbh 	$t8
    wsbh 	$t9
    rotr 	$t4, 16
    rotr 	$t5, 16
    rotr 	$t6, 16
    rotr 	$t7, 16
    rotr 	$t8, 16
    rotr 	$t9, 16
#endif
    // Store first part of key data to ctx
    sw		$t0, 0($a0)
    sw		$t1, 4($a0)
    sw		$t2, 8($a0)
    sw		$t3, 12($a0)
    sw 		$t4, 16($a0)
    sw 		$t5, 20($a0)
    // Load second part of key data
    lw 		$t0, 24($a1)
    lw 		$t1, 28($a1)
    lw 		$t2, 0($a2)
    lw 		$t3, 4($a2)
    sw 		$t6, 24($a0)
    sw 		$t7, 28($a0)
    sw 		$t8, 32($a0)
    sw 		$t9, 36($a0)
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    // Convert to Little Endian
    wsbh 	$t0
    wsbh 	$t1
    wsbh 	$t2
    wsbh 	$t3
    rotr 	$t0, 16
    rotr 	$t1, 16
    rotr 	$t2, 16
    rotr 	$t3, 16
#endif
    // Store second part of key data to ctx
    sw 		$zero, 48($a0)
    sw 		$zero, 52($a0)
    sw 		$t0, 40($a0)
    sw 		$t1, 44($a0)
    sw 		$t2, 56($a0)
    sw 		$t3, 60($a0)
    // Jump back
    jr 		$ra
    nop
.end chacha20_keysetup


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

// static void chacha20_block_generic(struct chacha20_ctx *ctx, void *stream)

.align 4
//.set noat
.set noreorder
.globl chacha20_block_mips
.ent chacha20_block_mips
chacha20_block_mips:
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
.Loop_chacha_rounds:
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
	bnez	loop_cnt, .Loop_chacha_rounds
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
.end chacha20_block_mips
.set at
.set reorder



// static void chacha20_block_xor_mips(struct chacha20_ctx *ctx, void *dst)

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



//static void chacha20_crypt(
// $a0 = struct chacha20_ctx *ctx, 
// $a1 = u8 *dst,
// $a2 = const u8 *src,
// $a3 = u32 bytes,
// STACK = bool have_simd)

//    u8 buf[CHACHA20_BLOCK_SIZE = 64]; = 8xu32 


# Stack size in number of bytes.
# In our case CHACHA20_BLOCK_SIZE + save some registers.
#define stack_size_crypt (64+(4*32))


#define CRYPT_IN_CTX	$a0
#define CRYPT_IN_DST	$a1
#define CRYPT_IN_SRC	$a2
#define CRYPT_IN_BYTES	$a3

#define CRYPT_CTX	$s0
#define CRYPT_DST	$s1
#define CRYPT_SRC	$s2
#define CRYPT_BYTES	$s3
#define CRYPT_LAST_BLOCK	$s4

#define PTR_STACK(x)  (x*4) ## ($sp)

#define LOAD_stack(R, L)	lw R, PTR_STACK(R);
#define STORE_stack(R,L)	sw R, PTR_STACK(R);

//static void chacha20_crypt(
//	struct chacha20_ctx *ctx, 
//	u8 *dst, 
//	const u8 *src,
//	u32 bytes, 
//	bool have_simd)


.align 4
.set at
.set reorder
.globl chacha20_crypt_mips_asm
.ent chacha20_crypt_mips_asm
chacha20_crypt_mips_asm:
	
	/*
	 * Check Bytes = 0 then return
	 */
	beqz    CRYPT_IN_BYTES, .Lcrypt_end1
	nop
	
.Lcrypt_start:

	/*
	 * store the used save registers.
	 */
	addiu	$sp, -(stack_size_crypt)

	// store the used save registers.
	sw	$ra, PTR_STACK(0)
	sw	$s0, PTR_STACK(1)
	sw	$s1, PTR_STACK(2)
	sw	$s2, PTR_STACK(3)
	sw	$s3, PTR_STACK(4)
	sw	$s4, PTR_STACK(5)
	sw	$s5, PTR_STACK(6)
	sw	$s6, PTR_STACK(7)
	sw	$s7, PTR_STACK(8)


	sw	$a0, PTR_STACK(8)
	sw	$a1, PTR_STACK(9)
	sw	$a2, PTR_STACK(10)
	sw	$a3, PTR_STACK(11)

	// Store input variables in Save registers for later
	move	CRYPT_CTX, CRYPT_IN_CTX
	move	CRYPT_DST, CRYPT_IN_DST
	move	CRYPT_SRC, CRYPT_IN_SRC
	move	CRYPT_BYTES, CRYPT_IN_BYTES

	sltiu	CRYPT_LAST_BLOCK, CRYPT_IN_BYTES, CHACHA20_BLOCK_SIZE

	// skip memorycopy if DST=SRC
	beq	CRYPT_IN_DST, CRYPT_IN_SRC, .Lcrypt_loop_skip_memcpy
	nop

	// setup memcpy vars.
	move	$a0, CRYPT_DST
	move	$a1, CRYPT_SRC
	move	$a2, CRYPT_BYTES
	// call memcpy (dst, src, count)
	jal	memcpy
	nop

.Lcrypt_loop_skip_memcpy:
	// Check bytes less then CHACHA20_BLOCK_SIZE then jump .Lcrypt_nonfull_block
	bnez	CRYPT_LAST_BLOCK, .Lcrypt_nonfull_block
	nop

.Lcrypt_loop_full_block:
	// Check Only has 1 full block? then it is the last block
	sltiu	CRYPT_LAST_BLOCK, CRYPT_BYTES, (CHACHA20_BLOCK_SIZE*2)
	// Decresse bytes
	addiu	CRYPT_BYTES, -CHACHA20_BLOCK_SIZE

	/* Select optimizes version vs generic */
#if  1
	// chacha20_block_generic(ctx);
	// location of buf
	move	$a0, CRYPT_CTX
	move	$a1, CRYPT_DST
	jal	chacha20_block_xor_mips
	nop
#else
	// chacha20_block_generic(ctx);
	// location of buf
	move	$a0, CRYPT_CTX
	jal	chacha20_block_mips
	nop

	// xor
	move	$a0, CRYPT_DST
	addiu	$a1, CRYPT_CTX, CHACHA20_CTX_STREAM_OFFSET
	li	$a2, CHACHA20_BLOCK_SIZE
	jal 	crypto_xor
	nop
#endif


	// inc DST address for next round.
	addiu	CRYPT_DST, CHACHA20_BLOCK_SIZE

	// Last Full Block?
	beqz	CRYPT_LAST_BLOCK, .Lcrypt_loop_full_block
	nop

// ### END .Lcrypt_loop_full_block

	// No bytes left, 
	beqz	CRYPT_BYTES, .Lcrypt_done
	nop

.Lcrypt_nonfull_block:
	// chacha20_block_generic(ctx);
	// location of buf
	move	$a0, CRYPT_CTX
	jal	chacha20_block_mips
	nop

	/* Select optimizes version vs generic */
# if 0
.Loop_xor_byte:
	addi	CRYPT_BYTES, -1
	lbu	$a0, 0(CRYPT_DST)
	lbu 	$a1, 64(CRYPT_CTX)
	addiu	CRYPT_CTX, 1
	xor	$a0, $a1
	sb	$a0, 0(CRYPT_DST)
	addiu	CRYPT_DST, 1
	bnez	CRYPT_BYTES, .Loop_xor_byte
	nop
#else
	move	$a0, CRYPT_DST
	addiu	$a1, CRYPT_CTX, CHACHA20_CTX_STREAM_OFFSET
	move	$a2, CRYPT_BYTES
	jal 	crypto_xor
	nop
#endif

.Lcrypt_done:
	lw	$ra, PTR_STACK(0)
	lw	$s0, PTR_STACK(1)
	lw	$s1, PTR_STACK(2)
	lw	$s2, PTR_STACK(3)
	lw	$s3, PTR_STACK(4)
	lw	$s4, PTR_STACK(5)
	lw	$s5, PTR_STACK(6)
	lw	$s6, PTR_STACK(7)
	lw	$s7, PTR_STACK(8)

	addiu	$sp, stack_size_crypt

.Lcrypt_end1:
	// Jump Back
	jr	$ra
	nop

.end chacha20_crypt_mips_asm

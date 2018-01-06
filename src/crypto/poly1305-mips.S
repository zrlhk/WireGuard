/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2016-2017 René van Dorst <opensource@vdorst.com>. All Rights Reserved.
 */

#include <linux/linkage.h>

#define POLY1305_CTX_H 0
#define POLY1305_CTX_R POLY1305_CTX_H + (5*4)
#define POLY1305_BLOCK_SIZE 16

.text
#define H0 $t0
#define H1 $t1
#define H2 $t2
#define H3 $t3
#define H4 $t4

#define R0 $t5
#define R1 $t6
#define R2 $t7
#define R3 $t8

#define I0 $s0
#define I1 $s4
#define I2 $s5
#define I3 $s6

#define O0 $s0
#define O1 $s4
#define O2 $s5
#define O3 $s6
#define O4 $s7

#define S1 $s1
#define S2 $s2
#define S3 $s3

#define SC $v1
#define CA $v0

#define __in_ctx_poly $a0
#define src        $a1
#define srclen     $a2
#define hibit      $a3

#define PTR_POLY1305_R(n) (POLY1305_CTX_R + (n*4)) ## ($a0)
#define PTR_POLY1305_H(n) (POLY1305_CTX_H + (n*4)) ## ($a0)

#define LOAD_ctx_r(n)        lw R##n, PTR_POLY1305_R(n);
#define LOAD_ctx_h(n)        lw H##n, PTR_POLY1305_H(n);
#define STORE_ctx_h(n)       sw H##n, PTR_POLY1305_H(n);

#define POLY1305_BLOCK_SIZE 16
#define POLY1305_STACK_SIZE 8 * 4

// static unsigned int poly1305_blocks_mips   (struct poly1305_ctx *ctx, const u8 *src, unsigned int srclen, u32 hibit)
// static void         poly1305_blocks_generic(void *ctx, const u8 *inp, size_t len, u32 padbit)
.set reorder
.globl poly1305_blocks_mips
.ent poly1305_blocks_mips
poly1305_blocks_mips:
	.frame  $sp,POLY1305_STACK_SIZE,$31
	// store the used save registers.
	addiu	$sp, -POLY1305_STACK_SIZE

	// return if srclen < POLY1305_BLOCK_SIZE
	slti	SC, srclen, POLY1305_BLOCK_SIZE
	bnez	SC, .Lpoly1305_blocks_mips_end
	nop

	LOAD_ctx_r(0)
	LOAD_ctx_r(1)
	LOAD_ctx_r(2)
	LOAD_ctx_r(3)

	// store the used save registers.
	sw  $s0, 0($sp)
	sw  $s1, 4($sp)
	sw  $s2, 8($sp)
	sw  $s3, 12($sp)
	sw  $s4, 16($sp)
	sw  $s5, 20($sp)
	sw  $s6, 24($sp)
	sw  $s7, 28($sp)

	LOAD_ctx_h(0)
	LOAD_ctx_h(1)
	LOAD_ctx_h(2)
	LOAD_ctx_h(3)
	LOAD_ctx_h(4)

	srl S1, R1, 2
	srl S2, R2, 2
	srl S3, R3, 2
	addu S1, R1
	addu S2, R2
	addu S3, R3

.Lpoly1305_loop:
	lw I0, 0(src)
	lw I1, 4(src)
	lw I2, 8(src)
	lw I3,12(src)

	addiu SC, $zero, 1
	addiu src,     POLY1305_BLOCK_SIZE
	addiu srclen, -POLY1305_BLOCK_SIZE

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	wsbh I0
	wsbh I1
	wsbh I2
	wsbh I3
	rotr I0, 16
	rotr I1, 16
	rotr I2, 16
	rotr I3, 16
#endif

	// h0 = (u32)(d0 = (u64)h0 + le32_to_cpuvp(inp + 0));

	multu H0, SC
	maddu I0, SC
	mflo  O0
	mfhi  CA

	// h1 = (u32)(d1 = (u64)h1 + (d0 >> 32) + le32_to_cpuvp(inp + 4));

	multu H1, SC
	maddu I1, SC
	maddu CA, SC
	mflo  O1
	mfhi  CA

	// h2 = (u32)(d2 = (u64)h2 + (d1 >> 32) + le32_to_cpuvp(inp + 8));

	multu H2, SC
	maddu I2, SC
	maddu CA, SC
	mflo  O2
	mfhi  CA

	// h3 = (u32)(d3 = (u64)h3 + (d2 >> 32) + le32_to_cpuvp(inp + 12));

	multu H3, SC
	maddu I3, SC
	maddu CA, SC
	mflo  O3
	mfhi  CA

	// h4 += (u32)(d3 >> 32) + padbit;

	addu O4, H4, hibit
	addu O4, CA

	// D0

	multu O0, R0
	maddu O1, S3
	maddu O2, S2
	maddu O3, S1

	mflo	H0
	mfhi	CA

	// D1

	multu O0, R1
	maddu O1, R0
	maddu O2, S3
	maddu O3, S2
	maddu O4, S1
	maddu CA, SC

	mflo	H1
	mfhi	CA

	// D2

	multu O0, R2
	maddu O1, R1
	maddu O2, R0
	maddu O3, S3
	maddu O4, S2
	maddu CA, SC

	mflo	H2
	mfhi	CA

	// D3

	multu O0, R3
	maddu O1, R2
	maddu O2, R1
	maddu O3, R0
	maddu O4, S3
	maddu CA, SC

	mflo	H3
	mfhi	CA

	// H4
	mul	H4, O4, R0
	addu	H4, CA

	// c = (h4 >> 2) + (h4 & ~3U);
	srl	O0, H4, 2
	move	CA, H4
	ins	CA, $zero, 0, 2
	addu	CA, O0

	andi	H4, 3

	// check length
	slti	SC, srclen, POLY1305_BLOCK_SIZE

	// CONSTANT_TIME_CARRY
	addu	H0, CA
	sltu	CA, H0, CA
	addu	H1, CA
	sltu	CA, H1, CA
	addu	H2, CA
	sltu	CA, H2, CA
	addu	H3, CA
	sltu	CA, H3, CA
	addu	H4, CA

	// able to do a 16 byte block.
	beqz SC, .Lpoly1305_loop
	nop

	// restore the used save registers.
	lw  $s0, 0($sp)
	lw  $s1, 4($sp)
	lw  $s2, 8($sp)
	lw  $s3, 12($sp)
	lw  $s4, 16($sp)
	lw  $s5, 20($sp)
	lw  $s6, 24($sp)
	lw  $s7, 28($sp)

	STORE_ctx_h(0)
	STORE_ctx_h(1)
	STORE_ctx_h(2)
	STORE_ctx_h(3)
	STORE_ctx_h(4)

.Lpoly1305_blocks_mips_end:
	// return remaining bytes
	move	$v0, srclen

	.set noreorder
	// Jump Back
	jr	$ra
	addiu	$sp, POLY1305_STACK_SIZE
	.set reorder

.end poly1305_blocks_mips
.set at
.set reorder

#define PR0 $t4
#define PR1 $t5
#define PR2 $t6
#define PR3 $t7
#define PT0 $t0

#define LOAD_key(RG,n)		lw RG, (n * 4) ## ($a1);

// asmlinkage void poly1305_init_mips(void *ctx, const u8 key[16]);
.globl poly1305_init_mips
.ent poly1305_init_mips
poly1305_init_mips:
	LOAD_key(PR0, 0)
	LOAD_key(PR1, 1)
	LOAD_key(PR2, 2)
	LOAD_key(PR3, 3)

	lui PT0, 0x0FFF

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	wsbh PR0
	wsbh PR1
	wsbh PR2
	wsbh PR3
	rotr PR0, 16
	rotr PR1, 16
	rotr PR2, 16
	rotr PR3, 16
#endif

	sw $zero, PTR_POLY1305_H(0)
	sw $zero, PTR_POLY1305_H(1)
	sw $zero, PTR_POLY1305_H(2)
	ori PT0, 0xFFFC
	sw $zero, PTR_POLY1305_H(3)
	sw $zero, PTR_POLY1305_H(4)

	// AND 0x0fffffff;
	ext PR0, PR0, 0, (32-4)
	// AND 0x0ffffffc;
	and PR1, PT0
	and PR2, PT0
	and PR3, PT0

	sw PR0, PTR_POLY1305_R(0);
	sw PR1, PTR_POLY1305_R(1);
	sw PR2, PTR_POLY1305_R(2);
	sw PR3, PTR_POLY1305_R(3);

	// Jump Back
	jr	$ra
	nop
.end poly1305_init_mips

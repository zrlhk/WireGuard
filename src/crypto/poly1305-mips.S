/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2016-2017 René van Dorst <opensource@vdorst.com>. All Rights Reserved.
 */


#include <linux/linkage.h>


#define POLY1305_CTX_H 0
#define POLY1305_CTX_R POLY1305_CTX_H + (5*4)

.text
#define H0  $t0
#define H1  $t1
#define H2  $t2
#define H3  $t3
#define H4  $t4

#define R0  $t5
#define R1  $t6
#define R2  $t7
#define R3  $t8

#define I0  $t0
#define I1  $t1
#define I2  $t2
#define I3  $t3

#define O0 $s0
#define O1 $s4
#define O2 $s5
#define O3 $s6
#define O4 $s7

#define S1 $s1
#define S2 $s2
#define S4 $s3

#define SC  $gp
#define CA  $v1
#define AT  $v1





#define R(n)  R ## n
#define S(n)  H ## n
#define H(n)  H ## n
#define O(n)  O ## n
#define I(n)  I ## n

#define __in_ctx_poly $a0
#define src        $a1
#define srclen     $a2
#define hibit      $a3

#define PTR_POLY1305_R(n) (POLY1305_CTX_R + (n*4)) ## ($a0)
#define PTR_POLY1305_H(n) (POLY1305_CTX_H + (n*4)) ## ($a0)

#define LOAD_ctx_r(n)        lw R(n), PTR_POLY1305_R(n);
#define LOAD_ctx_h(n)        lw H(n), PTR_POLY1305_H(n);
#define STORE_ctx_h(n)       sw H(n), PTR_POLY1305_H(n);

#define POLY1305_BLOCK_SIZE 16

#define GET_HILO_REG(RHI, RLO) \
	mflo RLO; \
	mfhi RHI;
#define AND_3FFFFFF(RT, RS) \
	ext RT, RS, 0, 26;
#define poly1305_frame_size 15 * 4

// MULTI_MUL_AND_ADD_PREV( R(2), R(1), R(0), S(4), S(3), H(1))
#define MULTI_MUL_AND_ADD_PREV( MUL1, MUL2, MUL3, MUL4, MUL5, PREV ) \
	mflo PREV; \
	mfhi SC;   \
	multu O(0), MUL1; \
	maddu O(1), MUL2; \
		addu AT,PREV,CA; \
	maddu O(2), MUL3; \
	maddu O(3), MUL4; \
		sltu PREV,AT,PREV; \
		srl  CA,AT,26; \
	maddu O(4), MUL5; \
		addu SC,PREV,SC; \
		AND_3FFFFFF( PREV, AT ); \
		ins CA,SC, 32-26, 26

#define ADD_CIO( A, B, C_I, C_O, OUT, SC ) \
	addu 	SC, A, C_I; \
	addu	OUT, A, B;  \
	
	
	

// static unsigned int poly1305_blocks_mips   (struct poly1305_ctx *ctx, const u8 *src, unsigned int srclen, u32 hibit)
// static void         poly1305_blocks_generic(void *ctx, const u8 *inp, size_t len, u32 padbit)
// .abicalls
// .text
.set noat
.set reorder
// .set nomips16
// .set nomicromips
.globl poly1305_blocks_mips
.ent poly1305_blocks_mips
poly1305_blocks_mips:
	.frame  $sp,poly1305_frame_size,$31
	// store the used save registers.
	addiu 	$sp, -poly1305_frame_size
	addiu srclen, -POLY1305_BLOCK_SIZE

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
	sw  $gp, 32($sp)
	
	srl S(3), R(3),2
	srl S(2), R(2),2
	srl S(1), R(1),2
	addu S(3), R(3)
	addu S(2), R(2)
	addu S(1), R(1)

	LOAD_ctx_h(0)
	LOAD_ctx_h(1)
	LOAD_ctx_h(2)
	LOAD_ctx_h(3)
	LOAD_ctx_h(4)

poly1305_loop:

	/* h += m[i] */
	lw I(0), 0(src)
	lw I(1), 4(src)
	lw I(2), 8(src)
	lw I(3),12(src)

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	wsbh 	I(0)
	wsbh 	I(1)
	wsbh 	I(2)
	wsbh 	I(3)
	rotr 	I(0), 16
	rotr 	I(1), 16
	rotr 	I(2), 16
	rotr 	I(3), 16
#endif


	addiu src, POLY1305_BLOCK_SIZE
	addiu srclen, -POLY1305_BLOCK_SIZE
	
	// h0 = (u32)(d0 = (u64)h0 + le32_to_cpuvp(inp + 0));
	
	// Add H0 + I0
	addu O(0), H(0), I(0)
	sltu CA, O(0), H(0)
	
	// h1 = (u32)(d1 = (u64)h1 + (d0 >> 32) + le32_to_cpuvp(inp + 4));
	
	addu O(1), H(1)
	addu O(1), CA

	// h2 = (u32)(d2 = (u64)h2 + (d1 >> 32) + le32_to_cpuvp(inp + 8));

	sltu O(2), O(1), H(1)
	addu O(2), H(1)
	addu O(2), SC
		
	// h3 = (u32)(d3 = (u64)h3 + (d2 >> 32) + le32_to_cpuvp(inp + 12));

	sltu O(3), O(2), H(2)
	addu O(3), H(2)
	addu O(3), SC

	// h4 += (u32)(d3 >> 32) + padbit;
	
	sltu O(4), O(3), O(4)
	addu O(4), H(4)
	addu O(4), hibit


	// D0
	multu O(0), R(0)
	maddu O(1), S(3)
	maddu O(2), S(2)
	maddu O(3), S(1)

	GET_HILO_REG (H(1), H(0))

	// D1
	multu O(4), S(1)
	mthi  $zero
	maddu O(0), R(1)
	maddu O(1), R(0)
	maddu O(2), S(3)
	maddu O(3), S(2)

	GET_HILO_REG (H(4), H(0))
	
	// D2
	
	multu O(0), R(1)
	maddu O(1), R(0)
	maddu O(2), S(3)
	maddu O(3), S(2)

	GET_HILO_REG (H(2), H(0))

	ins CA,SC, 32-26, 26

	MULTI_MUL_AND_ADD_PREV( R(2), R(1), R(0), S(4), S(3), H(1))

	MULTI_MUL_AND_ADD_PREV( R(3), R(2), R(1), R(0), S(4), H(2))

	MULTI_MUL_AND_ADD_PREV( R(1), R(3), R(2), R(1), R(0), H(3))

	GET_HILO_REG (SC, H(4))


poly1305_loop_finish:
	addu AT,H(4),CA

	sltu 	H(4),AT,H(4)
	srl 	CA,AT, 26
	addu 	SC,H(4),SC
	AND_3FFFFFF( H(4), AT )
	ins		CA,SC, 32-26, 26

	// Multiply 5
	// H(0) = H(0) + (CA * 5) = H(0) + CA + (CA << 2)
	sll   SC, CA, 2
	addu  H(0), H(0), CA
	addu  H(0), SC

	// H(1) = H(1) + (H(0) >> 26)
	srl   SC, H(0), 26
	addu H(1), SC

	// H(0) = H(0) & 0x3FFFFFF
	AND_3FFFFFF( H(0), H(0) )

	// able to do a 16 byte block.
	bgezl srclen, poly1305_loop
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
	lw  $gp, 32($sp)

	STORE_ctx_h(0)
	STORE_ctx_h(1)
	STORE_ctx_h(2)
	STORE_ctx_h(3)
	STORE_ctx_h(4)

	addiu 	$sp, poly1305_frame_size
	// return remaining bytes
	addiu	$v0, srclen, POLY1305_BLOCK_SIZE
	// Jump Back
	jr	$ra
	nop

.end poly1305_blocks_mips
.set at
.set reorder



#define PR0 $t4
#define PR1 $t5
#define PR2 $t6
#define PR3 $t7

#define PT0 $t0

#define PR(n)  PR ## n
#define PT(n)  PT ## n

#define STORE_zero_poly_h(n) 	sw $zero, PTR_POLY1305_H(n);
#define STORE_poly_r(n)		sw PR(n), PTR_POLY1305_R(n);
#define LOAD_key(RG,n)		lw RG, (n * 4) ## ($a1);


// static void poly1305_init(struct poly1305_ctx *ctx, const u8 key[static POLY1305_KEY_SIZE])
// asmlinkage void poly1305_init_mips(void *ctx, const u8 key[16]);
.set noreorder
.globl poly1305_init_mips
.ent poly1305_init_mips
poly1305_init_mips:

	lui 	PT(0), 0x0FFF
	
	LOAD_key(PR(0), 0)
	LOAD_key(PR(1), 1)
	LOAD_key(PR(2), 2)
	LOAD_key(PR(3), 3)

	ori	PT(0), 0xFFFC

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	wsbh 	PR(0)
	wsbh 	PR(1)
	wsbh 	PR(2)
	wsbh 	PR(3)
	rotr 	PR(0), 16
	rotr 	PR(1), 16
	rotr 	PR(2), 16
	rotr 	PR(3), 16
#endif

	// AND 0x0fffffff;
	ext 	PR(0), PR(0), 0, (32-4)
	// AND 0x0ffffffc;
	and	PR(1), PR(1), PT(0)
	and	PR(2), PR(2), PT(0)
	and	PR(3), PR(3), PT(0)
	
	STORE_zero_poly_h(0)
	STORE_zero_poly_h(1)
	STORE_zero_poly_h(2)
	STORE_zero_poly_h(3)
	STORE_zero_poly_h(4)
	
	STORE_poly_r(0)
	STORE_poly_r(1)
	STORE_poly_r(2)
	STORE_poly_r(3)
	
	// Jump Back
	jr	$ra
	nop
.end poly1305_init_mips
.set reorder


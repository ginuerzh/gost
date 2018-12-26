#!/usr/bin/env python3
#
# To the extent possible under law, Yawning Angel has waived all copyright
# and related or neighboring rights to chacha20, using the Creative
# Commons "CC0" public domain dedication. See LICENSE or
# <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

#
# cgo sucks.  Plan 9 assembly sucks.  Real languages have SIMD intrinsics.
# The least terrible/retarded option is to use a Python code generator, so
# that's what I did.
#
# Code based on Ted Krovetz's vec128 C implementation, with corrections
# to use a 64 bit counter instead of 32 bit, and to allow unaligned input and
# output pointers.
#
# Dependencies: https://github.com/Maratyszcza/PeachPy
#
# python3 -m peachpy.x86_64 -mabi=goasm -S -o chacha20_amd64.s chacha20_amd64.py
#

from peachpy import *
from peachpy.x86_64 import *

x = Argument(ptr(uint32_t))
inp = Argument(ptr(const_uint8_t))
outp = Argument(ptr(uint8_t))
nrBlocks = Argument(ptr(size_t))

#
# SSE2 helper functions.  A temporary register is explicitly passed in because
# the main fast loop uses every single register (and even spills) so manual
# control is needed.
#
# This used to also have a DQROUNDS helper that did 2 rounds of ChaCha like
# in the C code, but the C code has the luxury of an optimizer reordering
# everything, while this does not.
#

def ROTW16_sse2(tmp, d):
    MOVDQA(tmp, d)
    PSLLD(tmp, 16)
    PSRLD(d, 16)
    PXOR(d, tmp)

def ROTW12_sse2(tmp, b):
    MOVDQA(tmp, b)
    PSLLD(tmp, 12)
    PSRLD(b, 20)
    PXOR(b, tmp)

def ROTW8_sse2(tmp, d):
    MOVDQA(tmp, d)
    PSLLD(tmp, 8)
    PSRLD(d, 24)
    PXOR(d, tmp)

def ROTW7_sse2(tmp, b):
    MOVDQA(tmp, b)
    PSLLD(tmp, 7)
    PSRLD(b, 25)
    PXOR(b, tmp)

def WriteXor_sse2(tmp, inp, outp, d, v0, v1, v2, v3):
    MOVDQU(tmp, [inp+d])
    PXOR(tmp, v0)
    MOVDQU([outp+d], tmp)
    MOVDQU(tmp, [inp+d+16])
    PXOR(tmp, v1)
    MOVDQU([outp+d+16], tmp)
    MOVDQU(tmp, [inp+d+32])
    PXOR(tmp, v2)
    MOVDQU([outp+d+32], tmp)
    MOVDQU(tmp, [inp+d+48])
    PXOR(tmp, v3)
    MOVDQU([outp+d+48], tmp)

# SSE2 ChaCha20 (aka vec128).  Does not handle partial blocks, and will
# process 4/2/1 blocks at a time.
with Function("blocksAmd64SSE2", (x, inp, outp, nrBlocks)):
    reg_x = GeneralPurposeRegister64()
    reg_inp = GeneralPurposeRegister64()
    reg_outp = GeneralPurposeRegister64()
    reg_blocks = GeneralPurposeRegister64()
    reg_sp_save = GeneralPurposeRegister64()

    LOAD.ARGUMENT(reg_x, x)
    LOAD.ARGUMENT(reg_inp, inp)
    LOAD.ARGUMENT(reg_outp, outp)
    LOAD.ARGUMENT(reg_blocks, nrBlocks)

    # Align the stack to a 32 byte boundary.
    MOV(reg_sp_save, registers.rsp)
    AND(registers.rsp, 0xffffffffffffffe0)
    SUB(registers.rsp, 0x20)

    # Build the counter increment vector on the stack, and allocate the scratch
    # space
    xmm_v0 = XMMRegister()
    PXOR(xmm_v0, xmm_v0)
    SUB(registers.rsp, 16+16)
    MOVDQA([registers.rsp], xmm_v0)
    reg_tmp = GeneralPurposeRegister32()
    MOV(reg_tmp, 0x00000001)
    MOV([registers.rsp], reg_tmp)
    mem_one = [registers.rsp]     # (Stack) Counter increment vector
    mem_tmp0 = [registers.rsp+16] # (Stack) Scratch space.

    mem_s0 = [reg_x]           # (Memory) Cipher state [0..3]
    mem_s1 = [reg_x+16]        # (Memory) Cipher state [4..7]
    mem_s2 = [reg_x+32]        # (Memory) Cipher state [8..11]
    mem_s3 = [reg_x+48]        # (Memory) Cipher state [12..15]

    # xmm_v0 allocated above...
    xmm_v1 = XMMRegister()
    xmm_v2 = XMMRegister()
    xmm_v3 = XMMRegister()

    xmm_v4 = XMMRegister()
    xmm_v5 = XMMRegister()
    xmm_v6 = XMMRegister()
    xmm_v7 = XMMRegister()

    xmm_v8 = XMMRegister()
    xmm_v9 = XMMRegister()
    xmm_v10 = XMMRegister()
    xmm_v11 = XMMRegister()

    xmm_v12 = XMMRegister()
    xmm_v13 = XMMRegister()
    xmm_v14 = XMMRegister()
    xmm_v15 = XMMRegister()

    xmm_tmp = xmm_v12

    #
    # 4 blocks at a time.
    #

    reg_rounds = GeneralPurposeRegister64()

    vector_loop4 = Loop()
    SUB(reg_blocks, 4)
    JB(vector_loop4.end)
    with vector_loop4:
        MOVDQU(xmm_v0, mem_s0)
        MOVDQU(xmm_v1, mem_s1)
        MOVDQU(xmm_v2, mem_s2)
        MOVDQU(xmm_v3, mem_s3)

        MOVDQA(xmm_v4, xmm_v0)
        MOVDQA(xmm_v5, xmm_v1)
        MOVDQA(xmm_v6, xmm_v2)
        MOVDQA(xmm_v7, xmm_v3)
        PADDQ(xmm_v7, mem_one)

        MOVDQA(xmm_v8, xmm_v0)
        MOVDQA(xmm_v9, xmm_v1)
        MOVDQA(xmm_v10, xmm_v2)
        MOVDQA(xmm_v11, xmm_v7)
        PADDQ(xmm_v11, mem_one)

        MOVDQA(xmm_v12, xmm_v0)
        MOVDQA(xmm_v13, xmm_v1)
        MOVDQA(xmm_v14, xmm_v2)
        MOVDQA(xmm_v15, xmm_v11)
        PADDQ(xmm_v15, mem_one)

        MOV(reg_rounds, 20)
        rounds_loop4 = Loop()
        with rounds_loop4:
            # a += b; d ^= a; d = ROTW16(d);
            PADDD(xmm_v0, xmm_v1)
            PADDD(xmm_v4, xmm_v5)
            PADDD(xmm_v8, xmm_v9)
            PADDD(xmm_v12, xmm_v13)
            PXOR(xmm_v3, xmm_v0)
            PXOR(xmm_v7, xmm_v4)
            PXOR(xmm_v11, xmm_v8)
            PXOR(xmm_v15, xmm_v12)

            MOVDQA(mem_tmp0, xmm_tmp) # Save

            ROTW16_sse2(xmm_tmp, xmm_v3)
            ROTW16_sse2(xmm_tmp, xmm_v7)
            ROTW16_sse2(xmm_tmp, xmm_v11)
            ROTW16_sse2(xmm_tmp, xmm_v15)

            # c += d; b ^= c; b = ROTW12(b);
            PADDD(xmm_v2, xmm_v3)
            PADDD(xmm_v6, xmm_v7)
            PADDD(xmm_v10, xmm_v11)
            PADDD(xmm_v14, xmm_v15)
            PXOR(xmm_v1, xmm_v2)
            PXOR(xmm_v5, xmm_v6)
            PXOR(xmm_v9, xmm_v10)
            PXOR(xmm_v13, xmm_v14)
            ROTW12_sse2(xmm_tmp, xmm_v1)
            ROTW12_sse2(xmm_tmp, xmm_v5)
            ROTW12_sse2(xmm_tmp, xmm_v9)
            ROTW12_sse2(xmm_tmp, xmm_v13)

            # a += b; d ^= a; d = ROTW8(d);
            MOVDQA(xmm_tmp, mem_tmp0) # Restore

            PADDD(xmm_v0, xmm_v1)
            PADDD(xmm_v4, xmm_v5)
            PADDD(xmm_v8, xmm_v9)
            PADDD(xmm_v12, xmm_v13)
            PXOR(xmm_v3, xmm_v0)
            PXOR(xmm_v7, xmm_v4)
            PXOR(xmm_v11, xmm_v8)
            PXOR(xmm_v15, xmm_v12)

            MOVDQA(mem_tmp0, xmm_tmp) # Save

            ROTW8_sse2(xmm_tmp, xmm_v3)
            ROTW8_sse2(xmm_tmp, xmm_v7)
            ROTW8_sse2(xmm_tmp, xmm_v11)
            ROTW8_sse2(xmm_tmp, xmm_v15)

            # c += d; b ^= c; b = ROTW7(b)
            PADDD(xmm_v2, xmm_v3)
            PADDD(xmm_v6, xmm_v7)
            PADDD(xmm_v10, xmm_v11)
            PADDD(xmm_v14, xmm_v15)
            PXOR(xmm_v1, xmm_v2)
            PXOR(xmm_v5, xmm_v6)
            PXOR(xmm_v9, xmm_v10)
            PXOR(xmm_v13, xmm_v14)
            ROTW7_sse2(xmm_tmp, xmm_v1)
            ROTW7_sse2(xmm_tmp, xmm_v5)
            ROTW7_sse2(xmm_tmp, xmm_v9)
            ROTW7_sse2(xmm_tmp, xmm_v13)

            # b = ROTV1(b); c = ROTV2(c);  d = ROTV3(d);
            PSHUFD(xmm_v1, xmm_v1, 0x39)
            PSHUFD(xmm_v5, xmm_v5, 0x39)
            PSHUFD(xmm_v9, xmm_v9, 0x39)
            PSHUFD(xmm_v13, xmm_v13, 0x39)
            PSHUFD(xmm_v2, xmm_v2, 0x4e)
            PSHUFD(xmm_v6, xmm_v6, 0x4e)
            PSHUFD(xmm_v10, xmm_v10, 0x4e)
            PSHUFD(xmm_v14, xmm_v14, 0x4e)
            PSHUFD(xmm_v3, xmm_v3, 0x93)
            PSHUFD(xmm_v7, xmm_v7, 0x93)
            PSHUFD(xmm_v11, xmm_v11, 0x93)
            PSHUFD(xmm_v15, xmm_v15, 0x93)

            MOVDQA(xmm_tmp, mem_tmp0) # Restore

            # a += b; d ^= a; d = ROTW16(d);
            PADDD(xmm_v0, xmm_v1)
            PADDD(xmm_v4, xmm_v5)
            PADDD(xmm_v8, xmm_v9)
            PADDD(xmm_v12, xmm_v13)
            PXOR(xmm_v3, xmm_v0)
            PXOR(xmm_v7, xmm_v4)
            PXOR(xmm_v11, xmm_v8)
            PXOR(xmm_v15, xmm_v12)

            MOVDQA(mem_tmp0, xmm_tmp) # Save

            ROTW16_sse2(xmm_tmp, xmm_v3)
            ROTW16_sse2(xmm_tmp, xmm_v7)
            ROTW16_sse2(xmm_tmp, xmm_v11)
            ROTW16_sse2(xmm_tmp, xmm_v15)

            # c += d; b ^= c; b = ROTW12(b);
            PADDD(xmm_v2, xmm_v3)
            PADDD(xmm_v6, xmm_v7)
            PADDD(xmm_v10, xmm_v11)
            PADDD(xmm_v14, xmm_v15)
            PXOR(xmm_v1, xmm_v2)
            PXOR(xmm_v5, xmm_v6)
            PXOR(xmm_v9, xmm_v10)
            PXOR(xmm_v13, xmm_v14)
            ROTW12_sse2(xmm_tmp, xmm_v1)
            ROTW12_sse2(xmm_tmp, xmm_v5)
            ROTW12_sse2(xmm_tmp, xmm_v9)
            ROTW12_sse2(xmm_tmp, xmm_v13)

            # a += b; d ^= a; d = ROTW8(d);
            MOVDQA(xmm_tmp, mem_tmp0) # Restore

            PADDD(xmm_v0, xmm_v1)
            PADDD(xmm_v4, xmm_v5)
            PADDD(xmm_v8, xmm_v9)
            PADDD(xmm_v12, xmm_v13)
            PXOR(xmm_v3, xmm_v0)
            PXOR(xmm_v7, xmm_v4)
            PXOR(xmm_v11, xmm_v8)
            PXOR(xmm_v15, xmm_v12)

            MOVDQA(mem_tmp0, xmm_tmp) # Save

            ROTW8_sse2(xmm_tmp, xmm_v3)
            ROTW8_sse2(xmm_tmp, xmm_v7)
            ROTW8_sse2(xmm_tmp, xmm_v11)
            ROTW8_sse2(xmm_tmp, xmm_v15)

            # c += d; b ^= c; b = ROTW7(b)
            PADDD(xmm_v2, xmm_v3)
            PADDD(xmm_v6, xmm_v7)
            PADDD(xmm_v10, xmm_v11)
            PADDD(xmm_v14, xmm_v15)
            PXOR(xmm_v1, xmm_v2)
            PXOR(xmm_v5, xmm_v6)
            PXOR(xmm_v9, xmm_v10)
            PXOR(xmm_v13, xmm_v14)
            ROTW7_sse2(xmm_tmp, xmm_v1)
            ROTW7_sse2(xmm_tmp, xmm_v5)
            ROTW7_sse2(xmm_tmp, xmm_v9)
            ROTW7_sse2(xmm_tmp, xmm_v13)

            # b = ROTV1(b); c = ROTV2(c);  d = ROTV3(d);
            PSHUFD(xmm_v1, xmm_v1, 0x93)
            PSHUFD(xmm_v5, xmm_v5, 0x93)
            PSHUFD(xmm_v9, xmm_v9, 0x93)
            PSHUFD(xmm_v13, xmm_v13, 0x93)
            PSHUFD(xmm_v2, xmm_v2, 0x4e)
            PSHUFD(xmm_v6, xmm_v6, 0x4e)
            PSHUFD(xmm_v10, xmm_v10, 0x4e)
            PSHUFD(xmm_v14, xmm_v14, 0x4e)
            PSHUFD(xmm_v3, xmm_v3, 0x39)
            PSHUFD(xmm_v7, xmm_v7, 0x39)
            PSHUFD(xmm_v11, xmm_v11, 0x39)
            PSHUFD(xmm_v15, xmm_v15, 0x39)

            MOVDQA(xmm_tmp, mem_tmp0) # Restore

            SUB(reg_rounds, 2)
            JNZ(rounds_loop4.begin)

        MOVDQA(mem_tmp0, xmm_tmp)

        PADDD(xmm_v0, mem_s0)
        PADDD(xmm_v1, mem_s1)
        PADDD(xmm_v2, mem_s2)
        PADDD(xmm_v3, mem_s3)
        WriteXor_sse2(xmm_tmp, reg_inp, reg_outp, 0, xmm_v0, xmm_v1, xmm_v2, xmm_v3)
        MOVDQU(xmm_v3, mem_s3)
        PADDQ(xmm_v3, mem_one)

        PADDD(xmm_v4, mem_s0)
        PADDD(xmm_v5, mem_s1)
        PADDD(xmm_v6, mem_s2)
        PADDD(xmm_v7, xmm_v3)
        WriteXor_sse2(xmm_tmp, reg_inp, reg_outp, 64, xmm_v4, xmm_v5, xmm_v6, xmm_v7)
        PADDQ(xmm_v3, mem_one)

        PADDD(xmm_v8, mem_s0)
        PADDD(xmm_v9, mem_s1)
        PADDD(xmm_v10, mem_s2)
        PADDD(xmm_v11, xmm_v3)
        WriteXor_sse2(xmm_tmp, reg_inp, reg_outp, 128, xmm_v8, xmm_v9, xmm_v10, xmm_v11)
        PADDQ(xmm_v3, mem_one)

        MOVDQA(xmm_tmp, mem_tmp0)

        PADDD(xmm_v12, mem_s0)
        PADDD(xmm_v13, mem_s1)
        PADDD(xmm_v14, mem_s2)
        PADDD(xmm_v15, xmm_v3)
        WriteXor_sse2(xmm_v0, reg_inp, reg_outp, 192, xmm_v12, xmm_v13, xmm_v14, xmm_v15)
        PADDQ(xmm_v3, mem_one)

        MOVDQU(mem_s3, xmm_v3)

        ADD(reg_inp, 4 * 64)
        ADD(reg_outp, 4 * 64)

        SUB(reg_blocks, 4)
        JAE(vector_loop4.begin)

    ADD(reg_blocks, 4)
    out = Label()
    JZ(out)

    # Past this point, we no longer need to use every single register to hold
    # the in progress state.

    xmm_s0 = xmm_v8
    xmm_s1 = xmm_v9
    xmm_s2 = xmm_v10
    xmm_s3 = xmm_v11
    xmm_one = xmm_v13
    MOVDQU(xmm_s0, mem_s0)
    MOVDQU(xmm_s1, mem_s1)
    MOVDQU(xmm_s2, mem_s2)
    MOVDQU(xmm_s3, mem_s3)
    MOVDQA(xmm_one, mem_one)

    #
    # 2 blocks at a time.
    #

    process_1_block = Label()
    SUB(reg_blocks, 2)
    JB(process_1_block) # < 2 blocks remaining.

    MOVDQA(xmm_v0, xmm_s0)
    MOVDQA(xmm_v1, xmm_s1)
    MOVDQA(xmm_v2, xmm_s2)
    MOVDQA(xmm_v3, xmm_s3)

    MOVDQA(xmm_v4, xmm_v0)
    MOVDQA(xmm_v5, xmm_v1)
    MOVDQA(xmm_v6, xmm_v2)
    MOVDQA(xmm_v7, xmm_v3)
    PADDQ(xmm_v7, xmm_one)

    MOV(reg_rounds, 20)
    rounds_loop2 = Loop()
    with rounds_loop2:
        # a += b; d ^= a; d = ROTW16(d);
        PADDD(xmm_v0, xmm_v1)
        PADDD(xmm_v4, xmm_v5)
        PXOR(xmm_v3, xmm_v0)
        PXOR(xmm_v7, xmm_v4)
        ROTW16_sse2(xmm_tmp, xmm_v3)
        ROTW16_sse2(xmm_tmp, xmm_v7)

        # c += d; b ^= c; b = ROTW12(b);
        PADDD(xmm_v2, xmm_v3)
        PADDD(xmm_v6, xmm_v7)
        PXOR(xmm_v1, xmm_v2)
        PXOR(xmm_v5, xmm_v6)
        ROTW12_sse2(xmm_tmp, xmm_v1)
        ROTW12_sse2(xmm_tmp, xmm_v5)

        # a += b; d ^= a; d = ROTW8(d);
        PADDD(xmm_v0, xmm_v1)
        PADDD(xmm_v4, xmm_v5)
        PXOR(xmm_v3, xmm_v0)
        PXOR(xmm_v7, xmm_v4)
        ROTW8_sse2(xmm_tmp, xmm_v3)
        ROTW8_sse2(xmm_tmp, xmm_v7)

        # c += d; b ^= c; b = ROTW7(b)
        PADDD(xmm_v2, xmm_v3)
        PADDD(xmm_v6, xmm_v7)
        PXOR(xmm_v1, xmm_v2)
        PXOR(xmm_v5, xmm_v6)
        ROTW7_sse2(xmm_tmp, xmm_v1)
        ROTW7_sse2(xmm_tmp, xmm_v5)

        # b = ROTV1(b); c = ROTV2(c);  d = ROTV3(d);
        PSHUFD(xmm_v1, xmm_v1, 0x39)
        PSHUFD(xmm_v5, xmm_v5, 0x39)
        PSHUFD(xmm_v2, xmm_v2, 0x4e)
        PSHUFD(xmm_v6, xmm_v6, 0x4e)
        PSHUFD(xmm_v3, xmm_v3, 0x93)
        PSHUFD(xmm_v7, xmm_v7, 0x93)

        # a += b; d ^= a; d = ROTW16(d);
        PADDD(xmm_v0, xmm_v1)
        PADDD(xmm_v4, xmm_v5)
        PXOR(xmm_v3, xmm_v0)
        PXOR(xmm_v7, xmm_v4)
        ROTW16_sse2(xmm_tmp, xmm_v3)
        ROTW16_sse2(xmm_tmp, xmm_v7)

        # c += d; b ^= c; b = ROTW12(b);
        PADDD(xmm_v2, xmm_v3)
        PADDD(xmm_v6, xmm_v7)
        PXOR(xmm_v1, xmm_v2)
        PXOR(xmm_v5, xmm_v6)
        ROTW12_sse2(xmm_tmp, xmm_v1)
        ROTW12_sse2(xmm_tmp, xmm_v5)

        # a += b; d ^= a; d = ROTW8(d);
        PADDD(xmm_v0, xmm_v1)
        PADDD(xmm_v4, xmm_v5)
        PXOR(xmm_v3, xmm_v0)
        PXOR(xmm_v7, xmm_v4)
        ROTW8_sse2(xmm_tmp, xmm_v3)
        ROTW8_sse2(xmm_tmp, xmm_v7)

        # c += d; b ^= c; b = ROTW7(b)
        PADDD(xmm_v2, xmm_v3)
        PADDD(xmm_v6, xmm_v7)
        PXOR(xmm_v1, xmm_v2)
        PXOR(xmm_v5, xmm_v6)
        ROTW7_sse2(xmm_tmp, xmm_v1)
        ROTW7_sse2(xmm_tmp, xmm_v5)

        # b = ROTV1(b); c = ROTV2(c);  d = ROTV3(d);
        PSHUFD(xmm_v1, xmm_v1, 0x93)
        PSHUFD(xmm_v5, xmm_v5, 0x93)
        PSHUFD(xmm_v2, xmm_v2, 0x4e)
        PSHUFD(xmm_v6, xmm_v6, 0x4e)
        PSHUFD(xmm_v3, xmm_v3, 0x39)
        PSHUFD(xmm_v7, xmm_v7, 0x39)

        SUB(reg_rounds, 2)
        JNZ(rounds_loop2.begin)

    PADDD(xmm_v0, xmm_s0)
    PADDD(xmm_v1, xmm_s1)
    PADDD(xmm_v2, xmm_s2)
    PADDD(xmm_v3, xmm_s3)
    WriteXor_sse2(xmm_tmp, reg_inp, reg_outp, 0, xmm_v0, xmm_v1, xmm_v2, xmm_v3)
    PADDQ(xmm_s3, xmm_one)

    PADDD(xmm_v4, xmm_s0)
    PADDD(xmm_v5, xmm_s1)
    PADDD(xmm_v6, xmm_s2)
    PADDD(xmm_v7, xmm_s3)
    WriteXor_sse2(xmm_tmp, reg_inp, reg_outp, 64, xmm_v4, xmm_v5, xmm_v6, xmm_v7)
    PADDQ(xmm_s3, xmm_one)

    ADD(reg_inp, 2 * 64)
    ADD(reg_outp, 2 * 64)
    SUB(reg_blocks, 2)

    LABEL(process_1_block)
    ADD(reg_blocks, 2)
    out_serial = Label()
    JZ(out_serial)

    #
    # 1 block at a time.  Only executed once, because if there was > 1,
    # the parallel code would have processed it already.
    #

    MOVDQA(xmm_v0, xmm_s0)
    MOVDQA(xmm_v1, xmm_s1)
    MOVDQA(xmm_v2, xmm_s2)
    MOVDQA(xmm_v3, xmm_s3)

    MOV(reg_rounds, 20)
    rounds_loop1 = Loop()
    with rounds_loop1:
        # a += b; d ^= a; d = ROTW16(d);
        PADDD(xmm_v0, xmm_v1)
        PXOR(xmm_v3, xmm_v0)
        ROTW16_sse2(xmm_tmp, xmm_v3)

        # c += d; b ^= c; b = ROTW12(b);
        PADDD(xmm_v2, xmm_v3)
        PXOR(xmm_v1, xmm_v2)
        ROTW12_sse2(xmm_tmp, xmm_v1)

        # a += b; d ^= a; d = ROTW8(d);
        PADDD(xmm_v0, xmm_v1)
        PXOR(xmm_v3, xmm_v0)
        ROTW8_sse2(xmm_tmp, xmm_v3)

        # c += d; b ^= c; b = ROTW7(b)
        PADDD(xmm_v2, xmm_v3)
        PXOR(xmm_v1, xmm_v2)
        ROTW7_sse2(xmm_tmp, xmm_v1)

        # b = ROTV1(b); c = ROTV2(c);  d = ROTV3(d);
        PSHUFD(xmm_v1, xmm_v1, 0x39)
        PSHUFD(xmm_v2, xmm_v2, 0x4e)
        PSHUFD(xmm_v3, xmm_v3, 0x93)

        # a += b; d ^= a; d = ROTW16(d);
        PADDD(xmm_v0, xmm_v1)
        PXOR(xmm_v3, xmm_v0)
        ROTW16_sse2(xmm_tmp, xmm_v3)

        # c += d; b ^= c; b = ROTW12(b);
        PADDD(xmm_v2, xmm_v3)
        PXOR(xmm_v1, xmm_v2)
        ROTW12_sse2(xmm_tmp, xmm_v1)

        # a += b; d ^= a; d = ROTW8(d);
        PADDD(xmm_v0, xmm_v1)
        PXOR(xmm_v3, xmm_v0)
        ROTW8_sse2(xmm_tmp, xmm_v3)

        # c += d; b ^= c; b = ROTW7(b)
        PADDD(xmm_v2, xmm_v3)
        PXOR(xmm_v1, xmm_v2)
        ROTW7_sse2(xmm_tmp, xmm_v1)

        # b = ROTV1(b); c = ROTV2(c);  d = ROTV3(d);
        PSHUFD(xmm_v1, xmm_v1, 0x93)
        PSHUFD(xmm_v2, xmm_v2, 0x4e)
        PSHUFD(xmm_v3, xmm_v3, 0x39)

        SUB(reg_rounds, 2)
        JNZ(rounds_loop1.begin)

    PADDD(xmm_v0, xmm_s0)
    PADDD(xmm_v1, xmm_s1)
    PADDD(xmm_v2, xmm_s2)
    PADDD(xmm_v3, xmm_s3)
    WriteXor_sse2(xmm_tmp, reg_inp, reg_outp, 0, xmm_v0, xmm_v1, xmm_v2, xmm_v3)
    PADDQ(xmm_s3, xmm_one)

    LABEL(out_serial)

    # Write back the updated counter.  Stoping at 2^70 bytes is the user's
    # problem, not mine.  (Skipped if there's exactly a multiple of 4 blocks
    # because the counter is incremented in memory while looping.)
    MOVDQU(mem_s3, xmm_s3)

    LABEL(out)

    # Paranoia, cleanse the scratch space.
    PXOR(xmm_v0, xmm_v0)
    MOVDQA(mem_tmp0, xmm_v0)

    # Remove our stack allocation.
    MOV(registers.rsp, reg_sp_save)

    RETURN()

#
# AVX2 helpers.  Like the SSE2 equivalents, the scratch register is explicit,
# and more helpers are used to increase readability for destructive operations.
#
# XXX/Performance: ROTW16_avx2/ROTW8_avx2 both can use VPSHUFFB.
#

def ADD_avx2(dst, src):
    VPADDD(dst, dst, src)

def XOR_avx2(dst, src):
    VPXOR(dst, dst, src)

def ROTW16_avx2(tmp, d):
    VPSLLD(tmp, d, 16)
    VPSRLD(d, d, 16)
    XOR_avx2(d, tmp)

def ROTW12_avx2(tmp, b):
    VPSLLD(tmp, b, 12)
    VPSRLD(b, b, 20)
    XOR_avx2(b, tmp)

def ROTW8_avx2(tmp, d):
    VPSLLD(tmp, d, 8)
    VPSRLD(d, d, 24)
    XOR_avx2(d, tmp)

def ROTW7_avx2(tmp, b):
    VPSLLD(tmp, b, 7)
    VPSRLD(b, b, 25)
    XOR_avx2(b, tmp)

def WriteXor_avx2(tmp, inp, outp, d, v0, v1, v2, v3):
    # XOR_WRITE(out+ 0, in+ 0, _mm256_permute2x128_si256(v0,v1,0x20));
    VPERM2I128(tmp, v0, v1, 0x20)
    VPXOR(tmp, tmp, [inp+d])
    VMOVDQU([outp+d], tmp)

    # XOR_WRITE(out+32, in+32, _mm256_permute2x128_si256(v2,v3,0x20));
    VPERM2I128(tmp, v2, v3, 0x20)
    VPXOR(tmp, tmp, [inp+d+32])
    VMOVDQU([outp+d+32], tmp)

    # XOR_WRITE(out+64, in+64, _mm256_permute2x128_si256(v0,v1,0x31));
    VPERM2I128(tmp, v0, v1, 0x31)
    VPXOR(tmp, tmp, [inp+d+64])
    VMOVDQU([outp+d+64], tmp)

    # XOR_WRITE(out+96, in+96, _mm256_permute2x128_si256(v2,v3,0x31));
    VPERM2I128(tmp, v2, v3, 0x31)
    VPXOR(tmp, tmp, [inp+d+96])
    VMOVDQU([outp+d+96], tmp)

# AVX2 ChaCha20 (aka avx2).  Does not handle partial blocks, will process
# 8/4/2 blocks at a time.
with Function("blocksAmd64AVX2", (x, inp, outp, nrBlocks), target=uarch.broadwell):
    reg_x = GeneralPurposeRegister64()
    reg_inp = GeneralPurposeRegister64()
    reg_outp = GeneralPurposeRegister64()
    reg_blocks = GeneralPurposeRegister64()
    reg_sp_save = GeneralPurposeRegister64()

    LOAD.ARGUMENT(reg_x, x)
    LOAD.ARGUMENT(reg_inp, inp)
    LOAD.ARGUMENT(reg_outp, outp)
    LOAD.ARGUMENT(reg_blocks, nrBlocks)

    # Align the stack to a 32 byte boundary.
    MOV(reg_sp_save, registers.rsp)
    AND(registers.rsp, 0xffffffffffffffe0)
    SUB(registers.rsp, 0x20)

    x_s0 = [reg_x]           # (Memory) Cipher state [0..3]
    x_s1 = [reg_x+16]        # (Memory) Cipher state [4..7]
    x_s2 = [reg_x+32]        # (Memory) Cipher state [8..11]
    x_s3 = [reg_x+48]        # (Memory) Cipher state [12..15]

    ymm_v0 = YMMRegister()
    ymm_v1 = YMMRegister()
    ymm_v2 = YMMRegister()
    ymm_v3 = YMMRegister()

    ymm_v4 = YMMRegister()
    ymm_v5 = YMMRegister()
    ymm_v6 = YMMRegister()
    ymm_v7 = YMMRegister()

    ymm_v8 = YMMRegister()
    ymm_v9 = YMMRegister()
    ymm_v10 = YMMRegister()
    ymm_v11 = YMMRegister()

    ymm_v12 = YMMRegister()
    ymm_v13 = YMMRegister()
    ymm_v14 = YMMRegister()
    ymm_v15 = YMMRegister()

    ymm_tmp0 = ymm_v12

    # Allocate the neccecary stack space for the counter vector and two ymm
    # registers that we will spill.
    SUB(registers.rsp, 96)
    mem_tmp0 = [registers.rsp+64]  # (Stack) Scratch space.
    mem_s3 = [registers.rsp+32]    # (Stack) Working copy of s3. (8x)
    mem_inc = [registers.rsp]      # (Stack) Counter increment vector.

    # Increment the counter for one side of the state vector.
    VPXOR(ymm_tmp0, ymm_tmp0, ymm_tmp0)
    VMOVDQU(mem_inc, ymm_tmp0)
    reg_tmp = GeneralPurposeRegister32()
    MOV(reg_tmp, 0x00000001)
    MOV([registers.rsp+16], reg_tmp)
    VBROADCASTI128(ymm_v3, x_s3)
    VPADDQ(ymm_v3, ymm_v3, [registers.rsp])
    VMOVDQA(mem_s3, ymm_v3)

    # As we process 2xN blocks at a time, so the counter increment for both
    # sides of the state vector is 2.
    MOV(reg_tmp, 0x00000002)
    MOV([registers.rsp], reg_tmp)
    MOV([registers.rsp+16], reg_tmp)

    out_write_even = Label()
    out_write_odd = Label()

    #
    # 8 blocks at a time.  Ted Krovetz's avx2 code does not do this, but it's
    # a decent gain despite all the pain...
    #

    reg_rounds = GeneralPurposeRegister64()

    vector_loop8 = Loop()
    SUB(reg_blocks, 8)
    JB(vector_loop8.end)
    with vector_loop8:
        VBROADCASTI128(ymm_v0, x_s0)
        VBROADCASTI128(ymm_v1, x_s1)
        VBROADCASTI128(ymm_v2, x_s2)
        VMOVDQA(ymm_v3, mem_s3)

        VMOVDQA(ymm_v4, ymm_v0)
        VMOVDQA(ymm_v5, ymm_v1)
        VMOVDQA(ymm_v6, ymm_v2)
        VPADDQ(ymm_v7, ymm_v3, mem_inc)

        VMOVDQA(ymm_v8, ymm_v0)
        VMOVDQA(ymm_v9, ymm_v1)
        VMOVDQA(ymm_v10, ymm_v2)
        VPADDQ(ymm_v11, ymm_v7, mem_inc)

        VMOVDQA(ymm_v12, ymm_v0)
        VMOVDQA(ymm_v13, ymm_v1)
        VMOVDQA(ymm_v14, ymm_v2)
        VPADDQ(ymm_v15, ymm_v11, mem_inc)

        MOV(reg_rounds, 20)
        rounds_loop8 = Loop()
        with rounds_loop8:
            # a += b; d ^= a; d = ROTW16(d);
            ADD_avx2(ymm_v0, ymm_v1)
            ADD_avx2(ymm_v4, ymm_v5)
            ADD_avx2(ymm_v8, ymm_v9)
            ADD_avx2(ymm_v12, ymm_v13)
            XOR_avx2(ymm_v3, ymm_v0)
            XOR_avx2(ymm_v7, ymm_v4)
            XOR_avx2(ymm_v11, ymm_v8)
            XOR_avx2(ymm_v15, ymm_v12)

            VMOVDQA(mem_tmp0, ymm_tmp0) # Save

            ROTW16_avx2(ymm_tmp0, ymm_v3)
            ROTW16_avx2(ymm_tmp0, ymm_v7)
            ROTW16_avx2(ymm_tmp0, ymm_v11)
            ROTW16_avx2(ymm_tmp0, ymm_v15)

            # c += d; b ^= c; b = ROTW12(b);
            ADD_avx2(ymm_v2, ymm_v3)
            ADD_avx2(ymm_v6, ymm_v7)
            ADD_avx2(ymm_v10, ymm_v11)
            ADD_avx2(ymm_v14, ymm_v15)
            XOR_avx2(ymm_v1, ymm_v2)
            XOR_avx2(ymm_v5, ymm_v6)
            XOR_avx2(ymm_v9, ymm_v10)
            XOR_avx2(ymm_v13, ymm_v14)
            ROTW12_avx2(ymm_tmp0, ymm_v1)
            ROTW12_avx2(ymm_tmp0, ymm_v5)
            ROTW12_avx2(ymm_tmp0, ymm_v9)
            ROTW12_avx2(ymm_tmp0, ymm_v13)

            # a += b; d ^= a; d = ROTW8(d);
            VMOVDQA(ymm_tmp0, mem_tmp0) # Restore

            ADD_avx2(ymm_v0, ymm_v1)
            ADD_avx2(ymm_v4, ymm_v5)
            ADD_avx2(ymm_v8, ymm_v9)
            ADD_avx2(ymm_v12, ymm_v13)
            XOR_avx2(ymm_v3, ymm_v0)
            XOR_avx2(ymm_v7, ymm_v4)
            XOR_avx2(ymm_v11, ymm_v8)
            XOR_avx2(ymm_v15, ymm_v12)

            VMOVDQA(mem_tmp0, ymm_tmp0) # Save

            ROTW8_avx2(ymm_tmp0, ymm_v3)
            ROTW8_avx2(ymm_tmp0, ymm_v7)
            ROTW8_avx2(ymm_tmp0, ymm_v11)
            ROTW8_avx2(ymm_tmp0, ymm_v15)

            # c += d; b ^= c; b = ROTW7(b)
            ADD_avx2(ymm_v2, ymm_v3)
            ADD_avx2(ymm_v6, ymm_v7)
            ADD_avx2(ymm_v10, ymm_v11)
            ADD_avx2(ymm_v14, ymm_v15)
            XOR_avx2(ymm_v1, ymm_v2)
            XOR_avx2(ymm_v5, ymm_v6)
            XOR_avx2(ymm_v9, ymm_v10)
            XOR_avx2(ymm_v13, ymm_v14)
            ROTW7_avx2(ymm_tmp0, ymm_v1)
            ROTW7_avx2(ymm_tmp0, ymm_v5)
            ROTW7_avx2(ymm_tmp0, ymm_v9)
            ROTW7_avx2(ymm_tmp0, ymm_v13)

            # b = ROTV1(b); c = ROTV2(c);  d = ROTV3(d);
            VPSHUFD(ymm_v1, ymm_v1, 0x39)
            VPSHUFD(ymm_v5, ymm_v5, 0x39)
            VPSHUFD(ymm_v9, ymm_v9, 0x39)
            VPSHUFD(ymm_v13, ymm_v13, 0x39)
            VPSHUFD(ymm_v2, ymm_v2, 0x4e)
            VPSHUFD(ymm_v6, ymm_v6, 0x4e)
            VPSHUFD(ymm_v10, ymm_v10, 0x4e)
            VPSHUFD(ymm_v14, ymm_v14, 0x4e)
            VPSHUFD(ymm_v3, ymm_v3, 0x93)
            VPSHUFD(ymm_v7, ymm_v7, 0x93)
            VPSHUFD(ymm_v11, ymm_v11, 0x93)
            VPSHUFD(ymm_v15, ymm_v15, 0x93)

            # a += b; d ^= a; d = ROTW16(d);
            VMOVDQA(ymm_tmp0, mem_tmp0) # Restore

            ADD_avx2(ymm_v0, ymm_v1)
            ADD_avx2(ymm_v4, ymm_v5)
            ADD_avx2(ymm_v8, ymm_v9)
            ADD_avx2(ymm_v12, ymm_v13)
            XOR_avx2(ymm_v3, ymm_v0)
            XOR_avx2(ymm_v7, ymm_v4)
            XOR_avx2(ymm_v11, ymm_v8)
            XOR_avx2(ymm_v15, ymm_v12)

            VMOVDQA(mem_tmp0, ymm_tmp0) # Save

            ROTW16_avx2(ymm_tmp0, ymm_v3)
            ROTW16_avx2(ymm_tmp0, ymm_v7)
            ROTW16_avx2(ymm_tmp0, ymm_v11)
            ROTW16_avx2(ymm_tmp0, ymm_v15)

            # c += d; b ^= c; b = ROTW12(b);
            ADD_avx2(ymm_v2, ymm_v3)
            ADD_avx2(ymm_v6, ymm_v7)
            ADD_avx2(ymm_v10, ymm_v11)
            ADD_avx2(ymm_v14, ymm_v15)
            XOR_avx2(ymm_v1, ymm_v2)
            XOR_avx2(ymm_v5, ymm_v6)
            XOR_avx2(ymm_v9, ymm_v10)
            XOR_avx2(ymm_v13, ymm_v14)
            ROTW12_avx2(ymm_tmp0, ymm_v1)
            ROTW12_avx2(ymm_tmp0, ymm_v5)
            ROTW12_avx2(ymm_tmp0, ymm_v9)
            ROTW12_avx2(ymm_tmp0, ymm_v13)

            # a += b; d ^= a; d = ROTW8(d);
            VMOVDQA(ymm_tmp0, mem_tmp0) # Restore

            ADD_avx2(ymm_v0, ymm_v1)
            ADD_avx2(ymm_v4, ymm_v5)
            ADD_avx2(ymm_v8, ymm_v9)
            ADD_avx2(ymm_v12, ymm_v13)
            XOR_avx2(ymm_v3, ymm_v0)
            XOR_avx2(ymm_v7, ymm_v4)
            XOR_avx2(ymm_v11, ymm_v8)
            XOR_avx2(ymm_v15, ymm_v12)

            VMOVDQA(mem_tmp0, ymm_tmp0) # Save

            ROTW8_avx2(ymm_tmp0, ymm_v3)
            ROTW8_avx2(ymm_tmp0, ymm_v7)
            ROTW8_avx2(ymm_tmp0, ymm_v11)
            ROTW8_avx2(ymm_tmp0, ymm_v15)

            # c += d; b ^= c; b = ROTW7(b)
            ADD_avx2(ymm_v2, ymm_v3)
            ADD_avx2(ymm_v6, ymm_v7)
            ADD_avx2(ymm_v10, ymm_v11)
            ADD_avx2(ymm_v14, ymm_v15)
            XOR_avx2(ymm_v1, ymm_v2)
            XOR_avx2(ymm_v5, ymm_v6)
            XOR_avx2(ymm_v9, ymm_v10)
            XOR_avx2(ymm_v13, ymm_v14)
            ROTW7_avx2(ymm_tmp0, ymm_v1)
            ROTW7_avx2(ymm_tmp0, ymm_v5)
            ROTW7_avx2(ymm_tmp0, ymm_v9)
            ROTW7_avx2(ymm_tmp0, ymm_v13)

            # b = ROTV1(b); c = ROTV2(c);  d = ROTV3(d);
            VPSHUFD(ymm_v1, ymm_v1, 0x93)
            VPSHUFD(ymm_v5, ymm_v5, 0x93)
            VPSHUFD(ymm_v9, ymm_v9, 0x93)
            VPSHUFD(ymm_v13, ymm_v13, 0x93)
            VPSHUFD(ymm_v2, ymm_v2, 0x4e)
            VPSHUFD(ymm_v6, ymm_v6, 0x4e)
            VPSHUFD(ymm_v10, ymm_v10, 0x4e)
            VPSHUFD(ymm_v14, ymm_v14, 0x4e)
            VPSHUFD(ymm_v3, ymm_v3, 0x39)
            VPSHUFD(ymm_v7, ymm_v7, 0x39)
            VPSHUFD(ymm_v11, ymm_v11, 0x39)
            VPSHUFD(ymm_v15, ymm_v15, 0x39)

            VMOVDQA(ymm_tmp0, mem_tmp0) # Restore

            SUB(reg_rounds, 2)
            JNZ(rounds_loop8.begin)

        # ymm_v12 is in mem_tmp0 and is current....

        # XXX: I assume VBROADCASTI128 is about as fast as VMOVDQA....
        VBROADCASTI128(ymm_tmp0, x_s0)
        ADD_avx2(ymm_v0, ymm_tmp0)
        ADD_avx2(ymm_v4, ymm_tmp0)
        ADD_avx2(ymm_v8, ymm_tmp0)
        ADD_avx2(ymm_tmp0, mem_tmp0)
        VMOVDQA(mem_tmp0, ymm_tmp0)

        VBROADCASTI128(ymm_tmp0, x_s1)
        ADD_avx2(ymm_v1, ymm_tmp0)
        ADD_avx2(ymm_v5, ymm_tmp0)
        ADD_avx2(ymm_v9, ymm_tmp0)
        ADD_avx2(ymm_v13, ymm_tmp0)

        VBROADCASTI128(ymm_tmp0, x_s2)
        ADD_avx2(ymm_v2, ymm_tmp0)
        ADD_avx2(ymm_v6, ymm_tmp0)
        ADD_avx2(ymm_v10, ymm_tmp0)
        ADD_avx2(ymm_v14, ymm_tmp0)

        ADD_avx2(ymm_v3, mem_s3)
        WriteXor_avx2(ymm_tmp0, reg_inp, reg_outp, 0, ymm_v0, ymm_v1, ymm_v2, ymm_v3)
        VMOVDQA(ymm_v3, mem_s3)
        ADD_avx2(ymm_v3, mem_inc)

        ADD_avx2(ymm_v7, ymm_v3)
        WriteXor_avx2(ymm_tmp0, reg_inp, reg_outp, 128, ymm_v4, ymm_v5, ymm_v6, ymm_v7)
        ADD_avx2(ymm_v3, mem_inc)

        ADD_avx2(ymm_v11, ymm_v3)
        WriteXor_avx2(ymm_tmp0, reg_inp, reg_outp, 256, ymm_v8, ymm_v9, ymm_v10, ymm_v11)
        ADD_avx2(ymm_v3, mem_inc)

        VMOVDQA(ymm_v12, mem_tmp0)
        ADD_avx2(ymm_v15, ymm_v3)
        WriteXor_avx2(ymm_v0, reg_inp, reg_outp, 384, ymm_v12, ymm_v13, ymm_v14, ymm_v15)
        ADD_avx2(ymm_v3, mem_inc)

        VMOVDQA(mem_s3, ymm_v3)

        ADD(reg_inp, 8 * 64)
        ADD(reg_outp, 8 * 64)

        SUB(reg_blocks, 8)
        JAE(vector_loop8.begin)

    # ymm_v3 contains a current copy of mem_s3 either from when it was built,
    # or because the loop updates it.  Copy this before we mess with the block
    # counter in case we need to write it back and return.
    ymm_s3 = ymm_v11
    VMOVDQA(ymm_s3, ymm_v3)

    ADD(reg_blocks, 8)
    JZ(out_write_even)

    # We now actually can do everything in registers.
    ymm_s0 = ymm_v8
    VBROADCASTI128(ymm_s0, x_s0)
    ymm_s1 = ymm_v9
    VBROADCASTI128(ymm_s1, x_s1)
    ymm_s2 = ymm_v10
    VBROADCASTI128(ymm_s2, x_s2)
    ymm_inc = ymm_v14
    VMOVDQA(ymm_inc, mem_inc)

    #
    # 4 blocks at a time.
    #

    process_2_blocks = Label()
    SUB(reg_blocks, 4)
    JB(process_2_blocks) # < 4 blocks remaining.

    VMOVDQA(ymm_v0, ymm_s0)
    VMOVDQA(ymm_v1, ymm_s1)
    VMOVDQA(ymm_v2, ymm_s2)
    VMOVDQA(ymm_v3, ymm_s3)

    VMOVDQA(ymm_v4, ymm_v0)
    VMOVDQA(ymm_v5, ymm_v1)
    VMOVDQA(ymm_v6, ymm_v2)
    VPADDQ(ymm_v7, ymm_v3, ymm_inc)

    MOV(reg_rounds, 20)
    rounds_loop4 = Loop()
    with rounds_loop4:
        # a += b; d ^= a; d = ROTW16(d);
        ADD_avx2(ymm_v0, ymm_v1)
        ADD_avx2(ymm_v4, ymm_v5)
        XOR_avx2(ymm_v3, ymm_v0)
        XOR_avx2(ymm_v7, ymm_v4)
        ROTW16_avx2(ymm_tmp0, ymm_v3)
        ROTW16_avx2(ymm_tmp0, ymm_v7)

        # c += d; b ^= c; b = ROTW12(b);
        ADD_avx2(ymm_v2, ymm_v3)
        ADD_avx2(ymm_v6, ymm_v7)
        XOR_avx2(ymm_v1, ymm_v2)
        XOR_avx2(ymm_v5, ymm_v6)
        ROTW12_avx2(ymm_tmp0, ymm_v1)
        ROTW12_avx2(ymm_tmp0, ymm_v5)

        # a += b; d ^= a; d = ROTW8(d);
        ADD_avx2(ymm_v0, ymm_v1)
        ADD_avx2(ymm_v4, ymm_v5)
        XOR_avx2(ymm_v3, ymm_v0)
        XOR_avx2(ymm_v7, ymm_v4)
        ROTW8_avx2(ymm_tmp0, ymm_v3)
        ROTW8_avx2(ymm_tmp0, ymm_v7)

        # c += d; b ^= c; b = ROTW7(b)
        ADD_avx2(ymm_v2, ymm_v3)
        ADD_avx2(ymm_v6, ymm_v7)
        XOR_avx2(ymm_v1, ymm_v2)
        XOR_avx2(ymm_v5, ymm_v6)
        ROTW7_avx2(ymm_tmp0, ymm_v1)
        ROTW7_avx2(ymm_tmp0, ymm_v5)

        # b = ROTV1(b); c = ROTV2(c);  d = ROTV3(d);
        VPSHUFD(ymm_v1, ymm_v1, 0x39)
        VPSHUFD(ymm_v5, ymm_v5, 0x39)
        VPSHUFD(ymm_v2, ymm_v2, 0x4e)
        VPSHUFD(ymm_v6, ymm_v6, 0x4e)
        VPSHUFD(ymm_v3, ymm_v3, 0x93)
        VPSHUFD(ymm_v7, ymm_v7, 0x93)

        # a += b; d ^= a; d = ROTW16(d);
        ADD_avx2(ymm_v0, ymm_v1)
        ADD_avx2(ymm_v4, ymm_v5)
        XOR_avx2(ymm_v3, ymm_v0)
        XOR_avx2(ymm_v7, ymm_v4)
        ROTW16_avx2(ymm_tmp0, ymm_v3)
        ROTW16_avx2(ymm_tmp0, ymm_v7)

        # c += d; b ^= c; b = ROTW12(b);
        ADD_avx2(ymm_v2, ymm_v3)
        ADD_avx2(ymm_v6, ymm_v7)
        XOR_avx2(ymm_v1, ymm_v2)
        XOR_avx2(ymm_v5, ymm_v6)
        ROTW12_avx2(ymm_tmp0, ymm_v1)
        ROTW12_avx2(ymm_tmp0, ymm_v5)

        # a += b; d ^= a; d = ROTW8(d);
        ADD_avx2(ymm_v0, ymm_v1)
        ADD_avx2(ymm_v4, ymm_v5)
        XOR_avx2(ymm_v3, ymm_v0)
        XOR_avx2(ymm_v7, ymm_v4)
        ROTW8_avx2(ymm_tmp0, ymm_v3)
        ROTW8_avx2(ymm_tmp0, ymm_v7)

        # c += d; b ^= c; b = ROTW7(b)
        ADD_avx2(ymm_v2, ymm_v3)
        ADD_avx2(ymm_v6, ymm_v7)
        XOR_avx2(ymm_v1, ymm_v2)
        XOR_avx2(ymm_v5, ymm_v6)
        ROTW7_avx2(ymm_tmp0, ymm_v1)
        ROTW7_avx2(ymm_tmp0, ymm_v5)

        # b = ROTV1(b); c = ROTV2(c);  d = ROTV3(d);
        VPSHUFD(ymm_v1, ymm_v1, 0x93)
        VPSHUFD(ymm_v5, ymm_v5, 0x93)
        VPSHUFD(ymm_v2, ymm_v2, 0x4e)
        VPSHUFD(ymm_v6, ymm_v6, 0x4e)
        VPSHUFD(ymm_v3, ymm_v3, 0x39)
        VPSHUFD(ymm_v7, ymm_v7, 0x39)

        SUB(reg_rounds, 2)
        JNZ(rounds_loop4.begin)

    ADD_avx2(ymm_v0, ymm_s0)
    ADD_avx2(ymm_v1, ymm_s1)
    ADD_avx2(ymm_v2, ymm_s2)
    ADD_avx2(ymm_v3, ymm_s3)
    WriteXor_avx2(ymm_tmp0, reg_inp, reg_outp, 0, ymm_v0, ymm_v1, ymm_v2, ymm_v3)
    ADD_avx2(ymm_s3, ymm_inc)

    ADD_avx2(ymm_v4, ymm_s0)
    ADD_avx2(ymm_v5, ymm_s1)
    ADD_avx2(ymm_v6, ymm_s2)
    ADD_avx2(ymm_v7, ymm_s3)
    WriteXor_avx2(ymm_tmp0, reg_inp, reg_outp, 128, ymm_v4, ymm_v5, ymm_v6, ymm_v7)
    ADD_avx2(ymm_s3, ymm_inc)

    ADD(reg_inp, 4 * 64)
    ADD(reg_outp, 4 * 64)
    SUB(reg_blocks, 4)

    LABEL(process_2_blocks)
    ADD(reg_blocks, 4)
    JZ(out_write_even) # 0 blocks left.

    #
    # 2/1 blocks at a time.  The two codepaths are unified because
    # with AVX2 we do 2 blocks at a time anyway, and this only gets called
    # if 3/2/1 blocks are remaining, so the extra branches don't hurt that
    # much.
    #

    vector_loop2 = Loop()
    with vector_loop2:
        VMOVDQA(ymm_v0, ymm_s0)
        VMOVDQA(ymm_v1, ymm_s1)
        VMOVDQA(ymm_v2, ymm_s2)
        VMOVDQA(ymm_v3, ymm_s3)

        MOV(reg_rounds, 20)
        rounds_loop2 = Loop()
        with rounds_loop2:
            # a += b; d ^= a; d = ROTW16(d);
            ADD_avx2(ymm_v0, ymm_v1)
            XOR_avx2(ymm_v3, ymm_v0)
            ROTW16_avx2(ymm_tmp0, ymm_v3)

            # c += d; b ^= c; b = ROTW12(b);
            ADD_avx2(ymm_v2, ymm_v3)
            XOR_avx2(ymm_v1, ymm_v2)
            ROTW12_avx2(ymm_tmp0, ymm_v1)

            # a += b; d ^= a; d = ROTW8(d);
            ADD_avx2(ymm_v0, ymm_v1)
            XOR_avx2(ymm_v3, ymm_v0)
            ROTW8_avx2(ymm_tmp0, ymm_v3)

            # c += d; b ^= c; b = ROTW7(b)
            ADD_avx2(ymm_v2, ymm_v3)
            XOR_avx2(ymm_v1, ymm_v2)
            ROTW7_avx2(ymm_tmp0, ymm_v1)

            # b = ROTV1(b); c = ROTV2(c);  d = ROTV3(d);
            VPSHUFD(ymm_v1, ymm_v1, 0x39)
            VPSHUFD(ymm_v2, ymm_v2, 0x4e)
            VPSHUFD(ymm_v3, ymm_v3, 0x93)

            # a += b; d ^= a; d = ROTW16(d);
            ADD_avx2(ymm_v0, ymm_v1)
            XOR_avx2(ymm_v3, ymm_v0)
            ROTW16_avx2(ymm_tmp0, ymm_v3)

            # c += d; b ^= c; b = ROTW12(b);
            ADD_avx2(ymm_v2, ymm_v3)
            XOR_avx2(ymm_v1, ymm_v2)
            ROTW12_avx2(ymm_tmp0, ymm_v1)

            # a += b; d ^= a; d = ROTW8(d);
            ADD_avx2(ymm_v0, ymm_v1)
            XOR_avx2(ymm_v3, ymm_v0)
            ROTW8_avx2(ymm_tmp0, ymm_v3)

            # c += d; b ^= c; b = ROTW7(b)
            ADD_avx2(ymm_v2, ymm_v3)
            XOR_avx2(ymm_v1, ymm_v2)
            ROTW7_avx2(ymm_tmp0, ymm_v1)

            # b = ROTV1(b); c = ROTV2(c);  d = ROTV3(d);
            VPSHUFD(ymm_v1, ymm_v1, 0x93)
            VPSHUFD(ymm_v2, ymm_v2, 0x4e)
            VPSHUFD(ymm_v3, ymm_v3, 0x39)

            SUB(reg_rounds, 2)
            JNZ(rounds_loop2.begin)

        ADD_avx2(ymm_v0, ymm_s0)
        ADD_avx2(ymm_v1, ymm_s1)
        ADD_avx2(ymm_v2, ymm_s2)
        ADD_avx2(ymm_v3, ymm_s3)

        # XOR_WRITE(out+ 0, in+ 0, _mm256_permute2x128_si256(v0,v1,0x20));
        VPERM2I128(ymm_tmp0, ymm_v0, ymm_v1, 0x20)
        VPXOR(ymm_tmp0, ymm_tmp0, [reg_inp])
        VMOVDQU([reg_outp], ymm_tmp0)

        # XOR_WRITE(out+32, in+32, _mm256_permute2x128_si256(v2,v3,0x20));
        VPERM2I128(ymm_tmp0, ymm_v2, ymm_v3, 0x20)
        VPXOR(ymm_tmp0, ymm_tmp0, [reg_inp+32])
        VMOVDQU([reg_outp+32], ymm_tmp0)

        SUB(reg_blocks, 1)
        JZ(out_write_odd)

        ADD_avx2(ymm_s3, ymm_inc)

        # XOR_WRITE(out+64, in+64, _mm256_permute2x128_si256(v0,v1,0x31));
        VPERM2I128(ymm_tmp0, ymm_v0, ymm_v1, 0x31)
        VPXOR(ymm_tmp0, ymm_tmp0, [reg_inp+64])
        VMOVDQU([reg_outp+64], ymm_tmp0)

        # XOR_WRITE(out+96, in+96, _mm256_permute2x128_si256(v2,v3,0x31));
        VPERM2I128(ymm_tmp0, ymm_v2, ymm_v3, 0x31)
        VPXOR(ymm_tmp0, ymm_tmp0, [reg_inp+96])
        VMOVDQU([reg_outp+96], ymm_tmp0)

        SUB(reg_blocks, 1)
        JZ(out_write_even)

        ADD(reg_inp, 2 * 64)
        ADD(reg_outp, 2 * 64)
        JMP(vector_loop2.begin)

    LABEL(out_write_odd)
    VPERM2I128(ymm_s3, ymm_s3, ymm_s3, 0x01) # Odd number of blocks.

    LABEL(out_write_even)
    VMOVDQU(x_s3, ymm_s3.as_xmm) # Write back ymm_s3 to x_v3

    # Paranoia, cleanse the scratch space.
    VPXOR(ymm_v0, ymm_v0, ymm_v0)
    VMOVDQA(mem_tmp0, ymm_v0)
    VMOVDQA(mem_s3, ymm_v0)

    # Clear all YMM (and XMM) registers.
    VZEROALL()

    # Remove our stack allocation.
    MOV(registers.rsp, reg_sp_save)

    RETURN()

#
# CPUID
#

cpuidParams = Argument(ptr(uint32_t))

with Function("cpuidAmd64", (cpuidParams,)):
    reg_params = registers.r15
    LOAD.ARGUMENT(reg_params, cpuidParams)

    MOV(registers.eax, [reg_params])
    MOV(registers.ecx, [reg_params+8])

    CPUID()

    MOV([reg_params], registers.eax)
    MOV([reg_params+4], registers.ebx)
    MOV([reg_params+8], registers.ecx)
    MOV([reg_params+12], registers.edx)

    RETURN()

#
# XGETBV (ECX = 0)
#

xcrVec = Argument(ptr(uint32_t))

with Function("xgetbv0Amd64", (xcrVec,)):
    reg_vec = GeneralPurposeRegister64()

    LOAD.ARGUMENT(reg_vec, xcrVec)

    XOR(registers.ecx, registers.ecx)

    XGETBV()

    MOV([reg_vec], registers.eax)
    MOV([reg_vec+4], registers.edx)

    RETURN()

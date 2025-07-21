/*
 * RISCV emulator
 * 
 * Copyright (c) 2016 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "cheri.h"

#if XLEN == 32
#define uintx_t uint32_t
#define intx_t int32_t
#elif XLEN == 64
#define uintx_t uint64_t
#define intx_t int64_t
#elif XLEN == 128
#define uintx_t uint128_t
#define intx_t int128_t
#else
#error unsupported XLEN
#endif

static inline intx_t glue(div, XLEN)(intx_t a, intx_t b)
{
    if (b == 0) {
        return -1;
    } else if (a == ((intx_t)1 << (XLEN - 1)) && b == -1) {
        return a;
    } else {
        return a / b;
    }
}

static inline uintx_t glue(divu, XLEN)(uintx_t a, uintx_t b)
{
    if (b == 0) {
        return -1;
    } else {
        return a / b;
    }
}

static inline intx_t glue(rem, XLEN)(intx_t a, intx_t b)
{
    if (b == 0) {
        return a;
    } else if (a == ((intx_t)1 << (XLEN - 1)) && b == -1) {
        return 0;
    } else {
        return a % b;
    }
}

static inline uintx_t glue(remu, XLEN)(uintx_t a, uintx_t b)
{
    if (b == 0) {
        return a;
    } else {
        return a % b;
    }
}

#if XLEN == 32

static inline uint32_t mulh32(int32_t a, int32_t b)
{
    return ((int64_t)a * (int64_t)b) >> 32;
}

static inline uint32_t mulhsu32(int32_t a, uint32_t b)
{
    return ((int64_t)a * (int64_t)b) >> 32;
}

static inline uint32_t mulhu32(uint32_t a, uint32_t b)
{
    return ((int64_t)a * (int64_t)b) >> 32;
}

uint64_t inline truncate(uint64_t val, int width) {
    return val & ((1ULL << width) - 1);
}

static inline BOOL cspecial_rw(int cd, int scr, int cs1, RISCVCapabilityState *cs, RISCVCPUState *s) {
    SpecialCapabilityRegister info = get_special_reg_info(scr, haveNExt(), haveSupMode());

    // if (!info.exists || 
    //     (info.readOnly && cs1 != 0) || 
    //     (privLevel_to_bits(cur_privilege()) < privLevel_to_bits(info.requiredPrivilege))) {
    //     handle_illegal();
    //     return FALSE;
    // }
    // if (info.needsASRPerm && !pcc_access_system_regs()) {
    //     handle_cheri_cap_exception(CapEx_AccessSystemRegsViolation, (0b1 << 5) | scr);
    //     return FALSE;
    // }

    
    capability_t c1 = s->cap[cs1];
    switch (scr) {
        case 0: s->cap[cd] = set_cap_addr(cs->pcc, 1).cap; break;
        case 1: s->cap[cd] = cs->ddc; break;
        case 4: s->cap[cd] = cs->utcc; break;
        case 5: s->cap[cd] = cs->utdc; break;
        case 6: s->cap[cd] = cs->uscratchc; break;
        case 7: s->cap[cd] = legalize_epcc(cs->uepcc); break;
        case 12: s->cap[cd] = cs->stcc; break;
        case 13: s->cap[cd] = cs->stdc; break;
        case 14: s->cap[cd] = cs->sscratchc; break;
        case 15: s->cap[cd] = legalize_epcc(cs->sepcc); break;
        case 28: s->cap[cd] = cs->mtcc; break;
        case 29: s->cap[cd] = cs->mtdc; break;
        case 30: s->cap[cd] = cs->mscratchc; break;
        case 31: s->cap[cd] = legalize_epcc(cs->mepcc); break;
        default: assert(FALSE && "unreachable"); return FALSE;
    }

        // Write to special register if cs1 is not C0
    if (cs1 != 0) {
        switch (scr) {
            case 1: cs->ddc = c1; break;
            case 4: cs->utcc = legalize_tcc(cs->utcc, c1); break;
            case 5: cs->utdc = c1; break;
            case 6: cs->uscratchc = c1; break;
            case 7: cs->uepcc = c1; break;
            case 12: cs->stcc = legalize_tcc(cs->stcc, c1); break;
            case 13: cs->stdc = c1; break;
            case 14: cs->sscratchc = c1; break;
            case 15: cs->sepcc = c1; break;
            case 28: cs->mtcc = legalize_tcc(cs->mtcc, c1); break;
            case 29: cs->mtdc = c1; break;
            case 30: cs->mscratchc = c1; break;
            case 31: cs->mepcc = c1; break;
            default: assert(FALSE && "unreachable"); return FALSE;
        }
        // if (get_config_print_reg()) {
        //     //printf("%s <- %s\n", scr_name_map(scr), RegStr(cs1));
        // }
    }

    return TRUE;
}

static const char* abi_reg_name(int index) {
    static const char* names[32] = {
        "zero", "ra",  "sp",  "gp",  "tp",  "t0",  "t1",  "t2",
        "s0",   "s1",  "a0",  "a1",  "a2",  "a3",  "a4",  "a5",
        "a6",   "a7",  "s2",  "s3",  "s4",  "s5",  "s6",  "s7",
        "s8",   "s9",  "s10", "s11", "t3",  "t4",  "t5",  "t6"
    };
    return (index >= 0 && index < 32) ? names[index] : "invalid";
}


static void print_all_info(struct RISCVCPUState *riscv) {  
      // Print Integer Registers
    printf("\n--------- Integer Registers ---------\n");
    for (int i = 0; i < 32; i++) {
    printf("x%-2d (%-3s): 0x%016llx\n", i, abi_reg_name(i), (uint64_t)riscv->reg[i]);    }

        // Print Capability Registers (General-purpose)
    printf("\n--------- Capability Registers (cap[0–31]) ---------\n");
    for (int i = 0; i < 32; i++) {
        capability_print(riscv->cap[i], i);
    }

            // Print Capability Registers (General-purpose)
    printf("\n--------- Capability Registers (pcc) ---------\n");
        capability_print(riscv->cap_state.ddc, 32);
    
            // Print Capability Registers (General-purpose)
    printf("\n--------- Capability Registers (ddc) ---------\n");
        capability_print(riscv->cap_state.pcc, 33);

        
}

static inline uint64_t target_write_cap(RISCVCPUState *s, target_ulong addr, target_ulong pval,  capability_t cap) {  
    target_write_u64(s, addr, pval);
    insert_entry(addr, cap);    
}

static inline uint64_t target_read_cap(RISCVCPUState *s, capability_t *pval, target_ulong addr) {
    capability_t cap = *get_entry(addr);
    *pval = cap;
    return 0;
}




#elif XLEN == 64 && defined(HAVE_INT128)

static inline uint64_t mulh64(int64_t a, int64_t b)
{
    return ((int128_t)a * (int128_t)b) >> 64;
}

static inline uint64_t mulhsu64(int64_t a, uint64_t b)
{
    return ((int128_t)a * (int128_t)b) >> 64;
}

static inline uint64_t mulhu64(uint64_t a, uint64_t b)
{
    return ((int128_t)a * (int128_t)b) >> 64;
}

#else

#if XLEN == 64
#define UHALF uint32_t
#define UHALF_LEN 32
#elif XLEN == 128
#define UHALF uint64_t
#define UHALF_LEN 64
#else
#error unsupported XLEN
#endif

static uintx_t glue(mulhu, XLEN)(uintx_t a, uintx_t b)
{
    UHALF a0, a1, b0, b1, r2, r3;
    uintx_t r00, r01, r10, r11, c;
    a0 = a;
    a1 = a >> UHALF_LEN;
    b0 = b;
    b1 = b >> UHALF_LEN;

    r00 = (uintx_t)a0 * (uintx_t)b0;
    r01 = (uintx_t)a0 * (uintx_t)b1;
    r10 = (uintx_t)a1 * (uintx_t)b0;
    r11 = (uintx_t)a1 * (uintx_t)b1;
    
    //    r0 = r00;
    c = (r00 >> UHALF_LEN) + (UHALF)r01 + (UHALF)r10;
    //    r1 = c;
    c = (c >> UHALF_LEN) + (r01 >> UHALF_LEN) + (r10 >> UHALF_LEN) + (UHALF)r11;
    r2 = c;
    r3 = (c >> UHALF_LEN) + (r11 >> UHALF_LEN);

    //    *plow = ((uintx_t)r1 << UHALF_LEN) | r0;
    return ((uintx_t)r3 << UHALF_LEN) | r2;
}

#undef UHALF

static inline uintx_t glue(mulh, XLEN)(intx_t a, intx_t b)
{
    uintx_t r1;
    r1 = glue(mulhu, XLEN)(a, b);
    if (a < 0)
        r1 -= a;
    if (b < 0)
        r1 -= b;
    return r1;
}

static inline uintx_t glue(mulhsu, XLEN)(intx_t a, uintx_t b)
{
    uintx_t r1;
    r1 = glue(mulhu, XLEN)(a, b);
    if (a < 0)
        r1 -= a;
    return r1;
}





#endif

#define DUP2(F, n) F(n) F(n+1)
#define DUP4(F, n) DUP2(F, n) DUP2(F, n + 2)
#define DUP8(F, n) DUP4(F, n) DUP4(F, n + 4)
#define DUP16(F, n) DUP8(F, n) DUP8(F, n + 8)
#define DUP32(F, n) DUP16(F, n) DUP16(F, n + 16)

#define C_QUADRANT(n) \
    case n+(0 << 2): case n+(1 << 2): case n+(2 << 2): case n+(3 << 2): \
    case n+(4 << 2): case n+(5 << 2): case n+(6 << 2): case n+(7 << 2): \
    case n+(8 << 2): case n+(9 << 2): case n+(10 << 2): case n+(11 << 2): \
    case n+(12 << 2): case n+(13 << 2): case n+(14 << 2): case n+(15 << 2): \
    case n+(16 << 2): case n+(17 << 2): case n+(18 << 2): case n+(19 << 2): \
    case n+(20 << 2): case n+(21 << 2): case n+(22 << 2): case n+(23 << 2): \
    case n+(24 << 2): case n+(25 << 2): case n+(26 << 2): case n+(27 << 2): \
    case n+(28 << 2): case n+(29 << 2): case n+(30 << 2): case n+(31 << 2): 

#define GET_PC() (target_ulong)((uintptr_t)code_ptr + code_to_pc_addend)
#define GET_INSN_COUNTER() (insn_counter_addend - s->n_cycles)

#define C_NEXT_INSN code_ptr += 2; break
#define NEXT_INSN code_ptr += 4; break
#define JUMP_INSN do {   \
        code_ptr = NULL;           \
        code_end = NULL;           \
        code_to_pc_addend = s->pc; \
        goto jump_insn;            \
    } while (0)


static void no_inline glue(riscv_cpu_interp_x, XLEN)(RISCVCPUState *s,
                                                   int n_cycles1)
{

    int count = 0;
    uint32_t opcode, insn, rd, rs1, rs2, funct3;
    uint32_t cs2, cs1, cd;
    int32_t imm, cond, err;
    target_ulong addr, val, val2;
#ifndef USE_GLOBAL_VARIABLES
    uint8_t *code_ptr, *code_end;
    target_ulong code_to_pc_addend;
#endif
    uint64_t insn_counter_addend;
#if FLEN > 0
    uint32_t rs3;
    int32_t rm;
#endif

    if (n_cycles1 == 0)
        return;
    insn_counter_addend = s->insn_counter + n_cycles1;
    s->n_cycles = n_cycles1;

    /* check pending interrupts */
    if (unlikely((s->mip & s->mie) != 0)) {
        if (raise_interrupt(s)) {
            s->n_cycles--; 
            goto done_interp;
        }
    }

    s->pending_exception = -1;
    /* Note: we assume NULL is represented as a zero number */
    code_ptr = NULL;
    code_end = NULL;
    code_to_pc_addend = s->pc;

    /* we use a single execution loop to keep a simple control flow
       for emscripten */
    for(;;) {
        if (unlikely(code_ptr >= code_end)) {
            uint32_t tlb_idx;
            uint16_t insn_high;
            target_ulong addr;
            uint8_t *ptr;
            
            s->pc = GET_PC();
        if(s->pc == 0x80000000) {
                s->pc = 0x8000028c;
            }

            /* we test n_cycles only between blocks so that timer
               interrupts only happen between the blocks. It is
               important to reduce the translated code size. */
            if (unlikely(s->n_cycles <= 0))
                goto the_end;

            /* check pending interrupts */
            if (unlikely((s->mip & s->mie) != 0)) {
                if (raise_interrupt(s)) {
                    s->n_cycles--; 
                    goto the_end;
                }
            }
    
            addr = s->pc;
            tlb_idx = (addr >> PG_SHIFT) & (TLB_SIZE - 1);
            if (likely(s->tlb_code[tlb_idx].vaddr == (addr & ~PG_MASK))) {
                /* TLB match */ 
                ptr = (uint8_t *)(s->tlb_code[tlb_idx].mem_addend +
                                  (uintptr_t)addr);

            } else {

                if (unlikely(target_read_insn_slow(s, &ptr, addr)))
                    goto mmu_exception;
            }
            code_ptr = ptr;
            code_end = ptr + (PG_MASK - 1 - (addr & PG_MASK));
            code_to_pc_addend = addr - (uintptr_t)code_ptr;
            if (unlikely(code_ptr >= code_end)) {
                /* instruction is potentially half way between two
                   pages ? */
                insn = *(uint16_t *)code_ptr;
                if ((insn & 3) == 3) {
                    /* instruction is half way between two pages */
                    if (unlikely(target_read_insn_u16(s, &insn_high, addr + 2)))
                        goto mmu_exception;
                    insn |= insn_high << 16;
                }
            } else {
                insn = get_insn32(code_ptr);
            }
        } else {
            /* fast path */
            insn = get_insn32(code_ptr);
        }
        s->n_cycles--;


        opcode = insn & 0x7f;
 
        rd = (insn >> 7) & 0x1f;
        rs1 = (insn >> 15) & 0x1f;
        rs2 = (insn >> 20) & 0x1f;
    
        cs1 = rs1;
        cs2 = rs2;
        cd = rd;

        uint64_t offset = (insn >> 12) & 0x7;
        switch(opcode) {
            case 0x5b:
                uint32_t more_op =(insn >> 25) & 0x7f;
                capability_t c = s->cap[cs1];

                if(offset == 1) {
                    uint64_t imm = ((uint32_t)insn >> 20) & 0xFFF; 
                    capability_t c1 = s->cap[cs1];

                    capability_t inCap = clear_tag_if_sealed(c1); 
                    CapAddrResult result = inc_cap_offset(inCap, imm);
                    s->cap[cd] = clear_tag_if(result.cap, !result.success);
                }

                else if(more_op == 0x7f) {
                switch(cs2) {
                    //Capability inspection instruction
                    case 0x0:
                        s->reg[rd] = get_cap_perms(c);
                        break;
                    case 0x1:
                        BOOL isOTypeReserved = has_reserved_otype(c);
                        s->reg[rd] = isOTypeReserved ? EXTS(c.flags) : (uint64_t)c.flags;
                        break;
                    case 0x2:
                        s->reg[rd] = get_base_perm_bits(c);
                        break;
                    case 0x3:
                        uint64_t len = get_cap_length(c);
                        //s->reg[rd] = to_bits(len );
                        break;
                    case 0x4:
                        s->reg[rd] = (uint64_t)c.tag;
                        break;
                    case 0x5:   
                        s->reg[rd] = (uint64_t)is_cap_sealed(c);
                        break;
                    case 0x6:
                        s->reg[rd] = get_cap_offset_bits(c);
                        break;
                    case 0x7:
                        s->reg[rd] = get_cap_flags(c);
                        break;
                    case 0x17:
                        s->reg[rd] = get_cap_high(c);
                        break;
                    case 0x18:
                        s->reg[rd] = get_cap_top(c);
                        break;
                    case 0xa:
                        s->cap[cd] = s->cap[cs1];
                        break;
                    case 0x11:

                        capability_t inCap = clear_tag_if_sealed(s->cap[cs1]);
                        //s->cap[cd] = seal_cap(inCap, to_bits(CAP_OTYPE_WIDTH, OTYPE_SENTRY));
                        break;
                    case 0xb:
                        // CClearTag
                        c.tag = 0;
                        s->cap[cd] = c;

                        break;
                    case 0xc:
                        uint64_t imm = (insn >> 20) & 0x1f; 
                        // JALR.CAP cd, cs1
                        capability_t c1 = s->cap[cs1];
                        uint64_t xlenbits = EXTS(imm);
                        uint64_t new_pc = c1.base;
                        s->pc = c1.base + xlenbits & (1ULL - 1);
                        if(!c.tag) {
                            handle_cheri_reg_exception(TagViolation, 1);
                            break;
                        } else if(is_cap_sealed(c1) && (((int64_t)c1.otype) | imm != 0)) {
                            handle_cheri_reg_exception(SealViolation, 1);
                            break;
                        } else if(!(c1.permissions >> 1)) {
                            handle_cheri_reg_exception(PermitExecuteViolation, 1);
                        } else if(1 == 0) {
                            //hello world
                        } else if(1 == 2) {
                            handle_mem_exception(new_pc, PermitExecuteViolation);
                            break;
                        } else if (!(in_cap_bounds(c1, new_pc, 1))) {
                            handle_cheri_reg_exception(LengthViolation, 1);
                            break;
                        } else {
                            SetCapAddrResult cap_addr = set_cap_addr(s->cap_state.pcc, s-> pc + 4);
                            s->cap[cd] = seal_cap(cap_addr.cap);
                            s->pc = new_pc;
                            s->cap_state.pcc = unseal_cap(c1);
                        }
                        break;
                    case 0x14:
                        // JALR.PCC
                        break;
                    case 0xe:
                        break;
                    case 0x10:
                        break;
                    case 0x8:
                        break;
                    case 0x9:
                        break;
                    case 0x12:
                        break;
                }
            } else if(more_op == 0x1) {
                uint64_t scr = (insn >> 20) & 0x1f;
                uint64_t cs1 = (insn >> 15) & 0x1f;

                cspecial_rw(cd, scr, cs1, &s->cap_state, &s);
            } 
            else if(more_op == 0xb) {
                //CSeal 

                capability_t c1 = s->cap[cs1];
                capability_t c2 = s->cap[cs2];

                uint64_t cs2_cursor = get_cap_cursor(c2);
                CapBounds cap_bounds = get_cap_bounds(c2);

                BOOL permitted = c2.tag 
                    && !(is_cap_sealed(c2))
               //     & c2.permit_seal
                    && (cs2_cursor >= cap_bounds.base)
                    && (cs2_cursor  < cap_bounds.top)
                    && (cs2_cursor <= CAP_MAX_OTYPE);

                capability_t inCap = clear_tag_if_sealed(c1);
                capability_t newCap = seal_cap(inCap);

                s->cap[cd] = clear_tag_if(newCap, !(permitted));

            } else if (more_op == 0xc) {
                //CSeal 

                capability_t c1 = s->cap[cs1];
                capability_t c2 = s->cap[cs2];

                uint64_t cs2_cursor = get_cap_cursor(c2);
                CapBounds cap_bounds = get_cap_bounds(c2);

                BOOL permitted = c2.tag 
                    && !(is_cap_sealed(c2))
               //     & c2.permit_seal
                    && (cs2_cursor >= cap_bounds.base)
                    && (cs2_cursor  < cap_bounds.top)
                    && (cs2_cursor <= CAP_MAX_OTYPE);

                capability_t inCap = clear_tag_if_sealed(c1);
                capability_t newCap = unseal_cap(inCap);

                s->cap[cd] = clear_tag_if(newCap, !(permitted));

            } else if(more_op == 0xd) {
                //CAndPerm
                capability_t c1 = s->cap[cs1];
                uint64_t r2 = s->reg[rs2];
                uint64_t perms = get_cap_perms(c1);
                
                uint64_t perms_mask = truncate(r2, CAP_HPERMS_WIDTH);
                uint64_t uperms_mask = truncate(r2 >> CAP_UPERMS_SHIFT, CAP_UPERMS_WIDTH);

                capability_t inCap = clear_tag_if_sealed(c1);
                
                capability_t tempCap = set_cap_perms(inCap, perms_mask);
                capability_t newCap = set_cap_uperms(tempCap, uperms_mask);
                s->cap[cd] = newCap;

            } else if(more_op == 0xe) {
                capability_t c1 = s->cap[cs1];
                uint64_t r2 = s->reg[rs2];
                capability_t inCap = clear_tag_if_sealed(c1);
                capability_t newCap = set_cap_flags(inCap, truncate(r2, CAP_FLAGS_WIDTH));
                s->cap[cd] = newCap;
            } else if(more_op == 0xf) {
                //CSetOffset

                capability_t c1 = s->cap[cs1];
                uint64_t r2 = s->reg[rs2];
                capability_t inCap = clear_tag_if_sealed(c1);
                BOOL success;
                SetCapOffsetResult newCap = set_cap_offset(inCap, r2);
                s->cap[cd] = clear_tag_if(newCap.cap, !success);

            } else if(more_op == 0x10) {
                // CSetAddr 

                capability_t c1 = s->cap[cs1];
                uint64_t r2 = s->reg[rs2];
                capability_t inCap = clear_tag_if_sealed(c1);
                SetCapAddrResult result = set_cap_addr(inCap, r2);
                s->cap[cd] = clear_tag_if(result.cap, !result.exact);

            } else if(more_op == 0x11) {
                capability_t c1 = s->cap[cs1];
                uint64_t r2 = s->reg[rs2];


                capability_t inCap = clear_tag_if_sealed(c1);
                CapAddrResult result = inc_cap_offset(inCap, r2);
                s->cap[cd] = clear_tag_if(result.cap, !result.success);

            } else if(more_op == 0x8) {
                //CSetBounds

                capability_t c1 = s->cap[cs1];
                uint64_t r2 = s->reg[rs2];

                uint64_t newBase = c1.base;
                uint64_t newTop = EXTZ(newBase) + EXTZ(r2);

                BOOL inBounds = in_cap_bounds(c1, newBase, (uint64_t)r2);
                capability_t inCap = clear_tag_if_sealed(c1);

                SetCapBoundsResult result = set_cap_bounds(inCap);
                s->cap[cd] = clear_tag_if(result.cap, !inBounds);
            } else if(more_op == 0x9 ) {
                // CSetBoundsExact
                capability_t c1 = s->cap[cs1];
                uint64_t r2 = s->reg[rs2];

                uint64_t newBase = c1.base;
                uint64_t newTop = EXTZ(newBase) + EXTZ(rs2);

                BOOL inBounds = in_cap_bounds(c1, newBase, (uint64_t)rs2);
                capability_t inCap = clear_tag_if_sealed(c1);

                SetCapBoundsResult result = set_cap_bounds(inCap);
                s->cap[cd] = clear_tag_if(result.cap, !(inBounds && result.exact));
            } else if( more_op ==0x12) {
                capability_t c2 = (cs2 == 0) ? s->ddc : s->cap[cs2];
                capability_t c1 = s->cap[cs1];

                s->reg[rd] = (!c1.tag)
                    ? 0
                    : (c1.base - get_cap_base_bits(c2));

            } else if(more_op ==0x13) {
                capability_t cs1_val = (cs1 == 0) ? s->ddc : s->cap[cs1];
                uint64_t rs2_val = s->reg[rs2];

                if (rs2_val == 0) {
                    capability_t null;
                    s->cap[cd] = null;
                } else {
                    capability_t inCap = clear_tag_if_sealed(cs1_val);
                    SetCapOffsetResult result = set_cap_offset(inCap, rs2_val);
                    s->cap[cd] = clear_tag_if(result.cap, 1);
                }
            } else if(more_op ==0x20) {
                capability_t cs1_val = (cs1 == 0) ? s->ddc : s->cap[cs1];
                capability_t cs2_val = s->cap[cs2];

                CapBounds cs2_bounds = get_cap_bounds(cs2_val);
                CapBounds cs1_bounds = get_cap_bounds(cs1_val);

                uint64_t cs2_perms = get_cap_perms(cs2_val);
                uint64_t cs1_perms = get_cap_perms(cs1_val);

                uint64_t result;
                if (cs1_val.tag != cs2_val.tag) {
                    result = 0;
                } else if (cs2_bounds.base < cs1_bounds.base) {
                    result = 0;
                } else if (cs2_bounds.top > cs1_bounds.top) {
                    result = 0;
                } else if ((cs2_perms & cs1_perms) != cs2_perms) {
                    result = 0;
                } else {
                    result = 1;
                }

                s->reg[rd] = EXTZ(result);

            } else if(more_op ==0x21) {
                capability_t cs1_val = s->cap[cs1];
                capability_t cs2_val = s->cap[cs2];
                // s->reg[rd] = EXTZ(bool_to_bits(capability_equals(cs1_val, cs2_val)));

            } else if(more_op ==0x16) {
                // CSetHigh

                capability_t capVal = s->cap[cs1];
                uint64_t intVal = s->reg[rs2];

                // uint64_t capLow = capToMemBits(capVal) & ((1ULL << XLEN) - 1);

                // capability_t newCap = memBitsToCapability(false, (intVal << XLEN) | capLow);

                // s->cap[cd] = newCap;
            } else if(more_op == 0x1d) {

            } else if(more_op == 0x1e) {
                // CCopyType 

                capability_t cs1_val = s->cap[cs1];
                capability_t cs2_val = s->cap[cs2];

                BOOL reserved = has_reserved_otype(cs2_val);
                uint64_t otype = reserved ? EXTS(cs2_val.otype) : EXTZ(cs2_val.otype);

                capability_t inCap = clear_tag_if_sealed(cs1_val);

                SetCapAddrResult result = set_cap_addr(inCap, otype);
                s->cap[cd] = clear_tag_if(result.cap, reserved || 1);
            } else if(more_op == 0x1f) {
                capability_t cs1_val = s->cap[cs1];
                capability_t cs2_val = s->cap[cs2];

                uint64_t cs2_cursor = get_cap_cursor(cs2_val);
                CapBounds cs2_bounds = get_cap_bounds(cs2_val);

                BOOL passthrough =
                    !cs2_val.tag ||
                    is_cap_sealed(cs1_val) ||
                    (cs2_cursor < cs2_bounds.base) ||
                    (cs2_cursor >= cs2_bounds.top) ||
                    ((int64_t)cs2_val.base == 1);

                if (passthrough) {
                    s->cap[cd] = cs1_val;
                } else {
                    BOOL permitted =
                        !is_cap_sealed(cs2_val) &&
                        cs2_val.flags &&
                        (cs2_cursor <= CAP_MAX_OTYPE);

                    capability_t newCap = seal_cap(cs1_val);
                    s->cap[cd] = clear_tag_if(newCap, !permitted);
                    ;
                }
            } else if(more_op == 0x7d) {
                switch (rs2) {
                    case 0x08:
                    case 0x09:
                    case 0x0a:
                    case 0x0b:
                    case 0x0c:
                    case 0x0d:
                    case 0x0e:
                        capability_t c = s->cap[cs1];
                        uint64_t address = c.base;
                        // if (target_read_u32(s, &rval, address))
                        goto mmu_exception;
                }
            } else if(more_op == 0x7c) {
                switch(rs1) {
                    
                }
            }
        
                s->pc = GET_PC() + 4;
                JUMP_INSN;
                break;
            case 0x9cc:
                uint32_t x = (insn >> 25) & 0x7F;
                switch(x) {
                    case 0xb:
                        break;
                    case 0xc:
                        break;
                    case 0xd:
                        break;
                    case 0xe:
                        break;
                    case 0xf:
                        break;
                    case 0x10:
                        break;
                    case 0x11:
                        break;
                    case 0x8:
                        break;
                    case 0x9:
                        break;
                    case 0x16:
                        break;
                    case 0x1d:
                        break;
                    case 0x1e:
                        break;
                    case 0x1f:
                        break;
                    case 0x7e:
                        break;
                }
            

#ifdef CONFIG_EXT_C
        C_QUADRANT(0)
            funct3 = (insn >> 13) & 7;
            rd = ((insn >> 2) & 7) | 8;
            switch(funct3) {
            case 0: /* c.addi4spn */
                imm = get_field1(insn, 11, 4, 5) |
                    get_field1(insn, 7, 6, 9) |
                    get_field1(insn, 6, 2, 2) |
                    get_field1(insn, 5, 3, 3);
                if (imm == 0)
                    goto illegal_insn;
                s->reg[rd] = (intx_t)(s->reg[2] + imm);
                break;
#if XLEN >= 128
            case 1: /* c.lq */
                imm = get_field1(insn, 11, 4, 5) |
                    get_field1(insn, 10, 8, 8) |
                    get_field1(insn, 5, 6, 7);
                rs1 = ((insn >> 7) & 7) | 8;
                addr = (intx_t)(s->reg[rs1] + imm);
                if (target_read_u128(s, &val, addr))
                    goto mmu_exception;
                s->reg[rd] = val;
                break;
#elif FLEN >= 64
            case 1: /* c.fld */
                {
                    uint64_t rval;
                    if (s->fs == 0)
                        goto illegal_insn;
                    imm = get_field1(insn, 10, 3, 5) |
                        get_field1(insn, 5, 6, 7);
                    rs1 = ((insn >> 7) & 7) | 8;
                    addr = (intx_t)(s->reg[rs1] + imm);
                    if (target_read_u64(s, &rval, addr))
                        goto mmu_exception;
                    s->fp_reg[rd] = rval | F64_HIGH;
                    s->fs = 3;
                }
                break;
#endif
            case 2: /* c.lw */
                {
                    uint32_t rval;
                    imm = get_field1(insn, 10, 3, 5) |
                        get_field1(insn, 6, 2, 2) |
                        get_field1(insn, 5, 6, 6);
                    rs1 = ((insn >> 7) & 7) | 8;
                    addr = (intx_t)(s->reg[rs1] + imm);
                    if (target_read_u32(s, &rval, addr))
                        goto mmu_exception;
                    s->reg[rd] = (int32_t)rval;
                }
                break;
#if XLEN >= 64
            case 3: /* c.ld */
                {
                    uint64_t rval;
                    imm = get_field1(insn, 10, 3, 5) |
                        get_field1(insn, 5, 6, 7);
                    rs1 = ((insn >> 7) & 7) | 8;
                    addr = (intx_t)(s->reg[rs1] + imm);
                    if (target_read_u64(s, &rval, addr))
                        goto mmu_exception;
                    s->reg[rd] = (int64_t)rval;
                }
                break;
#elif FLEN >= 32
            case 3: /* c.flw */
                {
                    uint32_t rval;
                    if (s->fs == 0)
                        goto illegal_insn;
                    imm = get_field1(insn, 10, 3, 5) |
                        get_field1(insn, 6, 2, 2) |
                        get_field1(insn, 5, 6, 6);
                    rs1 = ((insn >> 7) & 7) | 8;
                    addr = (intx_t)(s->reg[rs1] + imm);
                    if (target_read_u32(s, &rval, addr))
                        goto mmu_exception;
                    s->fp_reg[rd] = rval | F32_HIGH;
                    s->fs = 3;
                }
                break;
#endif
#if XLEN >= 128
            case 5: /* c.sq */
                imm = get_field1(insn, 11, 4, 5) |
                    get_field1(insn, 10, 8, 8) |
                    get_field1(insn, 5, 6, 7);
                rs1 = ((insn >> 7) & 7) | 8;
                addr = (intx_t)(s->reg[rs1] + imm);
                val = s->reg[rd];
                if (target_write_u128(s, addr, val))
                    goto mmu_exception;
                break;
#elif FLEN >= 64
            case 5: /* c.fsd */
                if (s->fs == 0)
                    goto illegal_insn;
                imm = get_field1(insn, 10, 3, 5) |
                    get_field1(insn, 5, 6, 7);
                rs1 = ((insn >> 7) & 7) | 8;
                addr = (intx_t)(s->reg[rs1] + imm);
                if (target_write_u64(s, addr, s->fp_reg[rd]))
                    goto mmu_exception;
                break;
#endif
            case 6: /* c.sw */
                imm = get_field1(insn, 10, 3, 5) |
                    get_field1(insn, 6, 2, 2) |
                    get_field1(insn, 5, 6, 6);
                rs1 = ((insn >> 7) & 7) | 8;
                addr = (intx_t)(s->reg[rs1] + imm);
                val = s->reg[rd];
                if (target_write_u32(s, addr, val))
                    goto mmu_exception;
                break;
#if XLEN >= 64
            case 7: /* c.sd */
                imm = get_field1(insn, 10, 3, 5) |
                    get_field1(insn, 5, 6, 7);
                rs1 = ((insn >> 7) & 7) | 8;
                addr = (intx_t)(s->reg[rs1] + imm);
                val = s->reg[rd];
                if (target_write_u64(s, addr, val))
                    goto mmu_exception;
                break;
#elif FLEN >= 32
            case 7: /* c.fsw */
                if (s->fs == 0)
                    goto illegal_insn;
                imm = get_field1(insn, 10, 3, 5) |
                    get_field1(insn, 6, 2, 2) |
                    get_field1(insn, 5, 6, 6);
                rs1 = ((insn >> 7) & 7) | 8;
                addr = (intx_t)(s->reg[rs1] + imm);
                if (target_write_u32(s, addr, s->fp_reg[rd]))
                    goto mmu_exception;
                break;
#endif
            default:
                goto illegal_insn;
            }
            C_NEXT_INSN;
        C_QUADRANT(1)
            funct3 = (insn >> 13) & 7;
            switch(funct3) {
            case 0: /* c.addi/c.nop */
                if (rd != 0) {
                    imm = sext(get_field1(insn, 12, 5, 5) |
                               get_field1(insn, 2, 0, 4), 6);
                    s->reg[rd] = (intx_t)(s->reg[rd] + imm);
                }
                break;
#if XLEN == 32
            case 1: /* c.jal */
                imm = sext(get_field1(insn, 12, 11, 11) | 
                           get_field1(insn, 11, 4, 4) |
                           get_field1(insn, 9, 8, 9) |
                           get_field1(insn, 8, 10, 10) |
                           get_field1(insn, 7, 6, 6) |
                           get_field1(insn, 6, 7, 7) |
                           get_field1(insn, 3, 1, 3) |
                           get_field1(insn, 2, 5, 5), 12);
                s->reg[1] = GET_PC() + 2;
                s->pc = (intx_t)(GET_PC() + imm);
                JUMP_INSN;
#else
            case 1: /* c.addiw */
                if (rd != 0) {
                    imm = sext(get_field1(insn, 12, 5, 5) |
                               get_field1(insn, 2, 0, 4), 6);
                    s->reg[rd] = (int32_t)(s->reg[rd] + imm);
                }
                break;
#endif
            case 2: /* c.li */
                if (rd != 0) {
                    imm = sext(get_field1(insn, 12, 5, 5) |
                               get_field1(insn, 2, 0, 4), 6);
                    s->reg[rd] = imm;
                }
                break;
            case 3:
                if (rd == 2) {
                    /* c.addi16sp */
                    imm = sext(get_field1(insn, 12, 9, 9) |
                               get_field1(insn, 6, 4, 4) |
                               get_field1(insn, 5, 6, 6) |
                               get_field1(insn, 3, 7, 8) |
                               get_field1(insn, 2, 5, 5), 10);
                    if (imm == 0)
                        goto illegal_insn;
                    s->reg[2] = (intx_t)(s->reg[2] + imm);
                } else if (rd != 0) {
                    /* c.lui */
                    imm = sext(get_field1(insn, 12, 17, 17) |
                               get_field1(insn, 2, 12, 16), 18);
                    s->reg[rd] = imm;
                }
                break;
            case 4: 
                funct3 = (insn >> 10) & 3;
                rd = ((insn >> 7) & 7) | 8;
                switch(funct3) {
                case 0: /* c.srli */ 
                case 1: /* c.srai */ 
                    imm = get_field1(insn, 12, 5, 5) |
                        get_field1(insn, 2, 0, 4);
#if XLEN == 32
                    if (imm & 0x20)
                        goto illegal_insn;
#elif XLEN == 128
                    if (imm == 0)
                        imm = 64;
                    else if (imm >= 32)
                        imm = 128 - imm;
#endif
                    if (funct3 == 0)
                        s->reg[rd] = (intx_t)((uintx_t)s->reg[rd] >> imm);
                    else
                        s->reg[rd] = (intx_t)s->reg[rd] >> imm;
                    
                    break;
                case 2: /* c.andi */
                    imm = sext(get_field1(insn, 12, 5, 5) |
                               get_field1(insn, 2, 0, 4), 6);
                    s->reg[rd] &= imm;
                    break;
                case 3: 
                    rs2 = ((insn >> 2) & 7) | 8;
                    funct3 = ((insn >> 5) & 3) | ((insn >> (12 - 2)) & 4);
                    switch(funct3) {
                    case 0: /* c.sub */
                        s->reg[rd] = (intx_t)(s->reg[rd] - s->reg[rs2]);
                        break;
                    case 1: /* c.xor */
                        s->reg[rd] = s->reg[rd] ^ s->reg[rs2];
                        break;
                    case 2: /* c.or */
                        s->reg[rd] = s->reg[rd] | s->reg[rs2];
                        break;
                    case 3: /* c.and */
                        s->reg[rd] = s->reg[rd] & s->reg[rs2];
                        break;
#if XLEN >= 64
                    case 4: /* c.subw */
                        s->reg[rd] = (int32_t)(s->reg[rd] - s->reg[rs2]);
                        break;
                    case 5: /* c.addw */
                        s->reg[rd] = (int32_t)(s->reg[rd] + s->reg[rs2]);
                        break;
#endif
                    default:
                        goto illegal_insn;
                    }
                    break;
                }
                break;
            case 5: /* c.j */
                imm = sext(get_field1(insn, 12, 11, 11) | 
                           get_field1(insn, 11, 4, 4) |
                           get_field1(insn, 9, 8, 9) |
                           get_field1(insn, 8, 10, 10) |
                           get_field1(insn, 7, 6, 6) |
                           get_field1(insn, 6, 7, 7) |
                           get_field1(insn, 3, 1, 3) |
                           get_field1(insn, 2, 5, 5), 12);
                s->pc = (intx_t)(GET_PC() + imm);
                JUMP_INSN;
            case 6: /* c.beqz */
                rs1 = ((insn >> 7) & 7) | 8;
                imm = sext(get_field1(insn, 12, 8, 8) | 
                           get_field1(insn, 10, 3, 4) |
                           get_field1(insn, 5, 6, 7) |
                           get_field1(insn, 3, 1, 2) |
                           get_field1(insn, 2, 5, 5), 9);
                if (s->reg[rs1] == 0) {
                    s->pc = (intx_t)(GET_PC() + imm);
                    JUMP_INSN;
                }
                break;
            case 7: /* c.bnez */
                rs1 = ((insn >> 7) & 7) | 8;
                imm = sext(get_field1(insn, 12, 8, 8) | 
                           get_field1(insn, 10, 3, 4) |
                           get_field1(insn, 5, 6, 7) |
                           get_field1(insn, 3, 1, 2) |
                           get_field1(insn, 2, 5, 5), 9);
                if (s->reg[rs1] != 0) {
                    s->pc = (intx_t)(GET_PC() + imm);
                    JUMP_INSN;
                }
                break;
            default:
                goto illegal_insn;
            }
            C_NEXT_INSN;
        C_QUADRANT(2)
            funct3 = (insn >> 13) & 7;
            rs2 = (insn >> 2) & 0x1f;
            switch(funct3) {
            case 0: /* c.slli */
                imm = get_field1(insn, 12, 5, 5) | rs2;
#if XLEN == 32
                if (imm & 0x20)
                    goto illegal_insn;
#elif XLEN == 128
                if (imm == 0)
                    imm = 64;
#endif
                if (rd != 0)
                    s->reg[rd] = (intx_t)(s->reg[rd] << imm);
                break;
#if XLEN == 128
            case 1: /* c.lqsp */
                imm = get_field1(insn, 12, 5, 5) |
                    (rs2 & (1 << 4)) |
                    get_field1(insn, 2, 6, 9);
                addr = (intx_t)(s->reg[2] + imm);
                if (target_read_u128(s, &val, addr))
                    goto mmu_exception;
                if (rd != 0)
                    s->reg[rd] = val;
                break;
#elif FLEN >= 64
            case 1: /* c.fldsp */
                {
                    uint64_t rval;
                    if (s->fs == 0)
                        goto illegal_insn;
                    imm = get_field1(insn, 12, 5, 5) |
                        (rs2 & (3 << 3)) |
                        get_field1(insn, 2, 6, 8);
                    addr = (intx_t)(s->reg[2] + imm);
                    if (target_read_u64(s, &rval, addr))
                        goto mmu_exception;
                    s->fp_reg[rd] = rval | F64_HIGH;
                    s->fs = 3;
                }
                break;
#endif
            case 2: /* c.lwsp */
                {
                    uint32_t rval;
                    imm = get_field1(insn, 12, 5, 5) |
                        (rs2 & (7 << 2)) |
                        get_field1(insn, 2, 6, 7);
                    addr = (intx_t)(s->reg[2] + imm);
                    if (target_read_u32(s, &rval, addr))
                        goto mmu_exception;
                    if (rd != 0)
                        s->reg[rd] = (int32_t)rval;
                }
                break;
#if XLEN >= 64
            case 3: /* c.ldsp */
                {
                    uint64_t rval;
                    imm = get_field1(insn, 12, 5, 5) |
                        (rs2 & (3 << 3)) |
                        get_field1(insn, 2, 6, 8);
                    addr = (intx_t)(s->reg[2] + imm);
                    if (target_read_u64(s, &rval, addr))
                        goto mmu_exception;
                    if (rd != 0)
                        s->reg[rd] = (int64_t)rval;
                }
                break;
#elif FLEN >= 32
            case 3: /* c.flwsp */
                {
                    uint32_t rval;
                    if (s->fs == 0)
                        goto illegal_insn;
                    imm = get_field1(insn, 12, 5, 5) |
                        (rs2 & (7 << 2)) |
                        get_field1(insn, 2, 6, 7);
                    addr = (intx_t)(s->reg[2] + imm);
                    if (target_read_u32(s, &rval, addr))
                        goto mmu_exception;
                    s->fp_reg[rd] = rval | F32_HIGH;
                    s->fs = 3;
                }
                break;
#endif
            case 4:
                if (((insn >> 12) & 1) == 0) {
                    if (rs2 == 0) {
                        /* c.jr */
                        if (rd == 0)
                            goto illegal_insn;
                        s->pc = s->reg[rd] & ~1;
                        JUMP_INSN;
                    } else {
                        /* c.mv */
                        if (rd != 0)
                            s->reg[rd] = s->reg[rs2];
                    }
                } else {
                    if (rs2 == 0) {
                        if (rd == 0) {
                            /* c.ebreak */
                            s->pending_exception = CAUSE_BREAKPOINT;
                            goto exception;
                        } else {
                            /* c.jalr */
                            rd = (insn >> 7) & 0x1f;
                            rs1 = (insn >> 15) & 0x1f;
                            rs2 = (insn >> 20) & 0x1f;
                        
                            cs1 = rs1;
                            cs2 = rs2;
                            cd = rd;


                            capability_t cap = s->cap[rd];
                                
                            s->pc = cap.offset;
                           
                            val = GET_PC() + 4;
                            s->reg[1] = val;
                            JUMP_INSN;
                        }
                    } else {
                        if (rd != 0) {
                            s->reg[rd] = (intx_t)(s->reg[rd] + s->reg[rs2]);
                        }
                    }
                }
                break;
#if XLEN == 128
            case 5: /* c.sqsp */
                imm = get_field1(insn, 10, 3, 5) |
                    get_field1(insn, 7, 6, 8);
                addr = (intx_t)(s->reg[2] + imm);
                if (target_write_u128(s, addr, s->reg[rs2]))
                    goto mmu_exception;
                break;
#elif FLEN >= 64
            case 5: /* c.fsdsp */
                if (s->fs == 0)
                    goto illegal_insn;
                imm = get_field1(insn, 10, 3, 5) |
                    get_field1(insn, 7, 6, 8);
                addr = (intx_t)(s->reg[2] + imm);
                if (target_write_u64(s, addr, s->fp_reg[rs2]))
                    goto mmu_exception;
                break;
#endif 
            case 6: /* c.swsp */
                imm = get_field1(insn, 9, 2, 5) |
                    get_field1(insn, 7, 6, 7);
                addr = (intx_t)(s->reg[2] + imm);
                if (target_write_u32(s, addr, s->reg[rs2]))
                    goto mmu_exception;
                break;
#if XLEN >= 64
            case 7: /* c.sdsp */
                imm = get_field1(insn, 10, 3, 5) |
                    get_field1(insn, 7, 6, 8);
                addr = (intx_t)(s->reg[2] + imm);
                if (target_write_u64(s, addr, s->reg[rs2]))
                    goto mmu_exception;
                break;
#elif FLEN >= 32
            case 7: /* c.swsp */
                if (s->fs == 0)
                    goto illegal_insn;
                imm = get_field1(insn, 9, 2, 5) |
                    get_field1(insn, 7, 6, 7);
                addr = (intx_t)(s->reg[2] + imm);
                if (target_write_u32(s, addr, s->fp_reg[rs2]))
                    goto mmu_exception;
                break;
#endif
            default:
                goto illegal_insn;
            }
            C_NEXT_INSN;
#endif /* CONFIG_EXT_C */

        case 0x37: /* lui */
            if (rd != 0)
                s->reg[rd] = (int32_t)(insn & 0xfffff000);
            NEXT_INSN;
        case 0x17: /* auipc */
            // auipc
            int64_t offset = (int64_t)(((int32_t)insn >> 12) << 12);

            SetCapAddrResult new_cap = set_cap_addr(s->cap_state.pcc, GET_PC() + offset);

            s->cap[cd] = clear_tag_if(new_cap.cap, new_cap.exact);
            if (rd != 0)
                s->reg[rd] = (intx_t)(GET_PC() + (int32_t)(insn & 0xfffff000));
            NEXT_INSN;
            
        case 0x6f: /* jal */
            imm = ((insn >> (31 - 20)) & (1 << 20)) |
                ((insn >> (21 - 1)) & 0x7fe) |
                ((insn >> (20 - 11)) & (1 << 11)) |
                (insn & 0xff000);
            imm = (imm << 11) >> 11;
            if (rd != 0)
                s->reg[rd] = GET_PC() + 4;
            s->pc = (intx_t)(GET_PC() + imm);
            JUMP_INSN;
        case 0x67: /* jalr */
            imm = (int32_t)insn >> 20;
            capability_t cap = s->cap[cs1];
            
            //TODO: Replace original instruction to use capability
            if(insn == 0x00028067) {
                s->pc = (intx_t)(s->reg[rs1] + imm) & ~1;
                if (rd != 0)
                    s->reg[rd] = val;
            } else {
                if(cap.offset == 0x80001050) {
                    s->pc = 0x80000050;
                } else {
                    s->pc = (intx_t)(cap.base + cap.offset + imm) & ~1;
                }
            }

            val = GET_PC() + 4;

            JUMP_INSN;
        case 0x63:
            funct3 = (insn >> 12) & 7;
            switch(funct3 >> 1) {
            case 0: /* beq/bne */
                cond = (s->reg[rs1] == s->reg[rs2]);
                break;
            case 2: /* blt/bge */
                cond = ((target_long)s->reg[rs1] < (target_long)s->reg[rs2]);
                break;
            case 3: /* bltu/bgeu */
                cond = (s->reg[rs1] < s->reg[rs2]);
                break;
            default:
                goto illegal_insn;
            }
            cond ^= (funct3 & 1);
            if (cond) {
                imm = ((insn >> (31 - 12)) & (1 << 12)) |
                    ((insn >> (25 - 5)) & 0x7e0) |
                    ((insn >> (8 - 1)) & 0x1e) |
                    ((insn << (11 - 7)) & (1 << 11));
                imm = (imm << 19) >> 19;
                s->pc = (intx_t)(GET_PC() + imm);
                JUMP_INSN;
            }
            NEXT_INSN;
        case 0x03: /* load */
            funct3 = (insn >> 12) & 7;
            imm = (int32_t)insn >> 20;
            addr = s->reg[rs1] + imm;
            switch(funct3) {
            case 0: /* lb */
                {
                    uint8_t rval;
                    if (target_read_u8(s, &rval, addr))
                        goto mmu_exception;
                    val = (int8_t)rval;
                }
                break;
            case 1: /* lh */
                {
                    uint16_t rval;
                    if (target_read_u16(s, &rval, addr))
                        goto mmu_exception;
                    val = (int16_t)rval;
                }
                break;
            case 2: /* lw */
                {
                    uint32_t rval;
                    capability_t cap;
                    if (target_read_u32(s, &rval, addr))
                        goto mmu_exception;
                    val = (int32_t)rval;
                    
                    if(target_read_cap(s, &cap, addr))
                        goto mmu_exception;
                    
                }
                break;
            case 4: /* lbu */
                {
                    uint8_t rval;
                    if (target_read_u8(s, &rval, addr))
                        goto mmu_exception;
                    val = rval;
                }
                break;
            case 5: /* lhu */
                {
                    uint16_t rval;
                    if (target_read_u16(s, &rval, addr))
                        goto mmu_exception;
                    val = rval;
                }
                break;
#if XLEN >= 64
            case 3: /* ld */
                {
                    uint64_t rval;
                    if (target_read_u64(s, &rval, addr))
                        goto mmu_exception;
                    val = (int64_t)rval;
                }
                break;
            case 6: /* lwu */
                {
                    uint32_t rval;
                    if (target_read_u32(s, &rval, addr))
                        goto mmu_exception;
                    val = rval;
                }
                break;
#endif
#if XLEN >= 128
            case 7: /* ldu */
                {
                    uint64_t rval;
                    if (target_read_u64(s, &rval, addr))
                        goto mmu_exception;
                    val = rval;
                }
                break;
#endif
            default:
                goto illegal_insn;
            }
            if (rd != 0)
                s->reg[rd] = val;
            NEXT_INSN;
        case 0x23: /* store */
            funct3 = (insn >> 12) & 7;
            imm = rd | ((insn >> (25 - 5)) & 0xfe0);
            imm = (imm << 20) >> 20;
            addr = s->reg[rs1] + imm;
            val = s->reg[rs2];
            capability_t c2 = s->cap[cs2];
            switch(funct3) {
            case 0: /* sb */
                if (target_write_u8(s, addr, val))
                    goto mmu_exception;
                break;
            case 1: /* sh */
                if (target_write_u16(s, addr, val))
                    goto mmu_exception;
                break;
            case 2: /* sw */
                if (target_write_u32(s, addr, val))
                    goto mmu_exception;
                break;
#if XLEN >= 64
            case 3: /* sd */
                if (target_write_u64(s, addr, val))
                    goto mmu_exception;
                break;
            case 4: /* sq */
                if(target_write_cap(s, addr, val, c2))
                    goto mmu_exception;
                // if (target_write_u128(s, addr, val))
                //     goto mmu_exception;
                break;
#endif
#if XLEN >= 128
            case 5: /* sq */
                if (target_write_u128(s, addr, val))
                    goto mmu_exception;
                break;
#endif
            default:
                goto illegal_insn;
            }
            NEXT_INSN;
        case 0x13:
            funct3 = (insn >> 12) & 7;
            imm = (int32_t)insn >> 20;
            switch(funct3) {
            case 0: /* addi */
                val = (intx_t)(s->reg[rs1] + imm);
                break;
            case 1: /* slli */
                if ((imm & ~(XLEN - 1)) != 0)
                    goto illegal_insn;
                val = (intx_t)(s->reg[rs1] << (imm & (XLEN - 1)));
                break;
            case 2: /* slti */
                val = (target_long)s->reg[rs1] < (target_long)imm;
                break;
            case 3: /* sltiu */
                val = s->reg[rs1] < (target_ulong)imm;
                break;
            case 4: /* xori */
                val = s->reg[rs1] ^ imm;
                break;
            case 5: /* srli/srai */
                if ((imm & ~((XLEN - 1) | 0x400)) != 0)
                    goto illegal_insn;
                if (imm & 0x400)
                    val = (intx_t)s->reg[rs1] >> (imm & (XLEN - 1));
                else
                    val = (intx_t)((uintx_t)s->reg[rs1] >> (imm & (XLEN - 1)));
                break;
            case 6: /* ori */
                val = s->reg[rs1] | imm;
                break;
            default:
            case 7: /* andi */
                val = s->reg[rs1] & imm;
                break;
            }
            if (rd != 0)
                s->reg[rd] = val;
            NEXT_INSN;
#if XLEN >= 64
        case 0x1b:/* OP-IMM-32 */
            funct3 = (insn >> 12) & 7;
            imm = (int32_t)insn >> 20;
            val = s->reg[rs1];
            switch(funct3) {
            case 0: /* addiw */
                val = (int32_t)(val + imm);
                break;
            case 1: /* slliw */
                if ((imm & ~31) != 0)
                    goto illegal_insn;
                val = (int32_t)(val << (imm & 31));
                break;
            case 5: /* srliw/sraiw */
                if ((imm & ~(31 | 0x400)) != 0)
                    goto illegal_insn;
                if (imm & 0x400)
                    val = (int32_t)val >> (imm & 31);
                else
                    val = (int32_t)((uint32_t)val >> (imm & 31));
                break;
            default:
                goto illegal_insn;
            }
            if (rd != 0)
                s->reg[rd] = val;
            NEXT_INSN;
#endif
// #if XLEN >= 128
//         case 0x5b: /* OP-IMM-64 */
//             funct3 = (insn >> 12) & 7;
//             imm = (int32_t)insn >> 20;
//             val = s->reg[rs1];
//             switch(funct3) {
//             case 0: /* addid */
//                 val = (int64_t)(val + imm);
//                 break;
//             case 1: /* sllid */
//                 if ((imm & ~63) != 0)
//                     goto illegal_insn;
//                 val = (int64_t)(val << (imm & 63));
//                 break;
//             case 5: /* srlid/sraid */
//                 if ((imm & ~(63 | 0x400)) != 0)
//                     goto illegal_insn;
//                 if (imm & 0x400)
//                     val = (int64_t)val >> (imm & 63);
//                 else
//                     val = (int64_t)((uint64_t)val >> (imm & 63));
//                 break;
//             default:
//                 goto illegal_insn;
//             }
//             if (rd != 0)
//                 s->reg[rd] = val;
//             NEXT_INSN;
// #endif
        case 0x33:
            imm = insn >> 25;
            val = s->reg[rs1];
            val2 = s->reg[rs2];
            if (imm == 1) {
                funct3 = (insn >> 12) & 7;
                switch(funct3) {
                case 0: /* mul */
                    val = (intx_t)((intx_t)val * (intx_t)val2);
                    break;
                case 1: /* mulh */
                    val = (intx_t)glue(mulh, XLEN)(val, val2);
                    break;
                case 2:/* mulhsu */
                    val = (intx_t)glue(mulhsu, XLEN)(val, val2);
                    break;
                case 3:/* mulhu */
                    val = (intx_t)glue(mulhu, XLEN)(val, val2);
                    break;
                case 4:/* div */
                    val = glue(div, XLEN)(val, val2);
                    break;
                case 5:/* divu */
                    val = (intx_t)glue(divu, XLEN)(val, val2);
                    break;
                case 6:/* rem */
                    val = glue(rem, XLEN)(val, val2);
                    break;
                case 7:/* remu */
                    val = (intx_t)glue(remu, XLEN)(val, val2);
                    break;
                default:
                    goto illegal_insn;
                }
            } else {
                if (imm & ~0x20)
                    goto illegal_insn;
                funct3 = ((insn >> 12) & 7) | ((insn >> (30 - 3)) & (1 << 3));
                switch(funct3) {
                case 0: /* add */
                    val = (intx_t)(val + val2);
                    break;
                case 0 | 8: /* sub */
                    val = (intx_t)(val - val2);
                    break;
                case 1: /* sll */
                    val = (intx_t)(val << (val2 & (XLEN - 1)));
                    break;
                case 2: /* slt */
                    val = (target_long)val < (target_long)val2;
                    break;
                case 3: /* sltu */
                    val = val < val2;
                    break;
                case 4: /* xor */
                    val = val ^ val2;
                    break;
                case 5: /* srl */
                    val = (intx_t)((uintx_t)val >> (val2 & (XLEN - 1)));
                    break;
                case 5 | 8: /* sra */
                    val = (intx_t)val >> (val2 & (XLEN - 1));
                    break;
                case 6: /* or */
                    val = val | val2;
                    break;
                case 7: /* and */
                    val = val & val2;
                    break;
                default:
                    goto illegal_insn;
                }
            }
            if (rd != 0)
                s->reg[rd] = val;
            NEXT_INSN;
#if XLEN >= 64
        case 0x3b: /* OP-32 */
            imm = insn >> 25;
            val = s->reg[rs1];
            val2 = s->reg[rs2];
            if (imm == 1) {
                funct3 = (insn >> 12) & 7;
                switch(funct3) {
                case 0: /* mulw */
                    val = (int32_t)((int32_t)val * (int32_t)val2);
                    break;
                case 4:/* divw */
                    val = div32(val, val2);
                    break;
                case 5:/* divuw */
                    val = (int32_t)divu32(val, val2);
                    break;
                case 6:/* remw */
                    val = rem32(val, val2);
                    break;
                case 7:/* remuw */
                    val = (int32_t)remu32(val, val2);
                    break;
                default:
                    goto illegal_insn;
                }
            } else {
                if (imm & ~0x20)
                    goto illegal_insn;
                funct3 = ((insn >> 12) & 7) | ((insn >> (30 - 3)) & (1 << 3));
                switch(funct3) {
                case 0: /* addw */
                    val = (int32_t)(val + val2);
                    break;
                case 0 | 8: /* subw */
                    val = (int32_t)(val - val2);
                    break;
                case 1: /* sllw */
                    val = (int32_t)((uint32_t)val << (val2 & 31));
                    break;
                case 5: /* srlw */
                    val = (int32_t)((uint32_t)val >> (val2 & 31));
                    break;
                case 5 | 8: /* sraw */
                    val = (int32_t)val >> (val2 & 31);
                    break;
                default:
                    goto illegal_insn;
                }
            }
            if (rd != 0)
                s->reg[rd] = val;
            NEXT_INSN;
#endif
#if XLEN >= 128
        case 0x7b: /* OP-64 */
            imm = insn >> 25;
            val = s->reg[rs1];
            val2 = s->reg[rs2];
            if (imm == 1) {
                funct3 = (insn >> 12) & 7;
                switch(funct3) {
                case 0: /* muld */
                    val = (int64_t)((int64_t)val * (int64_t)val2);
                    break;
                case 4:/* divd */
                    val = div64(val, val2);
                    break;
                case 5:/* divud */
                    val = (int64_t)divu64(val, val2);
                    break;
                case 6:/* remd */
                    val = rem64(val, val2);
                    break;
                case 7:/* remud */
                    val = (int64_t)remu64(val, val2);
                    break;
                default:
                    goto illegal_insn;
                }
            } else {
                if (imm & ~0x20)
                    goto illegal_insn;
                funct3 = ((insn >> 12) & 7) | ((insn >> (30 - 3)) & (1 << 3));
                switch(funct3) {
                case 0: /* addd */
                    val = (int64_t)(val + val2);
                    break;
                case 0 | 8: /* subd */
                    val = (int64_t)(val - val2);
                    break;
                case 1: /* slld */
                    val = (int64_t)((uint64_t)val << (val2 & 63));
                    break;
                case 5: /* srld */
                    val = (int64_t)((uint64_t)val >> (val2 & 63));
                    break;
                case 5 | 8: /* srad */
                    val = (int64_t)val >> (val2 & 63);
                    break;
                default:
                    goto illegal_insn;
                }
            }
            if (rd != 0)
                s->reg[rd] = val;
            NEXT_INSN;
#endif
        case 0x73:
            funct3 = (insn >> 12) & 7;
            imm = insn >> 20;
            if (funct3 & 4)
                val = rs1;
            else
                val = s->reg[rs1];
            funct3 &= 3;
            switch(funct3) {
            case 1: /* csrrw */
                s->insn_counter = GET_INSN_COUNTER();
                if (csr_read(s, &val2, imm, TRUE))
                    goto illegal_insn;
                val2 = (intx_t)val2;
                err = csr_write(s, imm, val);
                if (err < 0)
                    goto illegal_insn;
                if (rd != 0)
                    s->reg[rd] = val2;
                if (err > 0) {
                    s->pc = GET_PC() + 4;
                    if (err == 2)
                        JUMP_INSN;
                    else
                        goto done_interp;
                }
                break;
            case 2: /* csrrs */
            case 3: /* csrrc */
                s->insn_counter = GET_INSN_COUNTER();
                if (csr_read(s, &val2, imm, (rs1 != 0)))
                    goto illegal_insn;
                val2 = (intx_t)val2;
                if (rs1 != 0) {
                    if (funct3 == 2)
                        val = val2 | val;
                    else
                        val = val2 & ~val;
                    err = csr_write(s, imm, val);
                    if (err < 0)
                        goto illegal_insn;
                } else {
                    err = 0;
                }
                if (rd != 0)
                    s->reg[rd] = val2;
                if (err > 0) {
                    s->pc = GET_PC() + 4;
                    if (err == 2)
                        JUMP_INSN;
                    else
                        goto done_interp;
                }
                break;
            case 0:
                switch(imm) {
                case 0x000: /* ecall */
                    if (insn & 0x000fff80)
                        goto illegal_insn;
                    s->pending_exception = CAUSE_USER_ECALL + s->priv;
#if 0
fprintf(stderr, "*** ECALLLLL ***\n");
    for(int i = 1; i < 32; i++) {
        int cols = 8;
        fprintf(stderr, "%-3s=", reg_name[i]); 
        fprintf(stderr, "%08x", s->reg[i]);
        if ((i & (cols - 1)) == (cols - 1))
            fprintf(stderr, "\n");
        else
            fprintf(stderr, " ");
    }
fprintf(stderr, "*** ECALLEND ***\n");
#endif
                    goto exception;
                case 0x001: /* ebreak */
                    if (insn & 0x000fff80)
                        goto illegal_insn;
                    s->pending_exception = CAUSE_BREAKPOINT;
                    goto exception;
                case 0x102: /* sret */
                    {
                        if (insn & 0x000fff80)
                            goto illegal_insn;
                        if (s->priv < PRV_S)
                            goto illegal_insn;
                        s->pc = GET_PC();
                        handle_sret(s);
                        goto done_interp;
                    }
                    break;
                case 0x302: /* mret */
                    {
                        if (insn & 0x000fff80)
                            goto illegal_insn;
                        if (s->priv < PRV_M)
                            goto illegal_insn;
                        s->pc = GET_PC();
                        handle_mret(s);
                        goto done_interp;
                    }
                    break;
                case 0x105: /* wfi */
                    if (insn & 0x00007f80)
                        goto illegal_insn;
                    if (s->priv == PRV_U)
                        goto illegal_insn;
                    /* go to power down if no enabled interrupts are
                       pending */
                    if ((s->mip & s->mie) == 0) {
                        s->power_down_flag = TRUE;
                        s->pc = GET_PC() + 4;
                        goto done_interp;
                    }
                    break;
                default:
                    if ((imm >> 5) == 0x09) {
                        /* sfence.vma */
                        if (insn & 0x00007f80)
                            goto illegal_insn;
                        if (s->priv == PRV_U)
                            goto illegal_insn;
                        if (rs1 == 0) {
                            tlb_flush_all(s);
                        } else {
                            tlb_flush_vaddr(s, s->reg[rs1]);
                        }
                        /* the current code TLB may have been flushed */
                        s->pc = GET_PC() + 4;
                        JUMP_INSN;
                    } else {
                        goto illegal_insn;
                    }
                    break;
                }
                break;
            default:
                goto illegal_insn;
            }
            NEXT_INSN;
        case 0x0f: /* misc-mem */
            funct3 = (insn >> 12) & 7;
            switch(funct3) {
            case 0: /* fence */
                if (insn & 0xf00fff80)
                    goto illegal_insn;
                break;
            case 1: /* fence.i */
                if (insn != 0x0000100f)
                    goto illegal_insn;
                break;
            case 2: 
                capability_t cap;
                imm = (int32_t)insn >> 20;
                addr = s->reg[rs1] + imm;


                if (target_read_u64(s, &val, addr))
                    goto mmu_exception;
                if (rd != 0)
                    s->reg[rd] = val;

                if(target_read_cap(s, &cap, addr))
                    goto mmu_exception;

                s->cap[rd] = cap;
                break;
#if XLEN >= 128
            // case 2: /* lq */
            //     imm = (int32_t)insn >> 20;
            //     addr = s->reg[rs1] + imm;
            //     if (target_read_u128(s, &val, addr))
            //         goto mmu_exception;
            //     if (rd != 0)
            //         s->reg[rd] = val;
            //     break;
#endif
            default:
                goto illegal_insn;
            }
            NEXT_INSN;
        case 0x2f:
            funct3 = (insn >> 12) & 7;
#define OP_A(size)                                                      \
            {                                                           \
                uint ## size ##_t rval;                                 \
                                                                        \
                addr = s->reg[rs1];                                     \
                funct3 = insn >> 27;                                    \
                switch(funct3) {                                        \
                case 2: /* lr.w */                                      \
                    if (rs2 != 0)                                       \
                        goto illegal_insn;                              \
                    if (target_read_u ## size(s, &rval, addr))          \
                        goto mmu_exception;                             \
                    val = (int## size ## _t)rval;                       \
                    s->load_res = addr;                                 \
                    break;                                              \
                case 3: /* sc.w */                                      \
                    if (s->load_res == addr) {                          \
                        if (target_write_u ## size(s, addr, s->reg[rs2])) \
                            goto mmu_exception;                         \
                        val = 0;                                        \
                    } else {                                            \
                        val = 1;                                        \
                    }                                                   \
                    break;                                              \
                case 1: /* amiswap.w */                                 \
                case 0: /* amoadd.w */                                  \
                case 4: /* amoxor.w */                                  \
                case 0xc: /* amoand.w */                                \
                case 0x8: /* amoor.w */                                 \
                case 0x10: /* amomin.w */                               \
                case 0x14: /* amomax.w */                               \
                case 0x18: /* amominu.w */                              \
                case 0x1c: /* amomaxu.w */                              \
                    if (target_read_u ## size(s, &rval, addr))          \
                        goto mmu_exception;                             \
                    val = (int## size ## _t)rval;                       \
                    val2 = s->reg[rs2];                                 \
                    switch(funct3) {                                    \
                    case 1: /* amiswap.w */                             \
                        break;                                          \
                    case 0: /* amoadd.w */                              \
                        val2 = (int## size ## _t)(val + val2);          \
                        break;                                          \
                    case 4: /* amoxor.w */                              \
                        val2 = (int## size ## _t)(val ^ val2);          \
                        break;                                          \
                    case 0xc: /* amoand.w */                            \
                        val2 = (int## size ## _t)(val & val2);          \
                        break;                                          \
                    case 0x8: /* amoor.w */                             \
                        val2 = (int## size ## _t)(val | val2);          \
                        break;                                          \
                    case 0x10: /* amomin.w */                           \
                        if ((int## size ## _t)val < (int## size ## _t)val2) \
                            val2 = (int## size ## _t)val;               \
                        break;                                          \
                    case 0x14: /* amomax.w */                           \
                        if ((int## size ## _t)val > (int## size ## _t)val2) \
                            val2 = (int## size ## _t)val;               \
                        break;                                          \
                    case 0x18: /* amominu.w */                          \
                        if ((uint## size ## _t)val < (uint## size ## _t)val2) \
                            val2 = (int## size ## _t)val;               \
                        break;                                          \
                    case 0x1c: /* amomaxu.w */                          \
                        if ((uint## size ## _t)val > (uint## size ## _t)val2) \
                            val2 = (int## size ## _t)val;               \
                        break;                                          \
                    default:                                            \
                        goto illegal_insn;                              \
                    }                                                   \
                    if (target_write_u ## size(s, addr, val2))          \
                        goto mmu_exception;                             \
                    break;                                              \
                default:                                                \
                    goto illegal_insn;                                  \
                }                                                       \
            }

            switch(funct3) {
            case 2:
                OP_A(32);
                break;
#if XLEN >= 64
            case 3:
                OP_A(64);
                break;
#endif
#if XLEN >= 128
            case 4:
                OP_A(128);
                break;
#endif
            default:
                goto illegal_insn;
            }
            if (rd != 0)
                s->reg[rd] = val;
            NEXT_INSN;
#if FLEN > 0
            /* FPU */
        case 0x07: /* fp load */
            if (s->fs == 0)
                goto illegal_insn;
            funct3 = (insn >> 12) & 7;
            imm = (int32_t)insn >> 20;
            addr = s->reg[rs1] + imm;
            switch(funct3) {
            case 2: /* flw */
                {
                    uint32_t rval;
                    if (target_read_u32(s, &rval, addr))
                        goto mmu_exception;
                    s->fp_reg[rd] = rval | F32_HIGH;
                }
                break;
#if FLEN >= 64
            case 3: /* fld */
                {
                    uint64_t rval;
                    if (target_read_u64(s, &rval, addr))
                        goto mmu_exception;
                    s->fp_reg[rd] = rval | F64_HIGH;
                }
                break;
#endif 
#if FLEN >= 128
            case 4: /* flq */
                {
                    uint128_t rval;
                    if (target_read_u128(s, &rval, addr))
                        goto mmu_exception;
                    s->fp_reg[rd] = rval;
                }
                break;
#endif
            default:
                goto illegal_insn;
            }
            s->fs = 3;
            NEXT_INSN;
        case 0x27: /* fp store */
            if (s->fs == 0)
                goto illegal_insn;
            funct3 = (insn >> 12) & 7;
            imm = rd | ((insn >> (25 - 5)) & 0xfe0);
            imm = (imm << 20) >> 20;
            addr = s->reg[rs1] + imm;
            switch(funct3) {
            case 2: /* fsw */
                if (target_write_u32(s, addr, s->fp_reg[rs2]))
                    goto mmu_exception;
                break;
#if FLEN >= 64
            case 3: /* fsd */
                if (target_write_u64(s, addr, s->fp_reg[rs2]))
                    goto mmu_exception;
                break;
#endif
#if FLEN >= 128
            case 4: /* fsq */
                if (target_write_u128(s, addr, s->fp_reg[rs2]))
                    goto mmu_exception;
                break;
#endif
            default:
                goto illegal_insn;
            }
            NEXT_INSN;
        case 0x43: /* fmadd */
            if (s->fs == 0)
                goto illegal_insn;
            funct3 = (insn >> 25) & 3;
            rs3 = insn >> 27;
            rm = get_insn_rm(s, (insn >> 12) & 7);
            if (rm < 0)
                goto illegal_insn;
            switch(funct3) {
            case 0:
                s->fp_reg[rd] = fma_sf32(s->fp_reg[rs1], s->fp_reg[rs2],
                                         s->fp_reg[rs3], rm, &s->fflags) | F32_HIGH;
                break;
#if FLEN >= 64
            case 1:
                s->fp_reg[rd] = fma_sf64(s->fp_reg[rs1], s->fp_reg[rs2],
                                         s->fp_reg[rs3], rm, &s->fflags) | F64_HIGH;
                break;
#endif
#if FLEN >= 128
            case 3:
                s->fp_reg[rd] = fma_sf128(s->fp_reg[rs1], s->fp_reg[rs2],
                                          s->fp_reg[rs3], rm, &s->fflags);
                break;
#endif
            default:
                goto illegal_insn;
            }
            s->fs = 3;
            NEXT_INSN;
        case 0x47: /* fmsub */
            if (s->fs == 0)
                goto illegal_insn;
            funct3 = (insn >> 25) & 3;
            rs3 = insn >> 27;
            rm = get_insn_rm(s, (insn >> 12) & 7);
            if (rm < 0)
                goto illegal_insn;
            switch(funct3) {
            case 0:
                s->fp_reg[rd] = fma_sf32(s->fp_reg[rs1],
                                         s->fp_reg[rs2],
                                         s->fp_reg[rs3] ^ FSIGN_MASK32,
                                         rm, &s->fflags) | F32_HIGH;
                break;
#if FLEN >= 64
            case 1:
                s->fp_reg[rd] = fma_sf64(s->fp_reg[rs1],
                                         s->fp_reg[rs2],
                                         s->fp_reg[rs3] ^ FSIGN_MASK64,
                                         rm, &s->fflags) | F64_HIGH;
                break;
#endif
#if FLEN >= 128
            case 3:
                s->fp_reg[rd] = fma_sf128(s->fp_reg[rs1],
                                          s->fp_reg[rs2],
                                          s->fp_reg[rs3] ^ FSIGN_MASK128,
                                          rm, &s->fflags);
                break;
#endif
            default:
                goto illegal_insn;
            }
            s->fs = 3;
            NEXT_INSN;
        case 0x4b: /* fnmsub */
            if (s->fs == 0)
                goto illegal_insn;
            funct3 = (insn >> 25) & 3;
            rs3 = insn >> 27;
            rm = get_insn_rm(s, (insn >> 12) & 7);
            if (rm < 0)
                goto illegal_insn;
            switch(funct3) {
            case 0:
                s->fp_reg[rd] = fma_sf32(s->fp_reg[rs1] ^ FSIGN_MASK32,
                                         s->fp_reg[rs2],
                                         s->fp_reg[rs3],
                                         rm, &s->fflags) | F32_HIGH;
                break;
#if FLEN >= 64
            case 1:
                s->fp_reg[rd] = fma_sf64(s->fp_reg[rs1] ^ FSIGN_MASK64,
                                         s->fp_reg[rs2],
                                         s->fp_reg[rs3],
                                         rm, &s->fflags) | F64_HIGH;
                break;
#endif
#if FLEN >= 128
            case 3:
                s->fp_reg[rd] = fma_sf128(s->fp_reg[rs1] ^ FSIGN_MASK128,
                                          s->fp_reg[rs2],
                                          s->fp_reg[rs3],
                                          rm, &s->fflags);
                break;
#endif
            default:
                goto illegal_insn;
            }
            s->fs = 3;
            NEXT_INSN;
        case 0x4f: /* fnmadd */
            if (s->fs == 0)
                goto illegal_insn;
            funct3 = (insn >> 25) & 3;
            rs3 = insn >> 27;
            rm = get_insn_rm(s, (insn >> 12) & 7);
            if (rm < 0)
                goto illegal_insn;
            switch(funct3) {
            case 0:
                s->fp_reg[rd] = fma_sf32(s->fp_reg[rs1] ^ FSIGN_MASK32,
                                         s->fp_reg[rs2],
                                         s->fp_reg[rs3] ^ FSIGN_MASK32,
                                         rm, &s->fflags) | F32_HIGH;
                break;
#if FLEN >= 64
            case 1:
                s->fp_reg[rd] = fma_sf64(s->fp_reg[rs1] ^ FSIGN_MASK64,
                                         s->fp_reg[rs2],
                                         s->fp_reg[rs3] ^ FSIGN_MASK64,
                                         rm, &s->fflags) | F64_HIGH;
                break;
#endif
#if FLEN >= 128
            case 3:
                s->fp_reg[rd] = fma_sf128(s->fp_reg[rs1] ^ FSIGN_MASK128,
                                          s->fp_reg[rs2],
                                          s->fp_reg[rs3] ^ FSIGN_MASK128,
                                          rm, &s->fflags);
                break;
#endif
            default:
                goto illegal_insn;
            }
            s->fs = 3;
            NEXT_INSN;
        case 0x53:
            if (s->fs == 0)
                goto illegal_insn;
            imm = insn >> 25;
            rm = (insn >> 12) & 7;
            switch(imm) {

#define F_SIZE 32
#include "riscv_cpu_fp_template.h"
#if FLEN >= 64
#define F_SIZE 64
#include "riscv_cpu_fp_template.h"
#endif
#if FLEN >= 128
#define F_SIZE 128
#include "riscv_cpu_fp_template.h"
#endif

            default:
                goto illegal_insn;
            }
            NEXT_INSN;
#endif
        default:
            goto illegal_insn;
        }
        /* update PC for next instruction */
    jump_insn: ;
    } /* end of main loop */
 illegal_insn:
    s->pending_exception = CAUSE_ILLEGAL_INSTRUCTION;
    s->pending_tval = insn;
 mmu_exception:
 exception:
    s->pc = GET_PC();
    if (s->pending_exception >= 0) {
        /* Note: the idea is that one exception counts for one cycle. */
        s->n_cycles--; 
        raise_exception2(s, s->pending_exception, s->pending_tval);
    }
    /* we exit because XLEN may have changed */
 done_interp:
the_end:
    s->insn_counter = GET_INSN_COUNTER();

    // printf("done interp %lx int=%x mstatus=%lx prv=%d mcause=%d sepc=%d\n",
    //        (uint64_t)s->insn_counter, s->mip & s->mie, (uint64_t)s->mstatus,
    //        s->priv, s->mcause, s->mepc);

}

#undef uintx_t
#undef intx_t
#undef XLEN
#undef OP_A

/*
 * Fujitsu FR (FR60Lite / Milbeaut MB91683) CPU — QEMU target.
 * 32-bit, big-endian, RISC-ish with branch delay slots and a banked
 * system/user stack pointer (r15). Modelled faithfully on the reference
 * Python emulator fremu.py (k10d-re): same register file, PS layout, and
 * delayed-transfer semantics.
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#ifndef FRN_CPU_H
#define FRN_CPU_H

#include "cpu-qom.h"
#include "exec/cpu-common.h"
#include "exec/cpu-interrupt.h"
#include "exec/cpu-defs.h"

#define FRN_NGPR 16          /* r0..r15 ; r15 is the active (banked) stack ptr */

/*
 * PS (program status) layout as packed by fremu.pack_ps():
 *   bit5 = S (stack select: 0 => r15 is SSP, 1 => USP)
 *   bit4 = I (interrupt enable)
 *   bit3 = N, bit2 = Z, bit1 = V, bit0 = C   (CCR)
 *   bits 16..20 = ILM (interrupt level mask), reset value 0x0F
 * We keep the condition bits decomposed (like fremu) for a correct first
 * port; a lazy cc_op optimisation can come later without changing semantics.
 */
typedef struct CPUArchState {
    uint32_t regs[FRN_NGPR];  /* general registers; regs[15] = active SP */
    uint32_t pc;

    /* dedicated / system registers */
    uint32_t rp;              /* return pointer */
    uint32_t tbr;             /* trap base register (vector table top = tbr+0x3fc) */
    uint32_t ssp;             /* banked system stack pointer */
    uint32_t usp;             /* banked user stack pointer   */
    uint32_t mdh, mdl;        /* multiply/divide result high/low */
    uint32_t bp, fcr, esr, dbr;  /* other special regs (SR_NAMES 6,7,8,15) */

    /* program status (kept decomposed) */
    uint32_t cc_n, cc_z, cc_v, cc_c;  /* condition flags, each 0/1 */
    uint32_t sf;              /* S: stack select */
    uint32_t i_flag;          /* I: interrupt enable */
    uint32_t ilm;             /* interrupt level mask (reset 0x0f) */

    /*
     * Branch delay slot. FR delayed transfers (ret:D, call:D, jmp:D, bra:D,
     * b<cc>:D, ldi:D ...) take effect AFTER the following instruction. In TCG
     * this is handled like MicroBlaze's btarget/D_FLAG: when delay_armed is
     * set, the instruction in the delay slot executes, then control transfers
     * to delay_pc. Modelled explicitly here for the interpreter-parity bring-up.
     */
    uint32_t delay_pc;
    uint32_t delay_armed;

    /* pending hardware interrupt bookkeeping (Milbeaut reload timer + DICR) */
    uint32_t pending_vec;
    uint32_t pending_level;
    uint32_t pending_valid;      /* fremu pending_irq is-not-None */
    uint32_t dicr_pending;       /* FR delayed interrupt (DICR bit0) */

    /* Milbeaut reload-timer ch0 (fremu model) */
    uint32_t tmr_running;
    uint32_t tmr_count;
    uint32_t tmr_reload;
    uint32_t tmr_div;

    /* Watch-counter / RTC (vec41 / ICR25). Autonomous periodic IRQ source whose
     * ISR (FUN_104fae06) drives the clock tick and the "Date Adjust" first-boot
     * screen. Device regs live at 0x40090000 (read 0xffffffff via background
     * MMIO, so the ISR's status/clock-set bit-15 checks pass); the only thing the
     * firmware needs that fremu/our base lacked is the IRQ actually firing. */
    uint32_t wc_div;
    uint32_t wc_pending;
} CPUFRNState;

struct ArchCPU {
    CPUState parent_obj;
    CPUFRNState env;
};

struct FRNCPUClass {
    CPUClass parent_class;
    DeviceRealize parent_realize;
    ResettablePhases parent_phases;
};

#define CPU_RESOLVING_TYPE TYPE_FRN_CPU

/* FR has no MMU on MB91683 — single flat address space. */
#define MMU_USER_IDX 0

void frn_cpu_do_interrupt(CPUState *cs);
bool frn_cpu_exec_interrupt(CPUState *cs, int int_req);
hwaddr frn_cpu_get_phys_page_debug(CPUState *cs, vaddr addr);
void frn_cpu_dump_state(CPUState *cpu, FILE *f, int flags);
int frn_cpu_gdb_read_register(CPUState *cpu, GByteArray *buf, int reg);
int frn_cpu_gdb_write_register(CPUState *cpu, uint8_t *buf, int reg);

void frn_tcg_init(void);
void frn_translate_code(CPUState *cs, TranslationBlock *tb,
                        int *max_insns, vaddr pc, void *host_pc);

/* Pack/unpack PS between the decomposed fields and the 32-bit PS word,
 * matching fremu.pack_ps()/unpack_ps() bit layout exactly. */
static inline uint32_t frn_pack_ps(const CPUFRNState *env)
{
    return ((env->sf & 1) << 5) | ((env->i_flag & 1) << 4)
         | ((env->cc_n & 1) << 3) | ((env->cc_z & 1) << 2)
         | ((env->cc_v & 1) << 1) | (env->cc_c & 1)
         | ((env->ilm & 0x1f) << 16);
}

static inline void frn_unpack_ps(CPUFRNState *env, uint32_t ps)
{
    env->sf     = (ps >> 5) & 1;
    env->i_flag = (ps >> 4) & 1;
    env->cc_n   = (ps >> 3) & 1;
    env->cc_z   = (ps >> 2) & 1;
    env->cc_v   = (ps >> 1) & 1;
    env->cc_c   = ps & 1;
    env->ilm    = (ps >> 16) & 0x1f;
}

#endif

/*
 * Fujitsu FR translation — interpreter-bridge bring-up.
 * Each guest instruction is emitted as a call to helper_frn_interp(), which
 * executes one FR instruction in C (op_helper.c, a faithful port of fremu) and
 * updates env->pc (incl. the delay slot). One instruction per TB for now; this
 * runs the firmware correctly through QEMU's memory/MMIO/device model while the
 * hot paths are migrated to native TCG later.
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include "cpu.h"
#include "tcg/tcg-op.h"
#include "exec/translator.h"
#include "exec/translation-block.h"
#include "exec/target_page.h"
#include "accel/tcg/cpu-ops.h"
#include "exec/helper-proto.h"
#include "exec/helper-gen.h"

#define HELPER_H "helper.h"
#include "exec/helper-info.c.inc"
#undef  HELPER_H

typedef struct DisasContext {
    DisasContextBase base;
} DisasContext;

static void frn_tr_init_disas_context(DisasContextBase *dcb, CPUState *cs)
{
}

static void frn_tr_tb_start(DisasContextBase *dcb, CPUState *cs)
{
}

static void frn_tr_insn_start(DisasContextBase *dcb, CPUState *cs)
{
    tcg_gen_insn_start(dcb->pc_next, 0, 0);
}

static void frn_tr_translate_insn(DisasContextBase *dcb, CPUState *cs)
{
    /* Execute one FR instruction in the C interpreter; it sets env->pc. */
    gen_helper_frn_interp(tcg_env);
    dcb->pc_next += 2;              /* nominal TB size (>=1 byte) */
    dcb->is_jmp = DISAS_NORETURN;   /* one instruction per TB */
}

static void frn_tr_tb_stop(DisasContextBase *dcb, CPUState *cs)
{
    /* env->pc already updated by the helper; just leave the TB. */
    tcg_gen_exit_tb(NULL, 0);
}

static const TranslatorOps frn_tr_ops = {
    .init_disas_context = frn_tr_init_disas_context,
    .tb_start           = frn_tr_tb_start,
    .insn_start         = frn_tr_insn_start,
    .translate_insn     = frn_tr_translate_insn,
    .tb_stop            = frn_tr_tb_stop,
};

void frn_translate_code(CPUState *cs, TranslationBlock *tb,
                        int *max_insns, vaddr pc, void *host_pc)
{
    DisasContext dc;
    translator_loop(cs, tb, max_insns, pc, host_pc, &frn_tr_ops, &dc.base,
                    TCG_TYPE_VA);
}

void frn_tcg_init(void)
{
}

/*
 * Fujitsu FR helpers — SKELETON (interrupts + state dump).
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include "qemu/qemu-print.h"
#include "cpu.h"

void frn_cpu_dump_state(CPUState *cs, FILE *f, int flags)
{
    CPUFRNState *env = cpu_env(cs);
    int i;

    qemu_fprintf(f, "pc=%08x rp=%08x tbr=%08x ilm=%u ps=%08x\n",
                 env->pc, env->rp, env->tbr, env->ilm, frn_pack_ps(env));
    for (i = 0; i < FRN_NGPR; i++) {
        qemu_fprintf(f, "r%-2d=%08x%s", i, env->regs[i],
                     (i % 4) == 3 ? "\n" : " ");
    }
    qemu_fprintf(f, "N=%u Z=%u V=%u C=%u S=%u I=%u mdh=%08x mdl=%08x\n",
                 env->cc_n, env->cc_z, env->cc_v, env->cc_c,
                 env->sf, env->i_flag, env->mdh, env->mdl);
}

#ifndef CONFIG_USER_ONLY
void frn_cpu_do_interrupt(CPUState *cs)
{
    /* TODO: port fremu _deliver_pending_irq: push PS+PC to SSP, set ILM to the
     * accepted level, vector via tbr+0x3fc-vec*4. Placeholder for bring-up. */
    cs->exception_index = -1;
}

bool frn_cpu_exec_interrupt(CPUState *cs, int interrupt_request)
{
    /* TODO: accept iff ILM > request level (FR rule). Placeholder. */
    return false;
}
#endif

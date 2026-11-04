/*
 * Fujitsu FR gdb stub — 16 GPR + pc.
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include "cpu.h"
#include "gdbstub/helpers.h"

int frn_cpu_gdb_read_register(CPUState *cs, GByteArray *mem_buf, int n)
{
    CPUFRNState *env = cpu_env(cs);

    if (n < FRN_NGPR) {
        return gdb_get_reg32(mem_buf, env->regs[n]);
    }
    if (n == FRN_NGPR) {          /* pc */
        return gdb_get_reg32(mem_buf, env->pc);
    }
    return 0;
}

int frn_cpu_gdb_write_register(CPUState *cs, uint8_t *mem_buf, int n)
{
    CPUFRNState *env = cpu_env(cs);
    uint32_t tmp = ldl_p(mem_buf);

    if (n < FRN_NGPR) {
        env->regs[n] = tmp;
        return 4;
    }
    if (n == FRN_NGPR) {
        env->pc = tmp;
        return 4;
    }
    return 0;
}

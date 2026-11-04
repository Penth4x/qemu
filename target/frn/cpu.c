/*
 * Fujitsu FR (FR60Lite / Milbeaut MB91683) CPU — QEMU target.
 * Modelled on the reference emulator fremu.py (k10d-re).
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qapi/error.h"
#include "cpu.h"
#include "qemu/module.h"
#include "hw/core/qdev-properties.h"
#include "exec/gdbstub.h"
#include "exec/translation-block.h"
#include "exec/cputlb.h"
#include "exec/page-protection.h"
#include "exec/target_page.h"
#include "accel/tcg/cpu-ops.h"
#include "tcg/tcg.h"

static void frn_cpu_set_pc(CPUState *cs, vaddr value)
{
    FRNCPU *cpu = FRN_CPU(cs);
    cpu->env.pc = value;
    cpu->env.delay_armed = 0;
}

static vaddr frn_cpu_get_pc(CPUState *cs)
{
    return FRN_CPU(cs)->env.pc;
}

static TCGTBCPUState frn_get_tb_cpu_state(CPUState *cs)
{
    CPUFRNState *env = cpu_env(cs);
    return (TCGTBCPUState){
        .pc = env->pc,
        .flags = env->delay_armed ? 1 : 0,
        .cs_base = env->delay_armed ? env->delay_pc : 0,
    };
}

static void frn_cpu_synchronize_from_tb(CPUState *cs, const TranslationBlock *tb)
{
    FRNCPU *cpu = FRN_CPU(cs);
    tcg_debug_assert(!tcg_cflags_has(cs, CF_PCREL));
    cpu->env.pc = tb->pc;
}

static void frn_restore_state_to_opc(CPUState *cs, const TranslationBlock *tb,
                                     const uint64_t *data)
{
    FRNCPU *cpu = FRN_CPU(cs);
    cpu->env.pc = data[0];
    cpu->env.delay_armed = data[1] & 1;
    cpu->env.delay_pc = data[2];
}

static int frn_cpu_mmu_index(CPUState *cs, bool ifetch)
{
    return MMU_USER_IDX;   /* no MMU on MB91683: single flat space */
}

#ifndef CONFIG_USER_ONLY
static bool frn_cpu_has_work(CPUState *cs)
{
    return cpu_test_interrupt(cs, CPU_INTERRUPT_HARD);
}

/* FR has no MMU: identity-map every access so softmmu never faults. */
static bool frn_cpu_tlb_fill(CPUState *cs, vaddr address, int size,
                             MMUAccessType access_type, int mmu_idx,
                             bool probe, uintptr_t retaddr)
{
    hwaddr paddr = address & TARGET_PAGE_MASK;
    tlb_set_page(cs, address & TARGET_PAGE_MASK, paddr,
                 PAGE_READ | PAGE_WRITE | PAGE_EXEC,
                 mmu_idx, TARGET_PAGE_SIZE);
    return true;
}
#endif

static void frn_cpu_reset_hold(Object *obj, ResetType type)
{
    CPUState *cs = CPU(obj);
    FRNCPU *cpu = FRN_CPU(cs);
    FRNCPUClass *fcc = FRN_CPU_GET_CLASS(obj);
    CPUFRNState *env = &cpu->env;

    if (fcc->parent_phases.hold) {
        fcc->parent_phases.hold(obj, type);
    }

    memset(env, 0, sizeof(*env));
    /* FR reset state (fremu.py): ILM = 0x0f; the board sets pc + r15 after
     * loading the firmware image (K10D: entry 0x10008000, r15 0x8003F000). */
    env->ilm = 0x0f;
}

static void frn_disas_set_info(const CPUState *cpu, disassemble_info *info)
{
    info->mach = bfd_arch_unknown;
    info->endian = BFD_ENDIAN_BIG;
}

static void frn_cpu_realizefn(DeviceState *dev, Error **errp)
{
    CPUState *cs = CPU(dev);
    FRNCPUClass *fcc = FRN_CPU_GET_CLASS(dev);
    Error *local_err = NULL;

    cpu_common_realize(cs, &local_err);
    if (local_err != NULL) {
        error_propagate(errp, local_err);
        return;
    }
    qemu_init_vcpu(cs);
    cpu_reset(cs);
    fcc->parent_realize(dev, errp);
}

static ObjectClass *frn_cpu_class_by_name(const char *cpu_model)
{
    return object_class_by_name(TYPE_FRN_CPU);
}

#ifndef CONFIG_USER_ONLY
#include "hw/core/sysemu-cpu-ops.h"

static const struct SysemuCPUOps frn_sysemu_ops = {
    .has_work = frn_cpu_has_work,
};
#endif

static const TCGCPUOps frn_tcg_ops = {
    .guest_default_memory_order = TCG_MO_ALL,
    .mttcg_supported = false,

    .initialize = frn_tcg_init,
    .translate_code = frn_translate_code,
    .get_tb_cpu_state = frn_get_tb_cpu_state,
    .synchronize_from_tb = frn_cpu_synchronize_from_tb,
    .restore_state_to_opc = frn_restore_state_to_opc,
    .mmu_index = frn_cpu_mmu_index,

#ifndef CONFIG_USER_ONLY
    .tlb_fill = frn_cpu_tlb_fill,
    .pointer_wrap = cpu_pointer_wrap_uint32,
    .cpu_exec_interrupt = frn_cpu_exec_interrupt,
    .cpu_exec_reset = cpu_reset,
    .do_interrupt = frn_cpu_do_interrupt,
#endif
};

static void frn_cpu_class_init(ObjectClass *oc, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    CPUClass *cc = CPU_CLASS(oc);
    FRNCPUClass *fcc = FRN_CPU_CLASS(oc);
    ResettableClass *rc = RESETTABLE_CLASS(oc);

    device_class_set_parent_realize(dc, frn_cpu_realizefn, &fcc->parent_realize);
    resettable_class_set_parent_phases(rc, NULL, frn_cpu_reset_hold, NULL,
                                       &fcc->parent_phases);

    cc->class_by_name = frn_cpu_class_by_name;
    cc->dump_state = frn_cpu_dump_state;
    cc->set_pc = frn_cpu_set_pc;
    cc->get_pc = frn_cpu_get_pc;
    cc->gdb_read_register = frn_cpu_gdb_read_register;
    cc->gdb_write_register = frn_cpu_gdb_write_register;

#ifndef CONFIG_USER_ONLY
    cc->sysemu_ops = &frn_sysemu_ops;
#endif
    cc->disas_set_info = frn_disas_set_info;
    cc->tcg_ops = &frn_tcg_ops;
}

static const TypeInfo frn_cpu_type_info = {
    .name = TYPE_FRN_CPU,
    .parent = TYPE_CPU,
    .instance_size = sizeof(FRNCPU),
    .instance_align = __alignof(FRNCPU),
    .class_size = sizeof(FRNCPUClass),
    .class_init = frn_cpu_class_init,
};

static void frn_cpu_register_types(void)
{
    type_register_static(&frn_cpu_type_info);
}

type_init(frn_cpu_register_types)

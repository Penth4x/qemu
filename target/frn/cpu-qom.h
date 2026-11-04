/*
 * Fujitsu FR CPU QOM header (target agnostic)
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#ifndef QEMU_FRN_CPU_QOM_H
#define QEMU_FRN_CPU_QOM_H

#include "hw/core/cpu.h"

#define TYPE_FRN_CPU "frn-cpu"

OBJECT_DECLARE_CPU_TYPE(FRNCPU, FRNCPUClass, FRN_CPU)

#endif

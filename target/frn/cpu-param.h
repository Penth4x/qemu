/*
 * Fujitsu FR (FR60Lite / Milbeaut MB91683) CPU parameters for QEMU.
 * 32-bit, big-endian, RISC-ish with branch delay slots.
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#ifndef FRN_CPU_PARAM_H
#define FRN_CPU_PARAM_H

#define TARGET_PHYS_ADDR_SPACE_BITS 32
#define TARGET_VIRT_ADDR_SPACE_BITS 32
/* FR has no MMU on the MB91683; flat 32-bit space. 4K pages for QEMU softmmu. */
#define TARGET_PAGE_BITS 12

#endif

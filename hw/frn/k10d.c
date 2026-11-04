/*
 * Pentax K10D (Fujitsu Milbeaut MB91683 / FR60Lite) bare-metal board.
 * Minimal bring-up board for the K10D firmware (FWDC162B.BIN). Maps the ROM,
 * SDRAM and work RAM, loads the firmware with -bios, and enters at the known
 * K10D entry point. Peripherals (Milbeaut timer, the stateful 0x67000000 block,
 * LCD) are added incrementally; unmapped MMIO reads-as-zero via an unimplemented
 * catch region for bring-up.
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qapi/error.h"
#include "hw/core/boards.h"
#include "hw/core/loader.h"
#include "system/address-spaces.h"
#include "system/memory.h"
#include "cpu.h"

/*
 * Background MMIO: everything that is not RAM/ROM reads as 0xffffffff and
 * ignores writes — matching fremu.py's mmio_default ("all ready bits set",
 * benign for status polls). Stateful peripherals (timer, 0x67000000 block,
 * LCD) are added later as higher-priority device regions over this.
 */
static uint64_t frn_bg_read(void *opaque, hwaddr addr, unsigned size)
{
    /* fremu: MMIO ranges read as all-ones (mmio_default); everything else is
     * RAM that reads 0 when unwritten. */
    if ((addr >= 0x01000000 && addr < 0x10000000) ||
        (addr >= 0x40000000 && addr < 0x50000000) ||
        (addr >= 0x67000000 && addr < 0x67001000)) {
        return 0xffffffffffffffffULL;
    }
    return 0;
}
static void frn_bg_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
    /*
     * Display-controller write logging (inspectability). FRN_LOG_DISP logs every
     * write into the 0x40000000 peripheral window — in particular the OSDC plane
     * base registers (0x40000000/0x40004000/0x40008000) and palette (~0x40040390)
     * — so we can find where the firmware points the real (planar) framebuffer
     * and recover the CLUT. Values that look like SDRAM pointers are flagged.
     */
    static int on = -1;
    if (on < 0) {
        on = getenv("FRN_LOG_DISP") ? 1 : 0;
    }
    if (on && addr >= 0x40000000 && addr < 0x40100000) {
        const char *tag = "";
        if ((val & 0xff000000u) == 0x80000000u || (val & 0xff000000u) == 0x6a000000u) {
            tag = "  <-- RAM ptr";
        }
        fprintf(stderr, "[disp] wr 0x%08x = 0x%08x (sz%u)%s\n",
                (uint32_t)addr, (uint32_t)val, size, tag);
    }
}
static const MemoryRegionOps frn_bg_ops = {
    .read = frn_bg_read,
    .write = frn_bg_write,
    .endianness = DEVICE_BIG_ENDIAN,
    .valid.min_access_size = 1,
    .valid.max_access_size = 4,
};

/*
 * 0x67000000 body-control peripheral (fremu p67 model): a 0x1000 register file.
 * Reads return the stored bytes (big-endian). Writes store, then force the
 * status/sequencer block to "all ops complete" (instant completion): status
 * 0x24=0x01F70F00, busy block 0x28-0x33 cleared, 0x2c-halfword bit1 (0x2d&0x02)
 * set as the wait-for-set ack. This is the device-ready handshake the boot polls.
 */
static uint8_t frn_p67[0x1000];

/*
 * Frame-sync (VSYNC) model. The OSDC overlays graphics onto an external video
 * frame whose vertical sync (VSYNC, a real input pin on the MB91610) arrives
 * ~60 Hz. The K10D's custom 0x67000000 block exposes the frame state at +0x30:
 * bit15 = a frame is available, bit0 = frame parity (toggles each frame so the
 * firmware's "wait for the next frame" edge check advances). Without this the
 * display/menu draw loop never runs. Synthesised in the read path because the
 * write handler clears 0x28-0x33. The parity advances on each poll so a busy
 * wait makes progress; good enough to drive the display pipeline for inspection.
 */
static uint64_t frn_p67_read(void *opaque, hwaddr off, unsigned size)
{
    static int p67log = -1;
    if (p67log < 0) p67log = getenv("FRN_LOG_P67") ? 1 : 0;
    if (p67log && !(off >= 0x24 && off <= 0x33)) {   /* skip the status/handshake block */
        uint64_t rv = 0;
        for (unsigned i = 0; i < size; i++) rv = (rv << 8) | frn_p67[(off + i) & 0xfff];
        fprintf(stderr, "[p67rd] off 0x%03x sz%u = 0x%0*llx\n",
                (unsigned)off, size, size * 2, (unsigned long long)rv);
    }
    if (off <= 0x31 && off + size > 0x30) {
        static uint32_t frame;
        frame++;
        uint16_t sync = 0x8000 | (frame & 1);   /* ready + toggling parity */
        frn_p67[0x30] = sync >> 8;
        frn_p67[0x31] = sync & 0xff;
    }
    uint64_t v = 0;
    for (unsigned i = 0; i < size; i++) {
        v = (v << 8) | frn_p67[(off + i) & 0xfff];   /* big-endian */
    }
    return v;
}
static void frn_p67_write(void *opaque, hwaddr off, uint64_t val, unsigned size)
{
    for (unsigned i = 0; i < size; i++) {
        frn_p67[(off + size - 1 - i) & 0xfff] = (val >> (8 * i)) & 0xff;
    }
    frn_p67[0x24] = 0x01; frn_p67[0x25] = 0xf7;
    frn_p67[0x26] = 0x0f; frn_p67[0x27] = 0x00;
    for (int b = 0x28; b < 0x34; b++) {
        frn_p67[b] = 0;
    }
    frn_p67[0x2d] |= 0x02;
}
static const MemoryRegionOps frn_p67_ops = {
    .read = frn_p67_read,
    .write = frn_p67_write,
    .endianness = DEVICE_BIG_ENDIAN,
    .valid.min_access_size = 1,
    .valid.max_access_size = 4,
};

/*
 * Watch-counter / RTC device at 0x40090000. The ISR (FUN_104fae06) reads:
 *   +0x06 bit15 : interrupt pending (acked by writing 0x8000) -> keep asserted
 *   +0x04 bit15 : "is the clock set?"  First boot = UNSET (bit15=0), which is
 *                 what makes the firmware raise the "Date Adjust" screen. Modeled
 *                 explicitly here rather than inheriting the 0xffffffff background
 *                 (which read as clock-SET and drove the wrong, time-running
 *                 branch, posting event 0x80000013 thousands of times).
 */
static uint64_t frn_wc_read(void *opaque, hwaddr off, unsigned size)
{
    uint8_t reg[0x10] = { 0 };
    reg[0x06] = 0x80;              /* +0x06 = 0x8000: IRQ pending */
    /* +0x04 bit15 = "clock set?". Default NOT set (first boot). Env override to
     * compare the clock-set branch (does it drive the rear-UI redraw?). */
    static int clkset = -1;
    if (clkset < 0) clkset = getenv("FRN_CLOCK_SET") ? 1 : 0;
    if (clkset) reg[0x04] = 0x80;  /* +0x04 = 0x8000: clock IS set */
    uint64_t v = 0;
    for (unsigned i = 0; i < size; i++) {
        v = (v << 8) | reg[(off + i) & 0xf];   /* big-endian */
    }
    return v;
}
static void frn_wc_write(void *opaque, hwaddr off, uint64_t val, unsigned size)
{
    /* ack (write 0x8000 to +0x06) is a no-op: the counter re-asserts each tick */
}
static const MemoryRegionOps frn_wc_ops = {
    .read = frn_wc_read,
    .write = frn_wc_write,
    .endianness = DEVICE_BIG_ENDIAN,
    .valid.min_access_size = 1,
    .valid.max_access_size = 4,
};

/* K10D memory map (from fremu.py / RE) */
#define K10D_ROM_BASE   0x10000000
#define K10D_ROM_SIZE   0x01000000      /* 16 MiB window (firmware ~8.4 MiB) */
#define K10D_SDRAM_BASE 0x80000000
#define K10D_SDRAM_SIZE 0x04000000      /* 64 MiB */
#define K10D_WRAM_BASE  0x6a000000
#define K10D_WRAM_SIZE  0x00100000      /* 1 MiB work RAM */
#define K10D_ENTRY      0x10008000
#define K10D_SP         0x8003F000

static void k10d_init(MachineState *machine)
{
    MemoryRegion *sysmem = get_system_memory();
    MemoryRegion *rom = g_new(MemoryRegion, 1);
    MemoryRegion *sdram = g_new(MemoryRegion, 1);
    MemoryRegion *wram = g_new(MemoryRegion, 1);
    FRNCPU *cpu;
    int sz;

    cpu = FRN_CPU(cpu_create(machine->cpu_type));

    /* Background default-MMIO over the whole 32-bit space (low priority). */
    MemoryRegion *bg = g_new(MemoryRegion, 1);
    memory_region_init_io(bg, NULL, &frn_bg_ops, NULL, "frn.mmio-default",
                          0x100000000ULL);
    memory_region_add_subregion_overlap(sysmem, 0, bg, -1);

    /* Low memory [0, 0x01000000): fremu treats this as RAM (control regs like
     * DICR 0x44, timer 0x48-0x4F, ICR table 0x440.. live here and must persist
     * across writes). Timer/DICR hardware side-effects are layered in the
     * interpreter helper. */
    MemoryRegion *lowram = g_new(MemoryRegion, 1);
    memory_region_init_ram(lowram, NULL, "k10d.lowram", 0x01000000, &error_fatal);
    memory_region_add_subregion(sysmem, 0, lowram);

    /* 0x67000000 body-control peripheral (stateful handshake). */
    frn_p67[0x24] = 0x01; frn_p67[0x25] = 0xf7;
    frn_p67[0x26] = 0x0f; frn_p67[0x27] = 0x00;
    frn_p67[0x2d] |= 0x02;
    MemoryRegion *p67 = g_new(MemoryRegion, 1);
    memory_region_init_io(p67, NULL, &frn_p67_ops, NULL, "frn.bodyctl", 0x1000);
    memory_region_add_subregion(sysmem, 0x67000000, p67);

    /* Watch-counter / RTC (clock-unset first-boot state) at 0x40090000. */
    MemoryRegion *wc = g_new(MemoryRegion, 1);
    memory_region_init_io(wc, NULL, &frn_wc_ops, NULL, "frn.watchcnt", 0x10);
    memory_region_add_subregion_overlap(sysmem, 0x40090000, wc, 1);

    /* ROM (firmware). Writable RAM-backed for bring-up simplicity. */
    memory_region_init_ram(rom, NULL, "k10d.rom", K10D_ROM_SIZE, &error_fatal);
    memory_region_add_subregion(sysmem, K10D_ROM_BASE, rom);

    memory_region_init_ram(sdram, NULL, "k10d.sdram", K10D_SDRAM_SIZE,
                           &error_fatal);
    memory_region_add_subregion(sysmem, K10D_SDRAM_BASE, sdram);

    memory_region_init_ram(wram, NULL, "k10d.wram", K10D_WRAM_SIZE,
                           &error_fatal);
    memory_region_add_subregion(sysmem, K10D_WRAM_BASE, wram);

    if (!machine->firmware) {
        error_report("k10d: supply the firmware with -bios FWDC162B.BIN");
        exit(1);
    }
    sz = load_image_targphys(machine->firmware, K10D_ROM_BASE, K10D_ROM_SIZE,
                             &error_fatal);
    if (sz < 0) {
        error_report("k10d: could not load firmware '%s'", machine->firmware);
        exit(1);
    }

    cpu->env.pc = K10D_ENTRY;
    cpu->env.regs[15] = K10D_SP;
}

static void k10d_machine_init(MachineClass *mc)
{
    mc->desc = "Pentax K10D (Fujitsu MB91683 / FR60Lite)";
    mc->init = k10d_init;
    mc->default_cpu_type = TYPE_FRN_CPU;
    mc->default_ram_size = K10D_SDRAM_SIZE;
    mc->no_parallel = 1;
    mc->no_floppy = 1;
    mc->no_cdrom = 1;
}

DEFINE_MACHINE("k10d", k10d_machine_init)

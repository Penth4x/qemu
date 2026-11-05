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
/* Unmapped-access trap (FRN_LOG_UNMAPPED): every access that falls through to the
 * background handler is to a region we have NOT modeled -- reads return a default
 * (all-ones or 0) and writes are DROPPED. Log each distinct address once, with the
 * firmware PC, so missing peripheral/RAM regions announce themselves instead of
 * silently misbehaving (Andrew d308). */
static inline uint32_t frn_cur_pc(void)
{
    return current_cpu ? FRN_CPU(current_cpu)->env.pc : 0;
}
static void frn_log_unmapped(const char *kind, uint32_t addr, uint32_t val, unsigned size)
{
    static int on = -1;
    if (on < 0) on = getenv("FRN_LOG_UNMAPPED") ? 1 : 0;
    if (!on) return;
    static uint32_t seen[2048]; static int ns, nlog;
    if (nlog > 16000) return;
    for (int i = 0; i < ns; i++) if (seen[i] == addr) return;   /* dedup by addr */
    if (ns < 2048) seen[ns++] = addr;
    /* tag: is it in the "all-ones default MMIO" window (partly expected) or truly dark? */
    int periph = (addr >= 0x40000000 && addr < 0x50000000) ||
                 (addr >= 0x67000000 && addr < 0x67001000);
    fprintf(stderr, "[UNMAPPED %s%s] 0x%08x = 0x%08x (sz%u) pc~0x%08x\n",
            kind, periph ? "/periph" : "/DARK", addr, val, size, frn_cur_pc());
    nlog++;
}

static uint64_t frn_bg_read(void *opaque, hwaddr addr, unsigned size)
{
    /* FRN_MMIO_ZERO=lo-hi : return 0 instead of all-ones in that range (test a
     * "first-boot blank persistent store" hypothesis for where the date-set flag
     * is sourced). */
    static long zlo = -2, zhi = 0;
    if (zlo == -2) {
        const char *s = getenv("FRN_MMIO_ZERO"); zlo = -1;
        if (s) { char *e; zlo = strtol(s, &e, 16); if (*e=='-') zhi = strtol(e+1, NULL, 16); }
    }
    if (zlo >= 0 && addr >= (uint64_t)zlo && addr < (uint64_t)zhi) {
        return 0;
    }
    /* FRN_LOG_RD=lo-hi : log each distinct read address in range (capped) to find
     * the key/button input poll register. */
    {
        static long rlo = -2, rhi = 0; static uint32_t seen[512]; static int ns, nlog;
        if (rlo == -2) { const char *s = getenv("FRN_LOG_RD"); rlo = -1;
            if (s) { char *e; rlo = strtol(s,&e,16); if (*e=='-') rhi = strtol(e+1,NULL,16); } }
        if (rlo >= 0 && addr >= (uint64_t)rlo && addr < (uint64_t)rhi && nlog < 4000) {
            int f = 0; for (int i=0;i<ns;i++) if (seen[i]==(uint32_t)addr){f=1;break;}
            if (!f && ns<512) { seen[ns++]=(uint32_t)addr;
                fprintf(stderr, "[rd] 0x%08x\n", (uint32_t)addr); nlog++; }
        }
    }
    /* FRN_KEYPULSE=addr:andmask:after:dur[,addr:...] — edge-triggered key
     * injection into the 0x40060000 GPIO key-port block. The key driver
     * (0x10451100-0x10451230) reads each 16-bit port every scan and detects a
     * press as an active-low HIGH->LOW transition (debounced over several
     * scans). A static FRN_FORCE can't make an edge, so we PULSE: counting reads
     * of the exact `addr`, for reads [after, after+dur) we return
     * (0xffff & ~andmask) (masked bits driven LOW = pressed); otherwise 0xffff
     * (released). That yields release->press->release so the debounce fires.
     * Units of after/dur = number of reads of that addr (~1 per frame scan). */
    {
        static int kp_init = 0;
        static uint32_t kp_a[8], kp_m[8]; static long kp_after[8], kp_dur[8], kp_cnt[8];
        static int kp_n = 0;
        if (!kp_init) { kp_init = 1;
            const char *s = getenv("FRN_KEYPULSE");
            while (s && *s && kp_n < 8) {
                char *e; uint32_t a = (uint32_t)strtoul(s, &e, 16);
                if (e == s || *e != ':') break;
                uint32_t m = (uint32_t)strtoul(e+1, &e, 16); if (*e==':') e++;
                long af = strtol(e, &e, 0); if (*e==':') e++;
                long du = strtol(e, &e, 0);
                kp_a[kp_n]=a; kp_m[kp_n]=m; kp_after[kp_n]=af; kp_dur[kp_n]=du; kp_cnt[kp_n]=0; kp_n++;
                s = (*e==',') ? e+1 : e;
            }
        }
        for (int i = 0; i < kp_n; i++) {
            if ((uint32_t)addr == kp_a[i]) {
                long c = kp_cnt[i]++;
                if (c >= kp_after[i] && c < kp_after[i] + kp_dur[i])
                    return (uint64_t)(0xffffu & ~kp_m[i]);
                return 0xffffu;
            }
        }
    }
    /* fremu: MMIO ranges read as all-ones (mmio_default); everything else is
     * RAM that reads 0 when unwritten. */
    if ((addr >= 0x01000000 && addr < 0x10000000) ||
        (addr >= 0x40000000 && addr < 0x50000000) ||
        (addr >= 0x67000000 && addr < 0x67001000)) {
        return 0xffffffffffffffffULL;
    }
    frn_log_unmapped("RD", (uint32_t)addr, 0, size);   /* truly-dark read -> 0 */
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
    frn_log_unmapped("WR", (uint32_t)addr, (uint32_t)val, size);  /* dropped write */
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
    /* FRN_P67BTN="off:val,off:val" : override p67 bytes on read (inject button
     * state). Lets us test whether the 0x67000000 chip is the button source and
     * find the MENU/4-way bits, to drive menus in-emulator. */
    static int btn_init = 0; static uint8_t btn_val[0x40]; static uint8_t btn_set[0x40];
    if (!btn_init) { btn_init = 1;
        const char *s = getenv("FRN_P67BTN");
        while (s && *s) { char *e; long o = strtol(s,&e,16); if (e==s||*e!=':') break;
            long v = strtol(e+1,&e,16); if (o>=0&&o<0x40){btn_val[o]=(uint8_t)v;btn_set[o]=1;}
            s = (*e==',')?e+1:e; }
    }
    if (off < 0x40) { for (unsigned i=0;i<size;i++) if (btn_set[(off+i)&0x3f]) {
        /* a byte in this access is overridden: build the value with overrides */
        uint64_t v=0; for (unsigned j=0;j<size;j++){ uint32_t a=(off+j)&0xfff;
            uint8_t b = (a<0x40 && btn_set[a])?btn_val[a]:frn_p67[a]; v=(v<<8)|b; }
        return v; } }
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
        /* 0x67000030 bit15 (0x8000) = "frame/screen ready". A prior model forced it
         * ALWAYS set, but the rear-UI draw guard FUN_1044b35e reads exactly this bit
         * to decide whether to draw the active screen -- and with it forced set, the
         * draw runs before any screen object exists (screenmgr+0x11c == NULL),
         * dereferences NULL and derails to pc 0x1c -> reset -> the boot reloop. On
         * real HW bit15 is 0 until the display pipeline is actually configured. Keep
         * the toggling parity (bit0) for frame-sync polls; leave bit15 clear unless
         * FRN_P67_READY forces it back (to compare the old behavior). */
        static int ready = -1;
        if (ready < 0) ready = getenv("FRN_P67_READY") ? 0x8000 : 0;
        uint16_t sync = (uint16_t)ready | (frame & 1);
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
#define K10D_SDRAM_SIZE 0x10000000      /* 256 MiB: firmware writes task stacks/TCB
                                         * pointers up to ~0x8fffffff (kernel init
                                         * pc 0x1000e858/e876); 64 MiB dropped them
                                         * -> corrupt kernel structs -> reloop (d308) */
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

    /* State/SRAM banks the firmware WRITES during app-main init and the peripheral
     * ISR handlers READ back (d308). Previously unmapped -> writes dropped, reads 0,
     * so every handler status-gate failed and no task ever woke. 0x6b000000 is a 2nd
     * SRAM bank adjacent to WRAM (written @app-main 0x10439558..); 0x5c000000 is a
     * display/peripheral state block (written @0x1043ec6e/0x10440488). Back them as
     * RAM so the firmware's own writes persist and the handlers read real state. */
    MemoryRegion *sram6b = g_new(MemoryRegion, 1);
    memory_region_init_ram(sram6b, NULL, "k10d.sram6b", 0x00100000, &error_fatal);
    memory_region_add_subregion(sysmem, 0x6b000000, sram6b);
    MemoryRegion *blk5c = g_new(MemoryRegion, 1);
    memory_region_init_ram(blk5c, NULL, "k10d.blk5c", 0x00100000, &error_fatal);
    memory_region_add_subregion(sysmem, 0x5c000000, blk5c);
    /* More dark regions the firmware uses (found via FRN_LOG_UNMAPPED, d308):
     * 0x50000000 written first in app-main (0x10439428, 3-channel controller);
     * 0x66000000 / 0x68000000 read by 0x1044b/0x104ab code. Back as RAM. */
    MemoryRegion *blk50 = g_new(MemoryRegion, 1);
    memory_region_init_ram(blk50, NULL, "k10d.blk50", 0x00100000, &error_fatal);
    memory_region_add_subregion(sysmem, 0x50000000, blk50);
    MemoryRegion *blk66 = g_new(MemoryRegion, 1);
    memory_region_init_ram(blk66, NULL, "k10d.blk66", 0x00100000, &error_fatal);
    memory_region_add_subregion(sysmem, 0x66000000, blk66);
    MemoryRegion *blk68 = g_new(MemoryRegion, 1);
    memory_region_init_ram(blk68, NULL, "k10d.blk68", 0x00100000, &error_fatal);
    memory_region_add_subregion(sysmem, 0x68000000, blk68);

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

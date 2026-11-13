/*
 * K10D image-processor block (0x40060000), operation engine only — behaviour model.
 *
 * What the firmware does with it (keypad_gpio_driver unit; the unit label predates this
 * analysis: the Nikon Hacker emulator calls the same Milbeaut block at 0x40060000 the
 * "main image processor component", and the K10D code below is not a key scanner):
 *  - parameters (0x104fe398 via 0x10459082..0x10459216):
 *      +0x80 control: operation/mode in the low bits, bit 14 = start (0x10459008)
 *      +0x82 two 5-bit fields, +0x84/+0x88 32-bit words,
 *      +0x8c/+0x8e strides (& 0x1ff0), +0x90 (& 0x1fff), +0x92 (& 0xfff),
 *      +0x94/+0x98 30-bit addresses = base + y*stride + x (source/destination rectangles),
 *      +0x9c bit 15 option
 *  - completion: interrupt status 0x40060032 (bits 0x04/0x08/0x20; the ISR path reads it
 *    and writes the same bits back to clear: 0x104520f0 / 0x10452100), enable mask
 *    0x40060030 (0x104520e0). Interrupt source 0x13 = vector 35 (ICR19, 0x453; raw handler
 *    0x1049113e) -> dispatcher 0x104f94a0 case 0x13 -> 0x104fa928 -> event 0x80000002 with
 *    the status bits -> 0x104fe330: bit 0x20 -> event 0x400001 (operation done).
 *  - 0x104fe398 enables bit 0x20 for event 0x80000002 just before starting the operation.
 * Model: a start (bit 14 written) completes after FRN_IMG_LATENCY instructions (default
 * 20000): status |= 0x20, bit 14 cleared. Vector 35 is requested while (status & enable &
 * 0x2c) != 0. Status is write-1-to-clear. The operation itself is not performed (its
 * semantics are not established). Registers 0x40060000-0x400600ff are kept in a register
 * file (unwritten halfwords read 0xffff as before). FRN_IMG_LOG=1 logs each start with its parameters.
 * FRN_IMG_MODEL=0 disables (registers stay plain RAM, as before).
 */
#include "qemu/osdep.h"
#include "k10d_imgproc.h"

#define IMG_BASE   0x40060000u
#define IMG_IEN    0x40060030u
#define IMG_STAT   0x40060032u
#define IMG_CTRL   0x40060080u

static int on = -1, log_on;
static uint16_t img_stat;
static long countdown = -1, latency = 20000;
static FILE *out;
/* Register file for 0x40060000-0x400600ff: the emulator's unbacked I/O space reads 0xffff
 * and drops writes, which broke the firmware's read-modify-write of these registers.
 * Halfwords never written keep reading the old default (0xffff). */
static uint16_t regs[0x80]; static uint8_t written[0x80];
static uint32_t r16(uint32_t a) { unsigned i = (a - IMG_BASE) >> 1; return written[i] ? regs[i] : 0xffff; }
static uint32_t r32(uint32_t a) { return (r16(a) << 16) | r16(a + 2); }

int k10d_img_enabled(void)
{
    if (on < 0) {
        const char *s = getenv("FRN_IMG_MODEL"); on = !(s && s[0] == '0');
        log_on = getenv("FRN_IMG_LOG") != NULL;
        const char *l = getenv("FRN_IMG_LATENCY"); if (l) latency = strtol(l, NULL, 0);
    }
    return on;
}

int k10d_img_read16(uint32_t a, uint32_t *v)
{
    if (!k10d_img_enabled() || a < IMG_BASE || a >= IMG_BASE + 0x100) return 0;
    if (a == IMG_STAT) { *v = img_stat; return 1; }
    unsigned i = (a - IMG_BASE) >> 1;
    if (!written[i]) return 0;
    *v = regs[i];
    return 1;
}
int k10d_img_read32(uint32_t a, uint32_t *v)
{
    if (!k10d_img_enabled() || a < IMG_BASE || a >= IMG_BASE + 0x100) return 0;
    unsigned i = (a - IMG_BASE) >> 1;
    if (!written[i] && !written[i + 1]) return 0;
    *v = r32(a);
    return 1;
}

/* Called after the store has been made to RAM. ram16 reads the stored halfword. */
int k10d_img_write16(uint32_t a, uint32_t v, FILE *log, uint32_t (*ram16)(uint32_t), uint32_t (*ram32)(uint32_t))
{
    if (!k10d_img_enabled()) return 0;
    out = log;
    if (a == IMG_STAT) { img_stat &= ~(uint16_t)v; return 1; }          /* write-1-to-clear */
    if (a >= IMG_BASE && a < IMG_BASE + 0x100) {
        unsigned i = (a - IMG_BASE) >> 1; regs[i] = (uint16_t)v; written[i] = 1;
    }
    if (a == IMG_CTRL && (v & 0x4000)) {
        countdown = latency;
        if (log_on)
            fprintf(out, "[img] start ctrl=%04x f82=%04x w84=%08x w88=%08x stride %04x/%04x "
                         "size %04x/%04x addr %08x -> %08x opt=%04x ien=%04x\n",
                    v & 0xffff, r16(IMG_BASE + 0x82), r32(IMG_BASE + 0x84), r32(IMG_BASE + 0x88),
                    r16(IMG_BASE + 0x8c), r16(IMG_BASE + 0x8e), r16(IMG_BASE + 0x90),
                    r16(IMG_BASE + 0x92), r32(IMG_BASE + 0x94), r32(IMG_BASE + 0x98),
                    r16(IMG_BASE + 0x9c), r16(IMG_IEN));
        (void)ram16; (void)ram32;
    }
    return 0;   /* the store itself stays (RAM-backed registers) */
}

/* Once per instruction. Returns 1 when the operation completes this instruction
 * (the caller clears bit 14 of the control register). */
int k10d_img_tick(void)
{
    if (countdown < 0) return 0;
    if (--countdown > 0) return 0;
    countdown = -1;
    img_stat |= 0x20;
    regs[(IMG_CTRL - IMG_BASE) >> 1] &= ~0x4000;      /* start bit self-clears */
    if (log_on && out) fprintf(out, "[img] operation complete: status=%04x\n", img_stat);
    return 1;
}

/* Level: vector 35 while an enabled status bit is pending. */
int k10d_img_irq(void)
{
    return k10d_img_enabled() && (img_stat & r16(IMG_IEN) & 0x2c) != 0;
}

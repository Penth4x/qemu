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
 * Three engines share the status register: A ctrl +0x80 -> bit 0x20 (0x104fe398),
 * B ctrl +0x100 (+0x104/+0x108 addresses, +0x10c/+0x112 strides) -> bit 0x04 (0x104fe72c),
 * C ctrl +0xc0 (+0xc2..+0xfe) -> bit 0x08 (0x104fe976).
 * Model: a start (bit 14 written) completes after FRN_IMG_LATENCY instructions (default
 * 20000): status |= the engine's bit, its bit 14 cleared. Vector 35 is requested while (status & enable &
 * 0x2c) != 0. Status is write-1-to-clear. The operation itself is not performed (its
 * semantics are not established). Registers 0x40060000-0x400601ff are kept in a register
 * file (unwritten halfwords read 0xffff as before). FRN_IMG_LOG=1 logs each start with its parameters.
 * FRN_IMG_MODEL=0 disables (registers stay plain RAM, as before).
 */
#include "qemu/osdep.h"
#include "k10d_imgproc.h"

#define IMG_BASE   0x40060000u
#define IMG_IEN    0x40060030u
#define IMG_STAT   0x40060032u

static int on = -1, log_on;
static uint16_t img_stat;
static long latency = 20000;
/* Three operation engines: start = bit 14 of their control register; completion bit in
 * the shared status register (0x104fe398 / 0x104fe72c / 0x104fe976 enable these bits for
 * event 0x80000002 before starting; 0x104fe330 maps them to events 0x400001/2/3). */
static const struct { uint32_t ctrl; uint16_t bit; char name; } eng[3] = {
    { 0x40060080u, 0x20, 'A' }, { 0x40060100u, 0x04, 'B' }, { 0x400600c0u, 0x08, 'C' },
};
static long countdown[3] = { -1, -1, -1 };
static FILE *out;
/* Register file for 0x40060000-0x400601ff: the emulator's unbacked I/O space reads 0xffff
 * and drops writes, which broke the firmware's read-modify-write of these registers.
 * Halfwords never written keep reading the old default (0xffff). */
static uint16_t regs[0x100]; static uint8_t written[0x100];
static uint32_t r16(uint32_t a) { unsigned i = (a - IMG_BASE) >> 1; return written[i] ? regs[i] : 0xffff; }
static uint32_t r32(uint32_t a) { return (r16(a) << 16) | r16(a + 2); }

/* Resolution converter units at 0x40020000 and 0x400F0000 (Nikon Hacker emulator:
 * Expeed4002IoListener / FrResolutionConverter cover the same two bases). K10D layout,
 * from the firmware: status 0x....1ffe bit 0x8000 and 0x....000e bit 8 (read 0x10452742 /
 * 0x104527a4, cleared by writing the bits back 0x10452780 / 0x104527e2), enables
 * 0x....1ffc and 0x....0010; unit 0 -> event 0x80000011 (irq source 0x17, vector 39),
 * unit 1 -> 0x80000012 (source 0x18, vector 40) -> 0x10504fd4 -> events 0x300001/2.
 * Start: bit 14 of +0x1000 (boot writes 0x406c after the parameters and the enables
 * +0x1ffc = 0x8000, +0x0010 = 0x0008). Model: completion after the same latency sets
 * status +0x1ffe bit 0x8000 (Nikon's FrResolutionConverter also signals with 0x8000);
 * vector 39/40 while (+0x1ffe & +0x1ffc & 0x8000) | (+0x000e & +0x0010 & 8). Status
 * registers are write-1-to-clear. Writes logged under FRN_IMG_LOG. */
#define RC_N 2
static const uint32_t rc_base[RC_N] = { 0x40020000u, 0x400f0000u };
static uint16_t rc_regs[RC_N][0x1000]; static uint8_t rc_written[RC_N][0x1000];
static uint16_t rc_st_hi[RC_N], rc_st_lo[RC_N]; static long rc_countdown[RC_N] = { -1, -1 };
static uint16_t rc_get(int u, unsigned off) { unsigned i = off >> 1; return rc_written[u][i] ? rc_regs[u][i] : 0; }
static int rc_unit(uint32_t a) { for (int u = 0; u < RC_N; u++) if (a - rc_base[u] < 0x2000) return u; return -1; }

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
    if (!k10d_img_enabled()) return 0;
    int u = rc_unit(a);
    if (u >= 0) {
        unsigned off = a - rc_base[u], i = off >> 1;
        if (off == 0x1ffe) { *v = rc_st_hi[u]; return 1; }
        if (off == 0x000e) { *v = rc_st_lo[u]; return 1; }
        if (!rc_written[u][i]) return 0; *v = rc_regs[u][i]; return 1; }
    if (a < IMG_BASE || a >= IMG_BASE + 0x200) return 0;
    if (a == IMG_STAT) { *v = img_stat; return 1; }
    unsigned i = (a - IMG_BASE) >> 1;
    if (!written[i]) return 0;
    *v = regs[i];
    return 1;
}
int k10d_img_read32(uint32_t a, uint32_t *v)
{
    if (!k10d_img_enabled()) return 0;
    int u = rc_unit(a);
    if (u >= 0) { unsigned i = (a - rc_base[u]) >> 1;
        if (!rc_written[u][i] && !rc_written[u][i + 1]) return 0;
        *v = ((uint32_t)(rc_written[u][i] ? rc_regs[u][i] : 0xffff) << 16) | (rc_written[u][i + 1] ? rc_regs[u][i + 1] : 0xffff);
        return 1; }
    if (a < IMG_BASE || a >= IMG_BASE + 0x200) return 0;
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
    int u = rc_unit(a);
    if (u >= 0) {
        unsigned off = a - rc_base[u], i = off >> 1;
        if (off == 0x1ffe) { rc_st_hi[u] &= ~(uint16_t)v; return 1; }
        if (off == 0x000e) { rc_st_lo[u] &= ~(uint16_t)v; return 1; }
        rc_regs[u][i] = (uint16_t)v; rc_written[u][i] = 1;
        if (off == 0x1000 && (v & 0x4000)) rc_countdown[u] = latency;
        if (log_on) fprintf(out, "[rc%d] +%04x <- %04x\n", u, off, v & 0xffff);
        return 0;
    }
    if (a == IMG_STAT) { img_stat &= ~(uint16_t)v; return 1; }          /* write-1-to-clear */
    if (a >= IMG_BASE && a < IMG_BASE + 0x200) {
        unsigned i = (a - IMG_BASE) >> 1; regs[i] = (uint16_t)v; written[i] = 1;
    }
    for (int k = 0; k < 3; k++) {
        if (a != eng[k].ctrl || !(v & 0x4000)) continue;
        countdown[k] = latency;
        if (log_on && k == 0)
            fprintf(out, "[img] start A ctrl=%04x f82=%04x w84=%08x w88=%08x stride %04x/%04x "
                         "size %04x/%04x addr %08x -> %08x opt=%04x ien=%04x\n",
                    v & 0xffff, r16(IMG_BASE + 0x82), r32(IMG_BASE + 0x84), r32(IMG_BASE + 0x88),
                    r16(IMG_BASE + 0x8c), r16(IMG_BASE + 0x8e), r16(IMG_BASE + 0x90),
                    r16(IMG_BASE + 0x92), r32(IMG_BASE + 0x94), r32(IMG_BASE + 0x98),
                    r16(IMG_BASE + 0x9c), r16(IMG_IEN));
        else if (log_on) {
            fprintf(out, "[img] start %c ctrl=%04x regs:", eng[k].name, v & 0xffff);
            for (uint32_t r = eng[k].ctrl + 2; r < eng[k].ctrl + 0x40; r += 2) fprintf(out, " %04x", r16(r));
            fprintf(out, " ien=%04x\n", r16(IMG_IEN));
        }
        (void)ram16; (void)ram32;
    }
    return 0;   /* the store itself stays (RAM-backed registers) */
}

/* Once per instruction. Returns 1 when the operation completes this instruction
 * (the caller clears bit 14 of the control register). */
int k10d_img_tick(void)
{
    int done = 0;
    for (int k = 0; k < 3; k++) {
        if (countdown[k] < 0 || --countdown[k] > 0) continue;
        countdown[k] = -1;
        img_stat |= eng[k].bit;
        regs[(eng[k].ctrl - IMG_BASE) >> 1] &= ~0x4000;   /* start bit self-clears */
        if (log_on && out) fprintf(out, "[img] operation %c complete: status=%04x\n", eng[k].name, img_stat);
        done = 1;
    }
    for (int u = 0; u < RC_N; u++) {
        if (rc_countdown[u] < 0 || --rc_countdown[u] > 0) continue;
        rc_countdown[u] = -1;
        rc_st_hi[u] |= 0x8000;
        rc_regs[u][0x1000 >> 1] &= ~0x4000;            /* start bit self-clears */
        if (log_on && out) fprintf(out, "[rc%d] operation complete\n", u);
        done = 1;
    }
    return done;
}

/* Vector for resolution-converter unit u (39 or 40) while an enabled status bit pends. */
int k10d_rc_irq(int u)
{
    if (!k10d_img_enabled() || u < 0 || u >= RC_N) return 0;
    return ((rc_st_hi[u] & rc_get(u, 0x1ffc) & 0x8000) | (rc_st_lo[u] & rc_get(u, 0x0010) & 8)) != 0;
}

/* Level: vector 35 while an enabled status bit is pending. */
int k10d_img_irq(void)
{
    return k10d_img_enabled() && (img_stat & r16(IMG_IEN) & 0x2c) != 0;
}

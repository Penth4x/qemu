/*
 * K10D program flash (0x10000000-0x107fffff) — command-set model.
 *
 * The firmware keeps its user settings in flash: boot copies the 0x344-byte block at
 * 0x10004000 to 0x8001dedc (0x10429930) and, on power-off (mode transition 3 ->
 * 0x10433f06), writes it back through the flash driver 0x1044431c (sector erase + word
 * program, run from RAM at 0x800004xx), with a second 0x108-byte block at 0x10005000.
 * Geometry from the firmware's sector table 0x105a0f88: eight 8 KiB boot sectors
 * (0x10000000-0x1000ffff), then 64 KiB sectors up to 0x10800000. Commands are the
 * standard AMD/Fujitsu x16 set at byte addresses 0xAAA / 0x554 (seen in traces:
 * AA, 55, 80, AA, 55, 30 = sector erase).
 *
 * Model: unlock cycles AA/55 then A0 (program one word: new = old & data), 80 AA 55 30
 * (sector erase -> 0xff), 80 AA 55 10 (chip erase: refused and logged), F0 / anything
 * else = reset. Operations complete at once, so DQ7 / DQ6 status polling reads the final
 * data and passes. Writes outside a command sequence do not reach the array (as on the
 * real chip). FRN_FLASH_SAVE=path: when the array has changed, the whole 8.25 MiB image
 * (same layout as the -bios file) is written there at exit and after the driver has been
 * idle for 2M instructions, so it can be booted again with -bios to keep the settings.
 * FRN_FLASH_MODEL=0 disables (stores go straight to the RAM-backed ROM, as before).
 */
#include "qemu/osdep.h"
#include "cpu.h"
#include "accel/tcg/cpu-ldst.h"
#include "k10d_flash.h"

#define FL_BASE  0x10000000u
#define FL_END   0x10800000u
#define IMG_SIZE 0x00840000u          /* size of FWDC162B.BIN as loaded with -bios */

static int on = -1, state, dirty, logn;
static long idle;
static const char *save_path;
static CPUFRNState *last_env;

static uint32_t sector_of(uint32_t a, uint32_t *len)
{
    if (a < FL_BASE + 0x10000u) { *len = 0x2000; return a & ~0x1fffu; }
    *len = 0x10000; return a & ~0xffffu;
}

static void save_image(void)
{
    if (!dirty || !save_path || !last_env) return;
    FILE *f = fopen(save_path, "wb");
    if (!f) return;
    for (uint32_t a = FL_BASE; a < FL_BASE + IMG_SIZE; a++) {
        uint8_t c = cpu_ldub_data(last_env, a); fwrite(&c, 1, 1, f);
    }
    fclose(f);
    fprintf(stderr, "[flash] image saved to %s\n", save_path);
    dirty = 0;
}

int k10d_flash_enabled(void)
{
    if (on < 0) {
        const char *s = getenv("FRN_FLASH_MODEL"); on = !(s && s[0] == '0');
        save_path = getenv("FRN_FLASH_SAVE");
        if (save_path) atexit(save_image);
    }
    return on;
}

static void flog(const char *what, uint32_t a, uint32_t v)
{
    if (logn++ < 40) fprintf(stderr, "[flash] %s @0x%08x 0x%04x\n", what, a, v);
}

/* A CPU store of `size` bytes to a; returns 1 when the store belongs to the flash
 * (handled here, the caller must not perform it). */
int k10d_flash_write(CPUFRNState *e, uint32_t a, uint32_t v, int size)
{
    if (!k10d_flash_enabled() || a < FL_BASE || a >= FL_END) return 0;
    last_env = e; idle = 0;
    uint32_t off = a - FL_BASE, d = v & (size == 1 ? 0xffu : 0xffffu);
    switch (state) {
    case 0: case 3:
        if (d == 0xf0) { state = 0; break; }
        state = (off == 0xaaa && (d & 0xff) == 0xaa) ? state + 1 : 0; break;
    case 1: case 4:
        state = (off == 0x554 && (d & 0xff) == 0x55) ? state + 1 : 0; break;
    case 2:
        if (off == 0xaaa && (d & 0xff) == 0xa0) state = 10;          /* program */
        else if (off == 0xaaa && (d & 0xff) == 0x80) state = 3;      /* erase setup */
        else state = 0;
        break;
    case 5:
        if ((d & 0xff) == 0x30) {                                    /* sector erase */
            uint32_t len, s = sector_of(a, &len);
            for (uint32_t i = 0; i < len; i++) cpu_stb_data(e, s + i, 0xff);
            dirty = 1; flog("sector erase", s, len);
        } else if (off == 0xaaa && (d & 0xff) == 0x10) {
            flog("chip erase REFUSED", a, d);
        }
        state = 0; break;
    case 10:                                                         /* program word */
        if (size == 1) cpu_stb_data(e, a, cpu_ldub_data(e, a) & d);
        else cpu_stw_be_data(e, a, cpu_lduw_be_data(e, a) & d);
        dirty = 1; flog("program", a, d);
        state = 0; break;
    default: state = 0;
    }
    return 1;
}

void k10d_flash_tick(void)
{
    if (dirty && save_path && ++idle == 2000000) save_image();
}

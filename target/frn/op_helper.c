/*
 * Fujitsu FR interpreter helper — faithful C port of fremu.py _execute.
 * Executes exactly one instruction at env->pc per call, carrying the FR branch
 * delay slot across calls via env->delay_armed/delay_pc. Memory goes through
 * QEMU's softmmu accessors (big-endian, matching FR), so RAM/ROM/MMIO/devices
 * all work "for free". Validated against fremu by PC/state parity.
 *
 * NOTE (bring-up scope): the Milbeaut timer tick + interrupt delivery and the
 * stateful 0x67000000 / timer-reg side effects are NOT modelled here yet (they
 * become real QEMU devices). The heap is NOT stubbed — real SDRAM means the
 * firmware's own allocator runs.
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "accel/tcg/cpu-ldst.h"

#define M32 0xffffffffu
#define FW_BASE 0x10000000u
#define FW_END  0x11000000u   /* ROM window top (approx; exact = base+fw_size) */
#define TIMER_VECTOR 24u
#define TIMER_ICR    0x448u
#define DELAYED_VEC  63u
/* Watch-counter / RTC: vec41 = ICR index 25 => ICR reg 0x440+25 = 0x459. The
 * firmware's watch-counter ISR drives the clock tick and (clock-unset) the
 * "Date Adjust" first-boot screen. Fire it periodically once enabled. */
#define WC_VECTOR    41u
#define WC_ICR       0x459u
#define WC_PERIOD    200000u   /* instructions between watch-counter ticks */

static void frn_timer_reg_written(CPUFRNState *e);

/* -------------------------------------------------------------------------
 * Inspectability: env-gated execution tracer (gold-standard core goal).
 * Performance is deliberately secondary; every interrupt and watched call is
 * observable. Controlled entirely by environment variables, parsed once:
 *   FRN_TRACE_FILE=path   send trace output here (default stderr)
 *   FRN_TRACE_IRQ=1       log every interrupt dispatch (vec, handler, from, ilm)
 *   FRN_TRACE_CALLS=hex,hex,...   log each time PC reaches one of these
 *                         addresses, with args r4-r7 and return addr (rp)
 * ------------------------------------------------------------------------- */
#define FRN_WATCH_MAX 32
static int      frn_tr_ready;
static FILE    *frn_tr_out;
static int      frn_tr_irq;
static uint32_t frn_tr_watch[FRN_WATCH_MAX];
static int      frn_tr_watch_n;

static void frn_trace_setup(void)
{
    const char *f, *s;
    if (frn_tr_ready) {
        return;
    }
    frn_tr_ready = 1;
    frn_tr_out = stderr;
    f = getenv("FRN_TRACE_FILE");
    if (f && *f) {
        FILE *fp = fopen(f, "w");
        if (fp) {
            frn_tr_out = fp;
            setvbuf(fp, NULL, _IOLBF, 0);
        }
    }
    frn_tr_irq = (getenv("FRN_TRACE_IRQ") != NULL);
    s = getenv("FRN_TRACE_CALLS");
    while (s && *s && frn_tr_watch_n < FRN_WATCH_MAX) {
        char *end;
        unsigned long v = strtoul(s, &end, 16);
        if (end == s) {
            break;
        }
        frn_tr_watch[frn_tr_watch_n++] = (uint32_t)v;
        s = (*end == ',') ? end + 1 : end;
    }
}

static inline int frn_tr_watched(uint32_t pc)
{
    for (int i = 0; i < frn_tr_watch_n; i++) {
        if (frn_tr_watch[i] == pc) {
            return 1;
        }
    }
    return 0;
}

/*
 * Memory snapshot for inspection. FRN_SNAP=path and FRN_SNAP_AT=<million insns>
 * dump the whole 64 MiB SDRAM (0x80000000..0x84000000) to a raw file once the
 * instruction count crosses the threshold, so the framebuffer can be rendered
 * offline. Written directly from the interpreter (no fragile monitor). A comma
 * list in FRN_SNAP_AT takes successive snapshots (path gets a .N suffix).
 */
/*
 * PC histogram (inspectability): when FRN_HIST is set, count executed PCs in
 * 16-byte buckets and dump the hottest to <FRN_SNAP>.hist.<idx> at snapshot
 * time, so we can see where the running task actually spends its cycles / what
 * loop it is parked in. Keyed by (pc>>4)&0xfffff -> the firmware's 16 MiB window.
 */
#define FRN_HIST_SZ (1u << 20)
static uint32_t *frn_hist;
static int frn_hist_on = -1;

static inline void frn_hist_tick(uint32_t pc)
{
    if (frn_hist_on < 0) {
        frn_hist_on = getenv("FRN_HIST") ? 1 : 0;
        if (frn_hist_on) {
            frn_hist = calloc(FRN_HIST_SZ, sizeof(uint32_t));
            if (!frn_hist) frn_hist_on = 0;
        }
    }
    if (frn_hist_on) {
        frn_hist[(pc >> 4) & (FRN_HIST_SZ - 1)]++;
    }
}

static void frn_hist_dump(const char *path, int idx)
{
    if (!frn_hist_on || !frn_hist) return;
    char fn[512];
    snprintf(fn, sizeof fn, "%s.hist.%d", path, idx);
    FILE *f = fopen(fn, "w");
    if (!f) return;
    for (int top = 0; top < 50; top++) {
        uint32_t best = 0, bi = 0;
        for (uint32_t i = 0; i < FRN_HIST_SZ; i++) {
            if (frn_hist[i] > best) { best = frn_hist[i]; bi = i; }
        }
        if (best == 0) break;
        fprintf(f, "0x%08x  %u\n", 0x10000000u | (bi << 4), best);
        frn_hist[bi] = 0;   /* consume so next iteration finds the next */
    }
    fclose(f);
    fprintf(stderr, "[frn] PC histogram %d -> %s\n", idx, fn);
}

/* Write-address histogram (inspectability): FRN_WRHIST counts writes per 4 KiB
 * page so the most-written region (the framebuffer) is found without guessing. */
static uint32_t *frn_wrhist;
static int frn_wrhist_on = -1;
static inline void frn_wr_hist(uint32_t a)
{
    if (frn_wrhist_on < 0) {
        frn_wrhist_on = getenv("FRN_WRHIST") ? 1 : 0;
        if (frn_wrhist_on) {
            frn_wrhist = calloc(1u << 20, sizeof(uint32_t));
            if (!frn_wrhist) frn_wrhist_on = 0;
        }
    }
    if (frn_wrhist_on) frn_wrhist[(a >> 12) & 0xfffff]++;
}

/* Read-address histogram for MMIO polls (FRN_RDHIST): the register the firmware
 * busy-polls (the wait gate) shows up as the hottest MMIO read. */
static uint32_t *frn_rdhist;
static int frn_rdhist_on = -1;
static inline int frn_is_mmio(uint32_t a)
{
    return (a >= 0x40000000u && a < 0x50000000u) ||
           (a >= 0x67000000u && a < 0x67100000u) ||
           (a >= 0x01000000u && a < 0x10000000u);
}
static inline void frn_rd_hist(uint32_t a)
{
    if (frn_rdhist_on < 0) {
        frn_rdhist_on = getenv("FRN_RDHIST") ? 1 : 0;
        if (frn_rdhist_on) {
            frn_rdhist = calloc(1u << 20, sizeof(uint32_t));
            if (!frn_rdhist) frn_rdhist_on = 0;
        }
    }
    if (frn_rdhist_on && frn_is_mmio(a)) frn_rdhist[(a >> 4) & 0xfffff]++;
}

static void frn_rdhist_dump(const char *path, int idx)
{
    if (!frn_rdhist_on || !frn_rdhist) return;
    char fn[512];
    snprintf(fn, sizeof fn, "%s.rdhist.%d", path, idx);
    FILE *f = fopen(fn, "w");
    if (!f) return;
    for (int top = 0; top < 40; top++) {
        uint32_t best = 0, bi = 0;
        for (uint32_t i = 0; i < (1u << 20); i++) {
            if (frn_rdhist[i] > best) { best = frn_rdhist[i]; bi = i; }
        }
        if (best == 0) break;
        fprintf(f, "0x%08x  %u reads\n", bi << 4, best);
        frn_rdhist[bi] = 0;
    }
    fclose(f);
    fprintf(stderr, "[frn] MMIO read histogram %d -> %s\n", idx, fn);
}

static void frn_wrhist_dump(const char *path, int idx)
{
    if (!frn_wrhist_on || !frn_wrhist) return;
    char fn[512];
    snprintf(fn, sizeof fn, "%s.wrhist.%d", path, idx);
    FILE *f = fopen(fn, "w");
    if (!f) return;
    for (int top = 0; top < 40; top++) {
        uint32_t best = 0, bi = 0;
        for (uint32_t i = 0; i < (1u << 20); i++) {
            if (frn_wrhist[i] > best) { best = frn_wrhist[i]; bi = i; }
        }
        if (best == 0) break;
        fprintf(f, "0x%08x  %u writes\n", bi << 12, best);
        frn_wrhist[bi] = 0;
    }
    fclose(f);
    fprintf(stderr, "[frn] write histogram %d -> %s\n", idx, fn);
}

static void frn_snapshot(CPUFRNState *e)
{
    static const char *path;
    static long counts[8];
    static int n_at, idx, setup;
    static long insns;
    if (!setup) {
        setup = 1;
        path = getenv("FRN_SNAP");
        const char *at = getenv("FRN_SNAP_AT");
        while (at && *at && n_at < 8) {
            char *end; long v = strtol(at, &end, 10);
            if (end == at) break;
            counts[n_at++] = v * 1000000L;
            at = (*end == ',') ? end + 1 : end;
        }
        if (n_at == 0) { counts[n_at++] = 2000L * 1000000L; }
    }
    if (!path || idx >= n_at) {
        return;
    }
    if (++insns < counts[idx]) {
        return;
    }
    char fn[512];
    uint8_t buf[4096];
    snprintf(fn, sizeof fn, "%s.%d", path, idx);
    FILE *f = fopen(fn, "wb");
    if (f) {
        for (uint32_t a = 0x80000000u; a != 0x84000000u; a += 4096) {
            for (int i = 0; i < 4096; i++) {
                buf[i] = cpu_ldub_data(e, a + i);
            }
            fwrite(buf, 1, 4096, f);
        }
        fclose(f);
        fprintf(stderr, "[frn] SDRAM snapshot %d -> %s (after %ld insns)\n",
                idx, fn, insns);
    }
    /* also dump WRAM (0x6a000000, 1 MiB): TCBs + RTOS lists live here */
    snprintf(fn, sizeof fn, "%s.wram.%d", path, idx);
    f = fopen(fn, "wb");
    if (f) {
        for (uint32_t a = 0x6a000000u; a != 0x6a100000u; a += 4096) {
            for (int i = 0; i < 4096; i++) {
                buf[i] = cpu_ldub_data(e, a + i);
            }
            fwrite(buf, 1, 4096, f);
        }
        fclose(f);
        fprintf(stderr, "[frn] WRAM snapshot %d -> %s\n", idx, fn);
    }
    frn_hist_dump(path, idx);
    frn_wrhist_dump(path, idx);
    frn_rdhist_dump(path, idx);
    idx++;
}

/* ---- memory (big-endian via target config) ----
 * Low control regs (<0x50) carry timer/DICR side effects and the timer-count
 * read (0x4A/0x4B), matching fremu's read_u8/write_u8; multi-byte accesses to
 * that window decompose to bytes so the side effects fire. */
/* Read-watchpoint (FRN_RDWATCH=hex): log PC whenever the firmware reads from the
 * 64-byte window at that address. Used to tell whether a code path (e.g. the
 * "Date Adjust" string access) is ever reached. */
static uint32_t frn_rdwatch = 0;
static int frn_rdwatch_init = 0;
static inline void frn_rd_watch(CPUFRNState *e, uint32_t a)
{
    if (!frn_rdwatch_init) {
        frn_rdwatch_init = 1;
        const char *s = getenv("FRN_RDWATCH");
        if (s) frn_rdwatch = (uint32_t)strtoul(s, NULL, 16);
    }
    if (frn_rdwatch && a >= frn_rdwatch && a < frn_rdwatch + 64) {
        static int n;
        if (n++ < 40) {
            fprintf(frn_tr_out ? frn_tr_out : stderr,
                    "[rdwatch] read 0x%08x from pc~0x%08x\n", a, e->pc);
        }
    }
}

/* Read-override (FRN_FORCE="addr:val,addr:val,…", up to 8): return val for a
 * read at addr. Lets me force a specific flag (e.g. the date-set bit) to a value
 * to test a gate hypothesis without patching the ROM. Width-agnostic: the value
 * is returned for the covering access. */
#define FRN_FORCE_MAX 8
static uint32_t frn_force_a[FRN_FORCE_MAX], frn_force_v[FRN_FORCE_MAX];
static int frn_force_n = -1;
static int frn_force_lookup(uint32_t a, uint32_t *out)
{
    if (frn_force_n < 0) {
        frn_force_n = 0;
        const char *s = getenv("FRN_FORCE");
        while (s && *s && frn_force_n < FRN_FORCE_MAX) {
            char *e1; unsigned long ad = strtoul(s, &e1, 16);
            if (e1 == s || *e1 != ':') break;
            char *e2; unsigned long va = strtoul(e1 + 1, &e2, 16);
            frn_force_a[frn_force_n] = (uint32_t)ad;
            frn_force_v[frn_force_n] = (uint32_t)va;
            frn_force_n++;
            s = (*e2 == ',') ? e2 + 1 : e2;
        }
    }
    for (int i = 0; i < frn_force_n; i++) {
        if (frn_force_a[i] == a) { *out = frn_force_v[i]; return 1; }
    }
    return 0;
}

static inline uint32_t rd8(CPUFRNState *e, uint32_t a)
{
    frn_rd_hist(a);
    frn_rd_watch(e, a);
    { uint32_t fv; if (frn_force_lookup(a, &fv)) return fv & 0xff; }
    if (a == 0x4A) return (e->tmr_count >> 8) & 0xff;
    if (a == 0x4B) return e->tmr_count & 0xff;
    return cpu_ldub_data(e, a);
}
static inline void wr8(CPUFRNState *e, uint32_t a, uint32_t v)
{
    frn_wr_hist(a);
    cpu_stb_data(e, a, v & 0xff);
    if (a == 0x44) {
        e->dicr_pending = v & 1;
    } else if (a >= 0x48 && a <= 0x4F) {
        frn_timer_reg_written(e);
    }
}
static inline uint32_t rd16(CPUFRNState *e, uint32_t a)
{
    if (a < 0x50) return (rd8(e, a) << 8) | rd8(e, a + 1);
    frn_rd_hist(a); frn_rd_watch(e, a);
    { uint32_t fv; if (frn_force_lookup(a, &fv)) return fv & 0xffff; }
    return cpu_lduw_be_data(e, a);
}
static inline uint32_t rd32(CPUFRNState *e, uint32_t a)
{
    if (a < 0x50) return (rd8(e, a) << 24) | (rd8(e, a + 1) << 16)
                       | (rd8(e, a + 2) << 8) | rd8(e, a + 3);
    frn_rd_hist(a); frn_rd_watch(e, a);
    { uint32_t fv; if (frn_force_lookup(a, &fv)) return fv; }
    return cpu_ldl_be_data(e, a);
}
static inline void wr16(CPUFRNState *e, uint32_t a, uint32_t v)
{
    if (a < 0x50) { wr8(e, a, v >> 8); wr8(e, a + 1, v); return; }
    frn_wr_hist(a);
    cpu_stw_be_data(e, a, v & 0xffff);
}
uint64_t frn_lcd_writes;      /* debug: count of LCD-reg writes */
uint32_t frn_lcd_scanout;     /* debug: scanout base once programmed */
static inline void wr32(CPUFRNState *e, uint32_t a, uint32_t v)
{
    if (a < 0x50) { wr8(e, a, v >> 24); wr8(e, a + 1, v >> 16);
                    wr8(e, a + 2, v >> 8); wr8(e, a + 3, v); return; }
    frn_wr_hist(a);
    if (a >= 0x40100000 && a < 0x40101000) {
        frn_lcd_writes++;
        if (a == 0x40100800 && v && !frn_lcd_scanout) {
            frn_lcd_scanout = v;
            fprintf(stderr, "[LCD] *** scanout base programmed: 0x40100800 <- %08x (lcd_writes=%llu) ***\n",
                    v, (unsigned long long)frn_lcd_writes);
        }
    }
    cpu_stl_be_data(e, a, v);
}

/* ---- arithmetic helpers (match fremu free helpers) ---- */
static inline int32_t  s32(uint32_t v) { return (int32_t)v; }
static inline int carry32(uint32_t a, uint32_t b)  { return ((uint64_t)a + (uint64_t)b) > M32; }
static inline int scarry32(uint32_t a, uint32_t b) { int64_t r = (int64_t)s32(a) + (int64_t)s32(b); return r < -2147483648LL || r > 2147483647LL; }
static inline int sborrow32(uint32_t a, uint32_t b){ int64_t r = (int64_t)s32(a) - (int64_t)s32(b); return r < -2147483648LL || r > 2147483647LL; }
static inline uint32_t sx8(uint32_t v)  { v &= 0xff; return (v & 0x80) ? v - 0x100 : v; }
static inline uint32_t sext(uint32_t v, int bits) {
    uint32_t m = (bits == 32) ? M32 : ((1u << bits) - 1);
    v &= m;
    if (v & (1u << (bits - 1))) { v |= ~m; }
    return v;
}

static inline void resflags(CPUFRNState *e, uint64_t res, int width) {
    uint64_t m = (width >= 64) ? ~0ULL : ((1ULL << width) - 1);
    e->cc_n = (res >> (width - 1)) & 1;
    e->cc_z = (res & m) == 0;
}

static uint32_t lsr_op(CPUFRNState *e, uint32_t val, int sh) {
    uint32_t mask = (sh == 0) ? 0 : (1u << (sh - 1));
    e->cc_c = (mask & val) != 0;
    uint32_t res = (sh >= 32) ? 0 : (val >> sh);
    resflags(e, res, 32); return res;
}
static uint32_t asr_op(CPUFRNState *e, uint32_t val, int sh) {
    uint32_t mask = (sh == 0) ? 0 : (1u << (sh - 1));
    e->cc_c = (mask & val) != 0;
    uint32_t res = (uint32_t)(s32(val) >> (sh >= 32 ? 31 : sh));
    resflags(e, res, 32); return res;
}
static uint32_t addc_op(CPUFRNState *e, uint32_t a, uint32_t b) {
    uint32_t cf = e->cc_c;
    e->cc_c = carry32(a, b); e->cc_v = scarry32(a, b);
    uint32_t r = a + b;
    e->cc_c = e->cc_c | carry32(r, cf);
    e->cc_v = e->cc_v ^ scarry32(r, cf);
    return r + cf;
}
static uint32_t subc_op(CPUFRNState *e, uint32_t a, uint32_t b) {
    uint32_t cf = e->cc_c;
    e->cc_c = (a < b); e->cc_v = sborrow32(a, b);
    uint32_t r = a - b;
    e->cc_c = e->cc_c | (r < cf);
    e->cc_v = e->cc_v ^ sborrow32(r, cf);
    return r - cf;
}

static int cond(CPUFRNState *e, int op_b) {
    switch (op_b) {
    case 2:  return e->cc_z == 1;
    case 3:  return e->cc_z == 0;
    case 4:  return e->cc_c == 1;
    case 5:  return e->cc_c == 0;
    case 6:  return e->cc_n == 1;
    case 7:  return e->cc_n == 0;
    case 8:  return e->cc_v == 1;
    case 9:  return e->cc_v == 0;
    case 10: return (e->cc_v ^ e->cc_n) == 1;
    case 11: return (e->cc_v ^ e->cc_n) == 0;
    case 12: return ((e->cc_v ^ e->cc_n) | e->cc_z) == 1;
    case 13: return ((e->cc_v ^ e->cc_n) | e->cc_z) == 0;
    case 14: return (e->cc_c | e->cc_z) == 1;
    case 15: return (e->cc_c | e->cc_z) == 0;
    default: return 0;
    }
}

static uint32_t pack_ccr(CPUFRNState *e) {
    return ((e->sf & 1) << 5) | ((e->i_flag & 1) << 4) | ((e->cc_n & 1) << 3)
         | ((e->cc_z & 1) << 2) | ((e->cc_v & 1) << 1) | (e->cc_c & 1);
}
static void set_sflag(CPUFRNState *e, int new_s) {
    new_s &= 1;
    if (new_s != (int)e->sf) {
        if (e->sf == 0) { e->ssp = e->regs[15]; e->regs[15] = e->usp; }
        else            { e->usp = e->regs[15]; e->regs[15] = e->ssp; }
    }
    e->sf = new_s;
}
static void unpack_ccr(CPUFRNState *e, uint32_t v) {
    set_sflag(e, (v >> 5) & 1);
    e->i_flag = (v >> 4) & 1;
    e->cc_n = (v >> 3) & 1; e->cc_z = (v >> 2) & 1;
    e->cc_v = (v >> 1) & 1; e->cc_c = v & 1;
}
static uint32_t pack_ps(CPUFRNState *e) { return (e->ilm << 16) | pack_ccr(e); }
static void unpack_ps(CPUFRNState *e, uint32_t v) {
    uint32_t new_ilm = (v >> 16) & 0x1f;
    if ((e->ilm >> 4) & 1) { new_ilm |= 0x10; }  /* FR ilm4-sticky */
    e->ilm = new_ilm;
    unpack_ccr(e, v & 0x3f);
}

static uint32_t get_sr(CPUFRNState *e, int idx) {
    switch (idx) {
    case 0: return e->tbr;
    case 1: return e->rp;
    case 2: return (e->sf == 0) ? e->regs[15] : e->ssp;
    case 3: return (e->sf == 1) ? e->regs[15] : e->usp;
    case 4: return e->mdh;  case 5: return e->mdl;
    case 6: return e->bp;   case 7: return e->fcr;
    case 8: return e->esr;  case 15: return e->dbr;
    default: return 0;
    }
}
static void set_sr(CPUFRNState *e, int idx, uint32_t val) {
    switch (idx) {
    case 0: e->tbr = val; break;
    case 1: e->rp = val; break;
    case 2: if (e->sf == 0) e->regs[15] = val; else e->ssp = val; break;
    case 3: if (e->sf == 1) e->regs[15] = val; else e->usp = val; break;
    case 4: e->mdh = val; break;  case 5: e->mdl = val; break;
    case 6: e->bp = val; break;   case 7: e->fcr = val; break;
    case 8: e->esr = val; break;  case 15: e->dbr = val; break;
    default: break;
    }
}

static inline void push32(CPUFRNState *e, uint32_t v) {
    e->regs[15] -= 4; wr32(e, e->regs[15], v);
}
/* arm a transfer: delayed => fire after next insn; else immediate */
static inline void go(CPUFRNState *e, uint32_t target, int delayed) {
    if (delayed) { e->delay_armed = 1; e->delay_pc = target; }
    else { e->pc = target; }
}
static inline void do_call(CPUFRNState *e, uint32_t target, uint32_t ret, int delayed) {
    e->rp = ret; go(e, target, delayed);
}

/* ---- Milbeaut reload timer + FR interrupt delivery (fremu port) ---- */
static void frn_timer_reg_written(CPUFRNState *e)
{
    uint32_t csr = (cpu_ldub_data(e, 0x4E) << 8) | cpu_ldub_data(e, 0x4F);
    e->tmr_reload = (cpu_ldub_data(e, 0x48) << 8) | cpu_ldub_data(e, 0x49);
    int cnte = (csr >> 1) & 1, trg = csr & 1;
    if (cnte && trg) { e->tmr_count = e->tmr_reload; e->tmr_running = 1; e->tmr_div = 0; }
    else if (!cnte) { e->tmr_running = 0; }
}

static void frn_timer_tick(CPUFRNState *e)
{
    if (!e->tmr_running) return;
    e->tmr_div++;
    if (e->tmr_div < 1) return;        /* TIMER_STEPS_PER_TICK = 1 */
    e->tmr_div = 0;
    uint32_t csr = (cpu_ldub_data(e, 0x4E) << 8) | cpu_ldub_data(e, 0x4F);
    int inte = (csr >> 3) & 1, reld = (csr >> 4) & 1;
    if (e->tmr_count == 0) {
        cpu_stb_data(e, 0x4F, cpu_ldub_data(e, 0x4F) | 0x04);   /* UF, raw */
        if (inte && !e->pending_valid) {
            e->pending_vec = TIMER_VECTOR;
            e->pending_level = cpu_ldub_data(e, TIMER_ICR) & 0x1F;
            e->pending_valid = 1;
        }
        e->tmr_count = reld ? e->tmr_reload : 0xFFFF;
    } else {
        e->tmr_count = (e->tmr_count - 1) & 0xFFFF;
    }
}

/* Watch-counter / RTC tick: once the firmware has enabled ICR25 (level != the
 * masked value 0x1f), raise vec41 every WC_PERIOD instructions. The ISR reads
 * its device regs at 0x40090000 (background MMIO => 0xffffffff => status/clock
 * bits set) and posts the clock event. Delivery itself is gated by ilm>level in
 * frn_deliver, so a masked ICR25 simply never fires. */
static void frn_watch_tick(CPUFRNState *e)
{
    uint32_t icr = cpu_ldub_data(e, WC_ICR) & 0x1F;
    if (icr == 0x1F) return;              /* not enabled by firmware yet */
    if (++e->wc_div < WC_PERIOD) return;
    e->wc_div = 0;
    e->wc_pending = 1;
}

static void frn_deliver(CPUFRNState *e)
{
    if (!e->i_flag) return;
    uint32_t lev[3], vec[3]; int kind[3], n = 0;
    if (e->pending_valid) { lev[n] = e->pending_level; vec[n] = e->pending_vec; kind[n] = 0; n++; }
    if (e->dicr_pending)  { lev[n] = cpu_ldub_data(e, 0x46f) & 0x1F; vec[n] = DELAYED_VEC; kind[n] = 1; n++; }
    if (e->wc_pending)    { lev[n] = cpu_ldub_data(e, WC_ICR) & 0x1F; vec[n] = WC_VECTOR; kind[n] = 2; n++; }
    if (n == 0) return;
    /* insertion sort ascending by level (highest priority = lowest number first) */
    for (int i = 1; i < n; i++) {
        uint32_t tl = lev[i], tv = vec[i]; int tk = kind[i];
        int j = i - 1;
        while (j >= 0 && lev[j] > tl) {
            lev[j+1] = lev[j]; vec[j+1] = vec[j]; kind[j+1] = kind[j]; j--;
        }
        lev[j+1] = tl; vec[j+1] = tv; kind[j+1] = tk;
    }
    for (int i = 0; i < n; i++) {
        if (!(e->ilm > lev[i])) continue;
        uint32_t handler = rd32(e, e->tbr + 0x3FC - vec[i] * 4);
        if (!(handler >= FW_BASE && handler < FW_END)) continue;
        if (kind[i] == 0) e->pending_valid = 0;  /* DICR stays until FW clears 0x44 */
        if (kind[i] == 2) e->wc_pending = 0;
        set_sflag(e, 0);
        push32(e, pack_ps(e));
        push32(e, e->pc);
        e->ilm = lev[i];
        e->pc = handler;
        if (frn_tr_irq) {
            static const char *nm[3] = { "timer", "dicr", "watch-cnt" };
            fprintf(frn_tr_out, "[irq] vec%-2u %-9s -> 0x%08x  ilm->%-2u  "
                    "from 0x%08x\n", vec[i], nm[kind[i]], handler, lev[i],
                    rd32(e, e->regs[15]));
        }
        return;
    }
}

void HELPER(frn_interp)(CPUFRNState *env)
{
    uint32_t *r = env->regs;
    if (!frn_tr_ready) {
        frn_trace_setup();
    }
    if (!env->delay_armed) {       /* instruction boundary (not a delay slot) */
        frn_timer_tick(env);
        frn_watch_tick(env);
        frn_deliver(env);          /* may set env->pc to an ISR handler */
    }
    frn_snapshot(env);
    uint32_t pc = env->pc;
    frn_hist_tick(pc);
    if (frn_tr_watch_n && frn_tr_watched(pc)) {
        static long minr6 = -1;
        if (minr6 < 0) {
            const char *m = getenv("FRN_TRACE_MINR6");
            minr6 = m ? atol(m) : 0;
        }
        static long maxhits = -1, hits;
        if (maxhits < 0) {
            const char *m = getenv("FRN_TRACE_MAXHITS");
            maxhits = m ? atol(m) : 0;   /* 0 = unlimited */
        }
        if ((long)r[6] >= minr6 && (maxhits == 0 || hits < maxhits)) {
            hits++;
            fprintf(frn_tr_out, "[call] 0x%08x  r4=0x%08x r5=0x%08x r6=0x%08x "
                    "r7=0x%08x r8=0x%08x r13=0x%08x r14=0x%08x  rp=0x%08x sp=0x%08x\n",
                    pc, r[4], r[5], r[6], r[7], r[8], r[13], r[14], env->rp, r[15]);
            /* walk the stack for firmware-range return addresses = call chain */
            fprintf(frn_tr_out, "       stack:");
            for (int k = 0; k < 96; k++) {
                uint32_t sv = cpu_ldl_be_data(env, r[15] + k * 4);
                if (sv >= FW_BASE && sv < FW_END) {
                    fprintf(frn_tr_out, " 0x%08x", sv);
                }
            }
            fprintf(frn_tr_out, "\n");
        }
    }
    uint32_t w = rd16(env, pc);
    uint32_t pending = env->delay_armed ? env->delay_pc : 0xffffffffu;
    int had_pending = env->delay_armed;
    env->delay_armed = 0;

    uint32_t hi8 = (w >> 8) & 0xff;
    uint32_t hi4 = (w >> 12) & 0xf;
    uint32_t t12 = (w >> 4) & 0xfff;
    int ri = w & 0xf;
    int rj = (w >> 4) & 0xf;
    uint32_t xc = (w >> 4) & 0xf;
    uint32_t td = w & 0xff;
    uint32_t op = hi8;

    env->pc = pc + 2;   /* default advance; overridden by transfers */

    do {
    /* ---- full-word opcodes ---- */
    if (w == 0x9720) { env->pc = env->rp; break; }                 /* ret */
    if (w == 0x9F20) { go(env, env->rp, 1); break; }               /* ret:D */
    if (w == 0x9730) {                                             /* reti */
        uint32_t ptr = rd32(env, r[15]); r[15] += 4;
        uint32_t ps = rd32(env, r[15]); r[15] += 4;
        unpack_ps(env, ps); env->pc = ptr; break;
    }
    if (w == 0x9FA0) { break; }                                    /* nop */
    if (w == 0x9F90) { r[15] = r[14] + 4; r[14] = rd32(env, r[15] - 4); break; } /* leave */
    if (w == 0x0790) { unpack_ps(env, rd32(env, r[15])); r[15] += 4; break; }    /* ld @r15+,ps */
    if (w == 0x1790) { push32(env, pack_ps(env)); break; }         /* st ps,@-r15 */
    if (w == 0x9F60 || w == 0x9F70 || w == 0x9F30) { break; }      /* div3/div4s/u_inte nop */

    /* ---- 12-bit opcodes ---- */
    if (t12 == 0x9F8) { r[ri] = rd32(env, pc + 2); env->pc = pc + 6; break; }    /* ldi:32 */
    if (hi8 == 0x9B) { uint32_t xl = rd16(env, pc + 2); r[ri] = ((xc << 16) | xl) & 0xfffff; env->pc = pc + 4; break; } /* ldi:20 */
    if (t12 == 0x970) { env->pc = r[ri]; break; }                  /* jmp @ri */
    if (t12 == 0x9F0) { go(env, r[ri], 1); break; }                /* jmp:D @ri */
    if (t12 == 0x971) {
        if (pc >= 0x10439674 && pc <= 0x104396d0) {
            static uint32_t _vs[16]; static int _vn;
            int f = 0; for (int k = 0; k < _vn; k++) if (_vs[k] == r[ri]) f = 1;
            if (frn_tr_irq && !f && _vn < 16) { _vs[_vn++] = r[ri];
                fprintf(frn_tr_out ? frn_tr_out : stderr, "[task1-vtable] pc=%08x -> method=%08x (obj r4=%08x)\n", pc, r[ri], r[4]); }
        }
        do_call(env, r[ri], pc + 2, 0); break;
    }   /* call @ri */
    if (t12 == 0x9F1) { do_call(env, r[ri], pc + 4, 1); break; }   /* call:D @ri */
    if (t12 == 0x070) { r[ri] = rd32(env, r[15]); if (ri != 15) r[15] += 4; break; } /* ld @r15+,ri */
    if (t12 == 0x078) { set_sr(env, ri, rd32(env, r[15])); r[15] += 4; break; }  /* ld @r15+,Rs */
    if (t12 == 0x170) { push32(env, r[ri]); break; }               /* st ri,@-r15 */
    if (t12 == 0x178) { push32(env, get_sr(env, ri)); break; }     /* st Rs,@-r15 */
    if (t12 == 0x171) { r[ri] = pack_ps(env); break; }             /* mov ps,ri */
    if (t12 == 0x071) { unpack_ps(env, r[ri]); break; }            /* mov ri,ps */
    if (t12 == 0x974) { int32_t num = s32(env->mdl), d = s32(r[ri]); if (d) { env->mdl = num / d; env->mdh = num % d; } break; } /* div0s */
    if (t12 == 0x975) { uint32_t num = env->mdl, d = r[ri]; if (d) { env->mdl = num / d; env->mdh = num % d; } break; } /* div0u */
    if (t12 == 0x976 || t12 == 0x977) { break; }                   /* div1/div2 nop */
    if (t12 == 0x978) { r[ri] = sext(r[ri], 8); break; }           /* extsb */
    if (t12 == 0x979) { r[ri] = r[ri] & 0xff; break; }             /* extub */
    if (t12 == 0x97A) { r[ri] = sext(r[ri], 16); break; }          /* extsh */
    if (t12 == 0x97B) { r[ri] = r[ri] & 0xffff; break; }           /* extuh */
    if (t12 == 0x97C) { int i; uint32_t v = r[ri]; r[ri] = 32; for (i = 0; i < 32; i++) if (!(v & (0x80000000u >> i))) { r[ri] = i; break; } break; } /* srch0 */
    if (t12 == 0x97D) { int i; uint32_t v = r[ri]; r[ri] = 32; for (i = 0; i < 32; i++) if (v & (0x80000000u >> i)) { r[ri] = i; break; } break; }  /* srch1 */

    /* ---- branch family (hi4 E/F) ---- */
    if (hi4 == 0xE || hi4 == 0xF) {
        int op_b = (w >> 8) & 0xf;
        int32_t disp = (td & 0x80) ? (int32_t)td - 0x100 : (int32_t)td;
        uint32_t target = pc + 2 + disp * 2;
        if (hi4 == 0xE) {
            if (op_b == 0) env->pc = target;
            else if (op_b == 1) { }
            else if (cond(env, op_b)) env->pc = target;
        } else {
            if (op_b == 1) { }
            else if (op_b == 0 || cond(env, op_b)) go(env, target, 1);
        }
        break;
    }

    /* ---- arithmetic (hi8) ---- */
    if (op == 0xA6) { uint32_t a = r[ri], b = r[rj]; env->cc_c = carry32(a, b); env->cc_v = scarry32(a, b); r[ri] = a + b; resflags(env, r[ri], 32); break; }
    if (op == 0xA4) { uint32_t a = r[ri]; env->cc_c = carry32(a, xc); env->cc_v = scarry32(a, xc); r[ri] = a + xc; resflags(env, r[ri], 32); break; }
    if (op == 0xA5) { uint32_t nx = (uint32_t)(-16 + (int)xc); uint32_t a = r[ri]; env->cc_c = carry32(a, nx); env->cc_v = scarry32(a, nx); r[ri] = a + nx; resflags(env, r[ri], 32); break; }
    if (op == 0xA7) { r[ri] = addc_op(env, r[ri], r[rj]); resflags(env, r[ri], 32); break; }
    if (op == 0xA2) { r[ri] = r[ri] + r[rj]; break; }
    if (op == 0xA0) { r[ri] = r[ri] + xc; break; }
    if (op == 0xA1) { r[ri] = r[ri] + (uint32_t)(-16 + (int)xc); break; }
    if (op == 0xAC) { uint32_t a = r[ri], b = r[rj]; env->cc_c = (a < b); env->cc_v = sborrow32(a, b); r[ri] = a - b; resflags(env, r[ri], 32); break; }
    if (op == 0xAD) { r[ri] = subc_op(env, r[ri], r[rj]); resflags(env, r[ri], 32); break; }
    if (op == 0xAE) { r[ri] = r[ri] - r[rj]; break; }
    if (op == 0xAA) { uint32_t a = r[ri], b = r[rj]; env->cc_c = (a < b); env->cc_v = sborrow32(a, b); resflags(env, a - b, 32); break; }
    if (op == 0xA8) { uint32_t a = r[ri]; env->cc_c = (a < xc); env->cc_v = sborrow32(a, xc); resflags(env, a - xc, 32); break; }
    if (op == 0xA9) { uint32_t nx = (uint32_t)(-16 + (int)xc), a = r[ri]; env->cc_c = (a < nx); env->cc_v = sborrow32(a, nx); resflags(env, a - nx, 32); break; }

    /* ---- logic ---- */
    if (op == 0x82) { r[ri] = r[ri] & r[rj]; resflags(env, r[ri], 32); break; }
    if (op == 0x84) { uint32_t v = rd32(env, r[ri]) & r[rj]; wr32(env, r[ri], v); resflags(env, v, 32); break; }
    if (op == 0x85) { uint32_t v = (rd16(env, r[ri]) & r[rj]) & 0xffff; wr16(env, r[ri], v); resflags(env, v, 16); break; }
    if (op == 0x86) { uint32_t v = (rd8(env, r[ri]) & r[rj]) & 0xff; wr8(env, r[ri], v); resflags(env, v, 8); break; }
    if (op == 0x92) { r[ri] = r[ri] | r[rj]; resflags(env, r[ri], 32); break; }
    if (op == 0x94) { uint32_t v = rd32(env, r[ri]) | r[rj]; wr32(env, r[ri], v); resflags(env, v, 32); break; }
    if (op == 0x95) { uint32_t v = (rd16(env, r[ri]) | r[rj]) & 0xffff; wr16(env, r[ri], v); resflags(env, v, 16); break; }
    if (op == 0x96) { uint32_t v = (rd8(env, r[ri]) | r[rj]) & 0xff; wr8(env, r[ri], v); resflags(env, v, 8); break; }
    if (op == 0x9A) { r[ri] = r[ri] ^ r[rj]; resflags(env, r[ri], 32); break; }
    if (op == 0x9C) { uint32_t v = rd32(env, r[ri]) ^ r[rj]; wr32(env, r[ri], v); resflags(env, v, 32); break; }
    if (op == 0x9D) { uint32_t v = (rd16(env, r[ri]) ^ r[rj]) & 0xffff; wr16(env, r[ri], v); resflags(env, v, 16); break; }
    if (op == 0x9E) { uint32_t v = (rd8(env, r[ri]) ^ r[rj]) & 0xff; wr8(env, r[ri], v); resflags(env, v, 8); break; }

    /* ---- bit ops on memory ---- */
    if (op == 0x80) { uint32_t t = rd8(env, r[ri]); wr8(env, r[ri], t & (xc + 0xf0)); break; }
    if (op == 0x81) { uint32_t t = rd8(env, r[ri]); wr8(env, r[ri], t & ((xc << 4) + 0x0f)); break; }
    if (op == 0x90) { uint32_t t = rd8(env, r[ri]); wr8(env, r[ri], t | (xc & 0x0f)); break; }
    if (op == 0x91) { uint32_t t = rd8(env, r[ri]); wr8(env, r[ri], t | ((xc << 4) & 0xf0)); break; }
    if (op == 0x98) { uint32_t t = rd8(env, r[ri]); wr8(env, r[ri], (xc ^ t) & 0xff); break; }
    if (op == 0x99) { uint32_t t = rd8(env, r[ri]); wr8(env, r[ri], ((xc << 4) ^ t) & 0xff); break; }
    if (op == 0x88) { uint32_t t = rd8(env, r[ri]); resflags(env, (xc & t) & 0x0f, 8); break; }
    if (op == 0x89) { uint32_t t = rd8(env, r[ri]); resflags(env, ((xc << 4) & t) & 0xffff, 16); break; }

    /* ---- mul ---- */
    if (op == 0xAF) { int64_t res = (int64_t)s32(r[ri]) * (int64_t)s32(r[rj]); uint64_t u = (uint64_t)res; resflags(env, u, 64); env->mdl = u & M32; env->mdh = (u >> 32) & M32; env->cc_v = (env->mdh != 0 && env->mdh != M32); break; }
    if (op == 0xAB) { uint64_t res = (uint64_t)r[ri] * (uint64_t)r[rj]; resflags(env, res, 64); env->mdl = res & M32; env->mdh = (res >> 32) & M32; env->cc_v = (env->mdh != 0); break; }
    if (op == 0xBF) { uint32_t res = (uint32_t)(sext(r[ri], 16) * sext(r[rj], 16)); resflags(env, res, 32); env->mdl = res; break; }
    if (op == 0xBB) { uint32_t res = (r[ri] & 0xffff) * (r[rj] & 0xffff); resflags(env, res, 32); env->mdl = res; break; }

    /* ---- shifts ---- */
    if (op == 0xB6) { int sh = r[rj] & 0xf; env->cc_c = (((uint64_t)0x100000000ULL >> sh) & r[ri]) != 0; r[ri] = (sh >= 32) ? 0 : (r[ri] << sh); resflags(env, r[ri], 32); break; }
    if (op == 0xB4) { int sh = xc; env->cc_c = (((uint64_t)0x100000000ULL >> sh) & r[ri]) != 0; r[ri] = (sh >= 32) ? 0 : (r[ri] << sh); resflags(env, r[ri], 32); break; }
    if (op == 0xB5) { int sh = xc + 16; env->cc_c = (((uint64_t)0x100000000ULL >> sh) & r[ri]) != 0; r[ri] = (sh >= 32) ? 0 : (r[ri] << sh); resflags(env, r[ri], 32); break; }
    if (op == 0xB2) { r[ri] = lsr_op(env, r[ri], r[rj] & 0x1f); break; }
    if (op == 0xB0) { r[ri] = lsr_op(env, r[ri], xc & 0x1f); break; }
    if (op == 0xB1) { r[ri] = lsr_op(env, r[ri], (xc + 16) & 0x1f); break; }
    if (op == 0xBA) { r[ri] = asr_op(env, r[ri], r[rj] & 0x1f); break; }
    if (op == 0xB8) { r[ri] = asr_op(env, r[ri], xc & 0x1f); break; }
    if (op == 0xB9) { r[ri] = asr_op(env, r[ri], (xc + 16) & 0x1f); break; }

    /* ---- ldi:8 ---- */
    if (hi4 == 0xC) { r[ri] = (w >> 4) & 0xff; break; }

    /* ---- loads ---- */
    if (op == 0x04) { r[ri] = rd32(env, r[rj]); break; }
    if (op == 0x00) { r[ri] = rd32(env, r[13] + r[rj]); break; }
    if (hi4 == 0x2) { r[ri] = rd32(env, r[14] + sx8((w >> 4) & 0xff) * 4); break; }
    if (op == 0x03) { r[ri] = rd32(env, r[15] + xc * 4); break; }
    if (op == 0x05) { r[ri] = rd16(env, r[rj]) & 0xffff; break; }
    if (op == 0x01) { r[ri] = rd16(env, r[13] + r[rj]) & 0xffff; break; }
    if (hi4 == 0x4) { r[ri] = rd16(env, r[14] + sx8((w >> 4) & 0xff) * 2) & 0xffff; break; }
    if (op == 0x06) { r[ri] = rd8(env, r[rj]) & 0xff; break; }
    if (op == 0x02) { r[ri] = rd8(env, r[13] + r[rj]) & 0xff; break; }
    if (hi4 == 0x6) { r[ri] = rd8(env, r[14] + sx8((w >> 4) & 0xff)) & 0xff; break; }

    /* ---- stores ---- */
    if (op == 0x14) { wr32(env, r[rj], r[ri]); break; }
    if (op == 0x10) { wr32(env, r[13] + r[rj], r[ri]); break; }
    if (hi4 == 0x3) { wr32(env, r[14] + sx8((w >> 4) & 0xff) * 4, r[ri]); break; }
    if (op == 0x13) { wr32(env, r[15] + xc * 4, r[ri]); break; }
    if (op == 0x15) { wr16(env, r[rj], r[ri]); break; }
    if (op == 0x11) { wr16(env, r[13] + r[rj], r[ri]); break; }
    if (hi4 == 0x5) { wr16(env, r[14] + sx8((w >> 4) & 0xff) * 2, r[ri]); break; }
    if (op == 0x16) { wr8(env, r[rj], r[ri]); break; }
    if (op == 0x12) { wr8(env, r[13] + r[rj], r[ri]); break; }
    if (hi4 == 0x7) { wr8(env, r[14] + sx8((w >> 4) & 0xff), r[ri]); break; }

    /* ---- moves ---- */
    if (op == 0x8B) { r[ri] = r[rj]; break; }
    if (op == 0xB7) { r[ri] = get_sr(env, rj); break; }
    if (op == 0xB3) { set_sr(env, rj, r[ri]); break; }

    /* ---- call direct ---- */
    if ((w >> 11) == 0x1A) { int32_t d = w & 0x7ff; if (d & 0x400) d -= 0x800; do_call(env, pc + 2 + d * 2, pc + 2, 0); break; }
    if ((w >> 11) == 0x1B) { int32_t d = w & 0x7ff; if (d & 0x400) d -= 0x800; do_call(env, pc + 2 + d * 2, pc + 4, 1); break; }

    /* ---- int #u8 ---- */
    if (op == 0x1F) {
        if (td == 0x40) {   /* DEBUG: log distinct REALOS service routines (r12) */
            static uint32_t _seen[128]; static int _ns;
            uint32_t svc = env->regs[12];
            int f = 0;
            for (int k = 0; k < _ns; k++) if (_seen[k] == svc) { f = 1; break; }
            if (frn_tr_irq && !f && _ns < 128) {
                _seen[_ns++] = svc;
                fprintf(frn_tr_out ? frn_tr_out : stderr, "[int40] service r12=%08x  r4=%08x r5=%08x  pc=%08x\n",
                        svc, env->regs[4], env->regs[5], pc);
            }
        }
        uint32_t ea = env->tbr + 0x3FC - (td * 4);
        uint32_t vec = rd32(env, ea);
        if (vec >= FW_BASE && vec < FW_END) {
            set_sflag(env, 0);
            push32(env, pack_ps(env));
            push32(env, pc + 2);
            env->i_flag = 0;
            env->pc = vec;
        } else {
            set_sflag(env, 0);
            env->i_flag = 0;
        }
        break;
    }

    /* ---- dmov (implicit r13) ---- */
    if (op == 0x08) { r[13] = rd32(env, td * 4); break; }
    if (op == 0x18) { wr32(env, td * 4, r[13]); break; }
    if (op == 0x0C) { wr32(env, r[13], rd32(env, td * 4)); r[13] += 4; break; }
    if (op == 0x1C) { wr32(env, td * 4, rd32(env, r[13])); r[13] += 4; break; }
    if (op == 0x0B) { r[15] -= 4; wr32(env, r[15], rd32(env, td * 4)); break; }
    if (op == 0x1B) { wr32(env, td * 4, rd32(env, r[15])); r[15] += 4; break; }
    if (op == 0x09) { r[13] = rd16(env, td * 2); break; }
    if (op == 0x19) { wr16(env, td * 2, r[13]); break; }
    if (op == 0x0D) { wr16(env, r[13], rd16(env, td * 2)); r[13] += 2; break; }
    if (op == 0x1D) { wr16(env, td * 2, rd16(env, r[13])); r[13] += 2; break; }
    if (op == 0x0A) { r[13] = rd8(env, td); break; }
    if (op == 0x1A) { wr8(env, td, r[13]); break; }
    if (op == 0x0E) { wr8(env, r[13], rd8(env, td)); r[13] += 1; break; }
    if (op == 0x1E) { wr8(env, td, rd8(env, r[13])); r[13] += 1; break; }

    /* ---- misc ---- */
    if (op == 0x83) { unpack_ccr(env, pack_ccr(env) & td); break; }
    if (op == 0x93) { unpack_ccr(env, pack_ccr(env) | td); break; }
    if (op == 0x87) { env->ilm = td & 0x1f; break; }
    if (op == 0xA3) { r[15] = r[15] + sx8(td) * 4; break; }
    if (op == 0x8A) { uint32_t tmp = r[ri] & 0xff; r[ri] = rd8(env, r[rj]) & 0xff; wr8(env, r[rj], tmp); break; }

    /* ---- ldm/stm/enter ---- */
    if (op == 0x8C) { for (int reg = 0; reg < 8; reg++) if (td & (1 << reg)) { r[reg] = rd32(env, r[15]); r[15] += 4; } break; }
    if (op == 0x8D) { for (int reg = 8; reg < 16; reg++) if (td & (1 << (reg - 8))) { r[reg] = rd32(env, r[15]); r[15] += 4; } break; }
    if (op == 0x8E) { for (int reg = 7; reg >= 0; reg--) if (td & (1 << (7 - reg))) { r[15] -= 4; wr32(env, r[15], r[reg]); } break; }
    if (op == 0x8F) { for (int reg = 15; reg > 7; reg--) if (td & (1 << (15 - reg))) { r[15] -= 4; wr32(env, r[15], r[reg]); } break; }
    if (op == 0x0F) { uint32_t ea = r[15] - 4; wr32(env, ea, r[14]); r[14] = ea; r[15] = r[15] - td * 4; break; }

    /* ---- unknown: leave pc advanced by 2 (skeleton tolerance) ---- */
    } while (0);

    if (had_pending) {
        env->pc = pending;
    }
}

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
    /* FRN_HIST_ALL=1 dumps every non-zero bucket (for full boot-chain coverage);
     * otherwise the top 50 by hit-count. */
    if (getenv("FRN_HIST_ALL")) {
        for (uint32_t i = 0; i < FRN_HIST_SZ; i++) {
            if (frn_hist[i]) fprintf(f, "0x%08x  %u\n", 0x10000000u | (i << 4), frn_hist[i]);
        }
    } else {
        for (int top = 0; top < 50; top++) {
            uint32_t best = 0, bi = 0;
            for (uint32_t i = 0; i < FRN_HIST_SZ; i++) {
                if (frn_hist[i] > best) { best = frn_hist[i]; bi = i; }
            }
            if (best == 0) break;
            fprintf(f, "0x%08x  %u\n", 0x10000000u | (bi << 4), best);
            frn_hist[bi] = 0;
        }
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

/* Read-before-write detector (FRN_LOG_RBW=lo-hi): find addresses the firmware READS
 * before ever WRITING them in [lo,hi) -- i.e. DATA it expects to have been pre-
 * initialized (by a boot-ROM stage we don't emulate). Logs addr+PC+value, deduped.
 * Byte-granularity written-bitmap over the window. (Andrew: "missing RAM/ROM data".) */
static uint8_t *frn_rbw_bm; static uint32_t frn_rbw_lo, frn_rbw_hi; static int frn_rbw_init = 0;
static void frn_rbw_setup(void)
{
    frn_rbw_init = 1;
    const char *s = getenv("FRN_LOG_RBW");
    if (!s) return;
    char *e; frn_rbw_lo = (uint32_t)strtoul(s, &e, 16);
    frn_rbw_hi = (*e == '-') ? (uint32_t)strtoul(e + 1, NULL, 16) : frn_rbw_lo + 0x800000;
    size_t n = (frn_rbw_hi - frn_rbw_lo + 7) / 8;
    frn_rbw_bm = calloc(n, 1);
    if (!frn_rbw_bm) frn_rbw_lo = frn_rbw_hi = 0;
}
static inline void frn_rbw_mark(uint32_t a, unsigned sz)
{
    if (!frn_rbw_init) frn_rbw_setup();
    if (!frn_rbw_bm) return;
    for (unsigned i = 0; i < sz; i++) { uint32_t x = a + i;
        if (x >= frn_rbw_lo && x < frn_rbw_hi) { uint32_t o = x - frn_rbw_lo; frn_rbw_bm[o >> 3] |= 1u << (o & 7); } }
}
static inline void frn_rbw_check(CPUFRNState *e, uint32_t a, unsigned sz, uint32_t v)
{
    if (!frn_rbw_init) frn_rbw_setup();
    if (!frn_rbw_bm) return;
    if (a < frn_rbw_lo || a >= frn_rbw_hi) return;
    uint32_t o = a - frn_rbw_lo;
    if (frn_rbw_bm[o >> 3] & (1u << (o & 7))) return;     /* already written */
    /* mark now so we log each address only once */
    for (unsigned i = 0; i < sz; i++) { uint32_t x = a + i; if (x >= frn_rbw_lo && x < frn_rbw_hi) {
        uint32_t oo = x - frn_rbw_lo; frn_rbw_bm[oo >> 3] |= 1u << (oo & 7); } }
    static int n;
    if (n++ < 4000)
        fprintf(frn_tr_out ? frn_tr_out : stderr,
                "[rbw] read-before-write 0x%08x (sz%u) = 0x%08x  pc~0x%08x\n", a, sz, v, e->pc);
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
    /* FRN_HIST_RESET: fully zero the PC histogram after each snapshot dump so the
     * NEXT snapshot's histogram is the delta since this one - isolates what a button
     * press (injected between snapshots) actually causes, instead of boot noise. */
    if (frn_hist_on && frn_hist && getenv("FRN_HIST_RESET"))
        memset(frn_hist, 0, FRN_HIST_SZ * sizeof(uint32_t));
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
    if (frn_rdwatch) {
        static long len = -1;
        if (len < 0) { const char *l = getenv("FRN_RDWATCH_LEN"); len = l ? strtol(l, NULL, 0) : 64; }
        if (a >= frn_rdwatch && a < frn_rdwatch + len) {
            static int n;
            if (n++ < 200) {
                fprintf(frn_tr_out ? frn_tr_out : stderr,
                        "[rdwatch] read 0x%08x (+0x%lx) from pc~0x%08x\n",
                        a, (long)(a - frn_rdwatch), e->pc);
            }
        }
    }
    /* FRN_RDAT_PC=hex: when the PC is within [pc, pc+0x20), log the distinct
     * addresses this instruction window reads (the word a poll-loop spins on). */
    {
        static int rdat_init = 0; static uint32_t rdat_pc = 0;
        if (!rdat_init) { rdat_init = 1; const char *s = getenv("FRN_RDAT_PC");
            if (s) rdat_pc = (uint32_t)strtoul(s, NULL, 16); }
        if (rdat_pc && e->pc >= rdat_pc && e->pc < rdat_pc + 0x20) {
            static uint32_t seen[32]; static int nseen = 0; int found = 0;
            for (int i = 0; i < nseen; i++) if (seen[i] == a) { found = 1; break; }
            if (!found && nseen < 32) {
                seen[nseen++] = a;
                fprintf(frn_tr_out ? frn_tr_out : stderr,
                        "[rdat] pc 0x%08x reads addr 0x%08x\n", e->pc, a);
            }
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

/* --- Black-box DSP reply feeder (FRN_DSP_REPLY=hexbytes) ------------------
 * The CPUCOM task sends a command over TDR(0x58) then waits for the DSP's reply.
 * There is no DSP, so the reply never arrives (InSize=0 -> timeout). This models
 * the DSP as a black box: after the firmware writes the command to TDR, offer the
 * configured reply bytes on RDR(0x58) reads and assert RDRF in SSR(0x5e); fire
 * vec26 (FRN_FIRE_VECS=26) to drive the RX ISR. Discover the reply the firmware
 * accepts empirically by watching the cmd_handler transaction struct (FRN_DUMP_CMDH). */
static uint8_t  frn_dsp_reply[64]; static int frn_dsp_reply_len = -1;
static int      frn_dsp_pos = 0, frn_dsp_armed = 0;
static int      frn_dsp_rdrf = 0x10;      /* candidate RDRF bit; override FRN_SCI_RDRF */
static long     frn_dsp_feeds = 0, frn_dsp_maxfeeds = 0;
static void frn_dsp_init(void)
{
    if (frn_dsp_reply_len >= 0) return;
    frn_dsp_reply_len = 0;
    const char *s = getenv("FRN_DSP_REPLY");
    while (s && *s && frn_dsp_reply_len < 64) {
        while (*s==' '||*s==',') s++;
        if (!*s) break;
        char buf[3]={0}; int n=0; while (n<2 && isxdigit((unsigned char)*s)) buf[n++]=*s++;
        if (!n) break;
        frn_dsp_reply[frn_dsp_reply_len++] = (uint8_t)strtoul(buf,NULL,16);
    }
    const char *r = getenv("FRN_SCI_RDRF"); if (r) frn_dsp_rdrf = (int)strtoul(r,NULL,16);
    const char *m = getenv("FRN_DSP_MAXFEEDS"); frn_dsp_maxfeeds = m ? strtol(m,NULL,0) : 2000;
}
/* --- Black-box DSP: CPUCOM SPI/CSIO at 0x5c004040(status)/0x5c004043(data) ----
 * The Cmd:04 handshake is a full-duplex SPI transfer (cpucom_spi_xfer 0x10465958):
 * firmware writes a TX byte to the data reg then reads the simultaneous RX byte;
 * the status reg bit10(0x400)=BUSY is polled until clear. The regs are in the
 * 0x5c block (RAM-backed -> read 0 -> all-zero reply -> validation times out). This
 * models the DSP: never-busy status, and a per-byte response stream. The firmware
 * sends [Cmd][Size][data...] and reads [resp0][InSize][data...]; discover the reply
 * that makes the transfer validate (result 0) empirically via FRN_SPI_REPLY. */
#define SPI_STATUS 0x5c004040u
#define SPI_DATA   0x5c004043u
static uint8_t frn_spi_reply[64]; static int frn_spi_reply_len = -1;
static int frn_spi_pos = 0; static int frn_spi_on = 0;
static int frn_spi_busy = 0;   /* pulses 1 after a start, cleared on next status read */
static uint8_t frn_hs_reqprev = 0, frn_hs_pendack = 0;  /* 0x50000106 handshake: req edges -> ack pulse */
static void frn_spi_init(void)
{
    if (frn_spi_reply_len >= 0) return;
    frn_spi_reply_len = 0;
    const char *s = getenv("FRN_SPI_REPLY");
    /* The DSP/companion chip is ALWAYS physically present on the camera, so its
     * CPUCOM reply is permanent model behavior — not opt-in. Default ON (opt out
     * with FRN_NO_DSP for A/B testing). FRN_SPI_REPLY still overrides the reply
     * bytes. Without it, default to a single 0x01 ack (the known-good handshake
     * value) so the Cmd:04 transfer returns In Size:5 and POST passes. */
    frn_spi_on = (getenv("FRN_NO_DSP") == NULL);
    while (s && *s && frn_spi_reply_len < 64) {
        while (*s==' '||*s==',') s++;
        if (!*s) break;
        char buf[3]={0}; int n=0; while (n<2 && isxdigit((unsigned char)*s)) buf[n++]=*s++;
        if (!n) break;
        frn_spi_reply[frn_spi_reply_len++] = (uint8_t)strtoul(buf,NULL,16);
    }
    if (frn_spi_reply_len == 0) { frn_spi_reply[0] = 0x01; frn_spi_reply_len = 1; }
}
static inline uint32_t rd8(CPUFRNState *e, uint32_t a)
{
    frn_rd_hist(a);
    frn_rd_watch(e, a);
    /* Black-box DSP GPIO handshake at 0x50000106: the firmware sets bit 0x40 ("byte
     * ready" req to DSP) and polls bit 0x01 ("DSP ready" ack). Model the DSP acking:
     * bit 0x01 mirrors bit 0x40 (ack follows req), so the per-byte handshake proceeds. */
    /* dev2 (settings EEPROM/serial on 0x5c005000) status: bit0x01=ready. RAM-backed ->
     * never sets -> firmware spins (FUN_1043fd24). Report ready so transfers proceed. */
    if (a == 0x5c005000u) { frn_spi_init();
        if (frn_spi_on) return cpu_ldub_data(e, a) | 0x01u; }
    if (a == 0x50000106u) { frn_spi_init();
        if (frn_spi_on) { uint32_t b = cpu_ldub_data(e, a);
            /* DSP handshake (code-derived): main drives req bits 0x20/0x40/0x80 and the
             * cycle is req-up -> wait ack CLEAR, req-down -> wait ack SET. So the DSP ack
             * (0x01/0x02/0x04) is the INVERSE of the matching req (0x20/0x40/0x80): ack
             * asserts when the main releases req. ack = (~req) >> 5. */
            return (b & 0xf8u) | (((~b) >> 5) & 0x07u); } }
    if (a == SPI_DATA) { frn_spi_init();
        if (frn_spi_on) {
            uint8_t b = (frn_spi_pos < frn_spi_reply_len) ? frn_spi_reply[frn_spi_pos] : 0xff;
            if (getenv("FRN_SPI_LOG")) fprintf(frn_tr_out?frn_tr_out:stderr,
                "[spi] RX byte[%d]=0x%02x pc=0x%08x\n", frn_spi_pos, b, e->pc);
            frn_spi_pos++;
            return b;
        }
    }
    { uint32_t fv; if (frn_force_lookup(a, &fv)) return fv & 0xff; }
    if (a == 0x4A) return (e->tmr_count >> 8) & 0xff;
    if (a == 0x4B) return e->tmr_count & 0xff;
    /* Debug UART status reg at 0x60: bit3 (0x08) = TX buffer ready/empty. The
     * firmware's serial puts() (FUN_103b764c) busy-waits on this before writing
     * the TX data reg 0x61. Unmodeled -> infinite wait. Report TX always ready. */
    if (a == 0x60) return 0x08;
    { uint32_t r = cpu_ldub_data(e, a); frn_rbw_check(e, a, 1, r); return r; }
}
/* Write-watchpoint (FRN_WRWATCH=hex[,FRN_WRWATCH_LEN]): log PC+value on writes
 * into the window — to find the code that populates a struct (e.g. the settings
 * load that reveals the persistent-store interface). */
static uint32_t frn_wrwatch = 0; static long frn_wrwatch_len = 0; static int frn_wrwatch_init = 0;
static inline void frn_wr_watch(CPUFRNState *e, uint32_t a, uint32_t v)
{
    if (!frn_wrwatch_init) {
        frn_wrwatch_init = 1;
        const char *s = getenv("FRN_WRWATCH");
        if (s) frn_wrwatch = (uint32_t)strtoul(s, NULL, 16);
        const char *l = getenv("FRN_WRWATCH_LEN"); frn_wrwatch_len = l ? strtol(l, NULL, 0) : 4;
    }
    if (frn_wrwatch && a >= frn_wrwatch && a < frn_wrwatch + frn_wrwatch_len) {
        static int nzinit = 0, nzonly = 0;
        if (!nzinit) { nzinit = 1; nzonly = getenv("FRN_WRWATCH_NZ") ? 1 : 0; }
        if (nzonly && v == 0) return;
        static int n;
        if (n++ < 20000) {
            fprintf(frn_tr_out ? frn_tr_out : stderr,
                    "[wrwatch] write 0x%08x (+0x%lx) = 0x%08x from pc~0x%08x\n",
                    a, (long)(a - frn_wrwatch), v, e->pc);
        }
    }
    /* FRN_WRAT_PC=hex[,len]: when PC is within [pc, pc+len) (default 0x40), log
     * the distinct addresses this code window WRITES — finds a rasterizer's
     * pixel target. Histograms targets into 0x10000-granular buckets. */
    {
        static int init = 0; static uint32_t wrat_pc = 0; static long wrat_len = 0x40;
        if (!init) { init = 1; const char *s = getenv("FRN_WRAT_PC");
            if (s) { char *e2; wrat_pc = (uint32_t)strtoul(s, &e2, 16);
                     if (e2 && *e2==',') wrat_len = strtol(e2+1, NULL, 0); } }
        if (wrat_pc && e->pc >= wrat_pc && e->pc < wrat_pc + wrat_len) {
            static uint32_t bk[64]; static uint32_t cnt[64]; static int nb = 0;
            uint32_t b = a & 0xffff0000u; int i;
            for (i = 0; i < nb; i++) if (bk[i] == b) { cnt[i]++; break; }
            if (i == nb && nb < 64) { bk[nb] = b; cnt[nb] = 1; nb++;
                fprintf(frn_tr_out ? frn_tr_out : stderr,
                        "[wrat] pc-window writes region 0x%08x (first val 0x%08x from pc 0x%08x)\n",
                        b, v, e->pc); }
        }
    }
}

static inline void wr8(CPUFRNState *e, uint32_t a, uint32_t v)
{
    frn_wr_hist(a);
    frn_wr_watch(e, a, v);
    cpu_stb_data(e, a, v & 0xff); frn_rbw_mark(a, 1);
    if (a == 0x44) {
        e->dicr_pending = v & 1;
    } else if (a >= 0x48 && a <= 0x4F) {
        frn_timer_reg_written(e);
    } else if (a == 0x50000106u) {
        /* DSP handshake: a req bit (0x20/0x40/0x80) rising schedules one ack pulse
         * (req>>5) that the next read of this reg will deliver then consume. */
        frn_spi_init();
        if (frn_spi_on) { uint8_t nv = v & 0xff;
            uint8_t rising = (uint8_t)(nv & 0xe0) & (uint8_t)~frn_hs_reqprev;
            frn_hs_pendack |= (uint8_t)((rising >> 5) & 0x07u);
            frn_hs_reqprev = nv & 0xe0; }
    } else if (a == 0x61) {
        /* Debug UART TX data reg: capture the firmware's serial output so boot
         * progress / debug banners are visible. Gated by FRN_UART (default on). */
        static int uinit = -1; if (uinit < 0) uinit = getenv("FRN_UART_OFF") ? 0 : 1;
        if (uinit) { fputc(v & 0xff, frn_tr_out ? frn_tr_out : stderr);
                     fflush(frn_tr_out ? frn_tr_out : stderr); }
    }
}
static inline uint32_t rd16(CPUFRNState *e, uint32_t a)
{
    if (a < 0x50) return (rd8(e, a) << 8) | rd8(e, a + 1);
    frn_rd_hist(a); frn_rd_watch(e, a);
    { uint32_t fv; if (frn_force_lookup(a, &fv)) return fv & 0xffff; }
    /* CPUCOM (main<->DSP) SCI status reg at 0x5e: bit2 (0x0004) = TX-complete. The
     * send loop (cpucom_sci_send_byte 0x1043c186) busy-waits while((st & 4)==0);
     * 0x5e is RAM so bit2 never sets -> spin. Report TX-complete so the send
     * progresses and the DSP handshake can proceed. Gated by FRN_DSP_OFF to disable. */
    if (a == SPI_STATUS) { frn_spi_init();
        uint32_t r = cpu_lduw_be_data(e, a);
        if (frn_spi_on) r &= ~0x0400u;   /* black-box DSP: transfer completes instantly (busy clear) */
        return r; }
    if (a == 0x5e) { static int off = -1; if (off < 0) off = getenv("FRN_DSP_OFF") ? 1 : 0;
        frn_dsp_init();
        uint32_t r = cpu_lduw_be_data(e, a); if (!off) r |= 0x0004;
        /* assert RDRF while a black-box reply byte is pending */
        if (frn_dsp_armed && frn_dsp_pos < frn_dsp_reply_len) r |= frn_dsp_rdrf;
        return r; }
    /* RDR(0x58) read: hand the next black-box reply byte to the firmware's RX reader */
    if (a == 0x58) { frn_dsp_init();
        if (frn_dsp_armed && frn_dsp_pos < frn_dsp_reply_len) {
            uint32_t b = frn_dsp_reply[frn_dsp_pos++]; frn_dsp_feeds++;
            if (frn_dsp_pos >= frn_dsp_reply_len) frn_dsp_armed = 0;
            if (getenv("FRN_DSP_LOG")) fprintf(frn_tr_out?frn_tr_out:stderr,
                "[dsp-reply] RDR read -> byte 0x%02x (%d/%d) pc=0x%08x\n", b, frn_dsp_pos, frn_dsp_reply_len, e->pc);
            return b; } }
    { uint32_t r = cpu_lduw_be_data(e, a); frn_rbw_check(e, a, 2, r); return r; }
}
static inline uint32_t rd32(CPUFRNState *e, uint32_t a)
{
    if (a < 0x50) return (rd8(e, a) << 24) | (rd8(e, a + 1) << 16)
                       | (rd8(e, a + 2) << 8) | rd8(e, a + 3);
    frn_rd_hist(a); frn_rd_watch(e, a);
    { uint32_t fv; if (frn_force_lookup(a, &fv)) return fv; }
    { uint32_t r = cpu_ldl_be_data(e, a); frn_rbw_check(e, a, 4, r); return r; }
}
static inline void wr16(CPUFRNState *e, uint32_t a, uint32_t v)
{
    if (a < 0x50) { wr8(e, a, v >> 8); wr8(e, a + 1, v); return; }
    frn_wr_hist(a); frn_wr_watch(e, a, v);
    cpu_stw_be_data(e, a, v & 0xffff); frn_rbw_mark(a, 2);
    /* CPUCOM SPI black-box: status write with config bit 0x200 = a new transaction
     * is being set up -> reset the per-byte response position. */
    if (a == SPI_STATUS) { frn_spi_init(); if (frn_spi_on) {
        if (v & 0x200) { if (getenv("FRN_SPI_LOG")) fprintf(frn_tr_out?frn_tr_out:stderr,
                "[spi] txn start (status<-0x%04x) reset pos\n", v & 0xffff);
            frn_spi_pos = 0; }
        if (v & 0x100) frn_spi_busy = 1;   /* bit8 start -> transfer in progress */
    } }
    /* DSP black-box: the firmware just wrote a byte to TDR(0x58) = sent a command
     * byte. Arm the reply (reset position) so the configured reply is offered on
     * the subsequent RDR reads once the firmware enters its receive state. */
    if (a == 0x58) { frn_dsp_init();
        if (frn_dsp_reply_len > 0 && (frn_dsp_maxfeeds==0 || frn_dsp_feeds < frn_dsp_maxfeeds)) {
            frn_dsp_armed = 1; frn_dsp_pos = 0; } }
}
uint64_t frn_lcd_writes;      /* debug: count of LCD-reg writes */
uint32_t frn_lcd_scanout;     /* debug: scanout base once programmed */
static inline void wr32(CPUFRNState *e, uint32_t a, uint32_t v)
{
    if (a < 0x50) { wr8(e, a, v >> 24); wr8(e, a + 1, v >> 16);
                    wr8(e, a + 2, v >> 8); wr8(e, a + 3, v); return; }
    frn_wr_hist(a); frn_wr_watch(e, a, v);
    if (a >= 0x40100000 && a < 0x40101000) {
        frn_lcd_writes++;
        if (a == 0x40100800 && v && !frn_lcd_scanout) {
            frn_lcd_scanout = v;
            fprintf(stderr, "[LCD] *** scanout base programmed: 0x40100800 <- %08x (lcd_writes=%llu) ***\n",
                    v, (unsigned long long)frn_lcd_writes);
        }
    }
    cpu_stl_be_data(e, a, v); frn_rbw_mark(a, 4);
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

/* Generic periodic-IRQ firer (FRN_FIRE_VECS="43,46,47,..."): fire each listed
 * vector periodically once the firmware has enabled its ICR (level != 0x1f).
 * This is RE-from-firmware: the K10D's imaging peripherals have no datasheet, so
 * we discover which autonomous interrupts advance the boot by firing the armed
 * ones (exactly how the watch-counter/vec41 was found) and watching the effect. */
#define FRN_FIRE_MAX 16
static uint32_t frn_fire_vec[FRN_FIRE_MAX], frn_fire_div[FRN_FIRE_MAX];
static uint8_t  frn_fire_pending[FRN_FIRE_MAX];
static int frn_fire_n = -1;
static long frn_fire_period = 200000;
static void frn_fire_tick(CPUFRNState *e)
{
    if (frn_fire_n < 0) {
        frn_fire_n = 0;
        const char *s = getenv("FRN_FIRE_VECS");
        const char *p = getenv("FRN_FIRE_PERIOD"); if (p) frn_fire_period = strtol(p, NULL, 0);
        while (s && *s && frn_fire_n < FRN_FIRE_MAX) {
            char *end; long v = strtol(s, &end, 0);
            if (end == s) break;
            frn_fire_vec[frn_fire_n++] = (uint32_t)v;
            s = (*end == ',') ? end + 1 : end;
        }
    }
    for (int i = 0; i < frn_fire_n; i++) {
        uint32_t icr = cpu_ldub_data(e, 0x440 + (frn_fire_vec[i] - 16)) & 0x1F;
        if (icr == 0x1F) continue;            /* not enabled yet */
        if (++frn_fire_div[i] < (uint32_t)frn_fire_period) continue;
        frn_fire_div[i] = 0;
        frn_fire_pending[i] = 1;
    }
}

/* Built-in autonomous (free-running) timers the firmware unmasks. On real
 * hardware the 32-bit free-run timer (vec43) and the base timers (vec48/49/50)
 * count on their own clock and raise their IRQ periodically once enabled; they
 * are NOT kicked by a task. So, exactly like the watch-counter (vec41), fire
 * each one periodically once the firmware unmasks its ICR (level != 0x1f). This
 * is the peripheral IMPLEMENTATION (always on), distinct from the FRN_FIRE_VECS
 * debug knob. Disable with FRN_NO_AUTOTIMER; retune with FRN_AUTOTIMER_PERIOD.
 * vec41 stays handled by frn_watch_tick. */
/* vec56 = OSDC SUB display IRQ (armed by firmware but never raised = no HW source
 * in emu). Its ISR (0x1043ce50) reads OSDC status 0x5c002000/10/20/30 (bits 0xc =
 * frame ready, modeled in k10d.c) and dispatches OSDC events 0x2c-0x2f; event 0x2d
 * sets Task23's render eventflag 0x804a976c. vec53 (OSDC MAIN) is NOT armed in this
 * boot (autotimer skips masked ICRs); vec56 is the live display IRQ. */
#define FRN_AUTOTIMER_N 6
static const uint32_t frn_autotimer_vec[FRN_AUTOTIMER_N] = { 43, 48, 49, 50, 53, 56 };
static uint32_t frn_autotimer_div[FRN_AUTOTIMER_N];
static uint8_t  frn_autotimer_pending[FRN_AUTOTIMER_N];
static long frn_autotimer_period = 200000;
static int  frn_autotimer_init = 0;
static void frn_autotimer_tick(CPUFRNState *e)
{
    if (!frn_autotimer_init) {
        frn_autotimer_init = 1;
        const char *p = getenv("FRN_AUTOTIMER_PERIOD");
        if (p) frn_autotimer_period = strtol(p, NULL, 0);
        if (getenv("FRN_NO_AUTOTIMER")) frn_autotimer_period = 0;   /* disable */
    }
    if (frn_autotimer_period <= 0) return;
    for (int i = 0; i < FRN_AUTOTIMER_N; i++) {
        uint32_t icr = cpu_ldub_data(e, 0x440 + (frn_autotimer_vec[i] - 16)) & 0x1F;
        if (icr == 0x1F) continue;                 /* not unmasked by firmware */
        if (++frn_autotimer_div[i] < (uint32_t)frn_autotimer_period) continue;
        frn_autotimer_div[i] = 0;
        frn_autotimer_pending[i] = 1;
    }
}

static void frn_deliver(CPUFRNState *e)
{
    if (!e->i_flag) return;
    uint32_t lev[3 + FRN_FIRE_MAX + FRN_AUTOTIMER_N], vec[3 + FRN_FIRE_MAX + FRN_AUTOTIMER_N];
    int kind[3 + FRN_FIRE_MAX + FRN_AUTOTIMER_N], n = 0;
    if (e->pending_valid) { lev[n] = e->pending_level; vec[n] = e->pending_vec; kind[n] = 0; n++; }
    if (e->dicr_pending)  { lev[n] = cpu_ldub_data(e, 0x46f) & 0x1F; vec[n] = DELAYED_VEC; kind[n] = 1; n++; }
    if (e->wc_pending)    { lev[n] = cpu_ldub_data(e, WC_ICR) & 0x1F; vec[n] = WC_VECTOR; kind[n] = 2; n++; }
    for (int i = 0; i < frn_fire_n; i++) {
        if (frn_fire_pending[i]) {
            lev[n] = cpu_ldub_data(e, 0x440 + (frn_fire_vec[i] - 16)) & 0x1F;
            vec[n] = frn_fire_vec[i]; kind[n] = 10 + i; n++;
        }
    }
    for (int i = 0; i < FRN_AUTOTIMER_N; i++) {
        if (frn_autotimer_pending[i]) {
            lev[n] = cpu_ldub_data(e, 0x440 + (frn_autotimer_vec[i] - 16)) & 0x1F;
            vec[n] = frn_autotimer_vec[i]; kind[n] = 30 + i; n++;
        }
    }
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
        if (kind[i] >= 10 && kind[i] < 30) frn_fire_pending[kind[i] - 10] = 0;
        if (kind[i] >= 30) frn_autotimer_pending[kind[i] - 30] = 0;
        uint32_t saved_ps = pack_ps(e);  /* FR: save pre-trap PS (user S=1) BEFORE entering system mode */
        set_sflag(e, 0);
        push32(e, saved_ps);
        push32(e, e->pc);
        e->ilm = lev[i];
        e->pc = handler;
        if (frn_tr_irq) {
            fprintf(frn_tr_out, "[irq] vec%-2u %-9s -> 0x%08x  ilm->%-2u  "
                    "from 0x%08x\n", vec[i],
                    kind[i]==0?"timer":kind[i]==1?"dicr":kind[i]==2?"watch-cnt":kind[i]>=30?"autotmr":"fire",
                    handler, lev[i], rd32(e, e->regs[15]));
        }
        return;
    }
}

/* UI-wake diagnostic (FRN_WAKE=flagobj_hex[,FRN_WAKE_PAT=pattern][,FRN_WAKE_AT=idle-hits]):
 * once the firmware has settled into the idle task (pc=0x10491512), inject a call to
 * the set_flg wrapper FUN_10459708(flagobj, pattern, 0, 0) to wake a task blocked on
 * that eventflag. Breaks the circular init cascade (no peripheral events -> no task
 * runs -> nothing gets wired) by posting the first event by hand, to discover which
 * eventflag drives the UI/compositor. Returns to idle after (rp=idle). */
#define FRN_IDLE_PC 0x10491512u
#define FRN_SETFLG  0x104596ccu   /* real set_flg wrapper (d309 Sable): set_flg(short* idptr, pat). NOT 0x10459708=wai_flg */
#define FRN_WAKE_SCRATCH 0x8ff00000u   /* unused high SDRAM: holds the injected flag id */
static void frn_wake_inject(CPUFRNState *e)
{
    static int init = 0, done = 0; static uint32_t flagobj = 0, pattern = 0xffffffff;
    static long delay = 2000, cnt = 0, next_fire = 0, period = 0, fires = 0, maxfires = 0;
    static long flagid = -1, call_fn = -1, call_arg = 0;
    static long call_fn2 = -1, call_arg2 = 0, gap2 = 3000;  /* optional 2nd sequential call after the 1st returns to idle */
    static uint32_t setflg_addr = FRN_SETFLG;
    if (!init) { init = 1;
        const char *s = getenv("FRN_WAKE"); if (s) flagobj = (uint32_t)strtoul(s, NULL, 16);
        const char *i = getenv("FRN_WAKE_ID"); if (i) flagid = strtol(i, NULL, 0);
        const char *p = getenv("FRN_WAKE_PAT"); if (p) pattern = (uint32_t)strtoul(p, NULL, 16);
        const char *d = getenv("FRN_WAKE_AT"); if (d) delay = strtol(d, NULL, 0);
        const char *pe = getenv("FRN_WAKE_PERIOD"); if (pe) period = strtol(pe, NULL, 0);   /* re-fire every N idle hits (emulate the key-scan timer tick) */
        const char *mf = getenv("FRN_WAKE_MAXFIRES"); if (mf) maxfires = strtol(mf, NULL, 0);
        const char *sf = getenv("FRN_SETFLG"); if (sf) setflg_addr = (uint32_t)strtoul(sf, NULL, 16);
        const char *c = getenv("FRN_CALL");
        if (c) { char *e2; call_fn = strtol(c, &e2, 16); if (*e2==':') call_arg = strtol(e2+1, NULL, 16); }
        const char *c2 = getenv("FRN_CALL2");
        if (c2) { char *e2; call_fn2 = strtol(c2, &e2, 16); if (*e2==':') call_arg2 = strtol(e2+1, NULL, 16); }
        const char *g2 = getenv("FRN_CALL2_GAP"); if (g2) gap2 = strtol(g2, NULL, 0);
        next_fire = delay;
    }
    if ((!flagobj && flagid < 0 && call_fn < 0) || done) return;
    { static uint32_t idle_pc = 0; if (!idle_pc) { const char *ip = getenv("FRN_IDLE_PC");
        idle_pc = ip ? (uint32_t)strtoul(ip, NULL, 16) : FRN_IDLE_PC; }
      if (e->pc != idle_pc) return; }       /* only from the settled idle task (FRN_IDLE_PC overridable) */
    if (cnt++ < next_fire) return;          /* wait until the next scheduled fire */
    /* schedule next fire: periodic (if period>0 and under maxfires) else one-shot */
    if (call_fn2 > 0 && fires == 0) next_fire = cnt + gap2;   /* schedule the 2nd sequential call */
    else if (period > 0 && (maxfires == 0 || fires + 1 < maxfires)) next_fire = cnt + period;
    else done = 1;
    fires++;
    if (call_fn > 0) {                       /* call an arbitrary func(arg) from idle */
        long cfn = (fires == 2 && call_fn2 > 0) ? call_fn2 : call_fn;
        long carg = (fires == 2 && call_fn2 > 0) ? call_arg2 : call_arg;
        e->regs[4] = (uint32_t)carg; e->regs[5] = 0; e->regs[6] = 0; e->regs[7] = 0;
        /* optional extra register args for non-standard ABIs (e.g. TA_ACT uses r8/r9) */
        { const char *s5=getenv("FRN_CALL_R5"); if(s5) e->regs[5]=(uint32_t)strtoul(s5,NULL,16);
          const char *s8=getenv("FRN_CALL_R8"); if(s8) e->regs[8]=(uint32_t)strtoul(s8,NULL,16);
          const char *s9=getenv("FRN_CALL_R9"); if(s9) e->regs[9]=(uint32_t)strtoul(s9,NULL,16);
          const char *s12=getenv("FRN_CALL_R12"); if(s12) e->regs[12]=(uint32_t)strtoul(s12,NULL,16);
          const char *ssp=getenv("FRN_CALL_SP"); if(ssp) e->regs[15]=(uint32_t)strtoul(ssp,NULL,16); }
        e->rp = FRN_IDLE_PC; e->pc = (uint32_t)cfn;
        fprintf(frn_tr_out ? frn_tr_out : stderr,
                "[wake] inject CALL 0x%08lx(r4=0x%08lx r8=0x%08x r9=0x%08x) from idle (fire %ld)\n",
                cfn, carg, e->regs[8], e->regs[9], fires);
        return;
    }
    uint32_t pobj = flagobj;
    if (flagid >= 0) {                      /* raw id: stash as 32-bit word (set_flg does ld @r4,r4 then extsh = low16), point param_1 there */
        cpu_stl_be_data(e, FRN_WAKE_SCRATCH, (uint32_t)(flagid & 0xffff));
        pobj = FRN_WAKE_SCRATCH;
    }
    e->regs[4] = pobj; e->regs[5] = pattern; e->regs[6] = 0; e->regs[7] = 0;
    e->rp = FRN_IDLE_PC;                     /* return to idle after set_flg */
    e->pc = setflg_addr;
    fprintf(frn_tr_out ? frn_tr_out : stderr,
            "[wake] inject set_flg@0x%08x(param1=0x%08x id=%ld pat=0x%08x) fire %ld\n",
            setflg_addr, pobj, flagid, pattern, fires);
}

/* FRN_POKE="addr:val[,addr:val]" : one-shot (or periodic via FRN_POKE_PERIOD) memory writes,
 * applied from the settled idle task. Used to feed the RTOS operational-phase trigger, e.g.
 * FRN_POKE=6a0036c4:1 writes task-id 1 into the act_tsk trigger slot so the tick handler
 * activates it through the firmware's own path. FRN_POKE_AT=idle-hits delay, FRN_POKE_SZ=1/2/4. */
static void frn_poke_tick(CPUFRNState *e)
{
    static int init = 0; static int n = 0; static uint32_t pa[32], pv[32];
    static long delay = 1500, cnt = 0, next = 0, period = 0, fires = 0, maxf = 0; static int sz = 4;
    if (!init) { init = 1;
        const char *s = getenv("FRN_POKE");
        while (s && *s && n < 32) { char *e2; uint32_t a=(uint32_t)strtoul(s,&e2,16);
            if (e2==s||*e2!=':') break; uint32_t v=(uint32_t)strtoul(e2+1,&e2,16);
            pa[n]=a; pv[n]=v; n++; s=(*e2==',')?e2+1:e2; }
        const char *d=getenv("FRN_POKE_AT"); if(d) delay=strtol(d,NULL,0);
        const char *p=getenv("FRN_POKE_PERIOD"); if(p) period=strtol(p,NULL,0);
        const char *m=getenv("FRN_POKE_MAXFIRES"); if(m) maxf=strtol(m,NULL,0);
        const char *z=getenv("FRN_POKE_SZ"); if(z) sz=atoi(z);
        next=delay;
    }
    if (n==0) return;
    static int anypc = -1; if (anypc < 0) anypc = getenv("FRN_POKE_ANYPC") ? 1 : 0;
    if (!anypc) {
        static uint32_t poke_pc = 0; if (!poke_pc) { const char *ip=getenv("FRN_IDLE_PC");
            poke_pc = ip ? (uint32_t)strtoul(ip,NULL,16) : 0x1000f530u; }  /* real idle = bra-self 0x1000f530 */
        if (e->pc != poke_pc) return;
    }  /* FRN_POKE_ANYPC: fire by instruction-boundary count (FRN_POKE_AT), not gated on a specific PC */
    if (cnt++ < next) return;
    if (period>0 && (maxf==0 || fires+1<maxf)) next=cnt+period; else next=0x7fffffffffffffffL;
    fires++;
    for (int i=0;i<n;i++){
        if (sz==1) cpu_stb_data(e,pa[i],(uint8_t)pv[i]);
        else if (sz==2) cpu_stw_be_data(e,pa[i],(uint16_t)pv[i]);
        else cpu_stl_be_data(e,pa[i],pv[i]);
    }
    fprintf(frn_tr_out?frn_tr_out:stderr,"[poke] fire %ld: wrote %d pair(s) sz%d (e.g. 0x%08x=0x%08x)\n",
            fires,n,sz,pa[0],pv[0]);
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
        frn_fire_tick(env);
        frn_autotimer_tick(env);
        frn_deliver(env);          /* may set env->pc to an ISR handler */
        frn_wake_inject(env);      /* diagnostic: post a chosen eventflag from idle */
        frn_poke_tick(env);        /* diagnostic: one-shot/periodic memory writes from idle */
    }
    frn_snapshot(env);
    uint32_t pc = env->pc;
    frn_hist_tick(pc);
    /* FRN_LOG_USER: holistic handover map — log every transition of the live S-flag
     * (env->sf): 0->1 = entry to USER mode (userland handover), 1->0 = back to system.
     * If sf never becomes 1, the kernel never hands any task to userland (the root). */
    { static int lu = -1; if (lu < 0) lu = getenv("FRN_LOG_USER") ? 1 : 0;
      if (lu) { static int prev = -1; static int n = 0;
        int cur = (int)(env->sf & 1);
        if (cur != prev) {
            if (n++ < 60) fprintf(frn_tr_out?frn_tr_out:stderr,
                "[user] sf %d->%d at pc=0x%08x curtask=0x%08x\n", prev<0?0:prev, cur, pc,
                cpu_ldl_be_data(env, 0x6a003758u));
            prev = cur;
        }
      } }
    /* FRN_LOG_FLG: log the eventflag id (low16 of *(r4)) at wai_flg/set_flg/clr_flg entry,
     * to discover the REAL ids the firmware waits/sets (e.g. what task23 blocks on). */
    { static int lf = -1; if (lf < 0) lf = getenv("FRN_LOG_FLG") ? 1 : 0;
      if (lf && (pc == 0x10459708u || pc == 0x104596ccu || pc == 0x104596e6u)) {
        uint32_t idp = r[4]; uint32_t idw = 0;
        if (idp >= 0x80000000u && idp < 0x84000000u) idw = cpu_ldl_be_data(env, idp);
        else if (idp >= 0x6a000000u && idp < 0x6a100000u) idw = cpu_ldl_be_data(env, idp);
        const char *nm = pc==0x10459708u?"wai_flg":(pc==0x104596ccu?"set_flg":"clr_flg");
        fprintf(frn_tr_out ? frn_tr_out : stderr,
            "[flg] %s id=0x%04x (idptr=0x%08x word=0x%08x) pat=0x%08x from rp~0x%08x\n",
            nm, idw & 0xffff, idp, idw, r[5], env->rp);
      } }
    /* FRN_LOG_GATE: log the scheduler-start gate inputs each time rtos_can_dispatch
     * (0x1000e758) or rtos_sched_start_gate (0x1000d208) runs, to see whether the gate
     * ever passes (ret 0) and which term fails. FR is big-endian. */
    { static int lg = -1; if (lg < 0) lg = getenv("FRN_LOG_GATE") ? 1 : 0;
      if (lg && (pc == 0x1000e758u || pc == 0x1000d208u)) {
        static int n;
        if (n++ < 400) {
            uint32_t ctxp = cpu_ldl_be_data(env, 0x6a003774u);
            uint8_t d4d = 0, d4f = 0;
            if (ctxp >= 0x6a000000u && ctxp < 0x6a100000u) {
                d4d = cpu_ldub_data(env, ctxp + 0x4d);
                d4f = cpu_ldub_data(env, ctxp + 0x4f);
            } else if (ctxp >= 0x80000000u && ctxp < 0x90000000u) {
                d4d = cpu_ldub_data(env, ctxp + 0x4d);
                d4f = cpu_ldub_data(env, ctxp + 0x4f);
            }
            uint8_t aa8 = cpu_ldub_data(env, 0x6a003aa8u);
            int d3a2 = (d4d == 0x1f && (d4f & 0x30) == 0x30) ? 0 : 1;
            int gate = (d3a2 != 0 || aa8 != 0) ? 1 : 0;
            fprintf(frn_tr_out ? frn_tr_out : stderr,
                "[gate] %s ctx=0x%08x +0x4d=0x%02x +0x4f=0x%02x aa8=0x%02x d3a2=%d gate=%d %s from rp~0x%08x\n",
                pc==0x1000e758u?"can_dispatch":"sched_start", ctxp, d4d, d4f, aa8, d3a2, gate,
                gate? "IDLE":"SCHEDULE", env->rp);
        }
      } }
    /* FRN_SET38=1: at the task frame-builder FUN_1000d3fe(entry=r4, sp=r5), set the
     * task's TCB+0x38 (resume fn, which cre_tsk never sets) = its ENTRY (r4), so the
     * dispatcher chain-walk resumes the sub-task into its body (first-run dispatch)
     * instead of calling NULL. Finds id by matching sp against SP-array 0x6a0018c0.
     * Skips id6 (garbage SP). Build: faithful first-run resume for sub-tasks. */
    { static int s38 = -1; if (s38 < 0) s38 = getenv("FRN_SET38") ? 1 : 0;
      if (s38 && pc == 0x1000d3feu) {
        uint32_t entry = r[4], sp = r[5];
        for (uint32_t id = 0; id < 34; id++) {
            if (id == 6) continue;
            uint32_t slot = cpu_ldl_be_data(env, 0x6a0018c0u + id * 4);
            if (slot == sp && sp >= 0x6a000000u) {
                uint32_t tcb38 = 0x6a001be8u + id * 0x44u + 0x38u;
                cpu_stl_be_data(env, tcb38, entry);
                static int nn; if (nn++ < 40) fprintf(frn_tr_out?frn_tr_out:stderr,
                    "[set38] task%u TCB+0x38 <- entry 0x%08x (sp 0x%08x)\n", id, entry, sp);
                break;
            }
        }
      } }
    /* FRN_LOG_TEXT: dump the string drawn by glyph_draw FUN_10492fde (r5 = char*),
     * to capture the ACTUAL menu text the firmware renders (e.g. "Date Adjust"),
     * independent of whether the pixel composite reaches a scanout surface. */
    { static int lt = -1; if (lt < 0) lt = getenv("FRN_LOG_TEXT") ? 1 : 0;
      if (lt && pc == 0x10492fdeu) {
        static int n;
        if (n++ < 300) {
            uint32_t sp = r[5]; char s[80]; int k = 0;
            if (sp >= 0x10000000u && sp < 0x90000000u) {
                for (; k < 79; k++) { uint8_t c = cpu_ldub_data(env, sp + k); if (!c) break;
                    s[k] = (c >= 0x20 && c < 0x7f) ? (char)c : '.'; }
            }
            s[k] = 0;
            if (k > 0) fprintf(frn_tr_out ? frn_tr_out : stderr,
                "[text] glyph_draw r4=0x%08x str@0x%08x = \"%s\"\n", r[4], sp, s);
        }
      } }
    /* FRN_LOG_DRAW: count the natural-boot render-path milestones to find where the
     * app-main-synchronous draw bails. r4 = first arg (the screen-mgr obj). */
    { static int ld = -1; if (ld < 0) ld = getenv("FRN_LOG_DRAW") ? 1 : 0;
      if (ld) {
        static long c_disp, c_vis, c_mark, c_draw; static int shown;
        if (pc == 0x10467a3eu) c_disp++;
        else if (pc == 0x10448a08u) {
            c_vis++;
            uint32_t mgr = r[4]; uint8_t dc = 0;
            if (mgr >= 0x80000000u && mgr < 0x90000000u) dc = cpu_ldub_data(env, mgr + 0xdc);
            if (c_vis <= 12) fprintf(frn_tr_out?frn_tr_out:stderr,
                "[draw] vis_gate mgr=0x%08x +0xdc=0x%02x (0=>can-mark)\n", mgr, dc);
        }
        else if (pc == 0x1044b346u) c_mark++;
        else if (pc == 0x10481298u) c_draw++;
        if (pc == 0x10491510u && !shown) { shown = 1;   /* reached idle: dump the tally */
            fprintf(frn_tr_out?frn_tr_out:stderr,
                "[draw] TALLY at idle: rear_draw_dispatch=%ld vis_gate=%ld mark_visible=%ld draw_substep=%ld\n",
                c_disp, c_vis, c_mark, c_draw);
        }
      } }
    /* FRN_DUMP_CMDH: at cpucom cmd_handler 0x10430554, dump the transaction struct
     * at r9 (fields per error_print: +0=OutCode,+4=InCmd,+8=InSize,+0xc=OutCmd,
     * +0x10=OutSize) so a PASSING txn (code 0x10003) can be compared to the failing
     * Cmd:04 - revealing exactly which field the black-box DSP must supply. */
    if (pc == 0x10430554u && getenv("FRN_DUMP_CMDH")) {
        uint32_t s = env->regs[9];
        fprintf(frn_tr_out ? frn_tr_out : stderr,
            "[cmdh] r5(code)=0x%08x r9=0x%08x  struct: OutCode=0x%08x InCmd=0x%02x InSize=0x%08x OutCmd=0x%02x OutSize=0x%08x\n",
            env->regs[5], s, cpu_ldl_be_data(env, s), cpu_ldub_data(env, s+4),
            cpu_ldl_be_data(env, s+8), cpu_ldub_data(env, s+0xc), cpu_ldl_be_data(env, s+0x10));
    }
    /* FRN_DUMP_SPI: at cpucom_spi_xfer 0x10465958 entry, dump the LIVE txn (r4) flag
     * objects so the exact completion-flag memory bit (addr+mask) is known. flag obj
     * layout: +0x10 = byte* to the flag memory, +0x1c = mask byte. */
    if (pc == 0x10465958u && getenv("FRN_DUMP_SPI")) {
        uint32_t t = env->regs[4];
        uint32_t fa = cpu_ldl_be_data(env, t+0x10), fb = cpu_ldl_be_data(env, t+0x14);
        fprintf(frn_tr_out ? frn_tr_out : stderr,
            "[spixfer] txn=0x%08x flagA(+0x10)=0x%08x[addr=0x%08x mask=0x%02x] flagB(+0x14)=0x%08x[addr=0x%08x mask=0x%02x] ch=0x%08x\n",
            t, fa, fa?cpu_ldl_be_data(env,fa+0x10):0, fa?cpu_ldub_data(env,fa+0x1c):0,
            fb, fb?cpu_ldl_be_data(env,fb+0x10):0, fb?cpu_ldub_data(env,fb+0x1c):0,
            cpu_ldl_be_data(env, t+0xc));
    }
    /* FRN_DUMP_FLAG: at the per-byte DSP-ready waiter FUN_10465f24 (0x10465f24),
     * dump the flag object it polls (*(txn+0x14)): active(+0x10c), byte-addr(+0x10),
     * mask(+0x1c), and the live byte value - so the handshake flag is known exactly. */
    if (pc == 0x10465f24u && getenv("FRN_DUMP_FLAG")) {
        uint32_t t = env->regs[4];
        uint32_t fb = cpu_ldl_be_data(env, t+0x14);
        uint32_t active = fb?cpu_ldl_be_data(env, fb+0x10c):0;
        uint32_t ba = fb?cpu_ldl_be_data(env, fb+0x10):0;
        uint32_t mask = fb?cpu_ldub_data(env, fb+0x1c):0;
        uint32_t val = ba?cpu_ldub_data(env, ba):0;
        fprintf(frn_tr_out ? frn_tr_out : stderr,
            "[flag] txn=0x%08x flagB=0x%08x active(+0x10c)=0x%08x byteaddr(+0x10)=0x%08x mask=0x%02x val@addr=0x%02x\n",
            t, fb, active, ba, mask, val);
    }
    /* FRN_DUMP_TF: at test_flag_clear/set (0x104398ac/0x104398c0), log the EXACT
     * dereference the firmware does - obj(r4), the byte-pointer *(obj+0x10), the
     * mask *(obj+0x1c), and the live byte - so the handshake flag's real binding is
     * ground-truth (no hand offset math). */
    /* FRN_DUMP_DEV2: at dev2 ready-poll FUN_1043fd24 (0x1043fd24), log its status-reg
     * addr *(obj+0x1c), the live byte, and data-reg addr *(obj+0x34) - the device the
     * firmware spins on after CPUCOM POST (looks like a settings EEPROM: cmd 0xe0/0x65 + 16B read). */
    if (pc == 0x1043fd24u && getenv("FRN_DUMP_DEV2")) {
        static int n; if (n++ < 6) { uint32_t o = env->regs[4];
            uint32_t sa = cpu_ldl_be_data(env, o+0x1c), da = cpu_ldl_be_data(env, o+0x34);
            fprintf(frn_tr_out ? frn_tr_out : stderr,
                "[dev2] obj=0x%08x statusreg=0x%08x byte=0x%02x datareg=0x%08x\n",
                o, sa, (sa>=0x40&&sa<0x90000000u)?cpu_ldub_data(env,sa):0xff, da); }
    }
    /* FRN_DUMP_FLG: log set_flag(0x1043986a)/clear_flag(0x10439822) that target
     * 0x50000106 - the main's req bit (addr+mask), to pair with the poller's ack bit. */
    if ((pc == 0x1043986au || pc == 0x10439822u) && getenv("FRN_DUMP_FLG")) {
        uint32_t o = env->regs[4];
        uint32_t ad = cpu_ldl_be_data(env, o+0x10), mk = cpu_ldub_data(env, o+0x1c);
        if (ad == 0x50000106u) { static int n; if (n++ < 20)
            fprintf(frn_tr_out ? frn_tr_out : stderr, "[flg] %s addr=0x%08x mask=0x%02x\n",
                pc==0x1043986au?"SET  ":"CLEAR", ad, mk); }
    }
    if ((pc == 0x104398acu || pc == 0x104398c0u) && getenv("FRN_DUMP_TF")) {
        static int nn; if (nn++ < 60) {
            uint32_t o = env->regs[4];
            uint32_t bp = cpu_ldl_be_data(env, o+0x10);
            uint32_t mask = cpu_ldub_data(env, o+0x1c);
            uint32_t val = (bp>=0x40 && bp<0x90000000u) ? cpu_ldub_data(env, bp) : 0xdead;
            fprintf(frn_tr_out ? frn_tr_out : stderr,
                "[tf] %s obj=0x%08x byteptr=0x%08x mask=0x%02x byte=0x%02x -> %s\n",
                pc==0x104398c0u?"SET ":"CLR ", o, bp, mask, val,
                (val!=0xdead && (val&mask))?"bit-SET":"bit-clear");
        }
    }
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
                    "r7=0x%08x r8=0x%08x r9=0x%08x r13=0x%08x r14=0x%08x  rp=0x%08x sp=0x%08x\n",
                    pc, r[4], r[5], r[6], r[7], r[8], r[9], r[13], r[14], env->rp, r[15]);
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

    /* FRN_ICALL_LO/HI=hex: log indirect calls (op 0x97 = call @r[ri]) over a PC
     * window, flagging targets that are null/garbage/non-ROM — a broken vtable
     * dispatch (object field uninitialized in the emulator) is the likely gate. */
    if (op == 0x97) {
        static int ic=0; static uint32_t lo=0,hi=0;
        if (!ic){ic=1; const char*l=getenv("FRN_ICALL_LO");const char*h=getenv("FRN_ICALL_HI");
            if(l)lo=(uint32_t)strtoul(l,NULL,16); if(h)hi=(uint32_t)strtoul(h,NULL,16);}
        if (lo && pc>=lo && pc<hi){
            uint32_t tgt=env->regs[ri];
            int bad = !(tgt>=0x10000000u && tgt<0x10600000u);
            fprintf(frn_tr_out?frn_tr_out:stderr,"[icall] pc=%08x call @r%d=%08x%s\n",
                    pc,ri,tgt, bad?"  <<BAD TARGET":"");
        }
    }

    /* FRN_DISAS_LO/HI=hex: per-instruction trace over a PC window — the real
     * interpreter narrating its own opcode stream, so I can read a function's
     * logic (e.g. act_tsk's bail) without a separate (fallible) disassembler. */
    {
        static int di = 0; static uint32_t dlo = 0, dhi = 0;
        if (!di) { di = 1; const char *l = getenv("FRN_DISAS_LO"); const char *h = getenv("FRN_DISAS_HI");
            if (l) dlo = (uint32_t)strtoul(l, NULL, 16); if (h) dhi = (uint32_t)strtoul(h, NULL, 16); }
        if (dlo && pc >= dlo && pc < dhi) {
            fprintf(frn_tr_out ? frn_tr_out : stderr,
                "[dis] pc=%08x w=%04x op=%02x ri=%x(%08x) rj=%x(%08x) td=%02x\n",
                pc, w, op, ri, env->regs[ri], rj, env->regs[rj], td);
        }
    }

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
                fprintf(frn_tr_out ? frn_tr_out : stderr, "[int40] service r12=%08x  r4=%08x r5=%08x  pc=%08x  vec=%08x\n",
                        svc, env->regs[4], env->regs[5], pc, rd32(env, env->tbr + 0x3FC - (td * 4)));
            }
            /* FRN_INT40_SVC=hex (comma list): log EVERY call to those REALOS services
             * with full args r4-r7 + rp = map a specific transaction (e.g. CPUCOM
             * snd_dtq/rcv_dtq). FRN_INT40_SVC=all logs all. */
            static long _if_init; static uint32_t _if[16]; static int _ifn; static int _ifall;
            if (!_if_init) { _if_init = 1; const char *s = getenv("FRN_INT40_SVC");
                if (s && (!strcmp(s,"all")||!strcmp(s,"ALL"))) _ifall = 1;
                while (s && *s && !_ifall && _ifn < 16) { char *e2; unsigned long v = strtoul(s,&e2,16);
                    if (e2==s) break; _if[_ifn++] = (uint32_t)v; s = (*e2==',')?e2+1:e2; } }
            int hit = _ifall;
            for (int k = 0; k < _ifn && !hit; k++) if (_if[k] == svc) hit = 1;
            if (hit) fprintf(frn_tr_out ? frn_tr_out : stderr,
                "[int40*] r12=%08x r4=%08x r5=%08x r6=%08x r7=%08x  pc=%08x rp=%08x\n",
                svc, env->regs[4], env->regs[5], env->regs[6], env->regs[7], pc, env->rp);
        }
        /* FRN_CPUCOM_ACK=<code hex>: EXPERIMENT. The CPUCOM task blocks in
         * rcv_mbx(id=4, TMO_FEVR) forever (no DSP posts to mailbox 4). When that
         * exact call happens, synthesize a success message instead of letting the
         * kernel primitive block: write msg{+0=next,+4=cmd,+8=code} to scratch,
         * set *r5=msgptr and ercd(r4)=0, and skip the real primitive. Observe
         * whether the firmware then advances to producing menu content. Gated on
         * the forever-timeout so normal polling receives are untouched. */
        if (td == 0x40 && env->regs[12] == 0x100111b0u) {
            static long ck_init = 0; static uint32_t ck_code = 0; static int ck_mbx = 4;
            static long ck_max = 0, ck_n = 0;
            if (!ck_init) { ck_init = 1;
                const char *c = getenv("FRN_CPUCOM_ACK"); if (c) ck_code = (uint32_t)strtoul(c, NULL, 16);
                const char *m = getenv("FRN_CPUCOM_ACK_MBX"); if (m) ck_mbx = (int)strtol(m, NULL, 0);
                const char *x = getenv("FRN_CPUCOM_ACK_N"); ck_max = x ? strtol(x, NULL, 0) : 32; }
            if (ck_code && env->regs[4] == (uint32_t)ck_mbx &&
                env->regs[6] == 0xffffffffu && (ck_max == 0 || ck_n < ck_max)) {
                uint32_t msg = 0x8ff00200u + (uint32_t)((ck_n & 7) * 0x40);
                wr32(env, msg + 0, 0);            /* next ptr */
                wr32(env, msg + 4, 0x04);         /* cmd */
                /* code field at +8 is read byte-wise and reassembled LITTLE-endian
                 * by 0x104598e8, so store it byte-swapped vs the BE wr32. */
                wr32(env, msg + 8, __builtin_bswap32(ck_code));  /* response Code (LE) */
                wr32(env, msg + 0xc, 0);
                wr32(env, msg + 0x10, 0);
                wr32(env, env->regs[5], msg);     /* *param_2 = msgptr */
                env->regs[4] = 0;                 /* ercd = E_OK */
                if (frn_tr_irq || getenv("FRN_CPUCOM_ACK_LOG"))
                    fprintf(frn_tr_out ? frn_tr_out : stderr,
                        "[cpucom-ack #%ld] rcv_mbx(%d) -> synth msg 0x%08x code=0x%08x  pc=%08x\n",
                        ck_n, ck_mbx, msg, ck_code, pc);
                ck_n++;
                env->pc = pc + 2;                 /* skip the real primitive */
                break;
            }
        }
        uint32_t ea = env->tbr + 0x3FC - (td * 4);
        uint32_t vec = rd32(env, ea);
        if (vec >= FW_BASE && vec < FW_END) {
            uint32_t saved_ps = pack_ps(env);  /* FR: save pre-trap PS (user S=1) BEFORE entering system mode */
            set_sflag(env, 0);
            push32(env, saved_ps);
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
    { static int lu=-1; static long ucnt=0;
      if(lu<0) lu=getenv("FRN_LOG_UNK")?1:0;
      if(lu){ uint32_t uw=rd16(env,pc);
        /* only log in the kernel/scheduler/activation range to cut noise; set FRN_LOG_UNK=all for everything */
        static int all=-1; if(all<0) all=getenv("FRN_LOG_UNK_ALL")?1:0;
        if(all || (pc>=0x1000c000u && pc<=0x10012000u))
          if(ucnt++ < 2000)
            fprintf(frn_tr_out?frn_tr_out:stderr,"[unk] pc=%08x w=%04x\n", pc, uw); } }
    } while (0);

    if (had_pending) {
        env->pc = pending;
    }
}

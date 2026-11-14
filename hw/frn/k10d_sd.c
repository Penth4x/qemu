/*
 * K10D SD card behind the SDHCI host at 0x67000000 (hw/frn/k10d.c frn_p67_*).
 *
 * FRN_SD=<image>: a standard-capacity SD card backed by that file (byte addressing,
 * CSD version 1 sized from the file, up to 2 GiB). Without it there is no card and the
 * host model keeps its old behaviour (present-state bit 16 clear).
 *
 * Firmware facts this rests on (K10D-BRINGUP.md d313, SDHCI correction):
 *  - command register +0x0E = index << 8 | flags (0x20 data present, low 2 bits response
 *    type); the driver uses CMD0/1/2/3/6/8/9/12/13/16/17/18/23/24/25/55, ACMD6/13/41/42/51;
 *  - 136-bit responses are in the standard SDHCI layout (bits 127:8, CRC stripped) across
 *    +0x10..+0x1F; the firmware de-shuffles them with the byte map at 0x105a198c;
 *  - data moves through the 32-bit buffer port +0x20, first card byte in the most
 *    significant byte (as the 8-byte SCR read already showed);
 *  - R1 status is checked against 0xfdf90008 (no error bits).
 */
#include "qemu/osdep.h"
#include "k10d_sd.h"

static int fd = -2;
static uint64_t img_size;
static int app_cmd;
static uint32_t rca = 0x1234;
static uint32_t blklen = 512;

static uint8_t buf[512];
static uint32_t buf_len, buf_pos;
static int rd_active, rd_multi, wr_active, wr_multi;
static uint64_t xfer_addr;

static int sd_open(void)
{
    if (fd == -2) {
        fd = -1;
        const char *p = getenv("FRN_SD");
        if (p && *p) {
            fd = open(p, O_RDWR);
            if (fd < 0) fprintf(stderr, "[sd] cannot open %s: %s\n", p, strerror(errno));
            else {
                img_size = lseek(fd, 0, SEEK_END);
                fprintf(stderr, "[sd] card image %s, %llu bytes\n", p, (unsigned long long)img_size);
            }
        }
    }
    return fd >= 0;
}

int k10d_sd_present(void) { return sd_open(); }

/* 136-bit register (16 bytes, MSB first, byte 15 = CRC) -> SDHCI response regs. */
static void put_r2(uint8_t *resp, const uint8_t reg[16])
{
    resp[0x0c] = 0; resp[0x0d] = reg[0]; resp[0x0e] = reg[1]; resp[0x0f] = reg[2];   /* RESP3 */
    memcpy(resp + 0x08, reg + 3, 4);                                                 /* RESP2 */
    memcpy(resp + 0x04, reg + 7, 4);                                                 /* RESP1 */
    memcpy(resp + 0x00, reg + 11, 4);                                                /* RESP0 */
}
static void put_r1(uint8_t *resp, uint32_t v)
{
    memset(resp, 0, 16);
    resp[0] = v >> 24; resp[1] = v >> 16; resp[2] = v >> 8; resp[3] = v;
}
/* set bits [hi:lo] of a 128-bit big-endian register */
static void setbits(uint8_t reg[16], int hi, int lo, uint32_t v)
{
    for (int b = lo; b <= hi; b++) {
        if (!(v >> (b - lo) & 1)) continue;
        reg[15 - b / 8] |= 1 << (b % 8);
    }
}

static void make_csd(uint8_t csd[16])
{
    memset(csd, 0, 16);
    /* capacity = (C_SIZE + 1) * 2^(C_SIZE_MULT + 2) * 2^READ_BL_LEN, C_SIZE <= 4095 */
    int bl = 9, mult = 7;
    uint64_t units = img_size >> (bl + mult + 2);
    while (units > 4096 && bl < 11) { bl++; units >>= 1; }
    if (units == 0) units = 1;
    if (units > 4096) units = 4096;
    setbits(csd, 127, 126, 0);          /* CSD version 1 */
    setbits(csd, 119, 112, 0x26);       /* TAAC */
    setbits(csd, 103, 96, 0x32);        /* TRAN_SPEED 25 MHz */
    setbits(csd, 95, 84, 0x5b5);        /* CCC */
    setbits(csd, 83, 80, bl);           /* READ_BL_LEN */
    setbits(csd, 79, 79, 1);            /* READ_BL_PARTIAL */
    setbits(csd, 73, 62, units - 1);    /* C_SIZE */
    setbits(csd, 61, 50, 0x3f8);        /* VDD currents */
    setbits(csd, 49, 47, mult);         /* C_SIZE_MULT */
    setbits(csd, 46, 46, 1);            /* ERASE_BLK_EN */
    setbits(csd, 45, 39, 0x7f);         /* SECTOR_SIZE */
    setbits(csd, 25, 22, bl);           /* WRITE_BL_LEN */
    setbits(csd, 0, 0, 1);
}
static void make_cid(uint8_t cid[16])
{
    static const uint8_t c[16] = { 0x03, 'S', 'D', 'Q', 'E', 'M', 'U', '1', 0x10,
                                   0x12, 0x34, 0x56, 0x78, 0x00, 0x6b, 0x01 };
    memcpy(cid, c, 16);
}

static void load_block(void)
{
    memset(buf, 0, sizeof buf);
    if (xfer_addr + blklen <= img_size && pread(fd, buf, blklen, xfer_addr) < 0)
        fprintf(stderr, "[sd] read error at %llu\n", (unsigned long long)xfer_addr);
    buf_len = blklen; buf_pos = 0;
}

/* A command was written to +0x0E. resp = host registers +0x10..+0x1F. Returns 1 when the
 * card handled it (the host must not apply its default response). */
uint32_t k10d_sd_dbg_regs[4];      /* host fills: +0x00 SDMA addr, +0x0c xfer mode, +0x06 count */
int k10d_sd_command(uint16_t cmd, uint32_t arg, uint8_t *resp, uint32_t blksize)
{
    if (!sd_open()) return 0;
    static int lg = -1, nl;
    if (lg < 0) lg = getenv("FRN_SD_LOG") ? 1 : 0;
    if (lg && nl++ < 400) fprintf(stderr, "[sd] %sCMD%d (0x%04x) arg 0x%08x blksz %u  sdma 0x%08x mode 0x%04x cnt %u\n",
                                  app_cmd ? "A" : "", cmd >> 8, cmd, arg, blksize,
                                  k10d_sd_dbg_regs[0], k10d_sd_dbg_regs[1], k10d_sd_dbg_regs[2]);
    int idx = cmd >> 8, app = app_cmd;
    app_cmd = 0;
    const uint32_t R1 = 0x00000900;     /* transfer state, ready for data */
    if (blksize >= 1 && blksize <= 512) blklen = blksize;
    switch (idx) {
    case 0:  rd_active = wr_active = 0; put_r1(resp, 0); break;
    case 8:  put_r1(resp, arg & 0xfff); break;
    case 55: app_cmd = 1; put_r1(resp, R1 | 0x20); break;
    case 41: put_r1(resp, 0x80ff8000); break;              /* ACMD41 OCR: powered up */
    case 1:  put_r1(resp, 0x80ff8000); break;
    case 2: case 10: { uint8_t r[16]; make_cid(r); put_r2(resp, r); break; }
    case 9:  { uint8_t r[16]; make_csd(r); put_r2(resp, r); break; }
    case 3:  put_r1(resp, rca << 16 | 0x0500); break;
    case 51: if (app) {                                     /* ACMD51 SCR */
                 static const uint8_t scr[8] = { 0x02, 0x05, 0, 0, 0, 0, 0, 0 };
                 memset(buf, 0, sizeof buf); memcpy(buf, scr, 8); buf_len = 8; buf_pos = 0;
                 rd_active = 1; rd_multi = 0;
             }
             put_r1(resp, R1); break;
    case 13: if (app && (cmd & 0x20)) {                     /* ACMD13 SD status: 64 bytes */
                 memset(buf, 0, sizeof buf); buf_len = 64; buf_pos = 0; rd_active = 1; rd_multi = 0;
             }
             put_r1(resp, R1); break;
    case 6:  if (!app && (cmd & 0x20)) {                    /* CMD6 SWITCH status: 64 bytes */
                 memset(buf, 0, sizeof buf);
                 for (int i = 0; i < 64; i += 4) { buf[i + 1] = 0x02; }   /* as the old model */
                 buf_len = 64; buf_pos = 0; rd_active = 1; rd_multi = 0;
             }
             put_r1(resp, R1); break;
    case 16: if (arg >= 1 && arg <= 512) blklen = arg; put_r1(resp, R1); break;
    case 17: case 18:
             xfer_addr = arg; rd_multi = idx == 18; rd_active = 1; wr_active = 0;
             load_block(); put_r1(resp, R1); break;
    case 24: case 25:
             xfer_addr = arg; wr_multi = idx == 25; wr_active = 1; rd_active = 0;
             buf_len = blklen; buf_pos = 0; put_r1(resp, R1); break;
    case 12: rd_active = wr_active = 0; put_r1(resp, R1); break;
    default: put_r1(resp, R1); break;
    }
    return 1;
}

int k10d_sd_read_ready(void) { return sd_open() && rd_active && buf_pos < buf_len; }
int k10d_sd_write_ready(void) { return sd_open() && wr_active; }

/* 32-bit read of the buffer port: returns 1 with the next four card bytes. */
int k10d_sd_data_read32(uint32_t *v)
{
    if (!sd_open() || !rd_active) return 0;
    if (buf_pos >= buf_len) {
        if (!rd_multi) { rd_active = 0; return 0; }
        xfer_addr += blklen; load_block();
    }
    { static int lg = -1, nl; if (lg < 0) lg = getenv("FRN_SD_LOG") ? 1 : 0;
      if (lg && buf_pos == 0 && nl++ < 200) fprintf(stderr, "[sd] data read starts @%llu: %02x %02x %02x %02x ...\n",
          (unsigned long long)xfer_addr, buf[0], buf[1], buf[2], buf[3]); }
    *v = (uint32_t)buf[buf_pos] << 24 | buf[buf_pos + 1] << 16 | buf[buf_pos + 2] << 8 | buf[buf_pos + 3];
    buf_pos += 4;
    if (buf_pos >= buf_len && !rd_multi) rd_active = 0;
    return 1;
}

/* 32-bit write of the buffer port during CMD24/25. */
int k10d_sd_data_write32(uint32_t v)
{
    if (!sd_open() || !wr_active) return 0;
    buf[buf_pos] = v >> 24; buf[buf_pos + 1] = v >> 16; buf[buf_pos + 2] = v >> 8; buf[buf_pos + 3] = v;
    buf_pos += 4;
    if (buf_pos >= buf_len) {
        if (xfer_addr + buf_len <= img_size && pwrite(fd, buf, buf_len, xfer_addr) < 0)
            fprintf(stderr, "[sd] write error at %llu\n", (unsigned long long)xfer_addr);
        xfer_addr += buf_len; buf_pos = 0;
        if (!wr_multi) wr_active = 0;
    }
    return 1;
}

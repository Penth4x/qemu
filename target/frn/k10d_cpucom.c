/*
 * K10D companion-CPU (CPUCOM) model.
 *
 * The K10D main CPU talks to a companion processor over a full-duplex SPI link
 * (data 0x5c004043, status 0x5c004040, byte handshake on GPIO 0x50000106, both
 * modelled in op_helper.c). Each transaction the main CPU sends
 *     [cmd][out_size][out_size bytes]
 * and simultaneously clocks in
 *     [resp0][in_size][in_size bytes]
 * resp0 routes the reply through the firmware's CPUCOM response registry
 * (0x104652f4: registry[resp0] -> handler slot 0x74). Facts this model rests on,
 * all read from the firmware (see K10D-BRINGUP.md d313):
 *
 *  - Cmd 0x01 is the main CPU's periodic status poll; its 5 out bytes carry the
 *    main CPU's own status. A reply with resp0 = 0x01 (command echo) is the plain
 *    acknowledgement (d312 sweep).
 *  - The companion CPU's status messages are replies whose resp0 is an ASCII
 *    command letter; the settings manager (cls_105a6a14) registers for 25 of them
 *    (table 0x105a5e06: letter, payload size; event codes 0x105a5e38) and forwards
 *    each as event 0xa00xx to its listeners. At runtime the listeners are:
 *    'A' (9 bytes) -> screen manager (status LCD); 'H' (0x45) and 'B' (0x17) ->
 *    mode controller ('H' sets flag 0x37 bit 0x80, which the startup task waits
 *    on); 'C', 'I' -> object 0x805329c0; 'X' -> object 0x804a9828.
 *  - Until 'A' arrives the main CPU polls ~300 times/s with status byte 3 = 0x10;
 *    the poll after 'A' carries 0x30. So bit 0x20 is the main CPU's "status
 *    received" acknowledgement, and the polling storm is it asking for 'A'.
 *  - After 'A' the main CPU sends Cmd 0x05 with 0x3d bytes (a settings block).
 *  - Response registry at runtime (0x80048318, 255 x ptr): 0x01 poll context;
 *    0x07 cls_105a7a9c (sends 05/1f/06/2f/07, table 0x105a7a3c); '@'..'Z' except
 *    'E','P' settings manager; 'E','P' cls_105a5cb4; 0x60-0x68 cls_105a7320;
 *    0x70.. cls_105a7230; 0x80..0xd6 cls_105a7640. A reply whose resp0 has no
 *    entry is dropped and its requester waits forever.
 *
 *  - Interrupt vector 31 (ICR15, 0x44f; raw handler 0x1049109e -> irq source 0xf)
 *    is handled by the task-5 poll object (vtable 0x105a7ea0, IRQ interface at
 *    obj+0x20): on source 0xf it posts its flag (obj+0x28) ONLY if its transfer
 *    object is active (0x1046614c). Raised as an "attention" line between
 *    transfers it is ignored every time, so it is not the message-pending signal;
 *    it looks like a transfer-complete/ready interrupt. Opt-in: FRN_DSP_ATTN=1.
 *
 * Behaviour: silent until the Cmd 0x04 POST handshake completes; then raise vector
 * 31 while a status message is pending; deliver it as the
 * reply to the main CPU's Cmd 0x00 (read) or Cmd 0x01 (poll). 'A' first (repeated
 * on polls until the main CPU's poll shows bit 0x20), then each queued boot status
 * message once (default 'H', 'B'), then plain echoes. Other commands are acknowledged by echoing the command byte with
 * in_size 0, except Cmd 0x04 (POST), which keeps the long-standing 0x01 ack.
 * Payloads are NOT known: they default to zero bytes and can be set per letter
 * with FRN_DSP_<letter>=hexbytes (payload only). FRN_DSP_BOOT=HB sets the queue.
 * FRN_DSP_LOG=1 logs every message the model sends and every command it sees.
 */
#include "qemu/osdep.h"
#include "k10d_cpucom.h"

#define MAXMSG 80

typedef struct { uint8_t b[MAXMSG + 2]; int len; } Msg;

/* payload sizes from the firmware's table 0x105a5e06 (letter -> size) */
static const struct { char c; uint8_t size; } k_sizes[] = {
    {'C',0x10},{'D',0x0c},{'W',0x02},{'T',0x20},{'M',0x20},{'O',0x20},{'Q',0x20},{'V',0x04},
    {'F',0x0b},{'H',0x45},{'J',0x10},{'B',0x17},{'K',0x10},{'L',0x10},{'R',0x04},{'@',0x04},
    {'G',0x0b},{'I',0x1b},{'S',0x01},{'N',0x08},{'U',0x01},{'X',0x05},{'A',0x09},{'Y',0x04},
    {'Z',0x06},
};

static int st_init, st_log, st_acked_a, st_cmd, st_pos;
static Msg st_cur;                 /* reply being clocked out this transaction */
static char st_queue[32]; static int st_qn, st_qi;
static uint8_t st_tx[MAXMSG + 2]; static int st_txlen;
static uint8_t st_last_status[8]; static int st_last_status_len;
static FILE *st_out;
static int st_attn_sent, st_a_sent, st_post_done;  /* POST = Cmd 0x04 handshake */           /* attention edge delivered for the current backlog */

static int letter_size(char c)
{
    for (size_t i = 0; i < sizeof k_sizes / sizeof k_sizes[0]; i++)
        if (k_sizes[i].c == c) return k_sizes[i].size;
    return -1;
}

static void build_status(char c, Msg *m)
{
    int n = letter_size(c);
    if (n < 0) n = 0;
    memset(m, 0, sizeof *m);
    m->b[0] = (uint8_t)c; m->b[1] = (uint8_t)n; m->len = 2 + n;
    char var[16]; snprintf(var, sizeof var, "FRN_DSP_%c", c);
    const char *s = getenv(var); int k = 0;
    while (s && *s && k < n) {
        while (*s == ' ' || *s == ',') s++;
        char hb[3] = {0}; int j = 0;
        while (j < 2 && isxdigit((unsigned char)*s)) hb[j++] = *s++;
        if (!j) break;
        m->b[2 + k++] = (uint8_t)strtoul(hb, NULL, 16);
    }
}

static void init(FILE *out)
{
    st_init = 1; st_out = out;
    st_log = getenv("FRN_DSP_LOG") != NULL;
    const char *q = getenv("FRN_DSP_BOOT");
    if (!q) q = "HB";
    for (; *q && st_qn < (int)sizeof st_queue; q++)
        if (letter_size(*q) >= 0) st_queue[st_qn++] = *q;
}

int k10d_cpucom_enabled(void)
{
    const char *s = getenv("FRN_DSP_MODEL");
    return !(s && s[0] == '0');
}

void k10d_cpucom_txn_start(FILE *out)
{
    if (!st_init) init(out);
    /* the finished transaction: if it was a status poll, keep the main CPU's status */
    if (st_txlen >= 2 && st_tx[0] == 0x01) {
        st_last_status_len = st_txlen - 2 > 8 ? 8 : st_txlen - 2;
        memcpy(st_last_status, st_tx + 2, st_last_status_len);
        if (!st_acked_a && st_last_status_len >= 4 && (st_last_status[3] & 0x20)) {
            st_acked_a = 1;
            if (st_log) fprintf(st_out, "[dsp] main CPU acknowledged status (poll status byte3=0x%02x)\n",
                                st_last_status[3]);
        }
    } else if (st_txlen >= 1 && st_tx[0] == 0x04 && !st_post_done) {
        st_post_done = 1;
        if (st_log) fprintf(st_out, "[dsp] POST handshake (Cmd:04) done: status messages may start\n");
    }
    if (st_txlen >= 1 && st_log && st_tx[0] != 0x01) {
        fprintf(st_out, "[dsp] main CPU sent Cmd:%02x out_size=%u:", st_tx[0], st_txlen > 1 ? st_tx[1] : 0);
        for (int i = 2; i < st_txlen && i < 2 + 16; i++) fprintf(st_out, " %02x", st_tx[i]);
        fprintf(st_out, "%s\n", st_txlen > 18 ? " ..." : "");
    }
    st_txlen = 0; st_pos = 0; st_cmd = -1;
    st_attn_sent = 0;              /* a transaction happened: may signal again if still pending */
}

/* Attention (vector 31): asserted while the model has a status message to deliver,
 * as one edge per completed transaction. Returns 1 when the caller should raise it. */
int k10d_cpucom_attention(void)
{
    static int on = -1; if (on < 0) on = getenv("FRN_DSP_ATTN") != NULL;
    if (!on || !st_init || st_attn_sent) return 0;
    if (!st_post_done) return 0;
    int pending = (!st_acked_a && !st_a_sent) || (st_acked_a && st_qi < st_qn);
    if (!pending) return 0;
    st_attn_sent = 1;
    if (st_log) fprintf(st_out, "[dsp] attention (vector 31): %s pending\n",
                        !st_acked_a ? "'A'" : "boot status");
    return 1;
}

void k10d_cpucom_tx(uint8_t v)
{
    if (st_txlen < (int)sizeof st_tx) st_tx[st_txlen++] = v;
}

/* The RX byte for position st_pos. The reply is chosen when byte 0 is read; by then
 * the command byte (TX byte 0) has been written. */
uint8_t k10d_cpucom_rx(FILE *out)
{
    if (!st_init) init(out);
    if (st_pos == 0) {
        st_cmd = st_txlen > 0 ? st_tx[0] : 0xff;
        memset(&st_cur, 0, sizeof st_cur);
        if (st_cmd == 0x00 || st_cmd == 0x01) {
            /* Cmd 0x00 = the main CPU reading the message we signalled (vector 31);
             * Cmd 0x01 = its status poll. Either carries our next status message. 'A' is
             * repeated on polls until the main CPU acknowledges it (bit 0x20). */
            if (st_post_done && !st_acked_a && (st_cmd == 0x01 || !st_a_sent)) { build_status('A', &st_cur); st_a_sent = 1; }
            else if (st_acked_a && st_qi < st_qn) build_status(st_queue[st_qi++], &st_cur);
            else if (st_cmd == 0x01) {
                static const uint8_t echo01[] = { 0x01, 0x04, 0xa1, 0xa2, 0xa3, 0xa4 };
                memcpy(st_cur.b, echo01, sizeof echo01); st_cur.len = sizeof echo01;
            } else { st_cur.b[0] = 0x00; st_cur.b[1] = 0; st_cur.len = 2; }
            if (st_log && st_cur.b[0] > 0x01)
                fprintf(st_out, "[dsp] status message '%c' (%d bytes) on Cmd:%02x\n",
                        st_cur.b[0], st_cur.len - 2, st_cmd);
        } else if (st_cmd == 0x04) {
            st_cur.b[0] = 0x01; st_cur.len = 1;        /* POST: known-good 0x01 then 0xff */
        } else if (st_cmd == 0x05 || st_cmd == 0x06 || st_cmd == 0x07 || st_cmd == 0x1f || st_cmd == 0x2f) {
            /* This family (table 0x105a7a3c, class cls_105a7a9c) is registered in the
             * response registry only under 0x07: its replies must carry resp0 = 0x07. */
            st_cur.b[0] = 0x07; st_cur.b[1] = 0; st_cur.len = 2;
        } else {
            st_cur.b[0] = (uint8_t)st_cmd; st_cur.b[1] = 0; st_cur.len = 2;   /* echo, no data */
        }
    }
    uint8_t b = st_pos < st_cur.len ? st_cur.b[st_pos] : 0xff;
    st_pos++;
    return b;
}

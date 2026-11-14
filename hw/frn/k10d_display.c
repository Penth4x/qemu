/*
 * K10D rear display + rear buttons for interactive use.
 *
 * Display: the display controller at 0x40040000 scans out two 640x480 layers, each a
 * planar YCbCr 4:2:0 frame (Y at base, Cb at base + 0x4b000, Cr at base + 0x5dc00).
 * Layer A (background) base register +0x308, layer B (text overlay) +0x328; registers
 * hold address & 0x3ffffff0 and the frames live in SDRAM at 0x80000000 | base. The
 * firmware double-buffers by rewriting these registers, so they are read every refresh.
 * Layer A is opaque; layer B carries a 4-bit alpha plane (two pixels per byte, high nibble
 * first) at the address in +0x334 (base + 0x70800), and is blended over A (see k10d-re
 * harness2/render_layers.py, which this mirrors). Before each redraw the firmware clears the
 * back buffer with image-processor fills (k10d_imgproc.c engine A, mode 0x700).
 *
 * Buttons: the companion CPU reports them in its 'A' status record, active-low; byte 3
 * (0x01 right, 0x02 left, 0x04 down, 0x08 up, 0x10 OK, 0x80 MENU; up/left confirmed by
 * Andrew on the live window). Keys: arrows, Enter = OK,
 * M = MENU; P = power off (an all-zero 'A' record, which drives the firmware into its
 * power-off path, where it saves settings to flash; see k10d_flash.c / FRN_FLASH_SAVE).
 * Each change of button state is handed to the companion-CPU model, which queues the
 * message and raises the request interrupt on the CPU thread.
 */
#include "qemu/osdep.h"
#include "ui/console.h"
#include "ui/input.h"
#include "system/address-spaces.h"
#include "system/memory.h"
#include "k10d_display.h"

void k10d_cpucom_post_key_record(const uint8_t *payload9);   /* target/frn/k10d_cpucom.c */

#define W 640
#define H 480
#define CB_OFF 0x4b000
#define CR_OFF 0x5dc00
#define FRAME  0x70800

static QemuConsole *con;
static uint8_t frame_a[FRAME], frame_b[FRAME], alpha_b[(W / 2) * H];
static uint8_t byte3 = 0xff;

static uint32_t rd32(hwaddr a)
{
    uint8_t b[4];
    address_space_read(&address_space_memory, a, MEMTXATTRS_UNSPECIFIED, b, 4);
    return ((uint32_t)b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3];
}

static inline uint32_t yuv2rgb(int y, int u, int v)
{
    u -= 128; v -= 128;
    int r = y + (1402 * v) / 1000, g = y - (344 * u + 714 * v) / 1000, b = y + (1772 * u) / 1000;
    r = r < 0 ? 0 : r > 255 ? 255 : r;
    g = g < 0 ? 0 : g > 255 ? 255 : g;
    b = b < 0 ? 0 : b > 255 ? 255 : b;
    return (r << 16) | (g << 8) | b;
}

static bool k10d_display_update(void *opaque)
{
    DisplaySurface *s = qemu_console_surface(con);
    uint32_t base_a = rd32(0x40040308) & 0x3ffffff0, base_b = rd32(0x40040328) & 0x3ffffff0;
    if (base_a) address_space_read(&address_space_memory, 0x80000000u | base_a, MEMTXATTRS_UNSPECIFIED, frame_a, FRAME);
    if (base_b) address_space_read(&address_space_memory, 0x80000000u | base_b, MEMTXATTRS_UNSPECIFIED, frame_b, FRAME);
    uint32_t base_al = rd32(0x40040334) & 0x3ffffff0;
    if (base_b && base_al)
        address_space_read(&address_space_memory, 0x80000000u | base_al, MEMTXATTRS_UNSPECIFIED, alpha_b, sizeof alpha_b);
    else memset(alpha_b, base_b ? 0xff : 0, sizeof alpha_b);
    uint8_t *dst = surface_data(s);
    int stride = surface_stride(s);
    for (int y = 0; y < H; y++) {
        uint32_t *row = (uint32_t *)(dst + y * stride);
        for (int x = 0; x < W; x++) {
            int c = (y / 2) * (W / 2) + x / 2;
            uint32_t pa = base_a ? yuv2rgb(frame_a[y * W + x], frame_a[CB_OFF + c], frame_a[CR_OFF + c]) : 0;
            uint8_t ab = alpha_b[y * (W / 2) + x / 2];
            int al = (x & 1) ? (ab & 0x0f) : (ab >> 4);           /* 4-bit alpha, two pixels per byte */
            uint32_t px = pa;
            if (base_b && al) {
                uint32_t pb = yuv2rgb(frame_b[y * W + x], frame_b[CB_OFF + c], frame_b[CR_OFF + c]);
                px = 0;
                for (int sh = 0; sh < 24; sh += 8) {
                    int ca = (pa >> sh) & 0xff, cbv = (pb >> sh) & 0xff;
                    px |= (uint32_t)((ca * (15 - al) + cbv * al) / 15) << sh;
                }
            }
            row[x] = px;
        }
    }
    qemu_console_update_full(con);
    return true;
}

static const GraphicHwOps k10d_display_ops = {
    .gfx_update = k10d_display_update,
};

static uint8_t rec[9] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

static void k10d_key_event(DeviceState *dev, QemuConsole *src, QemuInputEvent *evt)
{
    int q = qemu_input_linux_to_qcode(evt->key.key);
    bool down = evt->key.down;
    int byte; uint8_t bit;
    switch (q) {
    case Q_KEY_CODE_RIGHT: byte = 3; bit = 0x01; break;
    case Q_KEY_CODE_LEFT:  byte = 3; bit = 0x02; break;
    case Q_KEY_CODE_DOWN:  byte = 3; bit = 0x04; break;
    case Q_KEY_CODE_UP:    byte = 3; bit = 0x08; break;
    case Q_KEY_CODE_RET: case Q_KEY_CODE_KP_ENTER: byte = 3; bit = 0x10; break;
    case Q_KEY_CODE_M:     byte = 3; bit = 0x80; break;   /* MENU */
    case Q_KEY_CODE_I:     byte = 2; bit = 0x10; break;   /* INFO (opens the shooting-info screen from idle) */
    case Q_KEY_CODE_V:     byte = 2; bit = 0x20; break;   /* playback: item 0xe, the shooting-mode handler's mode switch (unconfirmed) */
    case Q_KEY_CODE_F:     byte = 5; bit = 0x08; break;   /* Fn (opens the Fn menu from idle) */
    case Q_KEY_CODE_P:
        if (down) {
            static const uint8_t off[9] = { 0 };
            fprintf(stderr, "[k10d] power off\n");
            k10d_cpucom_post_key_record(off);
        }
        return;
    default: return;
    }
    uint8_t nb = down ? (rec[byte] & ~bit) : (rec[byte] | bit);
    if (nb == rec[byte]) return;                  /* key repeat */
    rec[byte] = nb;
    k10d_cpucom_post_key_record(rec);
}

static const QemuInputHandler k10d_key_handler = {
    .name = "K10D rear buttons",
    .mask = INPUT_EVENT_MASK_KEY,
    .event = k10d_key_event,
};

void k10d_display_init(void)
{
    con = qemu_graphic_console_create(NULL, 0, &k10d_display_ops, NULL);
    qemu_console_resize(con, W, H);
    QemuInputHandlerState *hs = qemu_input_handler_register(NULL, &k10d_key_handler);
    qemu_input_handler_activate(hs);
}

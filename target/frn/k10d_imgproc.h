/* K10D image-processor block (0x40060000) operation-engine model — see k10d_imgproc.c. */
#ifndef K10D_IMGPROC_H
#define K10D_IMGPROC_H
#include <stdio.h>
#include <stdint.h>

int k10d_img_enabled(void);                       /* FRN_IMG_MODEL=0 disables */
int k10d_img_read16(uint32_t a, uint32_t *v);     /* 1 = handled */
int k10d_img_read32(uint32_t a, uint32_t *v);
int k10d_img_write16(uint32_t a, uint32_t v, FILE *log,
                     uint32_t (*ram16)(uint32_t), uint32_t (*ram32)(uint32_t));
int k10d_img_tick(void);                          /* per instruction; 1 = op completed now */
int k10d_img_irq(void);                           /* 1 = request vector 35 */
int k10d_rc_irq(int unit);
int k10d_img_write8(uint32_t a, uint32_t v);                       /* byte store hook (converter LUTs) */
void k10d_img_set_load(uint8_t (*ld8)(uint32_t a));
void k10d_img_set_store(void (*st8)(uint32_t a, uint8_t v));   /* memory store used by engine fills */                        /* 1 = request vector 39 (unit 0) / 40 (unit 1) */

#endif

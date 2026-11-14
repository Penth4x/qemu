/* K10D program flash command-set model — see k10d_flash.c. */
#ifndef K10D_FLASH_H
#define K10D_FLASH_H
#include <stdint.h>
int  k10d_flash_enabled(void);                                    /* FRN_FLASH_MODEL=0 disables */
int  k10d_flash_write(CPUFRNState *e, uint32_t a, uint32_t v, int size);   /* 1 = handled */
void k10d_flash_tick(void);                                       /* per instruction (deferred save) */
#endif

/* K10D SD card (image-backed) behind the SDHCI host — see k10d_sd.c. */
#ifndef HW_FRN_K10D_SD_H
#define HW_FRN_K10D_SD_H
#include <stdint.h>
int k10d_sd_present(void);
int k10d_sd_command(uint16_t cmd, uint32_t arg, uint8_t *resp, uint32_t blksize);
int k10d_sd_read_ready(void);
int k10d_sd_write_ready(void);
int k10d_sd_data_read32(uint32_t *v);
int k10d_sd_data_write32(uint32_t v);
#endif

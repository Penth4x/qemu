/* K10D companion-CPU (CPUCOM) model — see k10d_cpucom.c for the protocol facts. */
#ifndef K10D_CPUCOM_H
#define K10D_CPUCOM_H
#include <stdio.h>
#include <stdint.h>

int     k10d_cpucom_enabled(void);           /* FRN_DSP_MODEL=0 disables */
void    k10d_cpucom_txn_start(FILE *log);    /* status write with bit 0x200 */
void    k10d_cpucom_tx(uint8_t v);           /* main CPU wrote a data byte */
uint8_t k10d_cpucom_rx(FILE *log);           /* main CPU reads the simultaneous byte */
int     k10d_cpucom_attention(void);         /* 1 = raise vector 31 now (edge) */

#endif

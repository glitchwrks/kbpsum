/*
 * kbp_sum.h - the kbpsum checksum routine (CRCK, Keith B. Petersen, 1979)
 *
 * History: Fred Gutman published a bit-serial 8080 CRC routine in EDN
 * (June 5, 1979, p. 84). Keith B. Petersen, W8SDZ, used it in CRCK for CP/M
 * (first written 06/27/79) but fed it a whole byte per call with generator
 * 0xA097, which turned the CRC into an add-and-shift hash. CRCK and its
 * MS-DOS descendants (e.g. CRCK 6.71 by Howard Vigorita, 1986) called the
 * result a "CRC"; it is not one, hence the name kbpsum, after Petersen.
 *
 * Derived from the loop at offset 0x58E of the LZEXE-unpacked CRCK.EXE
 * ("MSDOS & Concurrent DOS high speed CRC version 6.71, 3/20/86,
 * Howard Vigorita").
 *
 * Despite the program's name this is not a true CRC: each byte is ADDed
 * into the low byte of the register (carry discarded) rather than XORed,
 * and the register shifts one bit per byte.
 *
 * Input is treated as a sequence of 128-byte CP/M records: a final partial
 * record is zero-padded, and the padding is included in the checksum.
 */
#ifndef KBP_SUM_H
#define KBP_SUM_H

#include <stddef.h>
#include <stdint.h>

#define KBP_POLY    0xA097u
#define KBP_RECORD  128u

typedef struct {
    uint16_t crc;      /* running register */
    unsigned rec;      /* bytes into the current 128-byte record */
} kbp_state;

/* Streaming interface: init, feed any number of chunks, then final. */
void     kbp_init(kbp_state *s);
void     kbp_update(kbp_state *s, const void *buf, size_t len);
uint16_t kbp_final(kbp_state *s);    /* pads to a whole record */

/* One-shot convenience wrapper. */
uint16_t kbp_buf(const void *buf, size_t len);

#endif /* KBP_SUM_H */

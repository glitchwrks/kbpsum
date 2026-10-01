/*
 * kbp_sum.c - the kbpsum checksum routine (CRCK, Keith B. Petersen, 1979)
 *
 * History: Fred Gutman published a bit-serial 8080 CRC routine in EDN
 * (June 5, 1979, p. 84). Keith B. Petersen, W8SDZ, used it in CRCK for CP/M
 * (first written 06/27/79) but fed it a whole byte per call with generator
 * 0xA097, which turned the CRC into an add-and-shift hash. CRCK and its
 * MS-DOS descendants (e.g. CRCK 6.71 by Howard Vigorita, 1986) called the
 * result a "CRC"; it is not one, hence the name kbpsum, after Petersen.
 *
 * Original 8086 loop (DS:SI = buffer, CX = count, BX = crc,
 * BP = 0A097h, DX = 8000h):
 *
 *   58E: mov  di,bx        ; remember old value
 *        shl  bx,1         ; shift left one bit
 *        lodsb             ; next byte
 *        add  bl,al        ; ADD into low byte, carry discarded
 *        test dx,di        ; was old bit 15 set?
 *        loope 58E
 *        je   next_block
 *        xor  bx,bp        ; yes: XOR with 0A097h
 *        jcxz next_block
 *        jmp  58E
 */
#include "kbp_sum.h"

static uint16_t kbp_step(uint16_t crc, uint8_t b)
{
    uint16_t top = crc & 0x8000u;

    crc = (uint16_t)(crc << 1);
    crc = (uint16_t)((crc & 0xFF00u) | ((crc + b) & 0x00FFu));
    if (top)
        crc ^= KBP_POLY;
    return crc;
}

void kbp_init(kbp_state *s)
{
    s->crc = 0;
    s->rec = 0;
}

void kbp_update(kbp_state *s, const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    uint16_t crc = s->crc;
    size_t i;

    for (i = 0; i < len; i++)
        crc = kbp_step(crc, p[i]);
    s->crc = crc;
    s->rec = (unsigned)((s->rec + len) % KBP_RECORD);
}

uint16_t kbp_final(kbp_state *s)
{
    /* The original rounds the last read up to a multiple of 128 bytes
       and fills the gap with zeros (0x576-0x58B). */
    if (s->rec) {
        unsigned pad = KBP_RECORD - s->rec;
        while (pad--)
            s->crc = kbp_step(s->crc, 0);
        s->rec = 0;
    }
    return s->crc;
}

uint16_t kbp_buf(const void *buf, size_t len)
{
    kbp_state s;

    kbp_init(&s);
    kbp_update(&s, buf, len);
    return kbp_final(&s);
}

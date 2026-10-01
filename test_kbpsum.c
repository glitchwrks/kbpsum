/*
 * test_kbpsum.c - known-answer tests for the checksum routine
 * (values produced by the verified Python reference).
 */
#include <stdio.h>
#include <string.h>
#include "kbp_sum.h"

static int failures;

static void expect(const char *name, uint16_t got, uint16_t want)
{
    if (got != want) {
        printf("FAIL %-22s got %04X want %04X\n", name, got, want);
        failures++;
    } else {
        printf("ok   %-22s %04X\n", name, got);
    }
}

int main(void)
{
    static unsigned char seq[768], hello[600], fives[128];
    kbp_state s;
    size_t i, off, step;

    for (i = 0; i < sizeof seq; i++)
        seq[i] = (unsigned char)i;
    for (i = 0; i < 50; i++)
        memcpy(hello + 12 * i, "hello world\n", 12);
    memset(fives, 0x55, sizeof fives);

    expect("empty", kbp_buf("", 0), 0x0000);
    expect("00 02", kbp_buf("\x00\x02", 2), 0x3346);
    expect("01 00 (collision)", kbp_buf("\x01\x00", 2), 0x3346);
    expect("\"AB\"", kbp_buf("AB", 2), 0xF9BF);
    expect("128 x 55h", kbp_buf(fives, sizeof fives), 0xEEFE);
    expect("00..FF x 3", kbp_buf(seq, sizeof seq), 0x03EE);
    expect("hello world x 50", kbp_buf(hello, sizeof hello), 0xC465);

    /* Streaming in odd-sized chunks must match the one-shot result. */
    for (step = 1; step <= 131; step += 13) {
        kbp_init(&s);
        for (off = 0; off < sizeof seq; off += step)
            kbp_update(&s, seq + off,
                        sizeof seq - off < step ? sizeof seq - off : step);
        expect("00..FF x 3 chunked", kbp_final(&s), 0x03EE);
    }

    printf(failures ? "%d FAILED\n" : "all passed\n", failures);
    return failures != 0;
}

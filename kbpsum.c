/*
 * kbpsum.c - the CRCK file checksum utility
 *
 * A reimplementation of CRCK 6.71 for MS-DOS (Howard Vigorita, 3/20/86).
 * Output and the CRCKLIST.CRC / CRCKFILE / -CATALOG file formats are kept
 * byte-for-byte compatible with the original.
 *
 * History: Fred Gutman published a bit-serial 8080 CRC routine in EDN
 * (June 5, 1979, p. 84). Keith B. Petersen, W8SDZ, used it in CRCK for CP/M
 * (first written 06/27/79) but fed it a whole byte per call with generator
 * 0xA097, which turned the CRC into an add-and-shift hash. CRCK and its
 * MS-DOS descendants (e.g. CRCK 6.71 by Howard Vigorita, 1986) called the
 * result a "CRC"; it is not one, hence the name kbpsum, after Petersen.
 *
 * Usage:
 *   kbpsum FILE...     checksum the named files; shell-expanded wildcards
 *                      and quoted DOS-style specs ('*.*') both work
 *   kbpsum FILE... F   same, and also write the results to CRCKLIST.CRC
 *                      (built as CRCKLIST.$$$, then renamed over the old one).
 *                      F must be the last argument, on its own.
 *   kbpsum             no arguments: find a digest file in the current
 *                      directory and verify the files it lists
 *
 * Derived from a disassembly of CRCK.EXE (LZEXE-unpacked). Offsets in
 * comments refer to the unpacked code segment. The checksum routine itself
 * is in kbp_sum.c.
 */
#include <dirent.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "kbp_sum.h"

#define CRLF "\r\n"

static const char BANNER[] =
    "MSDOS & Concurrent DOS high speed CRC version 6.71, 3/20/86, "
    "Howard Vigorita\r\nCTL-S pauses, CTL-C aborts\r\n\r\n";
static const char TEMP_NAME[] = "CRCKLIST.$$$";
static const char LIST_NAME[] = "CRCKLIST.CRC";

enum { OK = 0, ABORT = 1 };

/* ------------------------------------------------------------------------
 * Ctrl-C (handler at 0x6B4 in the original)
 * ------------------------------------------------------------------------ */

static volatile sig_atomic_t interrupted;

static void on_sigint(int sig)
{
    (void)sig;
    interrupted = 1;
}

/* ------------------------------------------------------------------------
 * Output: DOS console, CR/LF line ends, 7-bit characters (0x611)
 * ------------------------------------------------------------------------ */

static FILE *tee;          /* open CRCKLIST.$$$ while in F mode (0x61F) */
static int tee_error;

static void emit(const char *s, size_t n, int to_tee)
{
    char buf[256];

    while (n) {
        size_t k = n < sizeof buf ? n : sizeof buf, i;

        for (i = 0; i < k; i++)
            buf[i] = (char)(s[i] & 0x7F);
        fwrite(buf, 1, k, stdout);
        if (to_tee && tee && fwrite(buf, 1, k, tee) != k)
            tee_error = 1;
        s += k;
        n -= k;
    }
    fflush(stdout);
}

/* Character output via 0x611: console, plus the list file in F mode. */
static void out(const char *s)
{
    emit(s, strlen(s), 1);
}

/* Console only (INT 21h/09h strings). */
static void out_con(const char *s)
{
    emit(s, strlen(s), 0);
}

static void outf(const char *fmt, ...)
{
    char buf[512];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    out(buf);
}

static void warn(const char *arg, const char *why)
{
    fprintf(stderr, "kbpsum: %s: %s, skipped\n", arg, why);
}

static void *xmalloc(size_t n)
{
    void *p = malloc(n ? n : 1);

    if (!p) {
        fprintf(stderr, "kbpsum: out of memory\n");
        exit(2);
    }
    return p;
}

static char *xstrdup(const char *s)
{
    size_t n = strlen(s) + 1;

    return memcpy(xmalloc(n), s, n);
}

/* ------------------------------------------------------------------------
 * Checksum a file on disk
 * ------------------------------------------------------------------------ */

enum { SUM_OK = 0, SUM_FAILED = -1, SUM_INTERRUPTED = -2 };

static int checksum_file(const char *path, uint16_t *crc)
{
    static unsigned char buf[0xF800];      /* the original's read size */
    kbp_state s;
    FILE *fp;
    size_t n;
    int err;

    if (!(fp = fopen(path, "rb")))
        return SUM_FAILED;
    kbp_init(&s);
    while ((n = fread(buf, 1, sizeof buf, fp)) > 0) {
        kbp_update(&s, buf, n);
        if (interrupted)
            break;
    }
    err = ferror(fp);
    fclose(fp);
    if (interrupted)
        return SUM_INTERRUPTED;
    if (err)
        return SUM_FAILED;
    *crc = kbp_final(&s);
    return SUM_OK;
}

/* ------------------------------------------------------------------------
 * DOS 8.3 file lookup (FCB name fields + FindFirst/FindNext)
 * ------------------------------------------------------------------------ */

typedef struct {
    char *host;            /* name as found on disk / given on command line */
    char name8[9];         /* FCB name field, upper case, space padded */
    char ext3[4];          /* FCB extension field */
} hit_t;

static void pad_upper(char *dst, const char *src, size_t len, size_t width)
{
    size_t i;

    for (i = 0; i < width; i++) {
        unsigned char c = i < len ? (unsigned char)src[i] : ' ';

        dst[i] = (char)(c >= 'a' && c <= 'z' ? c - 32 : c);
    }
    dst[width] = '\0';
}

/* Split a host filename into space-padded FCB name/ext; 0 if not 8.3. */
static int fcb_fields(const char *f, char *name8, char *ext3)
{
    const char *dot = strchr(f, '.');
    size_t nl, el;

    if (f[0] == '.' || (dot && strchr(dot + 1, '.')) || strchr(f, ' '))
        return 0;
    nl = dot ? (size_t)(dot - f) : strlen(f);
    el = dot ? strlen(dot + 1) : 0;
    if (nl < 1 || nl > 8 || el > 3)
        return 0;
    pad_upper(name8, f, nl, 8);
    pad_upper(ext3, dot ? dot + 1 : "", el, 3);
    return 1;
}

/* DOS turns '*' into '?' for the rest of the field. */
static void expand_star(char *field)
{
    char *star = strchr(field, '*');

    if (star)
        for (; *star; star++)
            *star = '?';
}

static int field_match(const char *pat, const char *name)
{
    for (; *pat && *name; pat++, name++)
        if (*pat != '?' && *pat != *name)
            return 0;
    return 1;
}

static int is_regular(const char *path)
{
    struct stat st;

    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

static int cmp_names(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

/* Current directory, sorted so results are repeatable (DOS would use
   directory order). */
static char **list_dir(size_t *count)
{
    DIR *d = opendir(".");
    struct dirent *e;
    char **v = NULL;
    size_t n = 0, cap = 0;

    if (d) {
        while ((e = readdir(d)) != NULL) {
            if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
                continue;
            if (n == cap) {
                char **nv;

                cap = cap ? cap * 2 : 64;
                nv = realloc(v, cap * sizeof *v);
                if (!nv) {
                    fprintf(stderr, "kbpsum: out of memory\n");
                    exit(2);
                }
                v = nv;
            }
            v[n++] = xstrdup(e->d_name);
        }
        closedir(d);
    }
    if (n)
        qsort(v, n, sizeof *v, cmp_names);
    *count = n;
    return v;
}

static void free_list(char **v, size_t n)
{
    while (n--)
        free(v[n]);
    free(v);
}

/*
 * FindFirst (max == 1) / FindFirst+FindNext (max == 0: all) on an FCB-style
 * 8+3 pattern, case-insensitive. Returns the number of hits stored in *out.
 */
static size_t find_files(const char *name8, const char *ext3, size_t max,
                         hit_t **out)
{
    char pn[9], pe[4], fn[9], fe[4];
    char **names;
    size_t n, i, found = 0;
    hit_t *hits;

    pad_upper(pn, name8, strlen(name8), 8);
    pad_upper(pe, ext3, strlen(ext3), 3);
    expand_star(pn);
    expand_star(pe);

    names = list_dir(&n);
    hits = xmalloc((n ? n : 1) * sizeof *hits);
    for (i = 0; i < n && (!max || found < max); i++) {
        if (!is_regular(names[i]))          /* attribute 0: no dirs */
            continue;
        if (fcb_fields(names[i], fn, fe) && field_match(pn, fn) &&
            field_match(pe, fe)) {
            hits[found].host = xstrdup(names[i]);
            memcpy(hits[found].name8, fn, sizeof fn);
            memcpy(hits[found].ext3, fe, sizeof fe);
            found++;
        }
    }
    free_list(names, n);
    *out = hits;
    return found;
}

static void free_hits(hit_t *h, size_t n)
{
    while (n--)
        free(h[n].host);
    free(h);
}

/* ------------------------------------------------------------------------
 * Digest-file reader (FCB sequential reads, 0xA6 / 0x17A)
 * ------------------------------------------------------------------------ */

typedef struct {
    unsigned char *data;
    size_t size, pos;
} reader_t;

/* Read the whole digest file, zero-filled to a whole 128-byte record the
   way DOS fills a partial FCB record. Returns 0 on failure. */
static int reader_open(reader_t *rd, const char *path)
{
    FILE *fp = fopen(path, "rb");
    size_t cap = 4096, n = 0, got;

    if (!fp)
        return 0;
    rd->data = xmalloc(cap);
    while ((got = fread(rd->data + n, 1, cap - n, fp)) > 0) {
        n += got;
        if (n == cap) {
            unsigned char *nd = realloc(rd->data, cap *= 2);

            if (!nd) {
                fprintf(stderr, "kbpsum: out of memory\n");
                exit(2);
            }
            rd->data = nd;
        }
    }
    if (ferror(fp)) {
        fclose(fp);
        free(rd->data);
        return 0;
    }
    fclose(fp);
    if (n % 128) {
        size_t pad = 128 - n % 128;

        if (n + pad > cap) {
            unsigned char *nd = realloc(rd->data, n + pad);

            if (!nd) {
                fprintf(stderr, "kbpsum: out of memory\n");
                exit(2);
            }
            rd->data = nd;
        }
        memset(rd->data + n, 0, pad);
        n += pad;
    }
    rd->size = n;
    rd->pos = 0;
    return 1;
}

static int reader_getc(reader_t *rd)         /* 0xA6: 1Ah forever at EOF */
{
    return rd->pos < rd->size ? rd->data[rd->pos++] : 0x1A;
}

/* 0x17A. Fills line (up to 80 chars, NUL-terminated); 0 at end of file. */
static int read_line(reader_t *rd, unsigned char *line, size_t *len)
{
    for (;;) {
        size_t n = 0;

        for (;;) {
            int c = reader_getc(rd);

            if (c == 0x1A) {                 /* Ctrl-Z, before masking */
                line[n] = 0;
                *len = n;
                return n != 0;
            }
            c &= 0x7F;
            if (c == 0x0D || c == 0x0A)
                break;
            line[n++] = (unsigned char)c;
            if (n >= 80)                     /* long lines split at 80 */
                break;
        }
        if (n) {
            line[n] = 0;
            *len = n;
            return 1;
        }
        /* blank line: skip it */
    }
}

/* ------------------------------------------------------------------------
 * Line parsers. Each works on the line plus NUL padding, with a cursor,
 * mirroring the original subroutines (all fail on the NUL, so they never
 * read past the end of the line).
 * ------------------------------------------------------------------------ */

typedef struct {
    unsigned char b[128];
    size_t p;
} cursor_t;

static void cursor_init(cursor_t *c, const unsigned char *line, size_t len)
{
    memset(c->b, 0, sizeof c->b);
    memcpy(c->b, line, len);
    c->p = 0;
}

static int cur_next(cursor_t *c)
{
    return c->b[c->p++];
}

static int is_digit(int c)
{
    return c >= 0x30 && c <= 0x39;
}

static int cur_digit(cursor_t *c)            /* 0x3CD */
{
    return is_digit(cur_next(c));
}

static int is_blank(int c)
{
    return c == 0x20 || c == 0x09;
}

static int cur_whitespace(cursor_t *c)       /* 0x395: one or more */
{
    if (!is_blank(c->b[c->p]))
        return 0;
    while (is_blank(c->b[c->p]))
        c->p++;
    return 1;
}

static int name_char(int c)
{
    return (c >= 0x21 && c <= 0x7E) || c == 0x20;
}

/* 0x360: fixed "XXXXXXXX.XXX". Returns start offset, or -1. */
static long cur_filename(cursor_t *c)
{
    size_t start = c->p;
    int i, ch;

    ch = cur_next(c);
    if (ch < 0x21 || ch > 0x7E)
        return -1;
    for (i = 0; i < 7; i++)
        if (!name_char(cur_next(c)))
            return -1;
    if (cur_next(c) != 0x2E)
        return -1;
    for (i = 0; i < 3; i++)
        if (!name_char(cur_next(c)))
            return -1;
    return (long)start;
}

static int cur_hexdigit(cursor_t *c)         /* 0x412; -1 on failure */
{
    int ch = cur_next(c), v;

    if (ch < 0x30)
        return -1;
    v = ch - 0x30;
    if (v < 10)
        return v;
    v = ((v & 0x1F) - 7) & 0xFF;
    return v >= 10 && v <= 15 ? v : -1;
}

static int cur_hexbyte(cursor_t *c)          /* 0x3F3; -1 on failure */
{
    int hi = cur_hexdigit(c), lo;

    if (hi < 0)
        return -1;
    lo = cur_hexdigit(c);
    if (lo < 0)
        return -1;
    return (hi << 4) | lo;
}

static int cur_crc_pair(cursor_t *c, int *hi, int *lo)   /* 0x2BD */
{
    if ((*hi = cur_hexbyte(c)) < 0)
        return 0;
    if (cur_next(c) != 0x20) {
        out("Not a space between CRC values");
        return 0;
    }
    if ((*lo = cur_hexbyte(c)) < 0)
        return 0;
    return 1;
}

static int cur_catalog_number(cursor_t *c)   /* 0x3B0: "NNN" or "NN." */
{
    int ch;

    if (!cur_digit(c) || !cur_digit(c))
        return 0;
    ch = cur_next(c);
    if (is_digit(ch))
        return 1;
    if (ch == 0x2E) {
        c->p--;
        return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------------
 * Digest verification (no command-line argument)
 * ------------------------------------------------------------------------ */

typedef struct {
    unsigned matched, mismatched, badparse, notfound;
    int any_found;         /* 0x348: print the summary */
    int none_checked;      /* 0x317 */
} verifier_t;

/* 0xF8: locate and open a digest file. */
static int open_digest(verifier_t *v, const char *name8, reader_t *rd)
{
    hit_t *h;
    size_t n = find_files(name8, "???", 1, &h);
    int ok = n && reader_open(rd, h[0].host);

    if (!ok) {
        out_con("\tNot found");
        out(CRLF);
    } else {
        outf("\tChecking with file: %s.%s" CRLF CRLF, h[0].name8, h[0].ext3);
        v->matched = v->mismatched = v->badparse = v->notfound = 0;
    }
    free_hits(h, n);
    return ok;
}

/* 0x1CC: report an unparseable line. */
static void bad_line(verifier_t *v, const unsigned char *line)
{
    out((const char *)line);
    v->badparse++;
    out(CRLF);
}

/* 0x21B: check one listed file. */
static int check(verifier_t *v, const cursor_t *c, size_t start, int hi,
                 int lo)
{
    char raw[13], name8[9], ext3[4];
    hit_t *h;
    size_t n;
    uint16_t crc;
    int r;

    memcpy(raw, c->b + start, 12);
    raw[12] = 0;
    memcpy(name8, raw, 8);
    name8[8] = 0;
    memcpy(ext3, raw + 9, 3);
    ext3[3] = 0;
    outf("%s - ", raw);

    n = find_files(name8, ext3, 1, &h);
    if (!n) {
        out(" File not found" CRLF);
        v->notfound++;
        free_hits(h, n);
        return OK;
    }
    v->any_found = 1;
    r = checksum_file(h[0].host, &crc);
    free_hits(h, n);
    if (r == SUM_INTERRUPTED)
        return ABORT;
    if (r == SUM_FAILED) {
        out(" ++Open failed++" CRLF);
        return OK;
    }
    outf("%02X %02X", crc >> 8, crc & 0xFF);
    v->none_checked = 0;
    if ((crc >> 8) == hi && (crc & 0xFF) == lo) {
        out(" *Match*" CRLF);
        v->matched++;
    } else {
        outf(" <-- is, was --> %02X %02X" CRLF, hi, lo);
        v->mismatched++;
    }
    return OK;
}

/* 0x6E6 */
static void summary(const verifier_t *v)
{
    if (!v->any_found)
        return;
    outf(CRLF "Quantity of file CRC that matched - %u", v->matched & 0xFF);
    if (v->mismatched & 0xFF)
        outf(CRLF "Quantity of file CRC that did not match - %u",
             v->mismatched & 0xFF);
    if (v->badparse & 0xFF)
        outf(CRLF "Quantity of lines failed parse test - %u",
             v->badparse & 0xFF);
    if (v->notfound & 0xFF)
        outf(CRLF "Quantity of file(s) not found - %u", v->notfound & 0xFF);
}

/* 0x17A at EOF */
static int end_of_list(const verifier_t *v)
{
    if (v->none_checked) {
        out("*No CRC Files found*");
        return ABORT;
    }
    out_con(CRLF "DONE");
    summary(v);
    return OK;
}

/* 0x6F: CRCKLIST / CRCKFILE format */
static int run_list(verifier_t *v, reader_t *rd)
{
    static const unsigned char prefix[] = "--> FILE:  ";
    static const unsigned char crctag[] = "\t\tCRC = ";
    unsigned char line[84];
    size_t len;
    cursor_t c;
    long start;
    int hi, lo;

    for (;;) {
        if (interrupted)
            return ABORT;
        if (!read_line(rd, line, &len))
            return end_of_list(v);
        cursor_init(&c, line, len);
        if (memcmp(c.b, prefix, 11) != 0)
            goto fail;
        c.p = 11;
        if ((start = cur_filename(&c)) < 0)
            goto fail;
        if (memcmp(c.b + c.p, crctag, 8) != 0)
            goto fail;
        c.p += 8;
        if (!cur_crc_pair(&c, &hi, &lo))
            goto fail;
        if (check(v, &c, (size_t)start, hi, lo) == ABORT)
            return ABORT;
        continue;
fail:
        bad_line(v, line);
    }
}

/* 0x2FF: -CATALOG format */
static int run_catalog(verifier_t *v, reader_t *rd)
{
    unsigned char line[84];
    size_t len;
    cursor_t c;
    long start;
    int hi, lo, ch, early;

    for (;;) {
        if (interrupted)
            return ABORT;
        if (!read_line(rd, line, &len))
            return end_of_list(v);
        cursor_init(&c, line, len);

        /* Leading part: failures here are silent until a file has been
           checked (header lines of a catalog listing). */
        early = 1;
        if (!cur_catalog_number(&c) || c.b[c.p] != 0x2E)
            goto fail;
        c.p++;
        if (!cur_catalog_number(&c))        /* optional second number */
            c.p--;
        if (!cur_whitespace(&c))
            goto fail;
        if ((start = cur_filename(&c)) < 0)
            goto fail;
        early = 0;
        if (!cur_whitespace(&c))
            goto fail;
        if (!cur_digit(&c))                 /* size in K */
            goto fail;
        do
            ch = cur_next(&c);
        while (is_digit(ch));
        if (ch != 'K')
            goto fail;
        if (!cur_whitespace(&c))
            goto fail;
        if (!cur_crc_pair(&c, &hi, &lo))
            goto fail;
        if (check(v, &c, (size_t)start, hi, lo) == ABORT)
            return ABORT;
        continue;
fail:
        if (early && v->none_checked)
            continue;
        bad_line(v, line);
    }
}

static int verify(void)
{
    verifier_t v;
    reader_t rd;
    int r;

    memset(&v, 0, sizeof v);
    v.none_checked = 1;

    out(CRLF);
    out(BANNER);
    out("Searching for \"CRCKLIST\" file    ");
    if (!open_digest(&v, "CRCKLIST", &rd)) {
        out("Now searching for \"CRCKFILE\" file");
        if (!open_digest(&v, "CRCKFILE", &rd)) {
            out("Now searching for \"-CATALOG\" file");
            if (!open_digest(&v, "-CATALOG", &rd)) {
                r = ABORT;
                goto done;
            }
            r = run_catalog(&v, &rd);
            free(rd.data);
            goto done;
        }
    }
    r = run_list(&v, &rd);
    free(rd.data);
done:
    if (r == ABORT) {
        out_con(CRLF CRLF "++ABORTED++");
        summary(&v);
    }
    return 0;
}

/* ------------------------------------------------------------------------
 * Checksum files, optionally writing CRCKLIST.CRC (0x433)
 * ------------------------------------------------------------------------ */

/* Rough equivalent of the DOS FCB parse of a command-line argument:
   optional drive (ignored here), 8.3 fields, upper case, '*' -> '?'. */
static void parse_fcb(const char *arg, char *name8, char *ext3)
{
    const char *dot;
    size_t nl, el;

    if (arg[0] && arg[1] == ':')
        arg += 2;
    dot = strchr(arg, '.');
    nl = dot ? (size_t)(dot - arg) : strlen(arg);
    el = dot ? strlen(dot + 1) : 0;
    pad_upper(name8, arg, nl < 8 ? nl : 8, 8);
    pad_upper(ext3, dot ? dot + 1 : "", el < 3 ? el : 3, 3);
    expand_star(name8);
    expand_star(ext3);
}

static int same_dir_as_cwd(const char *arg)
{
    char here[PATH_MAX], there[PATH_MAX], *dir;
    const char *slash = strrchr(arg, '/');
    int same;

    if (!slash)
        return 1;
    dir = xstrdup(arg);
    dir[slash == arg ? 1 : (size_t)(slash - arg)] = '\0';
    same = realpath(".", here) && realpath(dir, there) &&
           strcmp(here, there) == 0;
    free(dir);
    return same;
}

/*
 * Turn command-line arguments into the list of files to checksum.
 *
 * The DOS original gets one unexpanded spec and runs FindFirst/FindNext on
 * it. A Unix shell usually expands wildcards first, so each argument is
 * either an existing file (taken as given, in argument order) or a spec the
 * shell left alone (quoted, or no match), which gets matched DOS-style:
 * case-insensitive, 8.3 names, current directory only. Files the original
 * could never list are skipped with a warning.
 */
static size_t resolve_args(char **args, size_t nargs, hit_t **out_hits)
{
    hit_t *result = NULL;
    size_t nres = 0, cap = 0, a;

    for (a = 0; a < nargs; a++) {
        const char *arg = args[a];
        struct stat st;
        hit_t *hits;
        size_t nh, i, j;

        if (lstat(arg, &st) == 0) {
            const char *base = strrchr(arg, '/');
            char n8[9], e3[4];

            base = base ? base + 1 : arg;
            if (!is_regular(arg)) {
                warn(arg, "not a regular file");
                continue;
            }
            if (!same_dir_as_cwd(arg)) {
                warn(arg, "not in the current directory");
                continue;
            }
            if (!fcb_fields(base, n8, e3)) {
                warn(arg, "not a DOS 8.3 name");
                continue;
            }
            hits = xmalloc(sizeof *hits);
            hits[0].host = xstrdup(arg);
            memcpy(hits[0].name8, n8, sizeof n8);
            memcpy(hits[0].ext3, e3, sizeof e3);
            nh = 1;
        } else {
            char n8[9], e3[4];

            parse_fcb(arg, n8, e3);
            nh = find_files(n8, e3, 0, &hits);
        }

        for (i = 0; i < nh; i++) {
            for (j = 0; j < nres; j++)
                if (!strcmp(result[j].name8, hits[i].name8) &&
                    !strcmp(result[j].ext3, hits[i].ext3))
                    break;
            if (j < nres) {
                free(hits[i].host);
                continue;
            }
            if (nres == cap) {
                hit_t *nr;

                cap = cap ? cap * 2 : 16;
                nr = realloc(result, cap * sizeof *result);
                if (!nr) {
                    fprintf(stderr, "kbpsum: out of memory\n");
                    exit(2);
                }
                result = nr;
            }
            result[nres++] = hits[i];
        }
        free(hits);
    }
    *out_hits = result;
    return nres;
}

/* 0x6B4 */
static int list_abort(void)
{
    if (tee) {
        fputc(0x1A, tee);
        fclose(tee);
        tee = NULL;
        remove(TEMP_NAME);
    }
    out_con(CRLF CRLF "++ABORTED++");
    return 1;
}

static int disk_full(void)
{
    out_con(CRLF "Disk full: CRCKLIST");
    return list_abort();
}

static int make_list(char **args, size_t nargs, int fmode)
{
    hit_t *files;
    size_t n = resolve_args(args, nargs, &files), i;
    int rc = 0;

    out_con(CRLF);
    out_con(BANNER);
    if (fmode) {
        if (!(tee = fopen(TEMP_NAME, "wb"))) {             /* 0x46E */
            out_con(CRLF "Can't make temporary file: CRCKLIST");
            out_con(CRLF CRLF "++ABORTED++");
            free_hits(files, n);
            return 1;
        }
        tee_error = 0;
    }

    for (i = 0; i < n; i++) {
        uint16_t crc;
        int r;

        if (interrupted) {
            rc = list_abort();
            goto done;
        }
        if (!strcmp(files[i].ext3, "$$$") || files[i].name8[0] == '-')
            continue;                                   /* 0x4F1 / 0x4FB */
        outf(CRLF "--> FILE:  %s.%s\t\tCRC = ", files[i].name8,
             files[i].ext3);
        if (tee_error) {
            rc = disk_full();
            goto done;
        }
        r = checksum_file(files[i].host, &crc);
        if (r == SUM_INTERRUPTED) {
            rc = list_abort();
            goto done;
        }
        if (r == SUM_FAILED) {
            out(" ++Open failed++" CRLF);                /* 0x540 */
            rc = list_abort();
            goto done;
        }
        outf("%02X %02X", crc >> 8, crc & 0xFF);
        if (tee_error) {
            rc = disk_full();
            goto done;
        }
    }

    if (tee) {                                          /* 0x4AB */
        out(CRLF);
        if (tee_error || fputc(0x1A, tee) == EOF) {
            rc = disk_full();
            goto done;
        }
        if (fclose(tee) != 0) {
            tee = NULL;
            remove(TEMP_NAME);
            out_con(CRLF "Can't close CRC file");
            out_con(CRLF CRLF "++ABORTED++");
            rc = 1;
            goto done;
        }
        tee = NULL;
        if (rename(TEMP_NAME, LIST_NAME) != 0) {       /* delete + rename */
            perror("kbpsum: " "CRCKLIST.$$$ -> CRCKLIST.CRC");
            rc = 1;
            goto done;
        }
    }
    out_con(CRLF "DONE");
done:
    free_hits(files, n);
    return rc;
}

/*
 * DOS saw 'CRCK *.* F' as exactly two tokens; after shell expansion the F
 * is simply the last argument. Only a standalone 'F' or 'f' counts, and
 * only when at least one file argument comes before it.
 */
int main(int argc, char **argv)
{
    struct sigaction sa;
    size_t nargs = (size_t)(argc - 1);
    int fmode = 0;

    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_sigint;
    sa.sa_flags = SA_RESTART;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);

    if (nargs == 0)
        return verify();
    if (nargs >= 2 && (!strcmp(argv[argc - 1], "F") ||
                       !strcmp(argv[argc - 1], "f"))) {
        fmode = 1;
        nargs--;
    }
    return make_list(argv + 1, nargs, fmode);
}

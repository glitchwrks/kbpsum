#!/usr/bin/env python3
"""kbpsum: the CRCK file checksum utility.

A reimplementation of CRCK 6.71 for MS-DOS (Howard Vigorita, 3/20/86). Output
and the CRCKLIST.CRC / CRCKFILE / -CATALOG file formats are kept byte-for-byte
compatible with the original.

History: Fred Gutman published a bit-serial 8080 CRC routine in EDN
(June 5, 1979, p. 84). Keith B. Petersen, W8SDZ, used it in CRCK for CP/M
(first written 06/27/79) but fed it a whole byte per call with generator
0xA097, which turned the CRC into an add-and-shift hash. CRCK and its
MS-DOS descendants (e.g. CRCK 6.71 by Howard Vigorita, 1986) called the
result a "CRC"; it is not one, hence the name kbpsum, after Petersen.

Usage:
    kbpsum.py FILE...     checksum the named files; shell-expanded wildcards
                          and quoted DOS-style specs ('*.*') both work
    kbpsum.py FILE... F   same, and also write the results to CRCKLIST.CRC
                          (built as CRCKLIST.$$$, then renamed over the old one).
                          F must be the last argument, on its own.
    kbpsum.py             no arguments: find a digest file in the current
                          directory and verify the files it lists

Everything below was derived from a disassembly of CRCK.EXE (LZEXE-unpacked).
Offsets in comments refer to the unpacked code segment.
"""
import os
import sys

# --------------------------------------------------------------------------
# Checksum (0x52B-0x5A0)
# --------------------------------------------------------------------------

def kbpsum(data: bytes) -> int:
    """kbpsum (CRCK) checksum. Not a true CRC: bytes are ADDed into the low byte."""
    if len(data) % 128:                       # pad to a whole CP/M record
        data += b'\0' * (128 - len(data) % 128)
    crc = 0
    for b in data:
        top = crc & 0x8000
        crc = (crc << 1) & 0xFFFF
        crc = (crc & 0xFF00) | ((crc + b) & 0xFF)   # add into low byte, no carry
        if top:
            crc ^= 0xA097
    return crc


# --------------------------------------------------------------------------
# Output helpers: DOS console, CR/LF line ends, 7-bit characters (0x611)
# --------------------------------------------------------------------------

CRLF = '\r\n'
BANNER = ('MSDOS & Concurrent DOS high speed CRC version 6.71, 3/20/86, '
          'Howard Vigorita\r\nCTL-S pauses, CTL-C aborts\r\n\r\n')


TEE = None          # open CRCKLIST.$$$ while in F mode (0x61F)


def out_con(s: str) -> None:
    """Console only (INT 21h/09h strings)."""
    sys.stdout.buffer.write(bytes(ord(c) & 0x7F for c in s))
    sys.stdout.buffer.flush()


def out(s: str) -> None:
    """Character output via 0x611: console, plus the list file in F mode."""
    b = bytes(ord(c) & 0x7F for c in s)
    sys.stdout.buffer.write(b)
    sys.stdout.buffer.flush()
    if TEE is not None:
        TEE.write(b)


def hexbyte(v: int) -> str:                   # 0x5DB
    return '%02X' % v


def dec8(v: int) -> str:                      # 0x740: byte, leading zeros suppressed
    return str(v & 0xFF)


# --------------------------------------------------------------------------
# DOS 8.3 file lookup (FCB name fields + FindFirst)
# --------------------------------------------------------------------------

def fcb_fields(filename: str):
    """Split a host filename into space-padded FCB name/ext, or None if not 8.3."""
    if filename.startswith('.') or filename.count('.') > 1:
        return None
    name, _, ext = filename.partition('.')
    if not (1 <= len(name) <= 8 and len(ext) <= 3):
        return None
    if ' ' in filename:
        return None
    return name.upper().ljust(8), ext.upper().ljust(3)


def expand_star(field: str) -> str:
    """DOS turns '*' into '?' for the rest of the field."""
    i = field.find('*')
    return field if i < 0 else field[:i] + '?' * (len(field) - i)


def field_match(pat: str, name: str) -> bool:
    return all(p == '?' or p == n for p, n in zip(pat, name))


def find_first(name8: str, ext3: str):
    """Return (host filename, name8, ext3) of the first regular file matching an
    FCB-style 8+3 pattern, case-insensitively. DOS returns directory order;
    here the directory is sorted so results are repeatable."""
    pn, pe = expand_star(name8.upper()), expand_star(ext3.upper())
    for f in sorted(os.listdir('.')):
        if not os.path.isfile(f):             # attribute 0: no dirs
            continue
        fields = fcb_fields(f)
        if fields and field_match(pn, fields[0]) and field_match(pe, fields[1]):
            return f, fields[0], fields[1]
    return None


# --------------------------------------------------------------------------
# Digest-file reader (FCB sequential reads, 0xA6 / 0x17A)
# --------------------------------------------------------------------------

class DigestReader:
    def __init__(self, data: bytes):
        # FCB reads come in 128-byte records; DOS zero-fills a partial one.
        if len(data) % 128:
            data += b'\0' * (128 - len(data) % 128)
        self.data = data
        self.pos = 0

    def getc(self) -> int:                    # 0xA6: returns 1Ah forever at EOF
        if self.pos >= len(self.data):
            return 0x1A
        c = self.data[self.pos]
        self.pos += 1
        return c

    def read_line(self):
        """0x17A. Returns the line as bytes, or None at end of file."""
        while True:
            buf = bytearray()
            while True:
                c = self.getc()
                if c == 0x1A:                 # Ctrl-Z (raw, before masking)
                    return bytes(buf) if buf else None
                c &= 0x7F
                if c in (0x0D, 0x0A):
                    break
                buf.append(c)
                if len(buf) >= 80:            # long lines are split at 80
                    break
            if buf:
                return bytes(buf)
            # blank line: skip it


# --------------------------------------------------------------------------
# Line parsers. Each works on the line plus a NUL terminator, with a cursor,
# mirroring the original subroutines (all fail on the NUL, so they never read
# past the end of the line).
# --------------------------------------------------------------------------

class ParseFail(Exception):
    pass


class Cursor:
    def __init__(self, line: bytes):
        self.b = line + b'\0' * 4
        self.p = 0

    def next(self) -> int:
        c = self.b[self.p]
        self.p += 1
        return c

    def digit(self) -> bool:                  # 0x3CD
        return 0x30 <= self.next() <= 0x39

    def whitespace(self) -> bool:             # 0x395: at least one space/tab
        if self.b[self.p] not in (0x20, 0x09):
            return False
        while self.b[self.p] in (0x20, 0x09):
            self.p += 1
        return True

    def filename(self):                       # 0x360: fixed "XXXXXXXX.XXX"
        start = self.p
        if not 0x21 <= self.next() <= 0x7E:
            return None
        for _ in range(7):
            c = self.next()
            if not (0x21 <= c <= 0x7E or c == 0x20):
                return None
        if self.next() != 0x2E:
            return None
        for _ in range(3):
            c = self.next()
            if not (0x21 <= c <= 0x7E or c == 0x20):
                return None
        return start

    def hexdigit(self):                       # 0x412
        c = self.next()
        if c < 0x30:
            return None
        v = c - 0x30
        if v < 10:
            return v
        v = ((v & 0x1F) - 7) & 0xFF
        return v if 10 <= v <= 15 else None

    def hexbyte(self):                        # 0x3F3
        hi = self.hexdigit()
        if hi is None:
            return None
        lo = self.hexdigit()
        if lo is None:
            return None
        return (hi << 4) | lo

    def crc_pair(self):                       # 0x2BD: "HH LL"
        hi = self.hexbyte()
        if hi is None:
            raise ParseFail
        if self.next() != 0x20:
            out('Not a space between CRC values')
            raise ParseFail
        lo = self.hexbyte()
        if lo is None:
            raise ParseFail
        return hi, lo

    def catalog_number(self) -> bool:         # 0x3B0: "NNN" or "NN" before '.'
        if not self.digit():
            return False
        if not self.digit():
            return False
        c = self.next()
        if 0x30 <= c <= 0x39:
            return True
        if c == 0x2E:
            self.p -= 1
            return True
        return False


# --------------------------------------------------------------------------
# Digest verification (no command-line argument)
# --------------------------------------------------------------------------

class Aborted(Exception):
    pass


class Verifier:
    LIST_PREFIX = b'--> FILE:  '
    LIST_CRC = b'\t\tCRC = '

    def __init__(self):
        self.matched = self.mismatched = self.badparse = self.notfound = 0
        self.any_found = False                # 0x348: print the summary
        self.none_checked = True              # 0x317

    # -- 0xF8: locate and open a digest file ------------------------------
    def open_digest(self, name8: str):
        hit = find_first(name8, '???')
        data = None
        if hit:
            try:
                with open(hit[0], 'rb') as fh:
                    data = fh.read()
            except OSError:
                data = None
        if data is None:
            out_con('\tNot found'); out(CRLF)
            return None
        out('\tChecking with file: %s.%s' % (hit[1], hit[2]) + CRLF + CRLF)
        self.matched = self.mismatched = self.badparse = self.notfound = 0
        return DigestReader(data)

    # -- 0x1CC: report an unparseable line -------------------------------
    def bad_line(self, line: bytes):
        out(line.split(b'\0')[0].decode('latin-1'))
        self.badparse += 1
        out(CRLF)

    # -- 0x21B: check one listed file ------------------------------------
    def check(self, cur: Cursor, start: int, hi: int, lo: int):
        raw = cur.b[start:start + 12].decode('latin-1')
        name8, ext3 = raw[:8], raw[9:12]
        out(raw + ' - ')
        hit = find_first(name8, ext3)
        if not hit:
            out(' File not found' + CRLF)
            self.notfound += 1
            return
        self.any_found = True
        try:
            with open(hit[0], 'rb') as fh:
                crc = kbpsum(fh.read())
        except OSError:
            out(' ++Open failed++' + CRLF)
            return
        out(hexbyte(crc >> 8) + ' ' + hexbyte(crc & 0xFF))
        self.none_checked = False
        if (crc >> 8) == hi and (crc & 0xFF) == lo:
            out(' *Match*' + CRLF)
            self.matched += 1
        else:
            out(' <-- is, was --> ' + hexbyte(hi) + ' ' + hexbyte(lo) + CRLF)
            self.mismatched += 1

    # -- 0x17A at EOF ----------------------------------------------------
    def end_of_list(self):
        if self.none_checked:
            out('*No CRC Files found*')
            raise Aborted
        out_con(CRLF + 'DONE')
        self.summary()

    # -- 0x6E6 -----------------------------------------------------------
    def summary(self):
        if not self.any_found:
            return
        out(CRLF + 'Quantity of file CRC that matched - ' + dec8(self.matched))
        if self.mismatched & 0xFF:
            out(CRLF + 'Quantity of file CRC that did not match - '
                + dec8(self.mismatched))
        if self.badparse & 0xFF:
            out(CRLF + 'Quantity of lines failed parse test - '
                + dec8(self.badparse))
        if self.notfound & 0xFF:
            out(CRLF + 'Quantity of file(s) not found - ' + dec8(self.notfound))

    # -- 0x6F: CRCKLIST / CRCKFILE format --------------------------------
    def run_list(self, rd: DigestReader):
        while True:
            line = rd.read_line()
            if line is None:
                return self.end_of_list()
            cur = Cursor(line)
            try:
                if cur.b[:11] != self.LIST_PREFIX:
                    raise ParseFail
                cur.p = 11
                start = cur.filename()
                if start is None:
                    raise ParseFail
                if cur.b[cur.p:cur.p + 8] != self.LIST_CRC:
                    raise ParseFail
                cur.p += 8
                hi, lo = cur.crc_pair()
            except ParseFail:
                self.bad_line(line)
                continue
            self.check(cur, start, hi, lo)

    # -- 0x2FF: -CATALOG format ------------------------------------------
    def run_catalog(self, rd: DigestReader):
        while True:
            line = rd.read_line()
            if line is None:
                return self.end_of_list()
            cur = Cursor(line)
            try:
                # Leading part: failures here are silent until a file has
                # been checked (header lines of a catalog listing).
                early = True
                if not cur.catalog_number() or cur.b[cur.p] != 0x2E:
                    raise ParseFail
                cur.p += 1
                if not cur.catalog_number():   # optional second number
                    cur.p -= 1
                if not cur.whitespace():
                    raise ParseFail
                start = cur.filename()
                if start is None:
                    raise ParseFail
                early = False
                if not cur.whitespace():
                    raise ParseFail
                if not cur.digit():            # size in K
                    raise ParseFail
                while True:
                    c = cur.next()
                    if not 0x30 <= c <= 0x39:
                        break
                if c != ord('K'):
                    raise ParseFail
                if not cur.whitespace():
                    raise ParseFail
                hi, lo = cur.crc_pair()
            except ParseFail:
                if early and self.none_checked:
                    continue
                self.bad_line(line)
                continue
            self.check(cur, start, hi, lo)

    def run(self):
        out(CRLF + BANNER)
        try:
            try:
                out('Searching for "CRCKLIST" file    ')
                rd = self.open_digest('CRCKLIST')
                if rd is None:
                    out('Now searching for "CRCKFILE" file')
                    rd = self.open_digest('CRCKFILE')
                if rd is not None:
                    return self.run_list(rd)
                out('Now searching for "-CATALOG" file')
                rd = self.open_digest('-CATALOG')
                if rd is None:
                    raise Aborted
                return self.run_catalog(rd)
            except KeyboardInterrupt:          # Ctrl-C handler at 0x6B4
                raise Aborted
        except Aborted:
            out_con(CRLF + CRLF + '++ABORTED++')
            self.summary()


# --------------------------------------------------------------------------
# Checksum files matching a spec, optionally writing CRCKLIST.CRC (0x433)
# --------------------------------------------------------------------------

TEMP_NAME = 'CRCKLIST.$$$'
LIST_NAME = 'CRCKLIST.CRC'


def parse_fcb(arg: str):
    """Rough equivalent of the DOS FCB parse of a command-line argument:
    optional drive (ignored here), 8.3 fields, upper case, '*' -> '?'."""
    if len(arg) >= 2 and arg[1] == ':':
        arg = arg[2:]
    name, _, ext = arg.upper().partition('.')
    name = expand_star(name[:8].ljust(8))
    ext = expand_star(ext[:3].ljust(3))
    return name, ext


def find_all(name8: str, ext3: str):
    """FindFirst/FindNext over the current directory (sorted)."""
    pn, pe = expand_star(name8), expand_star(ext3)
    for f in sorted(os.listdir('.')):
        if not os.path.isfile(f):
            continue
        fields = fcb_fields(f)
        if fields and field_match(pn, fields[0]) and field_match(pe, fields[1]):
            yield f, fields[0], fields[1]


def warn(msg: str) -> None:
    sys.stderr.write('kbpsum: %s\n' % msg)


def resolve_args(args):
    """Turn command-line arguments into the list of files to checksum.

    The DOS original gets one unexpanded spec and runs FindFirst/FindNext on
    it. A Unix shell usually expands wildcards first, so each argument is
    either an existing file (taken as given, in argument order) or a spec the
    shell left alone (quoted, or no match), which gets matched DOS-style:
    case-insensitive, 8.3 names, current directory only.
    Files the original could never list are skipped with a warning."""
    here = os.path.realpath('.')
    seen, result = set(), []
    for arg in args:
        if os.path.lexists(arg):
            if not os.path.isfile(arg):
                warn('%s: not a regular file, skipped' % arg)
                continue
            if os.path.realpath(os.path.dirname(arg) or '.') != here:
                warn('%s: not in the current directory, skipped' % arg)
                continue
            fields = fcb_fields(os.path.basename(arg))
            if fields is None:
                warn('%s: not a DOS 8.3 name, skipped' % arg)
                continue
            hits = [(arg, fields[0], fields[1])]
        else:
            hits = list(find_all(*parse_fcb(arg)))
        for host, name8, ext3 in hits:
            if (name8, ext3) not in seen:
                seen.add((name8, ext3))
                result.append((host, name8, ext3))
    return result


def split_args(argv):
    """Separate the trailing F option from the file arguments.

    DOS saw 'CRCK *.* F' as exactly two tokens; after shell expansion the F
    is simply the last argument. Only a standalone 'F' or 'f' counts, and
    only when at least one file argument comes before it."""
    if len(argv) >= 2 and argv[-1] in ('F', 'f'):
        return argv[:-1], True
    return argv, False


def make_list(args, fmode: bool) -> int:
    global TEE
    files = resolve_args(args)
    out_con(CRLF + BANNER)
    if fmode:
        try:
            TEE = open(TEMP_NAME, 'wb')                    # 0x46E
        except OSError:
            out_con(CRLF + "Can't make temporary file: CRCKLIST")
            out_con(CRLF + CRLF + '++ABORTED++')
            return 1

    def abort():                                           # 0x6B4
        global TEE
        if TEE is not None:
            TEE.write(b'\x1a')
            TEE.close()
            TEE = None
            try:
                os.remove(TEMP_NAME)
            except OSError:
                pass
        out_con(CRLF + CRLF + '++ABORTED++')
        return 1

    try:
        for host, name8, ext3 in files:
            if ext3 == '$$$' or name8.startswith('-'):     # 0x4F1 / 0x4FB
                continue
            out(CRLF + '--> FILE:  %s.%s\t\tCRC = ' % (name8, ext3))
            try:
                with open(host, 'rb') as fh:
                    crc = kbpsum(fh.read())
            except OSError:
                out(' ++Open failed++' + CRLF)             # 0x540
                return abort()
            out(hexbyte(crc >> 8) + ' ' + hexbyte(crc & 0xFF))
    except KeyboardInterrupt:
        return abort()
    except OSError:                                        # write error
        out_con(CRLF + 'Disk full: CRCKLIST')
        return abort()

    if TEE is not None:                                    # 0x4AB
        out(CRLF)
        TEE.write(b'\x1a')
        TEE.close()
        TEE = None
        os.replace(TEMP_NAME, LIST_NAME)                   # delete + rename
    out_con(CRLF + 'DONE')
    return 0


def main(argv):
    if not argv:
        Verifier().run()
        return 0
    files, fmode = split_args(argv)
    return make_list(files, fmode)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

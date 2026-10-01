#!/usr/bin/env python3
"""Differential test: run kbpsum.py and the C kbpsum side by side in identical
directories and compare stdout (byte for byte), stderr, exit status and the
resulting directory contents.

    python3 difftest.py PATH/TO/kbpsum.py PATH/TO/kbpsum [FUZZ_CASES]
"""
import os
import random
import shutil
import subprocess
import sys
import tempfile

PY, C = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
FUZZ = int(sys.argv[3]) if len(sys.argv) > 3 else 400


def kbpsum(data):
    if len(data) % 128:
        data += b'\0' * (128 - len(data) % 128)
    crc = 0
    for b in data:
        top = crc & 0x8000
        crc = (crc << 1) & 0xFFFF
        crc = (crc & 0xFF00) | ((crc + b) & 0xFF)
        if top:
            crc ^= 0xA097
    return crc


def snapshot(d):
    return {f: (open(os.path.join(d, f), 'rb').read()
                if os.path.isfile(os.path.join(d, f)) else 'DIR')
            for f in os.listdir(d)}


def run(cmd, d, args):
    p = subprocess.run(cmd + args, cwd=d, capture_output=True, timeout=60)
    return p.stdout, p.stderr, p.returncode, snapshot(d)


failures = 0


def compare(name, files, args, shell_glob=None):
    """files: {name: bytes or None for a directory}"""
    global failures
    results = []
    for cmd in (['python3', PY], [C]):
        d = tempfile.mkdtemp()
        try:
            for f, content in files.items():
                path = os.path.join(d, f)
                if content is None:
                    os.makedirs(path)
                else:
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    open(path, 'wb').write(content)
            a = list(args)
            if shell_glob is not None:          # emulate shell expansion
                a = sorted(os.listdir(d)) + a if shell_glob == '*' else a
            results.append(run(cmd, d, a))
        finally:
            shutil.rmtree(d)
    if results[0] != results[1]:
        failures += 1
        print('MISMATCH:', name, args)
        for label, a, b in zip(('stdout', 'stderr', 'status', 'files'),
                               results[0], results[1]):
            if a != b:
                print('  %s\n    py: %r\n    c:  %r' % (label, a, b))


# ---------------------------------------------------------------- fixtures
rnd = random.Random(1986)
HELLO = b'hello world\n' * 50
DATA = bytes(range(256)) * 3
BASE = {'HELLO.TXT': HELLO, 'data.bin': DATA, 'FOO.TXT': b'q\n',
        '-CATALOG.LST': b'x\n', 'JUNK.$$$': b'y\n',
        'long_filename.text': b'z\n', 'SUBDIR': None, 'SUBDIR/SUB.TXT': b's'}


def ent(n, e, c):
    return b'--> FILE:  %-8s.%-3s\t\tCRC = %02X %02X\r\n' % (
        n.encode(), e.encode(), c >> 8, c & 255)


# ------------------------------------------------------- fixed scenarios
compare('no digest', dict(BASE), [])
compare('list: match/mismatch/missing/wildcard/bad',
        dict(BASE, **{'CRCKLIST.CRC':
             ent('HELLO', 'TXT', kbpsum(HELLO)) +
             ent('DATA', 'BIN', 0x1234).replace(b'12 34', b'ab cd') +
             ent('GONE', 'DOC', 0) + ent('HEL?O', '*', kbpsum(HELLO)) +
             b'junk line here\r\n\r\n' +
             b'--> FILE:  HELLO   .TXT\t\tCRC = 12-34\r\n\x1a'}), [])
compare('crckfile, no ^Z', dict(BASE, CRCKFILE=ent('HELLO', 'TXT',
                                                    kbpsum(HELLO))), [])
compare('catalog', dict(BASE, **{'-CATALOG.LST':
        b'Catalog\r\n No. Name\r\n001. HELLO   .TXT   1K  %02X %02X\r\n'
        b'02.3. DATA    .BIN 12K 03 EE\r\n12.34 DATA    .BIN 3K 03 ee\r\n'
        b'footer\r\n\x1a' % (kbpsum(HELLO) >> 8, kbpsum(HELLO) & 255)}), [])
compare('list: nothing checked', dict(BASE, **{'CRCKLIST.CRC':
        ent('GONE', 'DOC', 0) + b'\x1a'}), [])
compare('list: 300 entries (8-bit counters)', dict(BASE, **{
        'CRCKLIST.CRC': ent('HELLO', 'TXT', kbpsum(HELLO)) * 300 +
        ent('HELLO', 'TXT', 1) * 260 + b'\x1a'}), [])
for args in (['*.*', 'F'], ['*', 'f'], ['HELLO.TXT', 'FOO.TXT'],
             ['*.TXT', 'F'], ['*.xyz', 'data.bin', 'F'],
             ['SUBDIR/SUB.TXT', 'F'], ['HELLO.TXT', 'HELLO.TXT', 'hello.txt',
                                       'F'], ['F'], ['nothing', 'F'],
             ['./HELLO.TXT', 'F'], ['c:*.TXT'], ['*.*']):
    compare('args', dict(BASE), args)
compare('shell-expanded *', dict(BASE), ['F'], shell_glob='*')
compare('F with old list present', dict(BASE, **{'CRCKLIST.CRC': b'old'}),
        ['*.*', 'F'])


# ---------------------------------------------------------------- fuzzing
NAMES = [('HELLO', 'TXT'), ('DATA', 'BIN'), ('FOO', 'TXT'), ('GONE', 'DOC'),
         ('HEL?O', '*'), ('*', 'TXT'), ('hello', 'txt'), ('-CATALOG', 'LST')]


def fuzz_line(catalog):
    n, e = rnd.choice(NAMES)
    c = rnd.choice([kbpsum(HELLO), kbpsum(DATA), kbpsum(b'q\n'), rnd.randrange(65536)])
    hh = '%02X %02X' % (c >> 8, c & 255)
    if rnd.random() < 0.2:
        hh = hh.lower()
    if catalog:
        num = rnd.choice(['001.', '01.', '1.', '12.34', '001.002', '01.2.', 'ab.'])
        line = '%s%s%-8s.%-3s%s%dK%s%s' % (
            num, rnd.choice([' ', '\t', '  ', '']), n, e,
            rnd.choice([' ', '\t\t', '']), rnd.randrange(200),
            rnd.choice([' ', '  ', '']), hh)
    else:
        line = '--> FILE:  %-8s.%-3s\t\tCRC = %s' % (n, e, hh)
    line = line.encode()
    r = rnd.random()
    if r < 0.15:                                   # mutate one byte
        i = rnd.randrange(len(line))
        line = line[:i] + bytes([rnd.randrange(256)]) + line[i + 1:]
    elif r < 0.2:
        line = line.replace(b' ', b'-', 1)
    elif r < 0.25:
        line += b' trailing junk'
    elif r < 0.3:
        line = bytes(rnd.randrange(256) for _ in range(rnd.randrange(1, 120)))
    elif r < 0.33:
        line = line * 3                            # > 80 chars
    return line + rnd.choice([b'\r\n', b'\n', b'\r', b'\r\n\r\n'])


for i in range(FUZZ):
    kind = rnd.choice(['CRCKLIST.CRC', 'CRCKFILE', '-CATALOG.LST',
                       'crcklist.x'])
    catalog = kind.startswith('-')
    body = b''.join(fuzz_line(catalog) for _ in range(rnd.randrange(1, 12)))
    if catalog and rnd.random() < 0.7:
        body = b'Header line\r\n' + body
    if rnd.random() < 0.6:
        body += b'\x1a' + bytes(rnd.randrange(256) for _ in range(rnd.randrange(20)))
    files = dict(BASE)
    files.pop('-CATALOG.LST')
    files[kind] = body
    compare('fuzz %d (%s)' % (i, kind), files, [])

print('%s: %d mismatch(es)' % ('FAIL' if failures else 'PASS', failures))
sys.exit(1 if failures else 0)

# Forensic Recovery v1.0.1 (`frecover`)

<div align="center">

[![License](https://img.shields.io/badge/License-MIT-teal?style=flat-square&labelColor=1a1a1a)](https://github.com/effjy/frecover/)
[![Language](https://img.shields.io/badge/Language-C%2B%2B-teal?style=flat-square&labelColor=1a1a1a)](https://github.com/effjy/frecover/)
[![Platform](https://img.shields.io/badge/Platform-Linux-8a2be2?style=flat-square&labelColor=1a1a1a)](https://github.com/effjy/frecover/)
[![Filesystem](https://img.shields.io/badge/Filesystem-ext2%2F3%2F4-teal?style=flat-square&labelColor=1a1a1a)](https://github.com/effjy/frecover/)
[![Mode](https://img.shields.io/badge/Mode-Read--only-8a2be2?style=flat-square&labelColor=1a1a1a)](https://github.com/effjy/frecover/)
[![Dependencies](https://img.shields.io/badge/Dependencies-debugfs%20%C2%B7%20file-teal?style=flat-square&labelColor=1a1a1a)](https://github.com/effjy/frecover/)

</div>

A small, **read-only** deleted-file inspector and recoverer for **ext2/3/4**
filesystems. It is a thin, safe orchestrator around `debugfs` that reproduces a
manual recovery workflow in three steps:

1. **scan** — list deleted inodes (`debugfs lsdel`)
2. **check** — assess whether an inode is still recoverable (`debugfs stat`)
3. **recover** — dump the file out and identify what it is (`debugfs dump` + type sniff)

Because inode-based undelete **does not work on ext4** (the block map is zeroed
on delete), it also provides **`carve`** — content/signature recovery that
ignores metadata and finds file data still sitting in free blocks. This is the
method that actually recovers freshly-deleted ext4 files. See
[Carving](#carving-carve--the-ext4-answer).

It also adds the usual recovery-suite conveniences — `info` (filesystem
summary), `preview` (read-only hex peek with no output file), SHA-256
chain-of-custody hashing of recovered files, and `report` (JSON output). See
[Recovery-suite features](#recovery-suite-features).

It never unmounts anything and never writes to the source device.

---

## Quick start

From a clone/copy of this directory:

```bash
# 1. Install prerequisites (Debian/Ubuntu)
sudo apt update
sudo apt install -y g++ e2fsprogs file util-linux

# 2. Compile
cd ~/work/forensic_recovery
make

# 3. Install globally (optional; otherwise run ./frecover in place)
sudo make install            # -> /usr/local/bin/frecover

# 4. Use it (root required for raw device reads)
DEV=$(findmnt -T ~/work -no SOURCE)   # the block device backing your data
sudo frecover scan "$DEV"             # list deleted inodes
```

To remove it later: `sudo make uninstall`.

Each step is expanded in the sections below
([Prerequisites](#prerequisites), [Compile](#compile),
[Install / uninstall globally](#install--uninstall-globally), [Usage](#usage)).

---

## Safety model

`frecover` is built so that inspecting a **live, mounted** filesystem is safe:

- **Source is always opened read-only.** `debugfs` is invoked *without* the `-w`
  flag, so it physically cannot modify the source device.
- **Recovery cannot cannibalize the source.** `recover`/`auto` refuse to write
  into a destination that lives on the **same filesystem** as the source device,
  so a recovery can never overwrite the free blocks that still hold other
  recoverable data. Use a separate disk, a USB stick, or a small recovery to a
  tmpfs such as `/dev/shm`.
- **Won't exhaust the destination.** If the expected size is known, recovery
  refuses a destination without enough free space — important when recovering to
  a RAM-backed tmpfs like `/dev/shm`, where a large file could otherwise pressure
  memory. Large recoveries should target a real disk.
- **Whitespace-free destinations only.** `debugfs` tokenizes its own command
  string on whitespace, so a `<dest-dir>` containing spaces/tabs is rejected.
- **No unmount required.** All operations are observational reads of the block
  device.

> ### Important caveat: "recoverable" ≠ "original bytes intact"
> On **ext4**, deleting a file often leaves the inode's data-block pointers
> (`EXTENTS`) in place, so `check` can report `RECOVERABLE`. But those blocks
> sit in free space and may already have been **overwritten** by newer data —
> especially on a full, actively-written volume. In that case `recover` will
> still produce a file, but its contents will be whatever now occupies those
> blocks (often high-entropy garbage), **not** your original data. Inode
> (metadata) survival and content survival are two different things.
>
> The sooner you inspect after a deletion, the better your odds. If the data
> truly matters, stop writing to the volume immediately.

---

## Prerequisites

| Requirement | Why | Install (Debian/Ubuntu) |
|-------------|-----|--------------------------|
| `g++` (C++11+) | compile the tool | `sudo apt install g++` |
| `e2fsprogs` (provides `debugfs`) | underlying read engine | `sudo apt install e2fsprogs` |
| `file` *(optional)* | richer file-type description | `sudo apt install file` |
| `util-linux` (provides `findmnt`) | same-filesystem safety guard | usually preinstalled |
| **root / sudo** | raw read access to the block device | — |
| An **ext2/3/4** filesystem | the only supported formats | — |

Install everything at once:

```bash
sudo apt update
sudo apt install -y g++ e2fsprogs file util-linux
```

> `file` is optional — the tool has a built-in magic-byte sniffer and will fall
> back to it. `findmnt` is only used to enforce the same-filesystem guard; if it
> is missing the guard is skipped with a warning.

---

## Compile

From the project directory, using the Makefile:

```bash
cd ~/work/forensic_recovery
make                       # produces ./frecover
```

Or compile directly:

```bash
g++ -O2 -Wall -Wextra -std=c++17 -o frecover frecover.cpp
```

Override the toolchain/flags if you like: `make CXX=clang++ CXXFLAGS='-O3'`.

## Install / uninstall globally

```bash
sudo make install          # -> /usr/local/bin/frecover
frecover                   # verify (prints usage)
sudo make uninstall        # remove it again
```

Change the location with `PREFIX` (e.g. `sudo make install PREFIX=/usr` ->
`/usr/bin/frecover`). `DESTDIR` is honored for staged/packaged installs:
`make install DESTDIR=/tmp/stage`.

`make clean` removes the local build, and `make help` lists every target.

---

## Finding your device

`frecover` operates on a **block device** (or LVM logical volume), not a mount
point. To find the device that backs a given path:

```bash
findmnt -T ~/work -o SOURCE,FSTYPE
# SOURCE                            FSTYPE
# /dev/mapper/ubuntu--vg-ubuntu--lv ext4
```

Use that `SOURCE` value as `<device>` below.

---

## Usage

```
frecover scan    <device>                  # list deleted inodes
frecover check   <device> <inode>          # assess recoverability of one inode
frecover recover <device> <inode> <dest-dir>   # dump + identify + hash
frecover auto    <device> <dest-dir>       # recover every recoverable inode
frecover info    <device>                  # filesystem summary
frecover preview <device> <inode> [bytes]  # read-only hex peek (writes nothing)
frecover report  <device>                  # JSON of scan + verdicts
frecover carve   <device> <dest> [opts]    # content/signature recovery (works on ext4!)
```

`carve` options: `--string <s>` (recover blocks containing a literal string),
`--types <list>` (comma list of `png,jpeg,gif,pdf,zip,gzip` or `all`; unknown
values are rejected), `--max-bytes <N>` (bound how much of the device is
scanned), `--block <N>` (block size for string mode, default 4096),
`--align <N>` (signature headers must start on an `N`-byte boundary, default
4096; use `--align 1` to match at every offset).

- `<device>`   — block device / LVM volume, e.g. `/dev/mapper/ubuntu--vg-ubuntu--lv`
- `<inode>`    — an inode number reported by `scan`
- `<dest-dir>` — an **existing directory on a DIFFERENT filesystem** than `<device>`
- `[bytes]`    — optional preview length (default 256)

Run all commands with `sudo` (raw device read access is required).

---

## Examples

### 1. Scan for deleted inodes

```bash
sudo frecover scan /dev/mapper/ubuntu--vg-ubuntu--lv
```

```
Forensic Recovery v1.0.1 - scan of /dev/mapper/ubuntu--vg-ubuntu--lv
INODE        OWNER   MODE     SIZE         DELETED
5908141      1000    40755    4096         Tue Jun 16 16:42:35 2026
12073554     102     100640   8662         Tue Jun 16 16:42:35 2026
-> 2 deleted inode(s) found.
```

- `MODE` is octal: values starting `40` are **directories** (e.g. `40755`),
  values starting `100` are **regular files** (e.g. `100640`).
- `OWNER` is the UID that owned the file.

### 2. Check whether an inode is recoverable

```bash
sudo frecover check /dev/mapper/ubuntu--vg-ubuntu--lv 12073554
```

```
... (full debugfs stat output) ...
EXTENTS:
(0):24231050, (1):29437698, (2):29831497

VERDICT: RECOVERABLE
REASON : data block pointers (EXTENTS) survive and Blockcount > 0
```

Exit status: `0` if recoverable, `1` if not. Possible reasons for *not*
recoverable include "Blockcount is 0" (no data) or "no EXTENTS listed" (ext4
zeroed the pointers — only carving might help).

### 3. Recover a file and identify its type

Recover to a tmpfs (separate filesystem) so the source free space is untouched:

```bash
sudo frecover recover /dev/mapper/ubuntu--vg-ubuntu--lv 12073554 /dev/shm
```

```
Recovered inode 12073554 -> /dev/shm/recovered_inode_12073554 (8662 bytes)
  SHA-256  : c17b01d39a9e4ea64bb6e427c5c5796d7721b84092f607c0fb3ec4736e7232a2
  Magic    : image/png
  file(1)  : PNG image data, 1024 x 768, 8-bit/color RGBA, non-interlaced
  Entropy  : 7.21 bits/byte
  CONTENT  : appears INTACT (recognized file structure).
```

The **SHA-256** line is a hash of the recovered bytes for chain-of-custody (see
[Recovery-suite features](#recovery-suite-features)); the **Magic** line is the
built-in sniffer (png/jpeg/gif/webp/bmp/pdf/gzip/zip/ELF/xz/bzip2/text/…); the
**file(1)** line is the authoritative description from the `file` command when
available; the **Entropy**/**CONTENT** lines are the content-survival check (see
[Content verdict](#content-verdict-recoverable-vs-intact)).

Where the blocks have already been reused, the same command instead reports the
content as overwritten:

```
Recovered inode 12073554 -> /dev/shm/recovered_inode_12073554 (8662 bytes)
  Magic    : application/octet-stream (binary data)
  file(1)  : data
  Entropy  : 7.97 bits/byte
  CONTENT  : LIKELY OVERWRITTEN or encrypted/compressed - near-random bytes, no recognizable structure.
```

The **same-filesystem guard** in action (recovering onto the source is refused):

```bash
sudo frecover recover /dev/mapper/ubuntu--vg-ubuntu--lv 12073554 /home/user/work
```

```
REFUSING: destination '/home/user/work' is on the SAME filesystem as the source.
Recovering there could overwrite still-recoverable free blocks.
Choose a dest on another disk/USB or a tmpfs (e.g. /dev/shm).
```

### 4. Recover a deleted directory

Directory inodes are dumped as their raw directory block; run `strings` to read
the entry names that were inside:

```bash
sudo frecover recover /dev/mapper/ubuntu--vg-ubuntu--lv 5908141 /dev/shm
strings /dev/shm/recovered_inode_5908141_dir.raw
```

### 5. Recover everything recoverable in one pass

```bash
sudo frecover auto /dev/mapper/ubuntu--vg-ubuntu--lv /dev/shm
```

```
Forensic Recovery v1.0.1 - auto: 2 deleted inode(s) on /dev/mapper/ubuntu--vg-ubuntu--lv

inode 5908141   owner=1000  mode=40755   size=4096     : RECOVERABLE
Recovered inode 5908141 -> /dev/shm/recovered_inode_5908141_dir.raw (4096 bytes)
  Type     : DIRECTORY (raw directory block - contains the filenames it held)
  Entropy  : 7.95 bits/byte
  CONTENT  : LIKELY OVERWRITTEN - directory block is near-random, not valid dir entries.

inode 12073554  owner=102   mode=100640  size=8662     : RECOVERABLE
Recovered inode 12073554 -> /dev/shm/recovered_inode_12073554 (8662 bytes)
  Magic    : application/octet-stream (binary data)
  file(1)  : data
  Entropy  : 7.97 bits/byte
  CONTENT  : LIKELY OVERWRITTEN or encrypted/compressed - near-random bytes, no recognizable structure.

-> recovered 2 file(s) into /dev/shm
```

> The example above is the real result on a week-old deletion on a near-full,
> active volume: the inodes are `RECOVERABLE` (metadata survived) but the
> `CONTENT` check shows the blocks were reused — exactly the metadata-vs-content
> distinction the entropy check exists to surface.

---

## Recovery-suite features

Beyond the core scan → check → recover flow, `frecover` includes the kind of
helpers a recovery/forensics suite is expected to have. All are **read-only**.

### Filesystem info (`info`)

Summarize the target filesystem before you dig in — type, state, block size, and
how full it is (a fuller volume means a shorter recovery window):

```bash
sudo frecover info /dev/mapper/ubuntu--vg-ubuntu--lv
```

```
Forensic Recovery v1.0.1 - filesystem info: /dev/mapper/ubuntu--vg-ubuntu--lv

  Filesystem volume name:   <none>
  Last mounted on:          /
  Filesystem UUID:          d102c5a4-cabd-4917-a2dc-2630f13dfe3c
  Filesystem state:         clean
  Inode count:              31055872
  Block count:              124222464
  Free blocks:              18415903
  Block size:               4096
  Last mount time:          Tue Jun 23 12:02:05 2026
  Lifetime writes:          47 TB
```

### Preview (`preview`) — triage without writing anything

Peek at the first bytes of a deleted inode as a hex + ASCII dump, straight to
your terminal. **No recovery file is written** — ideal for deciding whether an
inode is worth recovering. Default is 256 bytes; pass a length to change it:

```bash
sudo frecover preview /dev/mapper/ubuntu--vg-ubuntu--lv 12073554 96
```

```
Forensic Recovery v1.0.1 - preview inode 12073554 on /dev/... (first 96 bytes)

Type guess (file): data

00000000  c8 90 43 76 13 9d b2 ac  fc 9a 02 c0 03 40 7a a0  |..Cv.........@z.|
00000010  3b 48 5e fa 05 0b 55 e4  53 5e 9e 2e 6e 99 d5 c8  |;H^...U.S^..n...|
...
```

### Chain-of-custody hashing (SHA-256)

Every successful `recover`/`auto` prints a `SHA-256` of the recovered bytes (see
the recover example above). Capture it alongside your notes; you can re-verify
the file any time with `sha256sum <recovered-file>`.

### Machine-readable report (`report`)

Emit the full scan + recoverability verdict as JSON, for piping into other tools
or archiving as evidence:

```bash
sudo frecover report /dev/mapper/ubuntu--vg-ubuntu--lv > report.json
# filter to only recoverable inodes:
sudo frecover report /dev/mapper/ubuntu--vg-ubuntu--lv | jq '.inodes[] | select(.recoverable)'
```

```json
{
  "tool": "frecover",
  "version": "1.0.1",
  "device": "/dev/mapper/ubuntu--vg-ubuntu--lv",
  "deleted_inode_count": 2,
  "inodes": [
    {
      "inode": 12073554,
      "owner_uid": 102,
      "mode": "100640",
      "is_directory": false,
      "size": 8662,
      "deleted": "Tue Jun 16 16:42:35 2026",
      "recoverable": true,
      "reason": "data block pointers (EXTENTS/BLOCKS) survive and Blockcount > 0"
    }
  ]
}
```

---

## Carving (`carve`) — the ext4 answer

**Why this exists.** When you delete a file on **ext4**, the kernel zeroes the
inode's block map. That means `debugfs lsdel` — and therefore `scan`/`check`/
`recover` — finds **nothing** for normal ext4 deletions. (Verified: deleting 100
files and scanning returns `0 deleted inode(s)`.) The *file content*, however, is
still in the now-free blocks until it gets overwritten. `carve` recovers that
content directly, ignoring metadata entirely. It's the method that actually works
for fresh ext4 deletions.

`carve` is **read-only on the source** and writes only to `<dest>` (same guards
as `recover`: different filesystem, no whitespace).

### String mode — recover blocks containing known text

Best when you know something that was *inside* the file:

```bash
sudo frecover carve /dev/mapper/ubuntu--vg-ubuntu--lv /mnt/usb/out --string "HELLO WORLD"
```

```
Forensic Recovery v1.0.1 - carve /dev/mapper/ubuntu--vg-ubuntu--lv
  device size : 0.06 GiB
  mode        : string match "HELLO WORLD" (block=4096)

  match @ 8458240 -> /mnt/usb/out/carved_8458240.bin (4096 bytes)
  match @ 8462336 -> /mnt/usb/out/carved_8462336.bin (4096 bytes)
  ...
-> carved 100 file(s) into /mnt/usb/out
```

Each hit carves the 4096-byte block (tune with `--block`) containing the match.
This is exactly how the 100 deleted `HELLO WORLD` `.txt` files are recovered.

### Signature mode — carve by file type

With no `--string`, `carve` scans for file **headers** and extracts each file up
to its footer (or a per-type size cap). Built-in types: **png, jpeg, gif, pdf,
zip, gzip**.

```bash
sudo frecover carve /dev/mapper/ubuntu--vg-ubuntu--lv /mnt/usb/out --types png,jpeg,pdf
```

```
  mode        : signature carving (3 types)

  png  @ 8867840 -> /mnt/usb/out/carved_8867840.png (50 bytes)
-> carved 1 file(s) into /mnt/usb/out
```

### Bounding the scan

Carving reads the device sequentially. On a big disk that's a lot of (read-only)
I/O, so bound it when you can:

```bash
# only scan the first 2 GiB, only look for PNGs
sudo frecover carve "$DEV" /mnt/usb/out --types png --max-bytes 2147483648
```

### False-positive control

Short magic numbers (e.g. JPEG's 3-byte `FF D8 FF`) match by chance constantly
on a large disk. `carve` keeps that under control two ways:

- **Block alignment** (`--align`, default 4096): real files begin on a
  filesystem block boundary, so only aligned offsets are considered — removing
  the overwhelming majority of chance matches. Loosen with `--align 1` if you
  suspect non-aligned data (much slower, far noisier).
- **Header validation**: beyond the magic, each candidate is sanity-checked
  (e.g. JPEG's first marker, `GIF87a/89a`, `%PDF-<version>`, gzip's flag/method
  bytes) before anything is carved.

A **destination free-space guard** also refuses any single carve that wouldn't
fit (with a 1 MiB margin), so a bad match or a huge file can't fill `<dest>`.

### Output: manifest & ownership

Carved files are named `carved_<offset>.<ext>`, which says nothing about what
they are. So `carve` writes a **`carve_manifest.csv`** in `<dest>` — one row per
file with its source **offset**, **size**, **type** (`file -b`), **SHA-256**, and
filename:

```csv
offset,size,type,sha256,filename
154140672,418025,"PDF document, version 1.4, 69 page(s)",2613f843…,carved_154140672.pdf
355373056,257,"PNG image data, 16 x 16, 8-bit/color RGBA",c527f466…,carved_355373056.png
```

This gives you triage at a glance, plus dedup (identical SHA-256 = the same data
carved twice) and chain-of-custody hashing. Open it in any spreadsheet/CSV tool.

When run via `sudo`, carved files **and** the manifest are handed back to the
invoking user (`$SUDO_USER`), so you can inspect them without `sudo`. The same
applies to files from `recover`/`auto`. Ownership is just convenience — integrity
is anchored by the SHA-256 hashes, not by who owns the file.

### Notes & limits

- Files must be **contiguous and not yet overwritten** to carve cleanly
  (fragmented files may come back partial — true of all carvers).
- Headerless/footerless formats (e.g. plain text without a known string) can't be
  signature-carved; use `--string` for those.
- For exhaustive, fragment-aware carving of many formats, a dedicated tool like
  `photorec` is still the heavyweight option; `carve` covers the common cases
  built-in, with no extra dependencies.

---

## Content verdict (recoverable vs. intact)

`recover`/`auto` add a **content-survival check** on top of the inode verdict,
because (as the caveat above explains) a `RECOVERABLE` inode does **not**
guarantee the original bytes are still on disk. After dumping, the tool measures
the **Shannon entropy** of the recovered bytes and combines it with the magic
sniffer:

| Situation | `CONTENT` verdict |
|-----------|-------------------|
| Magic sniffer recognized a concrete type (png, pdf, zip, ELF, text, …) | `appears INTACT (recognized file structure)` |
| No recognized structure **and** entropy > 7.5 bits/byte | `LIKELY OVERWRITTEN or encrypted/compressed` |
| No recognized structure **and** entropy < 5.0 bits/byte | `plausibly intact - structured/text-like data` |
| Otherwise | `uncertain - inspect manually` |
| Directory block, entropy > 6.5 | `LIKELY OVERWRITTEN - not valid dir entries` |

**How to read it:** entropy near **8.0 bits/byte** means near-random data. For an
unidentifiable payload that almost always means the free blocks were **reused**
since deletion. Note the deliberate exception — **recognized** types short-circuit
the warning, because legitimately compressed/encrypted files (gzip, zip, xz, …)
are *also* near-8.0 but are real content. Treat the verdict as a strong hint, not
proof; when it says `uncertain`, look at the bytes yourself.

## How it works internally

| Step | What `frecover` runs | Notes |
|------|----------------------|-------|
| scan | `debugfs -R 'lsdel' <dev>` | parses the inode table for deleted entries |
| check | `debugfs -R 'stat <N>' <dev>` | verdict from `EXTENTS:` (ext4) or `BLOCKS:` (ext2/3) + `Blockcount` |
| recover | `debugfs -R 'dump <N> <out>' <dev>` | writes recovered bytes to `<dest-dir>`, then hashes + type-identifies + entropy-checks |
| info | `debugfs -R 'show_super_stats -h' <dev>` | filters the superblock summary to key fields |
| preview | `debugfs -R 'cat <N>' <dev> \| head -c N` | streams data to a hex+ASCII view; nothing written |
| report | `lsdel` + `stat` per inode | emits the results as JSON |
| carve | direct `pread()` scan of the raw device | finds content by string/signature; no `debugfs`, no metadata |

Every `debugfs` call omits `-w`, so the source is read-only throughout.
`recover` is the only command that writes anything, and only to `<dest-dir>`;
`info`, `preview`, and `report` write nothing at all. The entropy/content check
and SHA-256 run entirely on the recovered copy in `<dest-dir>` — never the source.

---

## Limitations

- **Inode undelete is ext2/3/4 only, and effectively ext2/3 in practice.** ext4
  zeroes the inode block map on delete, so `scan`/`check`/`recover` usually find
  nothing for fresh ext4 deletions — use **`carve`** for those.
- **`carve` is filesystem-agnostic but contiguity-dependent.** It reads raw
  blocks, so it works regardless of fs type, but cleanly recovers only files that
  are contiguous and not yet overwritten. Fragmented files may come back partial;
  for exhaustive fragment-aware carving, `photorec` remains the heavyweight option.
- **Destination constraints.** `<dest-dir>` must be on a different filesystem
  than the source, must not contain whitespace, and must have enough free space
  for the recovered file.
- **Overwritten blocks.** As noted above, a `RECOVERABLE` verdict reflects inode
  metadata, not a guarantee that the original bytes are still on disk.
- **Encrypted volumes.** Works on the *decrypted* mapper device (it reads
  plaintext blocks); it cannot do anything with a locked/closed container.

---

## Files

```
~/work/forensic_recovery/
├── frecover.cpp   # source
├── frecover       # compiled binary (after build)
└── README.md      # this file
```

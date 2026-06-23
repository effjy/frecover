// Forensic Recovery v1.0.1  (binary: frecover)
//
// A read-only deleted-file inspector/recoverer for ext2/3/4 filesystems,
// built as a thin, safe orchestrator around `debugfs`. It reproduces the
// manual workflow:
//   1) scan     - list deleted inodes            (debugfs lsdel)
//   2) check    - assess recoverability          (debugfs stat <inode>)
//   3) recover  - dump the file out + identify    (debugfs dump <inode>)
//
// SAFETY GUARANTEES
//   * debugfs is ALWAYS invoked without the -w flag => it physically
//     cannot write to / modify the source device. Inspection is safe even
//     while the filesystem is mounted.
//   * `recover` refuses to write into a destination that lives on the SAME
//     filesystem as the source device, so recovery can never overwrite the
//     free blocks that still hold other recoverable data.
//
// This tool never unmounts anything and never writes to the source.

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cmath>
#include <string>
#include <vector>
#include <array>
#include <algorithm>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <pwd.h>
#include <linux/fs.h>
#include <set>

namespace {

// ---- small helpers ---------------------------------------------------------

// Run a command and capture stdout. Returns exit status (-1 on spawn failure).
int run_capture(const std::string& cmd, std::string& out) {
    out.clear();
    FILE* p = popen(cmd.c_str(), "r");
    if (!p) return -1;
    std::array<char, 4096> buf{};
    size_t n;
    while ((n = fread(buf.data(), 1, buf.size(), p)) > 0)
        out.append(buf.data(), n);
    int rc = pclose(p);
    return (rc == -1) ? -1 : WEXITSTATUS(rc);
}

// Shell-quote a single argument (wrap in single quotes, escape embedded ').
std::string shq(const std::string& s) {
    std::string r = "'";
    for (char c : s) { if (c == '\'') r += "'\\''"; else r += c; }
    r += "'";
    return r;
}

// Build a read-only debugfs invocation:  debugfs -R '<cmd>' <device>
// NOTE: deliberately no -w; read-only is the whole point.
std::string debugfs_cmd(const std::string& device, const std::string& request) {
    return "debugfs -R " + shq(request) + " " + shq(device) + " 2>/dev/null";
}

bool is_root() { return geteuid() == 0; }

// st_dev of the filesystem a path resides on (the path or its parent dir).
dev_t fs_dev_of_path(const std::string& path) {
    struct stat st{};
    if (stat(path.c_str(), &st) == 0) return st.st_dev;
    // Fall back to the parent directory for a not-yet-existing target file.
    std::string parent = path;
    size_t slash = parent.find_last_of('/');
    parent = (slash == std::string::npos) ? "." : parent.substr(0, slash ? slash : 1);
    if (stat(parent.c_str(), &st) == 0) return st.st_dev;
    return (dev_t)-1;
}

// st_dev that the source block device currently backs (via its mountpoint).
// Best-effort: we stat the device node's backing filesystem by resolving the
// mountpoint with `findmnt`. If we cannot determine it, we return (dev_t)-1
// and the same-fs guard is skipped with a warning.
dev_t fs_dev_of_source(const std::string& device) {
    std::string out;
    if (run_capture("findmnt -n -o TARGET --source " + shq(device) + " 2>/dev/null", out) == 0) {
        // take first line
        size_t nl = out.find('\n');
        std::string mp = (nl == std::string::npos) ? out : out.substr(0, nl);
        if (!mp.empty()) {
            struct stat st{};
            if (stat(mp.c_str(), &st) == 0) return st.st_dev;
        }
    }
    return (dev_t)-1;
}

// ---- magic-byte sniffer (self-contained, common types) ---------------------

std::string sniff_magic(const std::string& path) {
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) return "unknown (cannot open)";
    unsigned char b[512];
    size_t n = fread(b, 1, sizeof(b), f);
    fclose(f);
    if (n == 0) return "empty";

    auto starts = [&](std::initializer_list<unsigned char> sig) {
        if (n < sig.size()) return false;
        size_t i = 0; for (unsigned char c : sig) if (b[i++] != c) return false;
        return true;
    };

    if (starts({0x89,'P','N','G',0x0D,0x0A,0x1A,0x0A})) return "image/png";
    if (starts({0xFF,0xD8,0xFF}))                       return "image/jpeg";
    if (n>=6 && (!memcmp(b,"GIF87a",6)||!memcmp(b,"GIF89a",6))) return "image/gif";
    if (n>=12 && !memcmp(b,"RIFF",4) && !memcmp(b+8,"WEBP",4))  return "image/webp";
    if (starts({'B','M'}))                              return "image/bmp";
    if (starts({'%','P','D','F'}))                      return "application/pdf";
    if (starts({0x1F,0x8B}))                            return "application/gzip";
    if (starts({'P','K',0x03,0x04}))                    return "application/zip (or docx/xlsx/odt/jar)";
    if (starts({0x7F,'E','L','F'}))                     return "application/x-executable (ELF)";
    if (starts({0x42,0x5A,0x68}))                       return "application/x-bzip2";
    if (starts({0xFD,'7','z','X','Z',0x00}))            return "application/x-xz";
    if (n>=4 && !memcmp(b,"\x00\x00\x01\x00",4))        return "image/x-icon";
    if (starts({0xEF,0xBB,0xBF}))                       return "text/plain (UTF-8 BOM)";
    if (starts({'#','!'}))                              return "text/plain (script, shebang)";

    // Heuristic text detection. Disqualify on any control byte outside
    // tab/LF/CR (e.g. NUL). High bytes (>=0x80) are allowed as possible UTF-8,
    // but to avoid calling a block of pure high bytes (e.g. all 0xFF) "text",
    // require that a meaningful fraction of the sample is printable ASCII.
    size_t printable = 0;
    bool disqualified = false;
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = b[i];
        if (c == 9 || c == 10 || c == 13) { ++printable; continue; }  // tab/LF/CR
        if (c >= 0x20 && c <= 0x7E)       { ++printable; continue; }  // printable ASCII
        if (c >= 0x80) continue;                                       // maybe UTF-8
        disqualified = true; break;                                    // control byte
    }
    bool textual = !disqualified && ((double)printable / (double)n) >= 0.30;
    return textual ? "text/plain (or other text)" : "application/octet-stream (binary data)";
}

// Shannon entropy (bits/byte, 0..8) over up to `cap` bytes of the file.
// Near 8.0 => near-random: either overwritten free space, or legitimately
// encrypted/compressed data. Returns -1.0 if the file can't be read/empty.
double file_entropy(const std::string& path, size_t cap = 1u << 20) {
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) return -1.0;
    unsigned long counts[256] = {0};
    unsigned long total = 0;
    unsigned char buf[65536];
    size_t n;
    while (total < cap && (n = fread(buf, 1, sizeof(buf), f)) > 0) {
        for (size_t i = 0; i < n; ++i) counts[buf[i]]++;
        total += n;
    }
    fclose(f);
    if (total == 0) return -1.0;
    double H = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (!counts[i]) continue;
        double p = (double)counts[i] / (double)total;
        H -= p * (log(p) / log(2.0));
    }
    return H;
}

// Did the magic sniffer recognize a concrete, structured type (as opposed to
// the "binary data" / unknown fallbacks)? Recognized types imply the bytes are
// real content, even if high-entropy (png/jpeg/gzip/zip/...).
bool magic_recognized(const std::string& m) {
    return m.rfind("application/octet-stream", 0) != 0 &&
           m.rfind("unknown", 0) != 0 &&
           m != "empty";
}

// When running as root under sudo, hand recovered files back to the invoking
// user so they can be inspected without sudo (chain-of-custody is preserved by
// the SHA-256 hashes, not by ownership). No-op otherwise.
void chown_to_invoker(const std::string& path) {
    if (geteuid() != 0) return;
    const char* su = getenv("SUDO_USER");
    if (!su || !*su) return;
    struct passwd* pw = getpwnam(su);
    if (pw && chown(path.c_str(), pw->pw_uid, pw->pw_gid) != 0) { /* best effort */ }
}

// Bytes available to a non-root writer on the filesystem containing `dir`.
// Returns (unsigned long long)-1 if it can't be determined.
unsigned long long avail_bytes(const std::string& dir) {
    struct statvfs s{};
    if (statvfs(dir.c_str(), &s) != 0) return (unsigned long long)-1;
    return (unsigned long long)s.f_bavail * (unsigned long long)s.f_frsize;
}

// Authoritative description via the `file` command, if present.
std::string file_describe(const std::string& path) {
    std::string out;
    if (run_capture("file -b " + shq(path) + " 2>/dev/null", out) == 0 && !out.empty()) {
        if (!out.empty() && out.back() == '\n') out.pop_back();
        return out;
    }
    return "(file command unavailable)";
}

// SHA-256 of a file via the `sha256sum` tool (for chain-of-custody hashing of
// recovered evidence). Returns empty string if unavailable.
std::string sha256_of(const std::string& path) {
    std::string out;
    if (run_capture("sha256sum " + shq(path) + " 2>/dev/null", out) == 0) {
        size_t sp = out.find(' ');
        return (sp == std::string::npos) ? out : out.substr(0, sp);
    }
    return "";
}

// Minimal JSON string escaper for the `report` output.
std::string json_escape(const std::string& s) {
    std::string r;
    for (char c : s) {
        switch (c) {
            case '"':  r += "\\\""; break;
            case '\\': r += "\\\\"; break;
            case '\n': r += "\\n";  break;
            case '\t': r += "\\t";  break;
            case '\r': r += "\\r";  break;
            default:
                if ((unsigned char)c < 0x20) { char b[8]; snprintf(b, sizeof(b), "\\u%04x", c); r += b; }
                else r += c;
        }
    }
    return r;
}

// ---- step 1: scan ----------------------------------------------------------

struct DelInode {
    long inode = 0;
    long owner = 0;
    std::string mode;   // octal as printed by debugfs (e.g. 100640, 40755)
    long size  = 0;
    std::string when;   // trailing "Time deleted" text
};

std::vector<DelInode> scan(const std::string& device) {
    std::vector<DelInode> v;
    std::string out;
    int rc = run_capture(debugfs_cmd(device, "lsdel"), out);
    if (rc != 0 && out.empty()) return v;

    std::string line;
    for (size_t i = 0; i <= out.size(); ++i) {
        if (i == out.size() || out[i] == '\n') {
            // process `line`
            if (!line.empty() &&
                line.find("Inode") == std::string::npos &&
                line.find("debugfs") == std::string::npos &&
                line.find("deleted inodes") == std::string::npos) {
                DelInode d;
                char modebuf[64] = {0};
                long blk_a, blk_b;
                // " 5908141   1000  40755   4096      1/     1 Tue Jun 16 ..."
                int got = sscanf(line.c_str(), "%ld %ld %63s %ld %ld/ %ld",
                                 &d.inode, &d.owner, modebuf, &d.size, &blk_a, &blk_b);
                if (got >= 4 && d.inode > 0) {
                    d.mode = modebuf;
                    // grab the trailing date text after the blocks column
                    size_t pos = line.find('/');
                    if (pos != std::string::npos) {
                        // skip the '/', the second blocks count, and spaces;
                        // the date (day-of-week) is the first alpha char after.
                        size_t dt = line.find_first_not_of(" 0123456789/", pos);
                        if (dt != std::string::npos) d.when = line.substr(dt);
                    }
                    v.push_back(d);
                }
            }
            line.clear();
        } else {
            line += out[i];
        }
    }
    return v;
}

bool mode_is_dir(const std::string& mode) {
    // ext mode is printed in octal; the type is the high nibble.
    // A directory is 04xxxx -> debugfs prints it as a 5-digit string whose
    // first digit is '4' (e.g. "40755", "42755" setgid, "41777" sticky).
    // Regular file=100xxx (6 digits), symlink=120xxx, FIFO=10xxx, chardev=20xxx.
    return mode.size() == 5 && mode[0] == '4';
}

// ---- step 2: check ---------------------------------------------------------

// Returns the raw stat text and sets `recoverable` / `reason`.
std::string check(const std::string& device, long inode,
                  bool& recoverable, std::string& reason) {
    std::string out;
    run_capture(debugfs_cmd(device, "stat <" + std::to_string(inode) + ">"), out);

    // ext4 prints an "EXTENTS:" section; ext2/3 (and non-extent ext4 files)
    // print a "BLOCKS:" section. We treat either, with listed block numbers,
    // as "data blocks still addressable from the inode".
    bool in_data_section = false;     // inside EXTENTS:/BLOCKS:
    bool data_listed = false;         // saw actual block numbers
    long blockcount = -1;

    std::string line;
    for (size_t i = 0; i <= out.size(); ++i) {
        if (i == out.size() || out[i] == '\n') {
            size_t hdr = line.find("EXTENTS:");
            if (hdr == std::string::npos) hdr = line.find("BLOCKS:");
            if (hdr != std::string::npos) {
                in_data_section = true;
                // numbers may follow the colon on the same line
                std::string rest = line.substr(line.find(':', hdr) + 1);
                if (rest.find_first_of("0123456789") != std::string::npos)
                    data_listed = true;
            } else if (in_data_section && !data_listed &&
                       line.find_first_of("0123456789") != std::string::npos) {
                data_listed = true; // continuation line like "(0):74268170" or "0-3"
            }
            if (const char* p = strstr(line.c_str(), "Blockcount:"))
                sscanf(p, "Blockcount: %ld", &blockcount);
            line.clear();
        } else line += out[i];
    }

    recoverable = false;
    if (data_listed && blockcount > 0) {
        recoverable = true;
        reason = "data block pointers (EXTENTS/BLOCKS) survive and Blockcount > 0";
    } else if (blockcount == 0) {
        reason = "Blockcount is 0 - no data blocks referenced (likely empty/truncated)";
    } else if (!data_listed) {
        reason = "no EXTENTS/BLOCKS listed - block pointers were zeroed; content not addressable from the inode (carving may still work)";
    } else {
        reason = "indeterminate";
    }
    return out;
}

// ---- usage -----------------------------------------------------------------

int usage(const char* argv0) {
    fprintf(stderr,
"Forensic Recovery v1.0.1 (frecover) - read-only deleted-file inspector for ext2/3/4\n"
"\n"
"USAGE:\n"
"  %s scan    <device>\n"
"  %s check   <device> <inode>\n"
"  %s recover <device> <inode> <dest-dir>\n"
"  %s auto    <device> <dest-dir>        # scan, then recover every recoverable inode\n"
"  %s info    <device>                   # filesystem summary (type, state, free space)\n"
"  %s preview <device> <inode> [bytes]   # read-only hex peek, writes nothing (default 256)\n"
"  %s report  <device>                   # machine-readable JSON of scan + verdicts\n"
"  %s carve   <device> <dest> [opts]     # content/signature recovery (works on ext4!)\n"
"           opts: --string <s> | --types <l> | --max-bytes <N> | --block <N> | --align <N>\n"
"\n"
"NOTES:\n"
"  * Source device is opened READ-ONLY (debugfs without -w); never modified.\n"
"  * <dest-dir> for recover/auto MUST be on a DIFFERENT filesystem than <device>.\n"
"  * Run as root (needs raw read access to the block device).\n"
"  * Recovered files are hashed (SHA-256) for chain-of-custody.\n"
"\n"
"EXAMPLE:\n"
"  sudo %s scan /dev/mapper/ubuntu--vg-ubuntu--lv\n",
        argv0, argv0, argv0, argv0, argv0, argv0, argv0, argv0, argv0);
    return 2;
}

// ---- recover ---------------------------------------------------------------

int do_recover(const std::string& device, long inode, const std::string& destdir,
               const std::string& mode_hint, long expected_size) {
    // debugfs tokenizes its own -R string on whitespace and offers no quoting,
    // so a dest path containing whitespace would corrupt the dump target.
    if (destdir.find_first_of(" \t\n") != std::string::npos) {
        fprintf(stderr,
            "ERROR: dest-dir '%s' contains whitespace.\n"
            "debugfs cannot write to a path with spaces; choose a whitespace-free dest.\n",
            destdir.c_str());
        return 3;
    }

    struct stat dstat{};
    if (stat(destdir.c_str(), &dstat) != 0 || !S_ISDIR(dstat.st_mode)) {
        fprintf(stderr, "ERROR: dest-dir '%s' is not an existing directory.\n", destdir.c_str());
        return 3;
    }

    // Guard: destination must not be on the source filesystem.
    dev_t src = fs_dev_of_source(device);
    dev_t dst = fs_dev_of_path(destdir);
    if (src == (dev_t)-1) {
        fprintf(stderr, "WARNING: could not determine source filesystem; "
                        "cannot verify dest is separate. Proceeding cautiously.\n");
    } else if (src == dst) {
        fprintf(stderr,
            "REFUSING: destination '%s' is on the SAME filesystem as the source.\n"
            "Recovering there could overwrite still-recoverable free blocks.\n"
            "Choose a dest on another disk/USB or a tmpfs (e.g. /dev/shm).\n",
            destdir.c_str());
        return 3;
    }

    // Guard: don't blow up RAM-backed dests (tmpfs like /dev/shm) or fill a
    // small disk. If we know the expected size, require it to fit with margin.
    if (expected_size > 0) {
        unsigned long long avail = avail_bytes(destdir);
        if (avail != (unsigned long long)-1 &&
            (unsigned long long)expected_size > avail) {
            fprintf(stderr,
                "REFUSING: inode %ld is ~%ld bytes but dest '%s' has only %llu bytes free.\n"
                "Recovering here could exhaust space (and on tmpfs like /dev/shm, RAM).\n"
                "Pick a larger destination on a separate disk.\n",
                inode, expected_size, destdir.c_str(), avail);
            return 3;
        }
    }

    std::string outpath = destdir + "/recovered_inode_" + std::to_string(inode);
    if (mode_is_dir(mode_hint)) outpath += "_dir.raw";  // raw directory block

    // Remove any prior output so a failed dump can't be mistaken for success
    // by leaving stale data from an earlier run in place.
    unlink(outpath.c_str());

    std::string dump_req = "dump <" + std::to_string(inode) + "> " + outpath;
    std::string out;
    int rc = run_capture(debugfs_cmd(device, dump_req), out);
    (void)rc;

    struct stat fst{};
    if (stat(outpath.c_str(), &fst) != 0) {
        fprintf(stderr, "Recovery produced no output for inode %ld (blocks may be gone).\n", inode);
        if (!out.empty()) fprintf(stderr, "debugfs: %s\n", out.c_str());
        return 4;
    }
    if (fst.st_size == 0) {
        // debugfs writes a 0-byte file for an empty/nonexistent inode; that's
        // not a recovery. Remove it so nothing stale is left behind.
        unlink(outpath.c_str());
        fprintf(stderr, "No data recovered for inode %ld (0 bytes - inode empty, "
                        "unallocated, or blocks gone).\n", inode);
        if (!out.empty()) fprintf(stderr, "debugfs: %s\n", out.c_str());
        return 4;
    }

    chown_to_invoker(outpath);  // hand the recovered file back to the sudo user
    printf("Recovered inode %ld -> %s (%lld bytes)\n",
           inode, outpath.c_str(), (long long)fst.st_size);

    std::string hash = sha256_of(outpath);
    if (!hash.empty()) printf("  SHA-256  : %s\n", hash.c_str());

    double H = file_entropy(outpath);
    char hbuf[32];
    if (H >= 0) snprintf(hbuf, sizeof(hbuf), "%.2f bits/byte", H);
    else        snprintf(hbuf, sizeof(hbuf), "n/a (empty/unreadable)");

    if (mode_is_dir(mode_hint)) {
        printf("  Type     : DIRECTORY (raw directory block - contains the filenames it held)\n");
        printf("  Entropy  : %s\n", hbuf);
        if (H >= 0 && H > 6.5)
            printf("  CONTENT  : LIKELY OVERWRITTEN - directory block is near-random, not valid dir entries.\n");
        else
            printf("  CONTENT  : plausibly intact - run `strings %s` to read the recoverable entry names.\n",
                   outpath.c_str());
    } else {
        std::string magic = sniff_magic(outpath);
        printf("  Magic    : %s\n", magic.c_str());
        printf("  file(1)  : %s\n", file_describe(outpath).c_str());
        printf("  Entropy  : %s\n", hbuf);
        // Content verdict: recognized structure => real bytes (even if high
        // entropy, e.g. compressed/encrypted). Unrecognized + high entropy =>
        // the blocks were most likely reused/overwritten since deletion.
        if (magic_recognized(magic))
            printf("  CONTENT  : appears INTACT (recognized file structure).\n");
        else if (H >= 0 && H > 7.5)
            printf("  CONTENT  : LIKELY OVERWRITTEN or encrypted/compressed - near-random bytes, no recognizable structure.\n");
        else if (H >= 0 && H < 5.0)
            printf("  CONTENT  : plausibly intact - low entropy, structured/text-like data.\n");
        else
            printf("  CONTENT  : uncertain - no recognized structure; inspect manually.\n");
    }
    return 0;
}

// ---- feature: info (filesystem summary) ------------------------------------

// Print a concise summary of the target filesystem for investigative context.
int cmd_info(const std::string& device) {
    std::string out;
    run_capture(debugfs_cmd(device, "show_super_stats -h"), out);
    if (out.empty()) {
        fprintf(stderr, "Could not read superblock from %s (need root? ext fs?).\n",
                device.c_str());
        return 1;
    }
    printf("Forensic Recovery v1.0.1 - filesystem info: %s\n\n", device.c_str());
    // Surface the fields most useful for triage; fall back to full dump.
    static const char* keys[] = {
        "Filesystem volume name", "Filesystem UUID", "Filesystem magic",
        "Filesystem state", "Errors behavior", "Inode count", "Block count",
        "Free blocks", "Free inodes", "Block size", "Last mounted on",
        "Mount count", "Last mount time", "Last write time", "Lifetime writes", nullptr
    };
    std::string line;
    bool printed_any = false;
    for (size_t i = 0; i <= out.size(); ++i) {
        if (i == out.size() || out[i] == '\n') {
            for (const char** k = keys; *k; ++k)
                if (line.find(*k) != std::string::npos) { printf("  %s\n", line.c_str()); printed_any = true; break; }
            line.clear();
        } else line += out[i];
    }
    if (!printed_any) printf("%s\n", out.c_str());  // unrecognized format: show raw
    return 0;
}

// ---- feature: preview (read-only hex peek, NO recovery file written) -------

// Dump the first `nbytes` of a (deleted) inode's content straight to stdout as
// a hex+ASCII view. Nothing is written to any disk - pure triage.
int cmd_preview(const std::string& device, long inode, long nbytes) {
    if (nbytes <= 0) nbytes = 256;
    // `cat` streams the inode's data blocks to stdout; we cap it with head -c.
    std::string cmd = "debugfs -R " + shq("cat <" + std::to_string(inode) + ">") +
                      " " + shq(device) + " 2>/dev/null | head -c " + std::to_string(nbytes);
    std::string data;
    run_capture(cmd, data);

    printf("Forensic Recovery v1.0.1 - preview inode %ld on %s (first %zu bytes)\n\n",
           inode, device.c_str(), data.size());
    if (data.empty()) {
        printf("(no readable data - inode empty, unallocated, or blocks gone)\n");
        return 1;
    }

    // Type guess straight from stdin (no temp file): pipe the same bytes to file.
    std::string desc;
    run_capture(cmd + " | file -b - 2>/dev/null", desc);
    if (!desc.empty() && desc.back() == '\n') desc.pop_back();
    if (!desc.empty()) printf("Type guess (file): %s\n\n", desc.c_str());

    // Hex + ASCII, 16 bytes per row.
    const unsigned char* b = reinterpret_cast<const unsigned char*>(data.data());
    for (size_t off = 0; off < data.size(); off += 16) {
        printf("%08zx  ", off);
        for (size_t j = 0; j < 16; ++j) {
            if (off + j < data.size()) printf("%02x ", b[off + j]); else printf("   ");
            if (j == 7) printf(" ");
        }
        printf(" |");
        for (size_t j = 0; j < 16 && off + j < data.size(); ++j) {
            unsigned char c = b[off + j];
            putchar((c >= 0x20 && c <= 0x7E) ? c : '.');
        }
        printf("|\n");
    }
    return 0;
}

// ---- feature: report (machine-readable JSON of scan + verdicts) ------------

int cmd_report(const std::string& device) {
    auto v = scan(device);
    printf("{\n");
    printf("  \"tool\": \"frecover\",\n");
    printf("  \"version\": \"1.0.1\",\n");
    printf("  \"device\": \"%s\",\n", json_escape(device).c_str());
    printf("  \"deleted_inode_count\": %zu,\n", v.size());
    printf("  \"inodes\": [\n");
    for (size_t i = 0; i < v.size(); ++i) {
        bool rec; std::string reason;
        check(device, v[i].inode, rec, reason);
        printf("    {\n");
        printf("      \"inode\": %ld,\n", v[i].inode);
        printf("      \"owner_uid\": %ld,\n", v[i].owner);
        printf("      \"mode\": \"%s\",\n", json_escape(v[i].mode).c_str());
        printf("      \"is_directory\": %s,\n", mode_is_dir(v[i].mode) ? "true" : "false");
        printf("      \"size\": %ld,\n", v[i].size);
        printf("      \"deleted\": \"%s\",\n", json_escape(v[i].when).c_str());
        printf("      \"recoverable\": %s,\n", rec ? "true" : "false");
        printf("      \"reason\": \"%s\"\n", json_escape(reason).c_str());
        printf("    }%s\n", (i + 1 < v.size()) ? "," : "");
    }
    printf("  ]\n");
    printf("}\n");
    return 0;
}

// ---- feature: carve (content/signature recovery, ext4's real answer) -------
//
// Inode undelete fails on ext4 (the block map is zeroed on delete). Carving
// ignores metadata entirely and scans the raw device for file content that is
// still sitting in now-free blocks. Read-only on the source; writes only to
// <dest>.

// Naive forward byte search; returns index >= start or SIZE_MAX.
size_t find_bytes(const unsigned char* h, size_t hlen,
                  const unsigned char* n, size_t nlen, size_t start) {
    if (nlen == 0 || nlen > hlen) return (size_t)-1;
    for (size_t i = start; i + nlen <= hlen; ++i)
        if (h[i] == n[0] && memcmp(h + i, n, nlen) == 0) return i;
    return (size_t)-1;
}

// Total size of a block device or image file behind an open fd.
unsigned long long dev_size(int fd) {
    struct stat st{};
    if (fstat(fd, &st) == 0) {
        if (S_ISREG(st.st_mode)) return (unsigned long long)st.st_size;
        if (S_ISBLK(st.st_mode)) {
            unsigned long long s = 0;
            if (ioctl(fd, BLKGETSIZE64, &s) == 0) return s;
        }
    }
    off_t e = lseek(fd, 0, SEEK_END);
    if (e > 0) { lseek(fd, 0, SEEK_SET); return (unsigned long long)e; }
    return 0;
}

// Copy [start, start+len) from the source fd to outpath, via pread (read-only).
// Refuses if the destination filesystem lacks room for `len` bytes (with a
// small margin) so a runaway/large carve cannot fill the destination disk.
bool carve_region(int fd, off_t start, off_t len, const std::string& outpath,
                  const std::string& destdir) {
    unsigned long long avail = avail_bytes(destdir);
    if (avail != (unsigned long long)-1 && (unsigned long long)len + (1u << 20) > avail) {
        fprintf(stderr, "  SKIP: %s would need %lld bytes but dest has only %llu free.\n",
                outpath.c_str(), (long long)len, avail);
        return false;
    }
    FILE* o = fopen(outpath.c_str(), "wb");
    if (!o) return false;
    std::vector<char> buf(1u << 20);
    off_t done = 0;
    while (done < len) {
        size_t want = (size_t)std::min<off_t>((off_t)buf.size(), len - done);
        ssize_t r = pread(fd, buf.data(), want, start + done);
        if (r <= 0) break;
        fwrite(buf.data(), 1, (size_t)r, o);
        done += r;
    }
    fclose(o);
    if (done <= 0) { unlink(outpath.c_str()); return false; }
    return true;
}

// Lightweight per-type sanity check on a header window, to reject the flood of
// false positives that short magics produce on real-world data. Returns true if
// the bytes look plausibly like the claimed type beyond just the magic.
bool sig_plausible(const std::string& name, const unsigned char* w, size_t n) {
    if (name == "jpeg") {
        // After SOI (FF D8) the next marker must be FF xx with a valid xx.
        if (n < 4 || w[0] != 0xFF || w[1] != 0xD8 || w[2] != 0xFF) return false;
        unsigned char m = w[3];
        return m == 0xE0 || m == 0xE1 || m == 0xDB || m == 0xC0 || m == 0xC2 || m == 0xFE;
    }
    if (name == "gif") {  // require full "GIF87a" or "GIF89a"
        return n >= 6 && (!memcmp(w, "GIF87a", 6) || !memcmp(w, "GIF89a", 6));
    }
    if (name == "pdf") {  // "%PDF-" followed by a version digit
        return n >= 6 && !memcmp(w, "%PDF-", 5) && w[5] >= '1' && w[5] <= '9';
    }
    if (name == "gzip") { // flags byte must have no reserved bits set
        return n >= 4 && w[0] == 0x1F && w[1] == 0x8B && w[2] == 0x08 && (w[3] & 0xE0) == 0;
    }
    // png and zip magics are long/specific enough on their own.
    return true;
}

struct Sig {
    const char* name; const char* ext;
    std::vector<unsigned char> hdr;
    std::vector<unsigned char> ftr;   // empty => no reliable footer (carve capped)
    size_t ftr_trailer;               // bytes to include after the footer match
    size_t maxsz;                     // cap per file / footer-search window
};

std::vector<Sig> default_sigs() {
    return {
        {"png","png",{0x89,'P','N','G',0x0D,0x0A,0x1A,0x0A},{'I','E','N','D'},4,32u<<20},
        {"jpeg","jpg",{0xFF,0xD8,0xFF},{0xFF,0xD9},0,32u<<20},
        {"gif","gif",{'G','I','F','8'},{0x3B},0,16u<<20},
        {"pdf","pdf",{'%','P','D','F'},{'%','%','E','O','F'},0,64u<<20},
        {"zip","zip",{'P','K',0x03,0x04},{'P','K',0x05,0x06},18,64u<<20},
        {"gzip","gz",{0x1F,0x8B},{},0,8u<<20},
    };
}

int cmd_carve(const std::string& device, const std::string& dest,
              const std::string& want_string, const std::string& types,
              unsigned long long max_bytes, long block, long align) {
    // Reuse the same destination guards as recover.
    if (dest.find_first_of(" \t\n") != std::string::npos) {
        fprintf(stderr, "ERROR: dest '%s' contains whitespace.\n", dest.c_str()); return 3;
    }
    struct stat dstat{};
    if (stat(dest.c_str(), &dstat) != 0 || !S_ISDIR(dstat.st_mode)) {
        fprintf(stderr, "ERROR: dest '%s' is not an existing directory.\n", dest.c_str()); return 3;
    }
    dev_t src = fs_dev_of_source(device), dst = fs_dev_of_path(dest);
    if (src != (dev_t)-1 && src == dst) {
        fprintf(stderr, "REFUSING: dest is on the SAME filesystem as the source; "
                        "carved data could overwrite unrecovered content. Use another disk.\n");
        return 3;
    }

    int fd = open(device.c_str(), O_RDONLY);
    if (fd < 0) { fprintf(stderr, "ERROR: cannot open %s (root? exists?).\n", device.c_str()); return 1; }
    unsigned long long size = dev_size(fd);
    unsigned long long scan_to = (max_bytes > 0 && max_bytes < size) ? max_bytes : size;

    printf("Forensic Recovery v1.0.1 - carve %s\n", device.c_str());
    printf("  device size : %.2f GiB%s\n", size / 1073741824.0,
           (scan_to < size) ? "  (scan limited)" : "");
    printf("  scanning    : %.2f GiB\n", scan_to / 1073741824.0);
    if (scan_to > (4ull<<30) && max_bytes == 0)
        printf("  NOTE: large scan; this is sequential read-only I/O. Use --max-bytes to bound it.\n");

    bool string_mode = !want_string.empty();
    std::vector<Sig> sigs;
    if (!string_mode) {
        // Tokenize --types on commas, match exact names, error on unknowns.
        auto all = default_sigs();
        if (types == "all") {
            sigs = all;
        } else {
            std::string tok; std::string t = types + ",";
            for (char c : t) {
                if (c == ',') {
                    if (!tok.empty()) {
                        bool ok = false;
                        for (auto& s : all) if (tok == s.name) { sigs.push_back(s); ok = true; break; }
                        if (!ok) {
                            fprintf(stderr, "ERROR: unknown --types value '%s' "
                                    "(valid: png,jpeg,gif,pdf,zip,gzip,all)\n", tok.c_str());
                            close(fd); return 2;
                        }
                        tok.clear();
                    }
                } else tok += c;
            }
        }
        printf("  mode        : signature carving (%zu types, %ld-byte aligned)\n",
               sigs.size(), align);
    } else {
        printf("  mode        : string match \"%s\" (block=%ld)\n", want_string.c_str(), block);
    }
    printf("\n");

    const size_t CHUNK = 8u << 20, OVERLAP = 1u << 20;
    std::vector<unsigned char> buf(CHUNK + OVERLAP);
    const unsigned char* needle = reinterpret_cast<const unsigned char*>(want_string.data());

    std::set<off_t> done_blocks;   // string mode: carved block starts
    off_t carved_to = 0;           // sig mode: end of the furthest carve so far

    // Manifest: one record per carved file (offset, size, type, hash, name).
    struct MEnt { off_t off; off_t len; std::string type, sha, fname; };
    std::vector<MEnt> manifest;
    auto record = [&](off_t off, off_t len, const std::string& out) {
        chown_to_invoker(out);     // give the carved file to the sudo user
        std::string fn = out.substr(out.find_last_of('/') + 1);
        manifest.push_back({off, len, file_describe(out), sha256_of(out), fn});
    };

    off_t filepos = 0; size_t prefix = 0; int found = 0;
    while ((unsigned long long)filepos < scan_to) {
        // Clamp the read so --max-bytes is honored (don't overshoot by a chunk).
        unsigned long long pos = (unsigned long long)filepos + prefix;
        if (pos >= scan_to) break;
        size_t toread = (size_t)std::min<unsigned long long>(CHUNK, scan_to - pos);
        ssize_t r = pread(fd, buf.data() + prefix, toread, (off_t)pos);
        if (r < 0) { perror("pread"); break; }
        size_t avail = prefix + (size_t)r;
        if (avail == 0) break;

        if (string_mode) {
            size_t at = 0;
            while ((at = find_bytes(buf.data(), avail, needle, want_string.size(), at)) != (size_t)-1) {
                off_t abs = filepos + (off_t)at;
                off_t bstart = (abs / block) * block;
                if (done_blocks.insert(bstart).second) {
                    off_t len = std::min<off_t>(block, (off_t)size - bstart);
                    std::string out = dest + "/carved_" + std::to_string(bstart) + ".bin";
                    if (carve_region(fd, bstart, len, out, dest)) {
                        printf("  match @ %lld -> %s (%lld bytes)\n",
                               (long long)abs, out.c_str(), (long long)len);
                        record(bstart, len, out);
                        ++found;
                    }
                }
                at += 1;
            }
        } else {
            for (auto& s : sigs) {
                size_t at = 0;
                while ((at = find_bytes(buf.data(), avail, s.hdr.data(), s.hdr.size(), at)) != (size_t)-1) {
                    off_t H = filepos + (off_t)at;
                    at += 1;
                    // Real file headers begin on a filesystem block boundary;
                    // requiring alignment removes the bulk of false positives.
                    if (align > 1 && (H % align) != 0) continue;
                    // Skip headers that fall inside a file we just carved.
                    if (H < carved_to) continue;
                    // Read a window to validate the header and locate the footer.
                    size_t win = (size_t)std::min<unsigned long long>(s.maxsz, size - H);
                    std::vector<unsigned char> w(win);
                    ssize_t wr = pread(fd, w.data(), win, H);
                    if (wr <= 0) continue;
                    size_t wlen = (size_t)wr;
                    if (!sig_plausible(s.name, w.data(), wlen)) continue;  // reject noise
                    off_t end;
                    if (!s.ftr.empty()) {
                        size_t fp = find_bytes(w.data(), wlen, s.ftr.data(), s.ftr.size(), s.hdr.size());
                        if (fp == (size_t)-1) continue;  // no footer in window: skip (likely noise)
                        end = H + (off_t)(fp + s.ftr.size() + s.ftr_trailer);
                    } else {
                        end = H + (off_t)wlen;            // footer-less: carve capped window
                    }
                    if (end > (off_t)size) end = (off_t)size;
                    std::string out = dest + "/carved_" + std::to_string(H) + "." + s.ext;
                    if (carve_region(fd, H, end - H, out, dest)) {
                        printf("  %-4s @ %lld -> %s (%lld bytes)\n",
                               s.name, (long long)H, out.c_str(), (long long)(end - H));
                        record(H, end - H, out);
                        if (end > carved_to) carved_to = end;
                        ++found;
                    }
                }
            }
        }

        // Carry the last OVERLAP bytes so matches spanning a chunk boundary survive.
        if (avail > OVERLAP) {
            memmove(buf.data(), buf.data() + avail - OVERLAP, OVERLAP);
            filepos += (off_t)(avail - OVERLAP);
            prefix = OVERLAP;
        } else {
            prefix = avail;
        }
        if ((size_t)r < toread) break;  // short read => end of device/image
    }
    close(fd);

    // Write a manifest so a pile of carved_<offset> files becomes a triage table.
    if (!manifest.empty()) {
        std::string mp = dest + "/carve_manifest.csv";
        FILE* m = fopen(mp.c_str(), "w");
        if (m) {
            fprintf(m, "offset,size,type,sha256,filename\n");
            for (auto& e : manifest) {
                std::string t;  // CSV-escape the type description
                for (char c : e.type) { if (c == '"') t += "\"\""; else if (c != '\n' && c != '\r') t += c; }
                fprintf(m, "%lld,%lld,\"%s\",%s,%s\n",
                        (long long)e.off, (long long)e.len, t.c_str(), e.sha.c_str(), e.fname.c_str());
            }
            fclose(m);
            chown_to_invoker(mp);
            printf("  manifest    : %s\n", mp.c_str());
        }
    }

    printf("\n-> carved %d file(s) into %s\n", found, dest.c_str());
    return found > 0 ? 0 : 4;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 3) return usage(argv[0]);
    std::string action = argv[1];
    std::string device = argv[2];

    if (!is_root())
        fprintf(stderr, "WARNING: not running as root; reading a raw block device "
                        "will likely fail (image files may still work).\n");

    if (action == "info")    return cmd_info(device);
    if (action == "report")  return cmd_report(device);

    if (action == "carve") {
        if (argc < 4) return usage(argv[0]);
        std::string dest = argv[3];
        std::string want_string, types = "all";
        unsigned long long max_bytes = 0; long block = 4096; long align = 4096;
        for (int i = 4; i < argc; ++i) {
            std::string a = argv[i];
            if (a == "--string"    && i + 1 < argc) want_string = argv[++i];
            else if (a == "--types"     && i + 1 < argc) types = argv[++i];
            else if (a == "--max-bytes" && i + 1 < argc) max_bytes = strtoull(argv[++i], nullptr, 10);
            else if (a == "--block"     && i + 1 < argc) block = strtol(argv[++i], nullptr, 10);
            else if (a == "--align"     && i + 1 < argc) align = strtol(argv[++i], nullptr, 10);
            else { fprintf(stderr, "carve: unknown/with-missing-arg option '%s'\n", a.c_str()); return usage(argv[0]); }
        }
        if (block <= 0) block = 4096;
        if (align < 1) align = 1;   // 1 = match at every offset (unaligned)
        return cmd_carve(device, dest, want_string, types, max_bytes, block, align);
    }

    if (action == "preview") {
        if (argc < 4) return usage(argv[0]);
        long inode = strtol(argv[3], nullptr, 10);
        long nbytes = (argc >= 5) ? strtol(argv[4], nullptr, 10) : 256;
        return cmd_preview(device, inode, nbytes);
    }

    if (action == "scan") {
        auto v = scan(device);
        printf("Forensic Recovery v1.0.1 - scan of %s\n", device.c_str());
        printf("%-12s %-7s %-8s %-12s %s\n", "INODE", "OWNER", "MODE", "SIZE", "DELETED");
        for (auto& d : v)
            printf("%-12ld %-7ld %-8s %-12ld %s\n",
                   d.inode, d.owner, d.mode.c_str(), d.size, d.when.c_str());
        printf("-> %zu deleted inode(s) found.\n", v.size());
        return 0;
    }

    if (action == "check") {
        if (argc < 4) return usage(argv[0]);
        long inode = strtol(argv[3], nullptr, 10);
        bool rec; std::string reason;
        std::string raw = check(device, inode, rec, reason);
        printf("Forensic Recovery v1.0.1 - check inode %ld on %s\n\n", inode, device.c_str());
        printf("%s\n", raw.c_str());
        printf("VERDICT: %s\n", rec ? "RECOVERABLE" : "NOT cleanly recoverable from inode");
        printf("REASON : %s\n", reason.c_str());
        return rec ? 0 : 1;
    }

    if (action == "recover") {
        if (argc < 5) return usage(argv[0]);
        long inode = strtol(argv[3], nullptr, 10);
        std::string destdir = argv[4];
        // get a mode/size hint from scan (label directories; size for guard)
        std::string mode_hint;
        long size_hint = 0;
        for (auto& d : scan(device)) if (d.inode == inode) { mode_hint = d.mode; size_hint = d.size; }
        return do_recover(device, inode, destdir, mode_hint, size_hint);
    }

    if (action == "auto") {
        if (argc < 4) return usage(argv[0]);
        std::string destdir = argv[3];
        auto v = scan(device);
        printf("Forensic Recovery v1.0.1 - auto: %zu deleted inode(s) on %s\n\n",
               v.size(), device.c_str());
        int recovered = 0;
        for (auto& d : v) {
            bool rec; std::string reason;
            check(device, d.inode, rec, reason);
            std::string status = rec ? std::string("RECOVERABLE") : ("skip (" + reason + ")");
            printf("inode %-10ld owner=%-5ld mode=%-7s size=%-8ld : %s\n",
                   d.inode, d.owner, d.mode.c_str(), d.size, status.c_str());
            if (rec) { if (do_recover(device, d.inode, destdir, d.mode, d.size) == 0) ++recovered; printf("\n"); }
        }
        printf("-> recovered %d file(s) into %s\n", recovered, destdir.c_str());
        return 0;
    }

    return usage(argv[0]);
}

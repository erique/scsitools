#!/usr/bin/env python3
"""
scsiformat.py - X68000 SxSI Disk Formatter

Formats an existing file/device as a bootable X68000 SxSI disk image.
Size is determined from the input file. Creates a single Human68k partition
with FAT16 filesystem and installs HUMAN.SYS + COMMAND.X for a bootable system.

Supports:
- Long filenames (Human68k 18+3 format with fileName2 field)
- Recursive subdirectory creation
- Shift-JIS filename handling (via cp932 encoding)
- File attribute preservation via .x68k_meta metadata file
- HUMAN.SYS/COMMAND.X replacement from --extra-files
"""

import argparse
import math
import os
import struct
import sys
import time

RECORD_SIZE = 1024
PARTITION_START_RECORD = 0x20  # 32
FAT_ENTRY_SIZE = 2
DIR_ENTRY_SIZE = 32

SCSI_SIGNATURE = b"X68SCSI1"
SCSI_DESCRIPTION = (
    b"This SCSI-UNIT format is 'SxSI' "
    b" for scsiform.  "
    b" by Hero Soft.  "
    b"     (C-lab CO)"
)
PARTITION_TABLE_SIGNATURE = b"X68K"
PARTITION_NAME = b"Human68k"

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")


# ============================================================================
# Data structures for directory tree
# ============================================================================

class FileEntry:
    __slots__ = ("name_bytes", "ext_bytes", "name2_bytes", "data", "attr",
                 "dos_time", "dos_date", "start_cluster", "num_clusters")

    def __init__(self, name_bytes, ext_bytes, name2_bytes, data,
                 attr=0x20, dos_time=0, dos_date=0):
        self.name_bytes = name_bytes
        self.ext_bytes = ext_bytes
        self.name2_bytes = name2_bytes
        self.data = data
        self.attr = attr
        self.dos_time = dos_time
        self.dos_date = dos_date
        self.start_cluster = 0
        self.num_clusters = 0


class DirEntry:
    __slots__ = ("name_bytes", "ext_bytes", "name2_bytes", "children", "attr",
                 "dos_time", "dos_date", "start_cluster", "num_clusters")

    def __init__(self, name_bytes, ext_bytes, name2_bytes, children=None,
                 attr=0x10, dos_time=0, dos_date=0):
        self.name_bytes = name_bytes
        self.ext_bytes = ext_bytes
        self.name2_bytes = name2_bytes
        self.children = children or []
        self.attr = attr
        self.dos_time = dos_time
        self.dos_date = dos_date
        self.start_cluster = 0
        self.num_clusters = 0


# ============================================================================
# BPB calculation
# ============================================================================

def solve_fat_recs(partition_records, spc):
    """Iteratively solve for fat_recs and cluster count."""
    reserved = 1
    fat_count = 2
    root_dir_recs = 32  # 1024 entries * 32 bytes / 1024

    fat_recs = 1
    for _ in range(30):
        data_recs = partition_records - reserved - fat_count * fat_recs - root_dir_recs
        clusters = data_recs // spc + 2
        needed = math.ceil(clusters * FAT_ENTRY_SIZE / RECORD_SIZE)
        if needed <= fat_recs:
            return needed, clusters
        fat_recs = needed
    return fat_recs, clusters


def calculate_bpb(partition_records, root_entries=1024):
    """Calculate BPB parameters matching SCSIFORMAT.X behavior.

    Returns (spc, fat_recs, clusters, root_dir_recs).
    """
    root_dir_recs = root_entries * DIR_ENTRY_SIZE // RECORD_SIZE

    # Try SPC=1 first with full FAT16 range (up to 65535 clusters)
    fat_recs, clusters = solve_fat_recs(partition_records, 1)
    if clusters <= 65535 and fat_recs <= 255:
        return 1, fat_recs, clusters, root_dir_recs

    # Need SPC>1: target max 65535 clusters (FAT16 limit)
    for spc in [2, 4, 8, 16, 32, 64, 128]:
        fat_recs, clusters = solve_fat_recs(partition_records, spc)
        if clusters <= 65535 and fat_recs <= 255:
            return spc, fat_recs, clusters, root_dir_recs

    raise ValueError(f"Disk too large: {partition_records} partition records")


# ============================================================================
# Low-level write functions
# ============================================================================

def write_scsi_header(f, total_records, verbose=False):
    """Write SCSI header at sector 0."""
    if verbose:
        print(f"  SCSI header: total_records={total_records}, last_record={total_records - 1}")

    header = bytearray(RECORD_SIZE)

    # +0x00: "X68SCSI1" signature
    header[0x00:0x08] = SCSI_SIGNATURE

    # +0x08: sector size indicator (0x0200)
    struct.pack_into(">H", header, 0x08, 0x0200)

    # +0x0A: total records - 1 (last record number, big-endian 32-bit)
    struct.pack_into(">I", header, 0x0A, total_records - 1)

    # +0x0E: flags (0x0100)
    struct.pack_into(">H", header, 0x0E, 0x0100)

    # +0x10: description string (80 bytes)
    header[0x10:0x10 + len(SCSI_DESCRIPTION)] = SCSI_DESCRIPTION

    f.seek(0)
    f.write(header)


def write_ipl(f, ipl_data, verbose=False):
    """Write IPL boot code at offset 0x400 (sectors 2-3, i.e. record 1)."""
    if verbose:
        print(f"  IPL: {len(ipl_data)} bytes at offset 0x400")

    if len(ipl_data) > RECORD_SIZE:
        raise ValueError(f"IPL data too large: {len(ipl_data)} bytes (max {RECORD_SIZE})")

    padded = ipl_data.ljust(RECORD_SIZE, b"\x00")
    f.seek(0x400)
    f.write(padded)


def write_driver(f, driver_data, verbose=False):
    """Write SASI device driver at offset 0xC00 (record 3 onward)."""
    if verbose:
        print(f"  Driver: {len(driver_data)} bytes at offset 0xC00")

    f.seek(0xC00)
    f.write(driver_data)


def write_partition_table(f, total_records, partition_records, verbose=False):
    """Write partition table at offset 0x800 (sector 4, i.e. record 2)."""
    if verbose:
        print(f"  Partition table: partition_records={partition_records}")

    table = bytearray(RECORD_SIZE)

    last_record = total_records - 1

    # +0x00: "X68K" signature
    table[0x00:0x04] = PARTITION_TABLE_SIGNATURE

    # +0x04, +0x08, +0x0C: total records - 1, repeated 3 times
    struct.pack_into(">I", table, 0x04, last_record)
    struct.pack_into(">I", table, 0x08, last_record)
    struct.pack_into(">I", table, 0x0C, last_record)

    # +0x10: partition name "Human68k"
    table[0x10:0x10 + len(PARTITION_NAME)] = PARTITION_NAME

    # +0x18: partition start record
    struct.pack_into(">I", table, 0x18, PARTITION_START_RECORD)

    # +0x1C: partition records (size of partition)
    struct.pack_into(">I", table, 0x1C, partition_records)

    f.seek(0x800)
    f.write(table)


def write_boot_sector(f, partition_offset, template, spc, fat_recs, partition_records, root_entries=1024, verbose=False):
    """Write partition boot sector with patched BPB fields."""
    if verbose:
        print(f"  Boot sector: spc={spc}, fat_recs={fat_recs}, root_entries={root_entries}")

    boot = bytearray(template)

    # Patch BPB fields (offsets from start of boot sector)
    # +0x12 (2B): bytes per sector
    struct.pack_into(">H", boot, 0x12, RECORD_SIZE)
    # +0x14 (1B): sectors per cluster
    boot[0x14] = spc
    # +0x15 (1B): number of FATs
    boot[0x15] = 2
    # +0x16 (2B): reserved sectors
    struct.pack_into(">H", boot, 0x16, 1)
    # +0x18 (2B): root directory entries
    struct.pack_into(">H", boot, 0x18, root_entries)
    # +0x1A (2B): total sectors 16-bit (unused, 0)
    struct.pack_into(">H", boot, 0x1A, 0)
    # +0x1C (1B): media descriptor
    boot[0x1C] = 0xF7
    # +0x1D (1B): FAT sectors per copy
    boot[0x1D] = fat_recs
    # +0x1E (4B): partition records (big-endian)
    struct.pack_into(">I", boot, 0x1E, partition_records)
    # +0x22 (4B): partition start record (big-endian)
    struct.pack_into(">I", boot, 0x22, PARTITION_START_RECORD)

    f.seek(partition_offset)
    f.write(boot)


def write_fat(f, partition_offset, fat_recs, cluster_chains, verbose=False):
    """Write two copies of the FAT.

    cluster_chains is a list of (start_cluster, num_clusters) tuples.
    Each file occupies sequential clusters from start_cluster.
    """
    fat_size = fat_recs * RECORD_SIZE
    fat = bytearray(fat_size)

    # Entry 0: media descriptor byte + 0xFF
    struct.pack_into(">H", fat, 0, 0xF7FF)
    # Entry 1: end-of-chain marker
    struct.pack_into(">H", fat, 2, 0xFFFF)

    # Write cluster chains for each file
    for start_cluster, num_clusters in cluster_chains:
        for i in range(num_clusters):
            cluster = start_cluster + i
            offset = cluster * FAT_ENTRY_SIZE
            if i < num_clusters - 1:
                # Point to next cluster
                struct.pack_into(">H", fat, offset, cluster + 1)
            else:
                # End-of-chain marker
                struct.pack_into(">H", fat, offset, 0xFFFF)

    # FAT1 starts after reserved sector (1 record)
    fat1_offset = partition_offset + RECORD_SIZE
    # FAT2 starts after FAT1
    fat2_offset = fat1_offset + fat_size

    if verbose:
        print(f"  FAT1 at offset 0x{fat1_offset:X}, FAT2 at 0x{fat2_offset:X} ({fat_recs} records each)")

    f.seek(fat1_offset)
    f.write(fat)
    f.seek(fat2_offset)
    f.write(fat)


# ============================================================================
# Directory entry creation
# ============================================================================

def make_dir_entry(name_bytes, ext_bytes, name2_bytes, attr, start_cluster,
                   file_size, dos_time=0, dos_date=0):
    """Create a 32-byte directory entry.

    name_bytes: 8 bytes (space-padded)
    ext_bytes: 3 bytes (space-padded)
    name2_bytes: 10 bytes (null-padded)
    Note: cluster number and file size are little-endian in directory entries.
    """
    entry = bytearray(DIR_ENTRY_SIZE)

    # +0x00 (8B): filename
    entry[0x00:0x08] = name_bytes
    # +0x08 (3B): extension
    entry[0x08:0x0B] = ext_bytes
    # +0x0B (1B): attributes
    entry[0x0B] = attr
    # +0x0C (10B): fileName2 (Human68k extended name)
    entry[0x0C:0x16] = name2_bytes
    # +0x16 (2B): time (big-endian, as stored on disk)
    struct.pack_into(">H", entry, 0x16, dos_time)
    # +0x18 (2B): date (big-endian, as stored on disk)
    struct.pack_into(">H", entry, 0x18, dos_date)
    # +0x1A (2B): start cluster (little-endian)
    struct.pack_into("<H", entry, 0x1A, start_cluster)
    # +0x1C (4B): file size (little-endian)
    struct.pack_into("<I", entry, 0x1C, file_size)

    return entry


# ============================================================================
# Filename parsing
# ============================================================================

def parse_human68k_filename(filename):
    """Parse a UTF-8 filename into Human68k directory entry fields.

    Returns (name_bytes[8], ext_bytes[3], name2_bytes[10]).
    Raises ValueError if the filename can't be encoded.

    Handles surrogate escapes (from raw bytes in filesystem filenames)
    by recovering the original byte values directly.
    """
    # First try to recover any raw bytes from surrogate escapes,
    # then re-encode as cp932. If the filename contains surrogates
    # (from fsck extracting raw Shift-JIS bytes), the raw bytes are
    # already SJIS — recover them via latin-1 round-trip.
    try:
        raw = filename.encode("utf-8", errors="surrogateescape")
    except UnicodeEncodeError:
        raise ValueError(f"Cannot encode '{filename!r}'")

    # raw is now the byte representation: valid UTF-8 for normal chars,
    # raw bytes for surrogate-escaped ones. Decode as SJIS → re-encode.
    # Actually, we need to convert UTF-8 portions to SJIS.
    # Strategy: try cp932 first; if it fails, do char-by-char conversion.
    try:
        sjis = filename.encode("cp932")
    except (UnicodeEncodeError, UnicodeDecodeError):
        # Contains surrogates or unencodable chars — build SJIS byte-by-byte
        parts = []
        for ch in filename:
            cp = ord(ch)
            if 0xDC80 <= cp <= 0xDCFF:
                # Surrogate escape: raw byte value is cp - 0xDC00
                parts.append(bytes([cp - 0xDC00]))
            else:
                try:
                    parts.append(ch.encode("cp932"))
                except UnicodeEncodeError:
                    raise ValueError(f"Cannot encode '{filename!r}' to Shift-JIS")
        sjis = b"".join(parts)

    # Find the last dot for extension split
    dot_pos = sjis.rfind(b".")
    if dot_pos > 0:
        name_part = sjis[:dot_pos]
        ext_part = sjis[dot_pos + 1:]
    else:
        name_part = sjis
        ext_part = b""

    if len(name_part) == 0:
        raise ValueError(f"Empty name in '{filename}'")
    if len(name_part) > 18:
        raise ValueError(f"Name too long ({len(name_part)} SJIS bytes, max 18) in '{filename}'")
    if len(ext_part) > 3:
        raise ValueError(f"Extension too long ({len(ext_part)} SJIS bytes, max 3) in '{filename}'")

    # Build name_bytes (8), name2_bytes (10)
    name_bytes = bytearray(8)
    name2_bytes = bytearray(10)

    copy_to_name = min(len(name_part), 8)
    name_bytes[:copy_to_name] = name_part[:copy_to_name]
    # Space-pad the remainder
    for i in range(copy_to_name, 8):
        name_bytes[i] = 0x20

    if len(name_part) > 8:
        overflow = len(name_part) - 8
        name2_bytes[:overflow] = name_part[8:8 + overflow]
        # Rest already zero

    # Build ext_bytes (3)
    ext_bytes = bytearray(3)
    copy_to_ext = min(len(ext_part), 3)
    ext_bytes[:copy_to_ext] = ext_part[:copy_to_ext]
    for i in range(copy_to_ext, 3):
        ext_bytes[i] = 0x20

    # Preserve case as-is (Human68k is case-insensitive but case-preserving)

    # Handle 0xE5 first-byte substitution
    if name_bytes[0] == 0xE5:
        name_bytes[0] = 0x05

    return bytes(name_bytes), bytes(ext_bytes), bytes(name2_bytes)


def name_bytes_to_str(name_bytes, ext_bytes, name2_bytes):
    """Convert parsed name fields back to a display string for diagnostics."""
    name = name_bytes.rstrip(b" ")
    name2 = name2_bytes.rstrip(b"\x00")
    ext = ext_bytes.rstrip(b" ")
    full = name + name2
    if full[0:1] == b"\x05":
        full = b"\xe5" + full[1:]
    if ext:
        full += b"." + ext
    try:
        return full.decode("cp932")
    except UnicodeDecodeError:
        return full.decode("latin-1")


# ============================================================================
# Metadata loading
# ============================================================================

def load_metadata(meta_path):
    """Load .x68k_meta file and return:
    - dict mapping path -> (attr, time, date)
    - dict mapping directory prefix -> [ordered entry names]

    The order dict maps each directory prefix (e.g. "" for root, "subdir/")
    to a list of entry names in their original disk order.
    """
    meta = {}
    order = {}
    if not os.path.isfile(meta_path):
        return meta, order
    with open(meta_path, "r", encoding="utf-8", errors="surrogateescape") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) != 4:
                continue
            path, attr_hex, time_hex, date_hex = parts
            try:
                meta[path] = (int(attr_hex, 16), int(time_hex, 16), int(date_hex, 16))
            except ValueError:
                continue

            # Build ordering: find the directory prefix and entry name
            # For "dir/subdir/file.txt", prefix is "dir/subdir/", name is "file.txt"
            # For "dir/", prefix is "", name is "dir/"
            if path.endswith("/"):
                # Directory entry
                stripped = path[:-1]
                slash_pos = stripped.rfind("/")
                if slash_pos >= 0:
                    prefix = stripped[:slash_pos + 1]
                    entry_name = stripped[slash_pos + 1:]
                else:
                    prefix = ""
                    entry_name = stripped
            else:
                slash_pos = path.rfind("/")
                if slash_pos >= 0:
                    prefix = path[:slash_pos + 1]
                    entry_name = path[slash_pos + 1:]
                else:
                    prefix = ""
                    entry_name = path

            if prefix not in order:
                order[prefix] = []
            order[prefix].append(entry_name)

    return meta, order


# ============================================================================
# Tree loading
# ============================================================================

def mtime_to_dos(mtime):
    """Convert a Unix mtime to DOS time and date words."""
    t = time.localtime(mtime)
    dos_time = (t.tm_hour << 11) | (t.tm_min << 5) | (t.tm_sec // 2)
    dos_date = ((t.tm_year - 1980) << 9) | (t.tm_mon << 5) | t.tm_mday
    return dos_time, dos_date


def load_extra_tree(directory):
    """Load all files and directories recursively from a host directory.

    Returns (tree_entries, human_data_or_None, command_data_or_None,
             human_meta, command_meta).

    human_meta and command_meta are (attr, time, date) tuples or None.
    """
    if not os.path.isdir(directory):
        print(f"Error: extra files directory not found: {directory}", file=sys.stderr)
        sys.exit(1)

    meta_path = os.path.join(directory, ".x68k_meta")
    meta, meta_order = load_metadata(meta_path)

    human_data = None
    command_data = None
    human_meta = None
    command_meta = None

    def build_tree(host_dir, rel_prefix):
        nonlocal human_data, command_data, human_meta, command_meta
        entries = []

        try:
            items_list = list(os.scandir(host_dir))
        except OSError as exc:
            print(f"Warning: cannot read directory {host_dir}: {exc}", file=sys.stderr)
            return entries

        # Sort by metadata order if available, otherwise alphabetically
        dir_order = meta_order.get(rel_prefix)
        if dir_order:
            order_map = {name: idx for idx, name in enumerate(dir_order)}
            items_list.sort(key=lambda e: order_map.get(e.name, len(dir_order)))
        else:
            items_list.sort(key=lambda e: e.name)

        for item in items_list:
            if item.name == ".x68k_meta":
                continue

            try:
                name_bytes, ext_bytes, name2_bytes = parse_human68k_filename(item.name)
            except ValueError as exc:
                print(f"Warning: skipping {item.path}: {exc}", file=sys.stderr)
                continue

            if item.is_dir(follow_symlinks=False):
                rel_path = rel_prefix + item.name + "/"
                meta_entry = meta.get(rel_path)
                if meta_entry:
                    attr, dos_time, dos_date = meta_entry
                else:
                    attr = 0x10
                    dos_time, dos_date = mtime_to_dos(item.stat().st_mtime)

                children = build_tree(item.path, rel_path)
                d = DirEntry(name_bytes, ext_bytes, name2_bytes, children,
                             attr, dos_time, dos_date)
                entries.append(d)

            elif item.is_file(follow_symlinks=False):
                rel_path = rel_prefix + item.name
                meta_entry = meta.get(rel_path)
                if meta_entry:
                    attr, dos_time, dos_date = meta_entry
                else:
                    attr = 0x20
                    dos_time, dos_date = mtime_to_dos(item.stat().st_mtime)

                with open(item.path, "rb") as fh:
                    data = fh.read()

                # Detect HUMAN.SYS and COMMAND.X at root level
                if rel_prefix == "":
                    upper = item.name.upper()
                    if upper == "HUMAN.SYS":
                        human_data = data
                        human_meta = meta_entry  # None if no metadata
                        continue
                    elif upper == "COMMAND.X":
                        command_data = data
                        command_meta = meta_entry  # None if no metadata
                        continue

                fe = FileEntry(name_bytes, ext_bytes, name2_bytes, data,
                               attr, dos_time, dos_date)
                entries.append(fe)

        return entries

    tree = build_tree(directory, "")
    return tree, human_data, command_data, human_meta, command_meta


# ============================================================================
# Cluster allocation
# ============================================================================

def allocate_clusters(entries, next_cluster, cluster_size):
    """Allocate clusters for all entries depth-first.

    For DirEntry: allocates clusters for subdirectory data, then recurses.
    For FileEntry: allocates clusters for file data.

    Returns updated next_cluster.
    """
    for entry in entries:
        if isinstance(entry, DirEntry):
            # Subdirectory needs (len(children)+2) entries for ., .., and children
            subdir_bytes = (len(entry.children) + 2) * DIR_ENTRY_SIZE
            entry.num_clusters = max(1, math.ceil(subdir_bytes / cluster_size))
            entry.start_cluster = next_cluster
            next_cluster += entry.num_clusters
            # Recurse into children
            next_cluster = allocate_clusters(entry.children, next_cluster, cluster_size)
        else:
            entry.num_clusters = max(1, math.ceil(len(entry.data) / cluster_size))
            entry.start_cluster = next_cluster
            next_cluster += entry.num_clusters
    return next_cluster


def collect_cluster_chains(entries):
    """Collect all (start, count) cluster chain tuples from the tree, depth-first."""
    chains = []
    for entry in entries:
        if isinstance(entry, DirEntry):
            if entry.num_clusters > 0:
                chains.append((entry.start_cluster, entry.num_clusters))
            chains.extend(collect_cluster_chains(entry.children))
        else:
            if entry.num_clusters > 0:
                chains.append((entry.start_cluster, entry.num_clusters))
    return chains


# ============================================================================
# Subdirectory and data writing
# ============================================================================

def build_subdir_data(dir_entry, parent_cluster, cluster_size):
    """Build subdirectory data containing . , .. , and child entries."""
    num_entries = len(dir_entry.children) + 2
    buf_size = max(num_entries * DIR_ENTRY_SIZE, dir_entry.num_clusters * cluster_size)
    buf = bytearray(buf_size)

    # "." entry - points to self
    dot_name = b".       "
    dot_ext = b"   "
    dot_name2 = b"\x00" * 10
    dot = make_dir_entry(dot_name, dot_ext, dot_name2, 0x10,
                         dir_entry.start_cluster, 0,
                         dir_entry.dos_time, dir_entry.dos_date)
    buf[0:32] = dot

    # ".." entry - points to parent (0 means root)
    dotdot_name = b"..      "
    dotdot_ext = b"   "
    dotdot_name2 = b"\x00" * 10
    dotdot = make_dir_entry(dotdot_name, dotdot_ext, dotdot_name2, 0x10,
                            parent_cluster, 0,
                            dir_entry.dos_time, dir_entry.dos_date)
    buf[32:64] = dotdot

    # Child entries
    for i, child in enumerate(dir_entry.children):
        if isinstance(child, DirEntry):
            entry = make_dir_entry(child.name_bytes, child.ext_bytes, child.name2_bytes,
                                   child.attr, child.start_cluster, 0,
                                   child.dos_time, child.dos_date)
        else:
            entry = make_dir_entry(child.name_bytes, child.ext_bytes, child.name2_bytes,
                                   child.attr, child.start_cluster, len(child.data),
                                   child.dos_time, child.dos_date)
        offset = (i + 2) * DIR_ENTRY_SIZE
        buf[offset:offset + DIR_ENTRY_SIZE] = entry

    return buf


def write_tree_data(f, data_offset, cluster_size, entries, parent_cluster, verbose=False):
    """Write all subdirectory and file data for entries, recursively."""
    for entry in entries:
        if isinstance(entry, DirEntry):
            subdir_data = build_subdir_data(entry, parent_cluster, cluster_size)
            file_offset = data_offset + (entry.start_cluster - 2) * cluster_size
            f.seek(file_offset)
            f.write(subdir_data)
            if verbose:
                name = name_bytes_to_str(entry.name_bytes, entry.ext_bytes, entry.name2_bytes)
                print(f"  Subdir {name}/: {len(subdir_data)} bytes at offset 0x{file_offset:X} "
                      f"(cluster {entry.start_cluster})")
            # Recurse into children
            write_tree_data(f, data_offset, cluster_size, entry.children,
                            entry.start_cluster, verbose)
        else:
            if entry.data:
                file_offset = data_offset + (entry.start_cluster - 2) * cluster_size
                f.seek(file_offset)
                f.write(entry.data)
                # Pad to cluster boundary
                remainder = len(entry.data) % cluster_size
                if remainder:
                    f.write(b"\x00" * (cluster_size - remainder))


def count_tree_entries(entries):
    """Count total directory entries including subdirectories (root level only)."""
    return len(entries)


def count_all_entries(entries):
    """Count all files and directories in the tree recursively."""
    total = 0
    for entry in entries:
        total += 1
        if isinstance(entry, DirEntry):
            total += count_all_entries(entry.children)
    return total


# ============================================================================
# Root directory writing
# ============================================================================

def write_root_directory(f, partition_offset, fat_recs, root_dir_recs, root_entries_list, verbose=False):
    """Write root directory entries.

    root_entries_list contains pre-built 32-byte directory entry bytearrays.
    """
    root_offset = partition_offset + RECORD_SIZE + fat_recs * RECORD_SIZE * 2
    root_size = root_dir_recs * RECORD_SIZE

    if verbose:
        print(f"  Root directory at offset 0x{root_offset:X} ({root_dir_recs} records)")

    root = bytearray(root_size)

    for i, entry_bytes in enumerate(root_entries_list):
        offset = i * DIR_ENTRY_SIZE
        root[offset:offset + DIR_ENTRY_SIZE] = entry_bytes

    f.seek(root_offset)
    f.write(root)


def write_file_data(f, data_offset, cluster_size, file_data, start_cluster, verbose=False):
    """Write file contents to sequential clusters starting from start_cluster."""
    file_offset = data_offset + (start_cluster - 2) * cluster_size

    if verbose:
        print(f"  File data: {len(file_data)} bytes at offset 0x{file_offset:X} (cluster {start_cluster})")

    f.seek(file_offset)
    f.write(file_data)

    # Pad to cluster boundary
    remainder = len(file_data) % cluster_size
    if remainder:
        f.write(b"\x00" * (cluster_size - remainder))


# ============================================================================
# File loading helpers
# ============================================================================

def load_file(path, description):
    """Load a binary file, raising a clear error if not found."""
    if not os.path.isfile(path):
        print(f"Error: {description} not found: {path}", file=sys.stderr)
        sys.exit(1)
    with open(path, "rb") as fh:
        return fh.read()


# ============================================================================
# Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Format a file as a bootable X68000 SxSI disk image"
    )
    parser.add_argument("image_file", help="Existing file to format as SxSI disk image")
    parser.add_argument("--ipl", default=os.path.join(DATA_DIR, "ipl.bin"),
                        help="Custom IPL binary (default: data/ipl.bin)")
    parser.add_argument("--boot-sector", default=os.path.join(DATA_DIR, "bootsect.bin"),
                        help="Custom partition boot sector template (default: data/bootsect.bin)")
    parser.add_argument("--human-sys", default=os.path.join(DATA_DIR, "HUMAN.SYS"),
                        help="Custom HUMAN.SYS (default: data/HUMAN.SYS)")
    parser.add_argument("--command-x", default=os.path.join(DATA_DIR, "COMMAND.X"),
                        help="Custom COMMAND.X (default: data/COMMAND.X)")
    parser.add_argument("--driver", default=os.path.join(DATA_DIR, "driver.bin"),
                        help="Custom SASI device driver (default: data/driver.bin)")
    parser.add_argument("--no-ipl", action="store_true",
                        help="Don't write IPL code")
    parser.add_argument("--root-entries", type=int, default=1024,
                        help="Root directory entries (default: 1024, must be multiple of 32)")
    parser.add_argument("--extra-files", metavar="DIR",
                        help="Install additional files/directories from directory")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show detailed output")
    parser.add_argument("-n", "--dry-run", action="store_true",
                        help="Show what would be written without modifying the image")

    args = parser.parse_args()

    # Validate root entries
    if args.root_entries % 32 != 0 or args.root_entries < 32:
        print("Error: --root-entries must be a positive multiple of 32", file=sys.stderr)
        sys.exit(1)

    # Get image file size
    if not os.path.isfile(args.image_file):
        print(f"Error: image file not found: {args.image_file}", file=sys.stderr)
        sys.exit(1)

    file_size = os.path.getsize(args.image_file)
    min_size = 8 * 1024 * 1024  # 8 MB minimum
    if file_size < min_size:
        print(f"Error: image too small ({file_size} bytes, minimum {min_size} = 8 MB)", file=sys.stderr)
        sys.exit(1)
    if file_size % RECORD_SIZE != 0:
        print(f"Error: image size ({file_size}) must be a multiple of {RECORD_SIZE}", file=sys.stderr)
        sys.exit(1)

    total_records = file_size // RECORD_SIZE
    partition_records = total_records - 33

    # Calculate BPB parameters
    spc, fat_recs, clusters, root_dir_recs = calculate_bpb(partition_records, args.root_entries)
    cluster_size = spc * RECORD_SIZE

    print(f"Image: {args.image_file} ({file_size} bytes, {total_records} records)")
    print(f"Partition: {partition_records} records, SPC={spc}, FAT={fat_recs} recs/copy, {clusters} clusters")

    # Load data files
    driver_data = load_file(args.driver, "SASI device driver")
    if not args.no_ipl:
        ipl_data = load_file(args.ipl, "IPL binary")
    boot_template = load_file(args.boot_sector, "Boot sector template")
    if len(boot_template) != RECORD_SIZE:
        print(f"Error: boot sector template must be {RECORD_SIZE} bytes", file=sys.stderr)
        sys.exit(1)

    # Load HUMAN.SYS and COMMAND.X defaults
    human_data = load_file(args.human_sys, "HUMAN.SYS")
    command_data = load_file(args.command_x, "COMMAND.X")
    human_attr, human_time, human_date = 0x24, 0x1C8D, 0x4457
    command_attr, command_time, command_date = 0x20, 0x0893, 0xB544

    # Load extra files tree
    extra_tree = []
    if args.extra_files:
        extra_tree, extra_human, extra_command, human_meta, command_meta = \
            load_extra_tree(args.extra_files)

        # Replace HUMAN.SYS/COMMAND.X if found in extra files
        if extra_human is not None:
            human_data = extra_human
            if human_meta:
                human_attr, human_time, human_date = human_meta
            print(f"HUMAN.SYS: replaced from {args.extra_files} ({len(human_data)} bytes)")
        if extra_command is not None:
            command_data = extra_command
            if command_meta:
                command_attr, command_time, command_date = command_meta
            print(f"COMMAND.X: replaced from {args.extra_files} ({len(command_data)} bytes)")

        total_extra = count_all_entries(extra_tree)
        if total_extra:
            print(f"Extra entries: {total_extra} from {args.extra_files}")

    # Calculate cluster allocations
    # HUMAN.SYS always first (contiguous at cluster 2)
    human_clusters = math.ceil(len(human_data) / cluster_size)
    human_start = 2
    command_start = human_start + human_clusters
    command_clusters = math.ceil(len(command_data) / cluster_size)
    next_cluster = command_start + command_clusters

    # Allocate clusters for extra tree
    next_cluster = allocate_clusters(extra_tree, next_cluster, cluster_size)

    if args.verbose:
        print(f"HUMAN.SYS: {len(human_data)} bytes, clusters {human_start}-{human_start + human_clusters - 1}")
        print(f"COMMAND.X: {len(command_data)} bytes, clusters {command_start}-{command_start + command_clusters - 1}")

    # Count root directory entries: HUMAN.SYS + COMMAND.X + extra tree root entries
    root_entry_count = 2 + count_tree_entries(extra_tree)
    if root_entry_count > args.root_entries:
        print(f"Error: too many root entries ({root_entry_count}) for root directory "
              f"({args.root_entries} max)", file=sys.stderr)
        sys.exit(1)

    if next_cluster - 2 > clusters - 2:
        print(f"Error: files need {next_cluster - 2} clusters but only {clusters - 2} available",
              file=sys.stderr)
        sys.exit(1)

    if args.dry_run:
        print("\nDry run - no changes made.")
        return

    # Compute offsets
    partition_offset = PARTITION_START_RECORD * RECORD_SIZE
    data_offset = partition_offset + RECORD_SIZE + fat_recs * RECORD_SIZE * 2 + root_dir_recs * RECORD_SIZE

    # Format the image
    with open(args.image_file, "r+b") as f:
        print("\nFormatting...")

        write_scsi_header(f, total_records, args.verbose)

        if not args.no_ipl:
            write_ipl(f, ipl_data, args.verbose)

        write_partition_table(f, total_records, partition_records, args.verbose)

        write_driver(f, driver_data, args.verbose)

        write_boot_sector(f, partition_offset, boot_template, spc, fat_recs,
                          partition_records, args.root_entries, args.verbose)

        # Build cluster chains: HUMAN.SYS, COMMAND.X, then extra tree
        cluster_chains = [
            (human_start, human_clusters),
            (command_start, command_clusters),
        ]
        cluster_chains.extend(collect_cluster_chains(extra_tree))
        write_fat(f, partition_offset, fat_recs, cluster_chains, args.verbose)

        # Build root directory entries
        human_name = b"HUMAN   "
        human_ext = b"SYS"
        human_name2 = b"\x00" * 10
        command_name = b"COMMAND "
        command_ext = b"X  "
        command_name2 = b"\x00" * 10

        root_entries_list = [
            make_dir_entry(human_name, human_ext, human_name2,
                           human_attr, human_start, len(human_data),
                           human_time, human_date),
            make_dir_entry(command_name, command_ext, command_name2,
                           command_attr, command_start, len(command_data),
                           command_time, command_date),
        ]

        # Add extra tree root-level entries
        for entry in extra_tree:
            if isinstance(entry, DirEntry):
                root_entries_list.append(
                    make_dir_entry(entry.name_bytes, entry.ext_bytes, entry.name2_bytes,
                                   entry.attr, entry.start_cluster, 0,
                                   entry.dos_time, entry.dos_date))
            else:
                root_entries_list.append(
                    make_dir_entry(entry.name_bytes, entry.ext_bytes, entry.name2_bytes,
                                   entry.attr, entry.start_cluster, len(entry.data),
                                   entry.dos_time, entry.dos_date))

        write_root_directory(f, partition_offset, fat_recs, root_dir_recs,
                             root_entries_list, args.verbose)

        # Write file data
        write_file_data(f, data_offset, cluster_size, human_data, human_start, args.verbose)
        write_file_data(f, data_offset, cluster_size, command_data, command_start, args.verbose)

        # Write extra tree data (subdirectories and files)
        write_tree_data(f, data_offset, cluster_size, extra_tree, 0, args.verbose)

    print("Done.")


if __name__ == "__main__":
    main()

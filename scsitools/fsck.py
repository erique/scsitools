#!/usr/bin/env python3
"""
fsck.py - X68000 Filesystem Checker

Reads and checks X68000 Human68k disk images (SxSI/SCSI format).
Supports filesystem checking, directory listing, file extraction,
and write operations (add, mkdir, rm).
"""

import argparse
import os
import struct
import sys
import time

# =============================================================================
# Constants
# =============================================================================

SECTOR_SIZE = 512
SCSI_SIGNATURE = b"X68SCSI1"
SXSI_SIGNATURE = b"SxSI"
SXSI_MARKER_OFFSET = 0x2A
PARTITION_SIGNATURE = b"X68K"
MAX_PARTITIONS = 15
LFN_ATTR = 0x0F

# FAT entry type
FAT_TYPE_LINKING = 0
FAT_TYPE_END = 1
FAT_TYPE_FREE = 2
FAT_TYPE_OTHERS = 3

# FAT refer status
FAT_REFER_OK = 0
FAT_REFER_FIXED = 1
FAT_REFER_END = 2
FAT_REFER_OUTOF = 3

# FAT refered status
FAT_REFERED_NO = 0
FAT_REFERED_ONE = 1
FAT_REFERED_MANY = 2
FAT_REFERED_FIXED = 3

# FAT loop status
FAT_LOOP_UNDECIDED = 0
FAT_LOOP_YES = 1
FAT_LOOP_NO = 2
FAT_LOOP_IN_SEARCH = 3

# FAT bad sector
FAT_BADSEC_OK = 0
FAT_BADSEC_YES = 1

# FAT subdir
FAT_SUBDIR_NOTYET = 0
FAT_SUBDIR_ALREADY = 1

# Attribute flags
ATTR_READONLY = 0x01
ATTR_HIDDEN = 0x02
ATTR_SYSTEM = 0x04
ATTR_VOLUME = 0x08
ATTR_DIRECTORY = 0x10
ATTR_ARCHIVE = 0x20

# Write error codes
WRITE_OK = 0
WRITE_ERR_DISK_FULL = -1
WRITE_ERR_DIR_FULL = -2
WRITE_ERR_PATH_NOT_FOUND = -3
WRITE_ERR_FILE_EXISTS = -4
WRITE_ERR_INVALID_NAME = -5
WRITE_ERR_READ_ERROR = -6
WRITE_ERR_WRITE_ERROR = -7
WRITE_ERR_NOT_FOUND = -8
WRITE_ERR_IS_DIRECTORY = -9

# =============================================================================
# Data structures
# =============================================================================

class FATEntry:
    __slots__ = ("value", "type", "refer", "refered", "loop", "badsec", "subdir")

    def __init__(self):
        self.value = 0
        self.type = FAT_TYPE_FREE
        self.refer = FAT_REFER_END
        self.refered = FAT_REFERED_NO
        self.loop = FAT_LOOP_UNDECIDED
        self.badsec = FAT_BADSEC_OK
        self.subdir = FAT_SUBDIR_NOTYET


class DiskInfo:
    def __init__(self, fp, partition_offset):
        self.fp = fp
        self.partition_offset = partition_offset
        self.sector_size = SECTOR_SIZE
        self.sectors_per_cluster = 2
        self.fat_top = 0
        self.fat_sectors = 0
        self.fat_count = 2
        self.root_top = 0
        self.root_sectors = 0
        self.data_top = 0
        self.cluster_num = 0
        self.cluster_length = 0
        self.little_endian = False
        self.is_2bytes = True
        self.fat = None
        self.writing = False


class DirEntryInfo:
    __slots__ = ("name", "attr", "cluster", "size", "time_val", "date_val",
                 "raw_name8", "raw_ext3", "raw_name2")

    def __init__(self):
        self.name = ""
        self.attr = 0
        self.cluster = 0
        self.size = 0
        self.time_val = 0
        self.date_val = 0
        self.raw_name8 = b""
        self.raw_ext3 = b""
        self.raw_name2 = b""


# =============================================================================
# Disk I/O
# =============================================================================

def read_sector(disk, sector, count=1):
    offset = disk.partition_offset + sector * SECTOR_SIZE
    disk.fp.seek(offset)
    return disk.fp.read(count * SECTOR_SIZE)


def write_sector(disk, sector, data):
    offset = disk.partition_offset + sector * SECTOR_SIZE
    disk.fp.seek(offset)
    disk.fp.write(data)
    disk.fp.flush()


def read_cluster(disk, cluster):
    if cluster < 2 or cluster >= disk.cluster_num:
        return b"\x00" * disk.cluster_length
    sector = disk.data_top + (cluster - 2) * disk.sectors_per_cluster
    return read_sector(disk, sector, disk.sectors_per_cluster)


def write_cluster(disk, cluster, data):
    if cluster < 2 or cluster >= disk.cluster_num:
        return
    sector = disk.data_top + (cluster - 2) * disk.sectors_per_cluster
    write_sector(disk, sector, data)


def read_raw_sector(fp, sector):
    fp.seek(sector * SECTOR_SIZE)
    return fp.read(SECTOR_SIZE)


# =============================================================================
# Byte reading helpers
# =============================================================================

def read_be16(data, offset=0):
    return struct.unpack_from(">H", data, offset)[0]


def read_be32(data, offset=0):
    return struct.unpack_from(">I", data, offset)[0]


def read_le16(data, offset=0):
    return struct.unpack_from("<H", data, offset)[0]


def read_le32(data, offset=0):
    return struct.unpack_from("<I", data, offset)[0]


# =============================================================================
# Partition parsing
# =============================================================================

def check_scsi_header(fp):
    buf = read_raw_sector(fp, 0)
    if len(buf) < SECTOR_SIZE:
        return 0
    if buf[:8] != SCSI_SIGNATURE:
        print("Warning: Not an X68000 SCSI disk image (missing X68SCSI1 signature)",
              file=sys.stderr)
        return 0
    bytes_per_record = read_be16(buf, 0x08)
    disk_end_record = read_be32(buf, 0x0A) + 1
    sxsi = buf[SXSI_MARKER_OFFSET:SXSI_MARKER_OFFSET + 4] == SXSI_SIGNATURE
    if sxsi:
        disk_end_record <<= 1
    return disk_end_record * (bytes_per_record // SECTOR_SIZE)


def parse_partition_table(fp):
    buf = read_raw_sector(fp, 4)
    if len(buf) < SECTOR_SIZE:
        return None
    if buf[:4] != PARTITION_SIGNATURE:
        print("Error: Invalid partition table (missing X68K signature)", file=sys.stderr)
        return None

    total_sectors = (read_be32(buf, 4) + 1) * 2
    partitions = []
    p = 16
    for i in range(MAX_PARTITIONS):
        name = buf[p:p + 8]
        start_sector = read_be32(buf, p + 8) * 2
        sector_count = read_be32(buf, p + 12) * 2
        partitions.append({
            "name": name,
            "start_sector": start_sector,
            "sector_count": sector_count,
        })
        p += 16

    return {"signature": buf[:4], "total_sectors": total_sectors, "partitions": partitions}


def parse_bpb(fp, partition_offset, partition_sectors):
    fp.seek(partition_offset)
    buf = fp.read(1024)
    if len(buf) < 1024:
        return None
    if buf[0] != 0x60:
        return None

    bps = read_be16(buf, 0x12)
    spc_records = buf[0x14]
    fat_count = buf[0x15]
    reserved_records = read_be16(buf, 0x16)
    root_entries = read_be16(buf, 0x18)
    media = buf[0x1C]
    fat_records_per_copy = buf[0x1D]

    if (bps != 1024 or spc_records == 0 or fat_count == 0 or
            reserved_records == 0 or root_entries == 0 or
            fat_records_per_copy == 0 or media != 0xF7):
        return None

    fat_start_sector = reserved_records * 2
    fat_sector_per_copy = fat_records_per_copy * 2
    root_start_sector = (reserved_records + fat_count * fat_records_per_copy) * 2
    root_sector_num = (root_entries * 32 + SECTOR_SIZE - 1) // SECTOR_SIZE
    data_start_sector = root_start_sector + root_sector_num
    spc_sectors = spc_records * 2

    data_sectors = partition_sectors - data_start_sector
    cluster_num = data_sectors // spc_sectors + 2

    max_from_fat = (fat_sector_per_copy * SECTOR_SIZE) // 2
    if cluster_num > max_from_fat:
        cluster_num = max_from_fat

    return {
        "sectors_per_cluster": spc_sectors,
        "fat_top": fat_start_sector,
        "fat_sectors": fat_sector_per_copy,
        "fat_count": fat_count,
        "root_top": root_start_sector,
        "root_sectors": root_sector_num,
        "data_top": data_start_sector,
        "cluster_num": cluster_num,
    }


def parse_partition(fp, partition_index):
    scsi_total = check_scsi_header(fp)
    table = parse_partition_table(fp)
    if table is None:
        return None

    if partition_index < 0 or partition_index >= MAX_PARTITIONS:
        print(f"Error: Invalid partition index {partition_index}", file=sys.stderr)
        return None

    part = table["partitions"][partition_index]
    if part["sector_count"] == 0:
        print(f"Error: Partition {partition_index} is empty", file=sys.stderr)
        return None

    partition_offset = part["start_sector"] * SECTOR_SIZE
    disk = DiskInfo(fp, partition_offset)

    bpb = parse_bpb(fp, partition_offset, part["sector_count"])
    if bpb is None:
        print("Error: Failed to parse BPB", file=sys.stderr)
        return None

    disk.sectors_per_cluster = bpb["sectors_per_cluster"]
    disk.fat_top = bpb["fat_top"]
    disk.fat_sectors = bpb["fat_sectors"]
    disk.fat_count = bpb["fat_count"]
    disk.root_top = bpb["root_top"]
    disk.root_sectors = bpb["root_sectors"]
    disk.data_top = bpb["data_top"]
    disk.cluster_num = bpb["cluster_num"]
    disk.cluster_length = disk.sectors_per_cluster * SECTOR_SIZE

    return disk


# =============================================================================
# Partition info display
# =============================================================================

def print_partitions(fp):
    print("=== Sector 0: SCSI Header (offset 0x000) ===\n")

    buf = read_raw_sector(fp, 0)
    scsi_total = 0
    sector_size = SECTOR_SIZE

    if len(buf) >= SECTOR_SIZE and buf[:8] == SCSI_SIGNATURE:
        print(f"  Signature:    {buf[:8].decode('ascii', errors='replace')} (valid X68000 SCSI disk)")
        sector_size = read_be16(buf, 0x08)
        disk_end_record = read_be32(buf, 0x0A) + 1
        sxsi = buf[SXSI_MARKER_OFFSET:SXSI_MARKER_OFFSET + 4] == SXSI_SIGNATURE
        if sxsi:
            disk_end_record <<= 1
        scsi_total = disk_end_record * (sector_size // SECTOR_SIZE)
        print(f"  Bytes/record: {sector_size} (offset 0x08)")
        sxsi_note = " (SxSI: doubled from 1024-byte count)" if sxsi else ""
        print(f"  Records:      {disk_end_record}{sxsi_note}")
        print(f"  Total sectors: {scsi_total} (512-byte)")
        print(f"  Disk size:    {scsi_total * SECTOR_SIZE / (1024 * 1024):.2f} MB")
    else:
        print("  WARNING: Missing X68SCSI1 signature!")

    print()
    print("=== Sectors 2-3: IPL Boot Code (offset 0x400-0x7FF) ===\n")

    ipl_buf = read_raw_sector(fp, 2) + read_raw_sector(fp, 3)
    if len(ipl_buf) >= 1024:
        if ipl_buf[0] == 0x60 and ipl_buf[1] == 0x00:
            print("  Status: IPL code present")
            ipl_valid = True
        elif ipl_buf[0] == 0x00 and ipl_buf[1] == 0x00 and ipl_buf[2] == 0x00 and ipl_buf[3] == 0x00:
            print("  Status: EMPTY (no IPL code present)")
            ipl_valid = False
        else:
            print(f"  First bytes: {ipl_buf[0]:02X} {ipl_buf[1]:02X} {ipl_buf[2]:02X} {ipl_buf[3]:02X}")
            ipl_valid = False
    else:
        ipl_valid = False

    print()
    print("=== Sector 4: Partition Table (offset 0x800) ===\n")

    table = parse_partition_table(fp)
    if table is None:
        print("  ERROR: Could not read partition table")
        return

    sig = table["signature"].decode("ascii", errors="replace")
    valid = " (valid)" if table["signature"] == PARTITION_SIGNATURE else " (INVALID!)"
    print(f"  Signature:       {sig}{valid}")
    print(f"  Total sectors:   {table['total_sectors']}")
    print()

    print("=== Partitions ===\n")

    part_count = 0
    for i, part in enumerate(table["partitions"]):
        if part["sector_count"] == 0:
            continue
        part_count += 1

        name = part["name"].rstrip(b"\x00").decode("ascii", errors="replace")
        start = part["start_sector"]
        count = part["sector_count"]
        byte_offset = start * sector_size

        print(f"  Partition {i}: \"{name}\"")
        print(f"    Start sector:  {start} (offset 0x{byte_offset:X})")
        print(f"    Sector count:  {count} ({count * sector_size / (1024 * 1024):.2f} MB)")

        partition_offset = byte_offset
        bpb = parse_bpb(fp, partition_offset, count)
        if bpb is not None:
            print(f"    Sectors/clust: {bpb['sectors_per_cluster']}")
            print(f"    FAT start:     sector {bpb['fat_top']} ({bpb['fat_count']} copies)")
            print(f"    FAT size:      {bpb['fat_sectors']} sectors/copy")
            print(f"    Root dir:      sector {bpb['root_top']} ({bpb['root_sectors']} sectors)")
            print(f"    Data area:     sector {bpb['data_top']}")
            print(f"    Clusters:      {bpb['cluster_num']}")

            # Check for volume label in root directory
            root_offset = partition_offset + bpb['root_top'] * SECTOR_SIZE
            root_size = bpb['root_sectors'] * SECTOR_SIZE
            fp.seek(root_offset)
            root_data = fp.read(root_size)
            for ri in range(len(root_data) // 32):
                raw = root_data[ri * 32:(ri + 1) * 32]
                if raw[0] == 0x00:
                    break
                if raw[0] == 0xE5:
                    continue
                if raw[11] == 0x08:
                    label = decode_sjis(raw[0:11]).rstrip()
                    print(f"    Volume label:  {label}")
                    break
        print()

    if part_count == 0:
        print("  No partitions defined.\n")

    print("=== Boot Status ===\n")
    print(f"  SCSI Header:     {'OK' if scsi_total > 0 else 'MISSING'}")
    print(f"  IPL Code:        {'OK' if ipl_valid else 'MISSING (not bootable)'}")
    print(f"  Partition Table: {'OK' if table['signature'] == PARTITION_SIGNATURE else 'INVALID'}")
    print(f"  Partitions:      {part_count} defined")
    print()


# =============================================================================
# FAT reading and classification
# =============================================================================

def read_fat(disk, force_2bytes=False, force_15bytes=False):
    raw = read_sector(disk, disk.fat_top, disk.fat_sectors)
    fat = [FATEntry() for _ in range(disk.cluster_num)]

    if force_15bytes:
        disk.is_2bytes = False
    elif force_2bytes:
        disk.is_2bytes = True
    # else: default is 2bytes (True)

    if disk.is_2bytes:
        if disk.little_endian:
            for i in range(disk.cluster_num):
                off = i * 2
                if off + 1 < len(raw):
                    fat[i].value = raw[off] | (raw[off + 1] << 8)
        else:
            for i in range(disk.cluster_num):
                off = i * 2
                if off + 1 < len(raw):
                    fat[i].value = (raw[off] << 8) | raw[off + 1]
    else:
        # 1.5-byte FAT (12-bit)
        src = 0
        i = 0
        while i < disk.cluster_num and src < len(raw):
            fat[i].value = raw[src] | ((raw[src + 1] & 0x0F) << 8) if src + 1 < len(raw) else raw[src]
            if fat[i].value > 0xFF6:
                fat[i].value |= 0xF000
            i += 1
            if i >= disk.cluster_num:
                break
            if src + 2 < len(raw):
                fat[i].value = ((raw[src + 1] & 0xF0) >> 4) | (raw[src + 2] << 4)
            elif src + 1 < len(raw):
                fat[i].value = (raw[src + 1] & 0xF0) >> 4
            if fat[i].value > 0xFF6:
                fat[i].value |= 0xF000
            i += 1
            src += 3

    disk.fat = fat


def check_fat_set(disk):
    for i in range(2, disk.cluster_num):
        v = disk.fat[i].value
        disk.fat[i].refered = FAT_REFERED_NO
        disk.fat[i].loop = FAT_LOOP_UNDECIDED
        disk.fat[i].badsec = FAT_BADSEC_OK
        disk.fat[i].subdir = FAT_SUBDIR_NOTYET

        if v == 0x0000:
            disk.fat[i].type = FAT_TYPE_FREE
            disk.fat[i].refer = FAT_REFER_END
        elif v == 0xFFF7:
            disk.fat[i].type = FAT_TYPE_OTHERS
            disk.fat[i].refer = FAT_REFER_OUTOF
            disk.fat[i].badsec = FAT_BADSEC_YES
        elif 0xFFF8 <= v <= 0xFFFE:
            disk.fat[i].type = FAT_TYPE_OTHERS
            disk.fat[i].refer = FAT_REFER_OUTOF
        elif v == 0xFFFF:
            disk.fat[i].type = FAT_TYPE_END
            disk.fat[i].refer = FAT_REFER_END
        else:
            disk.fat[i].type = FAT_TYPE_LINKING
            disk.fat[i].refer = FAT_REFER_OK


def check_fat_outof(disk, first_time, verbose=True):
    for i in range(2, disk.cluster_num):
        if disk.fat[i].badsec == FAT_BADSEC_YES:
            continue
        if disk.fat[i].type not in (FAT_TYPE_OTHERS, FAT_TYPE_LINKING):
            continue

        nxt = disk.fat[i].value
        if nxt <= 1 or nxt >= disk.cluster_num:
            if first_time and verbose:
                print(f"cluster {i:04X} refers to an out of cluster {nxt:04X}",
                      file=sys.stderr)
            if disk.writing:
                disk.fat[i].value = 0xFFFF
                write_fat_entry(disk, i)
                disk.fat[i].type = FAT_TYPE_END
            else:
                disk.fat[i].refer = FAT_REFER_OUTOF
            continue

        if disk.fat[nxt].badsec == FAT_BADSEC_YES:
            if first_time and verbose:
                print(f"cluster {i:04X} refers to a unusable cluster {nxt:04X}",
                      file=sys.stderr)
            disk.fat[i].value = disk.fat[nxt].value
            disk.fat[i].type = disk.fat[nxt].type
            disk.fat[i].refer = disk.fat[nxt].refer
            if disk.writing:
                write_fat_entry(disk, i)
            continue

        if disk.fat[nxt].type == FAT_TYPE_OTHERS:
            if first_time and verbose:
                print(f"cluster {i:04X} refers to an out of cluster {nxt:04X}",
                      file=sys.stderr)
            if disk.writing:
                disk.fat[i].value = 0xFFFF
                write_fat_entry(disk, i)
                disk.fat[i].type = FAT_TYPE_END
            else:
                disk.fat[i].refer = FAT_REFER_OUTOF

        elif disk.fat[nxt].type == FAT_TYPE_FREE:
            if first_time and verbose:
                print(f"cluster {i:04X} refers to a free cluster {nxt:04X}",
                      file=sys.stderr)
            if disk.writing:
                disk.fat[i].value = 0xFFFF
                write_fat_entry(disk, i)
                disk.fat[i].type = FAT_TYPE_END
            else:
                disk.fat[i].refer = FAT_REFER_OUTOF

        if disk.fat[nxt].refered == FAT_REFERED_NO:
            disk.fat[nxt].refered = FAT_REFERED_ONE
        elif disk.fat[nxt].refered == FAT_REFERED_ONE:
            disk.fat[nxt].refered = FAT_REFERED_MANY
            if first_time and verbose:
                print(f"cluster {nxt:04X} is refered many times", file=sys.stderr)


def check_fat_loop(disk, first_time, verbose=True):
    loop_cut = False
    for i in range(2, disk.cluster_num):
        if disk.fat[i].loop != FAT_LOOP_UNDECIDED:
            continue
        last = i
        test = i
        while True:
            lp = disk.fat[test].loop
            if lp == FAT_LOOP_IN_SEARCH:
                fill = FAT_LOOP_YES
                if first_time:
                    print(f"cluster {test:04X} rushes into a loop", file=sys.stderr)
                    if disk.writing:
                        loop_cut = True
                        disk.fat[last].value = 0xFFFF
                        write_fat_entry(disk, last)
                        disk.fat[last].type = FAT_TYPE_END
                        disk.fat[last].refer = FAT_REFER_END
                        fill = FAT_LOOP_NO
                break
            elif lp == FAT_LOOP_YES:
                fill = FAT_LOOP_YES
                break
            elif lp == FAT_LOOP_NO:
                fill = FAT_LOOP_NO
                break
            elif lp == FAT_LOOP_UNDECIDED:
                disk.fat[test].loop = FAT_LOOP_IN_SEARCH
                if disk.fat[test].refer == FAT_REFER_OK:
                    last = test
                    test = disk.fat[test].value
                    continue
                fill = FAT_LOOP_NO
                break
            else:
                fill = FAT_LOOP_NO
                break

        # Backfill loop status
        t = i
        while 2 <= t < disk.cluster_num and disk.fat[t].loop == FAT_LOOP_IN_SEARCH:
            nxt = disk.fat[t].value
            disk.fat[t].loop = fill
            t = nxt

    return loop_cut


def check_fat(disk, verbose=True):
    loop_cut = False
    check_fat_set(disk)
    check_fat_outof(disk, True, verbose)
    loop_cut = check_fat_loop(disk, True, verbose)
    if loop_cut:
        check_fat_set(disk)
        check_fat_outof(disk, False, verbose)
        check_fat_loop(disk, False, verbose)


def write_fat_entry(disk, cluster):
    if not disk.writing:
        return

    if disk.is_2bytes:
        half_length = SECTOR_SIZE // 2
        sector_index = cluster // half_length
        sector_start = sector_index * half_length

        sector_end = min(sector_start + half_length, disk.cluster_num)
        buf = bytearray(SECTOR_SIZE)
        pos = 0
        if disk.little_endian:
            for c in range(sector_start, sector_end):
                buf[pos] = disk.fat[c].value & 0xFF
                buf[pos + 1] = (disk.fat[c].value >> 8) & 0xFF
                pos += 2
        else:
            for c in range(sector_start, sector_end):
                buf[pos] = (disk.fat[c].value >> 8) & 0xFF
                buf[pos + 1] = disk.fat[c].value & 0xFF
                pos += 2

        write_sector(disk, disk.fat_top + sector_index, bytes(buf))
    else:
        # 1.5-byte FAT: rewrite entire FAT
        buf = bytearray(disk.fat_sectors * SECTOR_SIZE)
        pos = 0
        i = 0
        while i < disk.cluster_num:
            v = disk.fat[i].value
            buf[pos] = v & 0xFF
            if pos + 1 < len(buf):
                buf[pos + 1] = (buf[pos + 1] & 0xF0) | ((v >> 8) & 0x0F)
            i += 1
            if i >= disk.cluster_num:
                break
            v = disk.fat[i].value
            if pos + 1 < len(buf):
                buf[pos + 1] = (buf[pos + 1] & 0x0F) | ((v & 0x0F) << 4)
            if pos + 2 < len(buf):
                buf[pos + 2] = (v >> 4) & 0xFF
            i += 1
            pos += 3

        write_sector(disk, disk.fat_top, bytes(buf))


def expected_length(disk, cluster, length):
    cluster_count = 1
    c = cluster
    while True:
        if disk.fat[c].type != FAT_TYPE_LINKING:
            break
        if disk.fat[c].loop != FAT_LOOP_NO:
            break
        cluster_count += 1
        c = disk.fat[c].value

    min_length = (cluster_count - 1) * disk.cluster_length
    max_length = min_length + disk.cluster_length
    if length < 0:
        return max_length
    if min_length <= length <= max_length:
        return length
    return max_length


# =============================================================================
# Directory entry parsing
# =============================================================================

def decode_sjis(data):
    try:
        return data.decode("cp932")
    except (UnicodeDecodeError, ValueError):
        # Fallback: decode char by char
        result = []
        i = 0
        while i < len(data):
            b = data[i]
            if (0x81 <= b <= 0x9F or 0xE0 <= b <= 0xFC) and i + 1 < len(data):
                try:
                    result.append(data[i:i + 2].decode("cp932"))
                except (UnicodeDecodeError, ValueError):
                    result.append(f"\\x{b:02x}")
                    result.append(f"\\x{data[i + 1]:02x}")
                i += 2
            else:
                try:
                    result.append(bytes([b]).decode("cp932"))
                except (UnicodeDecodeError, ValueError):
                    result.append(f"\\x{b:02x}")
                i += 1
        return "".join(result)


def parse_dir_entry(raw):
    if len(raw) < 32:
        return None

    entry = DirEntryInfo()
    entry.raw_name8 = raw[0:8]
    entry.raw_ext3 = raw[8:11]
    entry.attr = raw[11]
    entry.raw_name2 = raw[12:22]

    entry.time_val = (raw[22] << 8) | raw[23]
    entry.date_val = (raw[24] << 8) | raw[25]
    entry.cluster = raw[27] << 8 | raw[26]  # little-endian
    entry.size = raw[26 + 2] | (raw[27 + 2] << 8) | (raw[28 + 2] << 16) | (raw[29 + 2] << 24)

    # Build name
    sjis_parts = bytearray()
    c = raw[0]
    if c == 0x05:
        c = 0xE5
    sjis_parts.append(c)

    for i in range(1, 8):
        if raw[i] == 0x20:
            break
        sjis_parts.append(raw[i])

    for i in range(10):
        if raw[12 + i] == 0:
            break
        sjis_parts.append(raw[12 + i])

    if raw[8] != 0x20:
        sjis_parts.append(ord('.'))
        for i in range(3):
            if raw[8 + i] == 0x20:
                break
            sjis_parts.append(raw[8 + i])

    entry.name = decode_sjis(bytes(sjis_parts))
    return entry


def is_valid_entry(raw):
    if len(raw) < 32:
        return False

    attr = raw[11]
    if attr == LFN_ATTR:
        return False
    if (attr & 0xC0) and attr != 0x0F:
        return False

    first = raw[0]
    if first == 0 or first == 0xE5:
        return False
    if first < 0x20 and first != 0x05:
        return False

    valid_special = set(b"!#$%&'()-@^_`{}~")
    for i in range(8):
        ch = raw[i]
        if ch == 0x20 or ch >= 0x80:
            continue
        if ord('A') <= ch <= ord('Z') or ord('a') <= ch <= ord('z') or ord('0') <= ch <= ord('9'):
            continue
        if ch in valid_special:
            continue
        if ch == 0x05:
            continue
        if ch < 0x20:
            return False

    return True


def format_attr(attr):
    return (
        ('d' if attr & ATTR_DIRECTORY else '-') +
        ('a' if attr & ATTR_ARCHIVE else '-') +
        ('s' if attr & ATTR_SYSTEM else '-') +
        ('h' if attr & ATTR_HIDDEN else '-') +
        ('r' if attr & ATTR_READONLY else '-')
    )


def format_size(size):
    if size < 1024:
        return str(size)
    elif size < 1024 * 1024:
        return f"{size / 1024:.1f}K"
    else:
        return f"{size / (1024 * 1024):.1f}M"


def is_dot_entry(raw):
    return (raw[0] == ord('.') and
            (raw[1] == 0x20 or (raw[1] == ord('.') and raw[2] == 0x20)))


# =============================================================================
# Directory iteration
# =============================================================================

def iter_directory(disk, cluster=0, skip_dots=True, skip_volume=True):
    """Yield DirEntryInfo for each valid entry in a directory.
    cluster=0 means root directory, otherwise follow FAT chain."""

    if cluster == 0:
        # Root directory
        for sec in range(disk.root_sectors):
            buf = read_sector(disk, disk.root_top + sec)
            for i in range(SECTOR_SIZE // 32):
                raw = buf[i * 32:(i + 1) * 32]
                if raw[0] == 0x00:
                    return
                if raw[0] == 0xE5:
                    continue
                if raw[11] == LFN_ATTR:
                    continue
                if skip_volume and (raw[11] & ATTR_VOLUME):
                    continue
                if not is_valid_entry(raw):
                    continue
                entry = parse_dir_entry(raw)
                if entry is not None:
                    yield entry
    else:
        current = cluster
        iterations = 0
        while current >= 2 and current < 0xFFF0 and iterations < 1000:
            buf = read_cluster(disk, current)
            for i in range(disk.cluster_length // 32):
                raw = buf[i * 32:(i + 1) * 32]
                if raw[0] == 0x00:
                    return
                if raw[0] == 0xE5:
                    continue
                if raw[11] == LFN_ATTR:
                    continue
                if not is_valid_entry(raw):
                    continue
                if skip_dots and is_dot_entry(raw):
                    continue
                entry = parse_dir_entry(raw)
                if entry is not None:
                    yield entry

            if disk.fat[current].refer != FAT_REFER_OK:
                break
            current = disk.fat[current].value
            iterations += 1


# =============================================================================
# tree command
# =============================================================================

def cmd_tree(disk, max_depth):
    print(".")
    _tree_recurse(disk, 0, "", 0, max_depth)


def _tree_recurse(disk, cluster, prefix, depth, max_depth):
    if depth > max_depth:
        return

    entries = list(iter_directory(disk, cluster))

    for i, entry in enumerate(entries):
        is_last = (i == len(entries) - 1)
        branch = "\u2514\u2500\u2500 " if is_last else "\u251c\u2500\u2500 "
        child_prefix = prefix + ("    " if is_last else "\u2502   ")

        if entry.attr & ATTR_DIRECTORY:
            print(f"{prefix}{branch}{entry.name}/")
            if entry.cluster >= 2:
                _tree_recurse(disk, entry.cluster, child_prefix, depth + 1, max_depth)
        else:
            size_str = format_size(entry.size)
            print(f"{prefix}{branch}{entry.name} ({size_str})")


# =============================================================================
# ls command
# =============================================================================

def cmd_ls(disk):
    print(f"\n/:")
    print(f"{'Attr':<5} {'Size':>10}  {'Name':<18}")
    print(f"{'-----':<5} {'----------':>10}  {'------------------':<18}")

    for entry in iter_directory(disk, 0, skip_volume=False):
        attr_str = format_attr(entry.attr)
        if entry.attr & ATTR_DIRECTORY:
            print(f"{attr_str} {'<DIR>':>10}  {entry.name}/")
        else:
            print(f"{attr_str} {entry.size:>10}  {entry.name}")


# =============================================================================
# extract command
# =============================================================================

def cmd_extract(disk, output_dir, verbose):
    os.makedirs(output_dir, exist_ok=True)

    meta_path = os.path.join(output_dir, ".x68k_meta")
    meta_file = open(meta_path, "w", encoding="utf-8")
    meta_file.write("# path\tattr\ttime\tdate\n")

    extracted, errors = _extract_directory(disk, 0, output_dir, verbose, meta_file, "")

    meta_file.close()
    print(f"Metadata written to: {meta_path}")
    print(f"\nExtraction {'complete' if errors == 0 else 'completed with errors'}.")
    return 0 if errors == 0 else 1


def _extract_directory(disk, cluster, output_dir, verbose, meta_file, rel_path):
    os.makedirs(output_dir, exist_ok=True)

    extracted = 0
    errors = 0

    for entry in iter_directory(disk, cluster):
        name = entry.name

        if rel_path:
            entry_rel = rel_path + name
        else:
            entry_rel = name

        out_path = os.path.join(output_dir, name)

        if entry.attr & ATTR_DIRECTORY:
            if name == "." or name == "..":
                continue

            meta_file.write(f"{entry_rel}/\t{entry.attr:02x}\t{entry.time_val:04x}\t{entry.date_val:04x}\n")

            if entry.cluster >= 2:
                if verbose:
                    print(f"Extracting directory: {out_path}/")
                sub_extracted, sub_errors = _extract_directory(
                    disk, entry.cluster, out_path, verbose, meta_file, entry_rel + "/")
                extracted += sub_extracted
                errors += sub_errors
        else:
            meta_file.write(f"{entry_rel}\t{entry.attr:02x}\t{entry.time_val:04x}\t{entry.date_val:04x}\n")

            if verbose:
                print(f"Extracting: {out_path} ({entry.size} bytes)")

            if entry.size > 0 and entry.cluster >= 2:
                if _extract_file(disk, entry.cluster, entry.size, out_path) == 0:
                    extracted += 1
                else:
                    errors += 1
            elif entry.size == 0:
                with open(out_path, "wb"):
                    pass
                extracted += 1

    return extracted, errors


def _extract_file(disk, start_cluster, file_size, output_path):
    try:
        with open(output_path, "wb") as f:
            cluster = start_cluster
            remaining = file_size
            iterations = 0

            while cluster >= 2 and cluster < 0xFFF0 and remaining > 0 and iterations < 100000:
                buf = read_cluster(disk, cluster)
                to_write = min(remaining, disk.cluster_length)
                f.write(buf[:to_write])
                remaining -= to_write

                if remaining > 0:
                    if disk.fat[cluster].refer != FAT_REFER_OK:
                        break
                    cluster = disk.fat[cluster].value

                iterations += 1

            return 0 if remaining == 0 else -1
    except IOError as e:
        print(f"Error: Cannot create file: {output_path}: {e}", file=sys.stderr)
        return -1


# =============================================================================
# check command
# =============================================================================

def cmd_check(disk, verbose, ignore_archive):
    print("Checking FAT links")
    check_fat(disk, verbose)

    print("Checking files")
    error_count = _check_files(disk, verbose, ignore_archive)

    print("Finding lost files")
    lost_count = _find_lost_files(disk, verbose)

    if error_count == 0 and lost_count == 0:
        print("No errors found.")
    else:
        if error_count > 0:
            print(f"{error_count} error(s) found.")
        if lost_count > 0:
            print(f"{lost_count} lost file chain(s) found.")

    return 0 if error_count == 0 and lost_count == 0 else 1


def _check_files_recurse(disk, cluster, path, verbose, ignore_archive, error_count):
    for entry in iter_directory(disk, cluster, skip_dots=True):
        file_path = path + entry.name

        # Check archive attribute
        if not ignore_archive and (entry.attr & 0x70) == 0:
            print(f"file {file_path} has no archive attribute", file=sys.stderr)
            error_count += 1

        file_cluster = entry.cluster
        if (file_cluster < 2 or file_cluster >= disk.cluster_num or
                disk.fat[file_cluster].type == FAT_TYPE_OTHERS or
                disk.fat[file_cluster].type == FAT_TYPE_FREE):
            print(f"file {file_path} has no body", file=sys.stderr)
            error_count += 1
            continue

        # Mark first cluster as referenced
        if disk.fat[file_cluster].refered == FAT_REFERED_NO:
            disk.fat[file_cluster].refered = FAT_REFERED_ONE
        elif disk.fat[file_cluster].refered == FAT_REFERED_ONE:
            disk.fat[file_cluster].refered = FAT_REFERED_MANY
            if verbose:
                print(f"cluster {file_cluster:04X} is cross-linked (file: {file_path})",
                      file=sys.stderr)
            error_count += 1

        if entry.attr & ATTR_DIRECTORY:
            child_cluster = entry.cluster
            if disk.fat[child_cluster].subdir == FAT_SUBDIR_NOTYET:
                disk.fat[child_cluster].subdir = FAT_SUBDIR_ALREADY

                # Check directory has zero length
                if entry.size != 0:
                    print(f"directory {file_path} has non zero length", file=sys.stderr)
                    error_count += 1

                error_count = _check_files_recurse(
                    disk, child_cluster, file_path + "/", verbose, ignore_archive, error_count)
            else:
                print(f"directory {file_path} is a loop", file=sys.stderr)
                error_count += 1
        elif not (entry.attr & ATTR_VOLUME):
            # Check file length vs cluster chain
            real_length = expected_length(disk, file_cluster, entry.size)
            if real_length != entry.size:
                print(f"file {file_path} has wrong length: "
                      f"recorded {entry.size}, expected {real_length}", file=sys.stderr)
                error_count += 1

    return error_count


def _check_files(disk, verbose, ignore_archive):
    for i in range(2, disk.cluster_num):
        disk.fat[i].subdir = FAT_SUBDIR_NOTYET

    return _check_files_recurse(disk, 0, "/", verbose, ignore_archive, 0)


def _find_lost_files(disk, verbose):
    lost_count = 0
    for i in range(2, disk.cluster_num):
        if disk.fat[i].type in (FAT_TYPE_LINKING, FAT_TYPE_END):
            if (disk.fat[i].refered == FAT_REFERED_NO and
                    disk.fat[i].badsec == FAT_BADSEC_OK):
                print(f"cluster {i:04X} has a lost file", file=sys.stderr)
                lost_count += 1
    return lost_count


# =============================================================================
# Write support: cluster allocation
# =============================================================================

def find_free_cluster(disk, start_from=2):
    if start_from < 2:
        start_from = 2

    for i in range(start_from, disk.cluster_num):
        if (disk.fat[i].type == FAT_TYPE_FREE and
                disk.fat[i].badsec == FAT_BADSEC_OK):
            return i

    for i in range(2, start_from):
        if (disk.fat[i].type == FAT_TYPE_FREE and
                disk.fat[i].badsec == FAT_BADSEC_OK):
            return i

    return 0


def allocate_cluster(disk):
    cluster = find_free_cluster(disk, 2)
    if cluster == 0:
        return 0

    disk.fat[cluster].value = 0xFFFF
    disk.fat[cluster].type = FAT_TYPE_END
    disk.fat[cluster].refer = FAT_REFER_END
    write_fat_entry(disk, cluster)
    return cluster


def link_clusters(disk, prev_cluster, next_cluster):
    disk.fat[prev_cluster].value = next_cluster
    disk.fat[prev_cluster].type = FAT_TYPE_LINKING
    disk.fat[prev_cluster].refer = FAT_REFER_OK
    write_fat_entry(disk, prev_cluster)


def free_cluster_chain(disk, cluster):
    while cluster >= 2 and cluster < disk.cluster_num:
        nxt = disk.fat[cluster].value
        was_linking = disk.fat[cluster].type == FAT_TYPE_LINKING

        disk.fat[cluster].value = 0x0000
        disk.fat[cluster].type = FAT_TYPE_FREE
        disk.fat[cluster].refer = FAT_REFER_END
        write_fat_entry(disk, cluster)

        if not was_linking:
            break
        cluster = nxt


# =============================================================================
# Write support: filename handling
# =============================================================================

def encode_to_sjis(utf8_name):
    try:
        return utf8_name.encode("cp932")
    except UnicodeEncodeError:
        # Char-by-char fallback for surrogate escapes
        result = bytearray()
        for ch in utf8_name:
            try:
                result.extend(ch.encode("cp932"))
            except UnicodeEncodeError:
                try:
                    result.extend(ch.encode("utf-8", errors="surrogateescape"))
                except UnicodeEncodeError:
                    pass
        return bytes(result)


def parse_filename_for_x68k(utf8_name):
    sjis = encode_to_sjis(utf8_name)
    sjis_len = len(sjis)

    dot_pos = sjis.rfind(ord('.'))
    if dot_pos >= 0:
        name_part = sjis[:dot_pos]
        ext_part = sjis[dot_pos + 1:]
    else:
        name_part = sjis
        ext_part = b""

    name8 = bytearray(b"        ")  # 8 spaces
    ext3 = bytearray(b"   ")  # 3 spaces
    name2 = bytearray(10)

    name_len = min(len(name_part), 18)
    copy_to_8 = min(name_len, 8)
    name8[:copy_to_8] = name_part[:copy_to_8]

    if name_len > 8:
        extra = name_len - 8
        name2[:extra] = name_part[8:8 + extra]

    ext_len = min(len(ext_part), 3)
    ext3[:ext_len] = ext_part[:ext_len]

    # Uppercase ASCII
    for i in range(8):
        if ord('a') <= name8[i] <= ord('z'):
            name8[i] = name8[i] - ord('a') + ord('A')
    for i in range(3):
        if ord('a') <= ext3[i] <= ord('z'):
            ext3[i] = ext3[i] - ord('a') + ord('A')
    for i in range(10):
        if ord('a') <= name2[i] <= ord('z'):
            name2[i] = name2[i] - ord('a') + ord('A')

    return bytes(name8), bytes(ext3), bytes(name2)


def match_entry_name(raw, name8, ext3, name2):
    def upper(b):
        if ord('a') <= b <= ord('z'):
            return b - ord('a') + ord('A')
        return b

    for i in range(8):
        ec = raw[i]
        if i == 0 and ec == 0x05:
            ec = 0xE5
        sc = name8[i]
        if upper(ec) != upper(sc):
            return False

    for i in range(3):
        if upper(raw[8 + i]) != upper(ext3[i]):
            return False

    for i in range(10):
        if upper(raw[12 + i]) != upper(name2[i]):
            return False

    return True


# =============================================================================
# Write support: directory navigation and entry creation
# =============================================================================

def search_directory_by_name(disk, dir_cluster, utf8_name):
    """Search directory for entry. Returns (cluster, attr) or None."""
    name8, ext3, name2 = parse_filename_for_x68k(utf8_name)

    if dir_cluster == 0:
        for sec in range(disk.root_sectors):
            buf = read_sector(disk, disk.root_top + sec)
            for i in range(SECTOR_SIZE // 32):
                raw = buf[i * 32:(i + 1) * 32]
                if raw[0] == 0x00:
                    return None
                if raw[0] == 0xE5:
                    continue
                if raw[11] == LFN_ATTR:
                    continue
                if match_entry_name(raw, name8, ext3, name2):
                    cluster = raw[26] | (raw[27] << 8)
                    return (cluster, raw[11])
    else:
        current = dir_cluster
        iterations = 0
        while current >= 2 and current < 0xFFF0 and iterations < 1000:
            buf = read_cluster(disk, current)
            for i in range(disk.cluster_length // 32):
                raw = buf[i * 32:(i + 1) * 32]
                if raw[0] == 0x00:
                    return None
                if raw[0] == 0xE5:
                    continue
                if raw[11] == LFN_ATTR:
                    continue
                if is_dot_entry(raw):
                    continue
                if match_entry_name(raw, name8, ext3, name2):
                    cluster = raw[26] | (raw[27] << 8)
                    return (cluster, raw[11])

            if disk.fat[current].refer != FAT_REFER_OK:
                break
            current = disk.fat[current].value
            iterations += 1

    return None


def navigate_to_directory(disk, path):
    """Navigate to directory by path. Returns cluster (0=root) or -1 if not found."""
    if not path:
        return 0
    path = path.strip("/")
    if not path:
        return 0

    current = 0
    for component in path.split("/"):
        if not component:
            continue
        result = search_directory_by_name(disk, current, component)
        if result is None:
            return -1
        cluster, attr = result
        if not (attr & ATTR_DIRECTORY):
            return -1
        current = cluster

    return current


def find_free_dir_slot(disk, dir_cluster):
    """Find a free slot (0x00 or 0xE5) in directory.
    Returns (sector_or_cluster, entry_index, is_root) or None."""

    if dir_cluster == 0:
        for sec in range(disk.root_sectors):
            buf = read_sector(disk, disk.root_top + sec)
            for i in range(SECTOR_SIZE // 32):
                raw = buf[i * 32:(i + 1) * 32]
                if raw[0] == 0x00 or raw[0] == 0xE5:
                    return (disk.root_top + sec, i, True)
    else:
        current = dir_cluster
        iterations = 0
        while current >= 2 and current < 0xFFF0 and iterations < 1000:
            buf = read_cluster(disk, current)
            for i in range(disk.cluster_length // 32):
                raw = buf[i * 32:(i + 1) * 32]
                if raw[0] == 0x00 or raw[0] == 0xE5:
                    return (current, i, False)

            if disk.fat[current].refer != FAT_REFER_OK:
                break
            current = disk.fat[current].value
            iterations += 1

    return None


def current_datetime():
    t = time.localtime()
    dos_time = ((t.tm_hour & 0x1F) << 11) | ((t.tm_min & 0x3F) << 5) | ((t.tm_sec // 2) & 0x1F)
    dos_date = (((t.tm_year - 1980) & 0x7F) << 9) | ((t.tm_mon & 0x0F) << 5) | (t.tm_mday & 0x1F)
    return dos_time, dos_date


def create_dir_entry(disk, dir_cluster, utf8_name, file_cluster, file_size, attr):
    slot = find_free_dir_slot(disk, dir_cluster)
    if slot is None:
        return WRITE_ERR_DIR_FULL

    location, entry_idx, is_root = slot
    name8, ext3, name2 = parse_filename_for_x68k(utf8_name)

    dos_time, dos_date = current_datetime()

    entry = bytearray(32)
    entry[0:8] = name8
    entry[8:11] = ext3
    entry[11] = attr
    entry[12:22] = name2
    entry[22] = (dos_time >> 8) & 0xFF
    entry[23] = dos_time & 0xFF
    entry[24] = (dos_date >> 8) & 0xFF
    entry[25] = dos_date & 0xFF
    entry[26] = file_cluster & 0xFF
    entry[27] = (file_cluster >> 8) & 0xFF
    entry[28] = file_size & 0xFF
    entry[29] = (file_size >> 8) & 0xFF
    entry[30] = (file_size >> 16) & 0xFF
    entry[31] = (file_size >> 24) & 0xFF

    if is_root:
        buf = bytearray(read_sector(disk, location))
        buf[entry_idx * 32:(entry_idx + 1) * 32] = entry
        write_sector(disk, location, bytes(buf))
    else:
        buf = bytearray(read_cluster(disk, location))
        buf[entry_idx * 32:(entry_idx + 1) * 32] = entry
        write_cluster(disk, location, bytes(buf))

    return WRITE_OK


def write_file_data(disk, data):
    if len(data) == 0:
        return 0

    first_cluster = 0
    prev_cluster = 0
    bytes_written = 0

    while bytes_written < len(data):
        cluster = allocate_cluster(disk)
        if cluster == 0:
            if first_cluster > 0:
                free_cluster_chain(disk, first_cluster)
            return 0

        if first_cluster == 0:
            first_cluster = cluster

        if prev_cluster > 0:
            link_clusters(disk, prev_cluster, cluster)

        to_write = min(len(data) - bytes_written, disk.cluster_length)
        cluster_buf = data[bytes_written:bytes_written + to_write]
        if len(cluster_buf) < disk.cluster_length:
            cluster_buf = cluster_buf + b"\x00" * (disk.cluster_length - len(cluster_buf))

        write_cluster(disk, cluster, cluster_buf)
        bytes_written += to_write
        prev_cluster = cluster

    return first_cluster


# =============================================================================
# Write commands: add, mkdir, rm
# =============================================================================

def cmd_add(disk, local_path, dest_path):
    if not disk.writing:
        print("Error: add requires -w (write mode)", file=sys.stderr)
        return 1

    try:
        with open(local_path, "rb") as f:
            file_data = f.read()
    except IOError as e:
        print(f"Error: Cannot read file: {local_path}: {e}", file=sys.stderr)
        return 1

    filename = os.path.basename(local_path)

    dest_cluster = navigate_to_directory(disk, dest_path)
    if dest_cluster < 0:
        print(f"Error: Destination path not found: {dest_path}", file=sys.stderr)
        return 1

    existing = search_directory_by_name(disk, dest_cluster, filename)
    if existing is not None:
        print(f"Error: File already exists: {filename}", file=sys.stderr)
        return 1

    first_cluster = 0
    if len(file_data) > 0:
        first_cluster = write_file_data(disk, file_data)
        if first_cluster == 0:
            print("Error: Disk full", file=sys.stderr)
            return 1

    result = create_dir_entry(disk, dest_cluster, filename, first_cluster,
                              len(file_data), ATTR_ARCHIVE)
    if result != WRITE_OK:
        if first_cluster > 0:
            free_cluster_chain(disk, first_cluster)
        errs = {
            WRITE_ERR_DIR_FULL: "Directory full",
            WRITE_ERR_INVALID_NAME: "Invalid filename",
        }
        print(f"Error: {errs.get(result, 'Write error')}", file=sys.stderr)
        return 1

    print(f"File added successfully.")
    return 0


def cmd_mkdir(disk, dir_path):
    if not disk.writing:
        print("Error: mkdir requires -w (write mode)", file=sys.stderr)
        return 1

    path = dir_path.rstrip("/")
    last_slash = path.rfind("/")
    if last_slash <= 0:
        parent_path = "/"
        new_name = path.lstrip("/")
    else:
        parent_path = path[:last_slash]
        new_name = path[last_slash + 1:]

    if not new_name:
        print("Error: Invalid directory name", file=sys.stderr)
        return 1

    parent_cluster = navigate_to_directory(disk, parent_path)
    if parent_cluster < 0:
        print(f"Error: Parent path not found: {parent_path}", file=sys.stderr)
        return 1

    existing = search_directory_by_name(disk, parent_cluster, new_name)
    if existing is not None:
        print(f"Error: Already exists: {new_name}", file=sys.stderr)
        return 1

    dir_cluster = allocate_cluster(disk)
    if dir_cluster == 0:
        print("Error: Disk full", file=sys.stderr)
        return 1

    # Initialize directory with . and .. entries
    dir_buf = bytearray(disk.cluster_length)
    dos_time, dos_date = current_datetime()

    # . entry
    dot = bytearray(32)
    dot[0:8] = b".       "
    dot[8:11] = b"   "
    dot[11] = ATTR_DIRECTORY
    dot[22] = (dos_time >> 8) & 0xFF
    dot[23] = dos_time & 0xFF
    dot[24] = (dos_date >> 8) & 0xFF
    dot[25] = dos_date & 0xFF
    dot[26] = dir_cluster & 0xFF
    dot[27] = (dir_cluster >> 8) & 0xFF
    dir_buf[0:32] = dot

    # .. entry
    dotdot = bytearray(32)
    dotdot[0:8] = b"..      "
    dotdot[8:11] = b"   "
    dotdot[11] = ATTR_DIRECTORY
    dotdot[22] = (dos_time >> 8) & 0xFF
    dotdot[23] = dos_time & 0xFF
    dotdot[24] = (dos_date >> 8) & 0xFF
    dotdot[25] = dos_date & 0xFF
    dotdot[26] = parent_cluster & 0xFF
    dotdot[27] = (parent_cluster >> 8) & 0xFF
    dir_buf[32:64] = dotdot

    write_cluster(disk, dir_cluster, bytes(dir_buf))

    result = create_dir_entry(disk, parent_cluster, new_name, dir_cluster, 0, ATTR_DIRECTORY)
    if result != WRITE_OK:
        free_cluster_chain(disk, dir_cluster)
        print("Error: Could not create directory entry", file=sys.stderr)
        return 1

    print("Directory created successfully.")
    return 0


def find_entry_by_path(disk, file_path):
    """Find entry location. Returns dict with entry info or None."""
    path = file_path.rstrip("/")
    last_slash = path.rfind("/")
    if last_slash <= 0:
        parent_path = "/"
        filename = path.lstrip("/")
    else:
        parent_path = path[:last_slash]
        filename = path[last_slash + 1:]

    if not filename:
        return None

    parent_cluster = navigate_to_directory(disk, parent_path)
    if parent_cluster < 0:
        return None

    name8, ext3, name2 = parse_filename_for_x68k(filename)

    if parent_cluster == 0:
        for sec in range(disk.root_sectors):
            buf = read_sector(disk, disk.root_top + sec)
            for i in range(SECTOR_SIZE // 32):
                raw = buf[i * 32:(i + 1) * 32]
                if raw[0] == 0x00:
                    return None
                if raw[0] == 0xE5:
                    continue
                if raw[11] == LFN_ATTR:
                    continue
                if match_entry_name(raw, name8, ext3, name2):
                    cluster = raw[26] | (raw[27] << 8)
                    return {
                        "cluster": cluster,
                        "attr": raw[11],
                        "is_root": True,
                        "sector": disk.root_top + sec,
                        "entry_idx": i,
                    }
    else:
        current = parent_cluster
        iterations = 0
        while current >= 2 and current < 0xFFF0 and iterations < 1000:
            buf = read_cluster(disk, current)
            for i in range(disk.cluster_length // 32):
                raw = buf[i * 32:(i + 1) * 32]
                if raw[0] == 0x00:
                    return None
                if raw[0] == 0xE5:
                    continue
                if raw[11] == LFN_ATTR:
                    continue
                if is_dot_entry(raw):
                    continue
                if match_entry_name(raw, name8, ext3, name2):
                    cluster = raw[26] | (raw[27] << 8)
                    return {
                        "cluster": cluster,
                        "attr": raw[11],
                        "is_root": False,
                        "dir_cluster": current,
                        "entry_idx": i,
                    }

            if disk.fat[current].refer != FAT_REFER_OK:
                break
            current = disk.fat[current].value
            iterations += 1

    return None


def mark_entry_deleted(disk, loc):
    if loc["is_root"]:
        buf = bytearray(read_sector(disk, loc["sector"]))
        buf[loc["entry_idx"] * 32] = 0xE5
        write_sector(disk, loc["sector"], bytes(buf))
    else:
        buf = bytearray(read_cluster(disk, loc["dir_cluster"]))
        buf[loc["entry_idx"] * 32] = 0xE5
        write_cluster(disk, loc["dir_cluster"], bytes(buf))


def delete_directory_contents(disk, dir_cluster):
    current = dir_cluster
    iterations = 0
    while current >= 2 and current < 0xFFF0 and iterations < 1000:
        buf = read_cluster(disk, current)
        modified = False
        buf = bytearray(buf)

        for i in range(disk.cluster_length // 32):
            raw = buf[i * 32:(i + 1) * 32]
            if raw[0] == 0x00:
                if modified:
                    write_cluster(disk, current, bytes(buf))
                return
            if raw[0] == 0xE5:
                continue
            if raw[11] == LFN_ATTR:
                continue
            if is_dot_entry(raw):
                continue

            entry_cluster = raw[26] | (raw[27] << 8)

            if raw[11] & ATTR_DIRECTORY:
                if entry_cluster >= 2:
                    delete_directory_contents(disk, entry_cluster)
                    free_cluster_chain(disk, entry_cluster)
                    # Re-read since recursive call may have changed things
                    buf = bytearray(read_cluster(disk, current))
            else:
                if entry_cluster >= 2:
                    free_cluster_chain(disk, entry_cluster)

            buf[i * 32] = 0xE5
            modified = True

        if modified:
            write_cluster(disk, current, bytes(buf))

        if disk.fat[current].type != FAT_TYPE_LINKING:
            break
        current = disk.fat[current].value
        iterations += 1


def cmd_rm(disk, rm_path, recursive=False):
    if not disk.writing:
        print("Error: rm requires -w (write mode)", file=sys.stderr)
        return 1

    loc = find_entry_by_path(disk, rm_path)
    if loc is None:
        print(f"Error: Not found: {rm_path}", file=sys.stderr)
        return 1

    if loc["attr"] & ATTR_DIRECTORY:
        if recursive:
            if loc["cluster"] >= 2:
                delete_directory_contents(disk, loc["cluster"])
                free_cluster_chain(disk, loc["cluster"])
        else:
            # Check if empty
            is_empty = True
            if loc["cluster"] >= 2:
                for entry in iter_directory(disk, loc["cluster"]):
                    is_empty = False
                    break
            if not is_empty:
                print(f"Error: Directory not empty: {rm_path} (use recursive mode)", file=sys.stderr)
                return 1
            if loc["cluster"] >= 2:
                free_cluster_chain(disk, loc["cluster"])
    else:
        if loc["cluster"] >= 2:
            free_cluster_chain(disk, loc["cluster"])

    mark_entry_deleted(disk, loc)
    print("Deleted successfully.")
    return 0


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="X68000 Filesystem Checker",
        usage="%(prog)s [options] <command> image.hda [args...]",
    )

    parser.add_argument("command", nargs="?", default="check",
                        choices=["check", "info", "tree", "ls", "extract", "add", "mkdir", "rm"],
                        help="command to run (default: check)")
    parser.add_argument("image", help="disk image file")
    parser.add_argument("args", nargs="*", help="command arguments")

    parser.add_argument("--depth", type=int, default=3,
                        help="tree depth (default: 3)")
    parser.add_argument("-w", action="store_true", dest="writing",
                        help="enable write mode")
    parser.add_argument("-p", type=int, default=0, dest="partition",
                        help="partition index (default: 0)")
    parser.add_argument("-v", action="store_true", dest="verbose", default=True,
                        help="verbose (default: on)")
    parser.add_argument("--force", action="store_true",
                        help="force read/write past bad sectors")
    parser.add_argument("--is2bytes", action="store_true",
                        help="force 2-byte FAT")
    parser.add_argument("--is1.5bytes", action="store_true", dest="is15bytes",
                        help="force 1.5-byte FAT")
    parser.add_argument("--ignore-archive-attrib", action="store_true",
                        help="ignore archive attr check")

    args = parser.parse_args()

    # Clamp depth
    if args.depth < 1:
        args.depth = 1
    elif args.depth > 20:
        args.depth = 20

    # Info command doesn't need full disk init
    if args.command == "info":
        try:
            with open(args.image, "rb") as fp:
                print_partitions(fp)
        except IOError as e:
            print(f"Error: Cannot open image: {args.image}: {e}", file=sys.stderr)
            return 1
        return 0

    # Open image
    mode = "r+b" if args.writing else "rb"
    try:
        fp = open(args.image, mode)
    except IOError as e:
        print(f"Error: Cannot open image: {args.image}: {e}", file=sys.stderr)
        return 1

    disk = parse_partition(fp, args.partition)
    if disk is None:
        fp.close()
        return 1

    disk.writing = args.writing

    # Read FAT
    read_fat(disk, force_2bytes=args.is2bytes, force_15bytes=args.is15bytes)

    # For write modes and check, classify FAT
    if args.command in ("check", "add", "mkdir", "rm"):
        check_fat(disk, verbose=(args.command == "check" and args.verbose))

    # Dispatch command
    result = 0
    if args.command == "check":
        result = cmd_check(disk, args.verbose, args.ignore_archive_attrib)
    elif args.command == "tree":
        check_fat_set(disk)
        cmd_tree(disk, args.depth)
    elif args.command == "ls":
        check_fat_set(disk)
        cmd_ls(disk)
    elif args.command == "extract":
        if not args.args:
            print("Error: extract requires output directory argument", file=sys.stderr)
            result = 1
        else:
            check_fat_set(disk)
            print(f"Extracting files to: {args.args[0]}\n")
            result = cmd_extract(disk, args.args[0], args.verbose)
    elif args.command == "add":
        if len(args.args) < 2:
            print("Error: add requires FILE and DEST arguments", file=sys.stderr)
            result = 1
        else:
            print(f"Adding file: {args.args[0]} -> {args.args[1]}")
            result = cmd_add(disk, args.args[0], args.args[1])
    elif args.command == "mkdir":
        if not args.args:
            print("Error: mkdir requires PATH argument", file=sys.stderr)
            result = 1
        else:
            print(f"Creating directory: {args.args[0]}")
            result = cmd_mkdir(disk, args.args[0])
    elif args.command == "rm":
        if not args.args:
            print("Error: rm requires PATH argument", file=sys.stderr)
            result = 1
        else:
            # Check for recursive flag in remaining args
            recursive = False
            rm_path = args.args[0]
            if len(args.args) > 1 and args.args[1] in ("-r", "--recursive"):
                recursive = True
            print(f"Deleting{'recursively' if recursive else ''}: {rm_path}")
            result = cmd_rm(disk, rm_path, recursive)

    fp.close()
    return result


if __name__ == "__main__":
    sys.exit(main())

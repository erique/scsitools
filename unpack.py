#!/usr/bin/env python3
"""
unpack.py - X68000 SxSI Disk Image Unpacker

Unpacks everything from an X68000 SxSI disk image into a directory structure
that captures all data needed to recreate the image with pack.py.

Extracts:
- SCSI header (sector 0)
- IPL boot code (sectors 2-3)
- SASI device driver (offset 0xC00)
- Partition table metadata
- For each partition: boot sector, all files/dirs with .x68k_meta
"""

import argparse
import json
import os
import struct
import sys

SECTOR_SIZE = 512
RECORD_SIZE = 1024
SCSI_SIGNATURE = b"X68SCSI1"
SXSI_SIGNATURE = b"SxSI"
SXSI_MARKER_OFFSET = 0x2A
PARTITION_SIGNATURE = b"X68K"
MAX_PARTITIONS = 15
LFN_ATTR = 0x0F
PARTITION_START_OFFSET = 0x8000  # Record 0x20


# =============================================================================
# Byte reading helpers
# =============================================================================

def read_be16(data, offset=0):
    return struct.unpack_from(">H", data, offset)[0]


def read_be32(data, offset=0):
    return struct.unpack_from(">I", data, offset)[0]


# =============================================================================
# SCSI header parsing
# =============================================================================

def parse_scsi_header(fp):
    fp.seek(0)
    buf = fp.read(SECTOR_SIZE)
    if len(buf) < SECTOR_SIZE or buf[:8] != SCSI_SIGNATURE:
        print("Error: Not an X68000 SCSI disk image (missing X68SCSI1 signature)",
              file=sys.stderr)
        return None

    bytes_per_record = read_be16(buf, 0x08)
    disk_end_record = read_be32(buf, 0x0A)
    sxsi = buf[SXSI_MARKER_OFFSET:SXSI_MARKER_OFFSET + 4] == SXSI_SIGNATURE
    total_records = disk_end_record + 1
    if sxsi:
        total_records <<= 1
    total_sectors = total_records * (bytes_per_record // SECTOR_SIZE)

    return {
        "bytes_per_record": bytes_per_record,
        "disk_end_record": disk_end_record,
        "total_records": total_records,
        "total_sectors": total_sectors,
        "sxsi": sxsi,
        "size_mb": total_sectors * SECTOR_SIZE / (1024 * 1024),
    }


# =============================================================================
# Partition table parsing
# =============================================================================

def parse_partition_table(fp):
    fp.seek(4 * SECTOR_SIZE)
    buf = fp.read(SECTOR_SIZE)
    if len(buf) < SECTOR_SIZE or buf[:4] != PARTITION_SIGNATURE:
        print("Error: Invalid partition table (missing X68K signature)", file=sys.stderr)
        return None

    total_records_minus1 = read_be32(buf, 4)
    partitions = []
    p = 16
    for i in range(MAX_PARTITIONS):
        name_raw = buf[p:p + 8]
        start_record = read_be32(buf, p + 8)
        record_count = read_be32(buf, p + 12)
        if record_count > 0:
            name = name_raw.rstrip(b"\x00").decode("ascii", errors="replace")
            partitions.append({
                "index": i,
                "name": name,
                "start_record": start_record,
                "record_count": record_count,
                "start_offset": start_record * RECORD_SIZE,
                "size_bytes": record_count * RECORD_SIZE,
            })
        p += 16

    return {
        "total_records_minus1": total_records_minus1,
        "partitions": partitions,
    }


# =============================================================================
# BPB parsing
# =============================================================================

def parse_bpb(fp, partition_offset, partition_records):
    fp.seek(partition_offset)
    buf = fp.read(RECORD_SIZE)
    if len(buf) < RECORD_SIZE or buf[0] != 0x60:
        return None

    bps = read_be16(buf, 0x12)
    spc = buf[0x14]
    fat_count = buf[0x15]
    reserved = read_be16(buf, 0x16)
    root_entries = read_be16(buf, 0x18)
    media = buf[0x1C]
    fat_recs = buf[0x1D]

    if bps != 1024 or spc == 0 or fat_count == 0 or reserved == 0 or fat_recs == 0:
        return None

    root_dir_recs = (root_entries * 32 + RECORD_SIZE - 1) // RECORD_SIZE
    fat_offset = partition_offset + reserved * RECORD_SIZE
    root_offset = partition_offset + (reserved + fat_count * fat_recs) * RECORD_SIZE
    data_offset = root_offset + root_dir_recs * RECORD_SIZE

    data_recs = partition_records - reserved - fat_count * fat_recs - root_dir_recs
    cluster_num = data_recs // spc + 2
    max_from_fat = (fat_recs * RECORD_SIZE) // 2
    if cluster_num > max_from_fat:
        cluster_num = max_from_fat

    return {
        "spc": spc,
        "fat_count": fat_count,
        "reserved": reserved,
        "root_entries": root_entries,
        "media": media,
        "fat_recs": fat_recs,
        "fat_offset": fat_offset,
        "root_offset": root_offset,
        "root_dir_recs": root_dir_recs,
        "data_offset": data_offset,
        "cluster_num": cluster_num,
        "cluster_size": spc * RECORD_SIZE,
    }


# =============================================================================
# FAT reading
# =============================================================================

def read_fat(fp, bpb):
    fp.seek(bpb["fat_offset"])
    raw = fp.read(bpb["fat_recs"] * RECORD_SIZE)

    fat = []
    for i in range(bpb["cluster_num"]):
        off = i * 2
        if off + 1 < len(raw):
            fat.append((raw[off] << 8) | raw[off + 1])
        else:
            fat.append(0)

    return fat


def get_cluster_chain(fat, start):
    chain = []
    c = start
    while 2 <= c < len(fat) and c < 0xFFF0:
        chain.append(c)
        c = fat[c]
        if len(chain) > 100000:
            break
    return chain


# =============================================================================
# Directory parsing
# =============================================================================

def decode_sjis(data):
    try:
        return data.decode("cp932")
    except (UnicodeDecodeError, ValueError):
        result = []
        i = 0
        while i < len(data):
            b = data[i]
            if (0x81 <= b <= 0x9F or 0xE0 <= b <= 0xFC) and i + 1 < len(data):
                try:
                    result.append(data[i:i + 2].decode("cp932"))
                except (UnicodeDecodeError, ValueError):
                    for raw_b in data[i:i + 2]:
                        if raw_b >= 0x80:
                            result.append(chr(0xDC00 + raw_b))
                        else:
                            result.append(chr(raw_b))
                i += 2
            else:
                try:
                    result.append(bytes([b]).decode("cp932"))
                except (UnicodeDecodeError, ValueError):
                    if b >= 0x80:
                        result.append(chr(0xDC00 + b))
                    else:
                        result.append(chr(b))
                i += 1
        return "".join(result)


def parse_entry_name(raw):
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

    return decode_sjis(bytes(sjis_parts))


def is_dot_entry(raw):
    return (raw[0] == ord('.') and
            (raw[1] == 0x20 or (raw[1] == ord('.') and raw[2] == 0x20)))


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
    return True


def parse_dir_entry(raw):
    if not is_valid_entry(raw):
        return None

    name = parse_entry_name(raw)
    attr = raw[11]
    time_val = (raw[22] << 8) | raw[23]
    date_val = (raw[24] << 8) | raw[25]
    cluster = raw[26] | (raw[27] << 8)
    size = raw[28] | (raw[29] << 8) | (raw[30] << 16) | (raw[31] << 24)

    return {
        "name": name,
        "attr": attr,
        "time": time_val,
        "date": date_val,
        "cluster": cluster,
        "size": size,
    }


def iter_directory(fp, bpb, fat, cluster=0):
    if cluster == 0:
        fp.seek(bpb["root_offset"])
        total_bytes = bpb["root_dir_recs"] * RECORD_SIZE
        data = fp.read(total_bytes)
        for i in range(len(data) // 32):
            raw = data[i * 32:(i + 1) * 32]
            if raw[0] == 0x00:
                return
            if raw[0] == 0xE5 or raw[11] == LFN_ATTR:
                continue
            entry = parse_dir_entry(raw)
            if entry is not None:
                yield entry
    else:
        chain = get_cluster_chain(fat, cluster)
        for c in chain:
            offset = bpb["data_offset"] + (c - 2) * bpb["cluster_size"]
            fp.seek(offset)
            data = fp.read(bpb["cluster_size"])
            for i in range(len(data) // 32):
                raw = data[i * 32:(i + 1) * 32]
                if raw[0] == 0x00:
                    return
                if raw[0] == 0xE5 or raw[11] == LFN_ATTR:
                    continue
                if is_dot_entry(raw):
                    continue
                entry = parse_dir_entry(raw)
                if entry is not None:
                    yield entry


# =============================================================================
# File extraction
# =============================================================================

def extract_file_data(fp, bpb, fat, start_cluster, file_size):
    chain = get_cluster_chain(fat, start_cluster)
    data = bytearray()
    for c in chain:
        offset = bpb["data_offset"] + (c - 2) * bpb["cluster_size"]
        fp.seek(offset)
        data.extend(fp.read(bpb["cluster_size"]))
    return bytes(data[:file_size])


def extract_directory(fp, bpb, fat, cluster, output_dir, meta_file, rel_path, verbose):
    os.makedirs(output_dir, exist_ok=True)
    extracted = 0
    errors = 0

    for entry in iter_directory(fp, bpb, fat, cluster):
        name = entry["name"]
        entry_rel = rel_path + name if rel_path else name
        out_path = os.path.join(output_dir, name)

        if entry["attr"] & 0x10:
            # Directory
            if name in (".", ".."):
                continue

            meta_file.write(f"{entry_rel}/\t{entry['attr']:02x}\t{entry['time']:04x}\t{entry['date']:04x}\n")

            if entry["cluster"] >= 2:
                if verbose:
                    print(f"  {entry_rel}/")
                sub_ext, sub_err = extract_directory(
                    fp, bpb, fat, entry["cluster"], out_path,
                    meta_file, entry_rel + "/", verbose)
                extracted += sub_ext
                errors += sub_err
        else:
            meta_file.write(f"{entry_rel}\t{entry['attr']:02x}\t{entry['time']:04x}\t{entry['date']:04x}\n")

            if verbose:
                print(f"  {entry_rel} ({entry['size']} bytes)")

            try:
                if entry["size"] > 0 and entry["cluster"] >= 2:
                    data = extract_file_data(fp, bpb, fat, entry["cluster"], entry["size"])
                    with open(out_path, "wb") as f:
                        f.write(data)
                    extracted += 1
                elif entry["size"] == 0:
                    with open(out_path, "wb"):
                        pass
                    extracted += 1
            except (IOError, OSError) as e:
                print(f"  Error extracting {entry_rel}: {e}", file=sys.stderr)
                errors += 1

    return extracted, errors


# =============================================================================
# Main extraction
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Unpack everything from an X68000 SxSI disk image"
    )
    parser.add_argument("image", help="Disk image file to extract from")
    parser.add_argument("output_dir", help="Output directory")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show detailed output")

    args = parser.parse_args()

    if not os.path.isfile(args.image):
        print(f"Error: image not found: {args.image}", file=sys.stderr)
        return 1

    with open(args.image, "rb") as fp:
        # Parse SCSI header
        header_info = parse_scsi_header(fp)
        if header_info is None:
            return 1

        # Parse partition table
        ptable = parse_partition_table(fp)
        if ptable is None:
            return 1

        os.makedirs(args.output_dir, exist_ok=True)

        # Extract SCSI header (raw sector 0)
        fp.seek(0)
        scsi_header_data = fp.read(SECTOR_SIZE)
        header_path = os.path.join(args.output_dir, "scsi_header.bin")
        with open(header_path, "wb") as f:
            f.write(scsi_header_data)
        print(f"SCSI header: {SECTOR_SIZE} bytes -> scsi_header.bin")
        print(f"  Total records: {header_info['total_records']}, "
              f"Size: {header_info['size_mb']:.1f} MB, "
              f"SxSI: {'yes' if header_info['sxsi'] else 'no'}")

        # Extract IPL (sectors 2-3, offset 0x400)
        fp.seek(0x400)
        ipl_data = fp.read(RECORD_SIZE)
        has_ipl = len(ipl_data) >= 4 and ipl_data[0] == 0x60 and ipl_data[1] == 0x00
        if has_ipl:
            ipl_path = os.path.join(args.output_dir, "ipl.bin")
            with open(ipl_path, "wb") as f:
                f.write(ipl_data)
            print(f"IPL: {RECORD_SIZE} bytes -> ipl.bin")
        else:
            print("IPL: not present (skipped)")

        # Extract SASI device driver (offset 0xC00 to partition start)
        driver_start = 0xC00
        # Find earliest partition start
        earliest_partition = PARTITION_START_OFFSET
        for part in ptable["partitions"]:
            part_off = part["start_record"] * RECORD_SIZE
            if part_off < earliest_partition:
                earliest_partition = part_off
        driver_size = earliest_partition - driver_start
        if driver_size > 0:
            fp.seek(driver_start)
            driver_data = fp.read(driver_size)
            # Check if there's actual data (not all zeros)
            if any(b != 0 for b in driver_data):
                driver_path = os.path.join(args.output_dir, "driver.bin")
                with open(driver_path, "wb") as f:
                    f.write(driver_data)
                print(f"SASI driver: {driver_size} bytes -> driver.bin")
            else:
                print("SASI driver: not present (all zeros, skipped)")

        # Save partition table metadata
        ptable_info = {
            "total_records_minus1": ptable["total_records_minus1"],
            "partitions": ptable["partitions"],
        }
        ptable_path = os.path.join(args.output_dir, "partitions.json")
        with open(ptable_path, "w") as f:
            json.dump(ptable_info, f, indent=2)
        print(f"Partition table: {len(ptable['partitions'])} partition(s) -> partitions.json")

        # Extract each partition
        for part in ptable["partitions"]:
            part_idx = part["index"]
            part_name = part["name"]
            part_offset = part["start_offset"]
            part_records = part["record_count"]
            part_size_mb = part["size_bytes"] / (1024 * 1024)

            part_dir = os.path.join(args.output_dir, f"partition_{part_idx}")
            os.makedirs(part_dir, exist_ok=True)

            print(f"\nPartition {part_idx}: \"{part_name}\" "
                  f"(record {part['start_record']}, {part_records} records, {part_size_mb:.1f} MB)")

            # Extract boot sector (1024 bytes)
            fp.seek(part_offset)
            bootsect_data = fp.read(RECORD_SIZE)
            bootsect_path = os.path.join(part_dir, "bootsect.bin")
            with open(bootsect_path, "wb") as f:
                f.write(bootsect_data)
            print(f"  Boot sector: {RECORD_SIZE} bytes -> partition_{part_idx}/bootsect.bin")

            # Parse BPB
            bpb = parse_bpb(fp, part_offset, part_records)
            if bpb is None:
                print(f"  Warning: could not parse BPB, skipping filesystem extraction",
                      file=sys.stderr)
                continue

            print(f"  BPB: SPC={bpb['spc']}, FAT={bpb['fat_recs']} recs/copy, "
                  f"root={bpb['root_entries']} entries, clusters={bpb['cluster_num']}")

            # Read FAT
            fat = read_fat(fp, bpb)

            # Extract all files
            meta_path = os.path.join(part_dir, ".x68k_meta")
            with open(meta_path, "w", encoding="utf-8", errors="surrogateescape") as meta_file:
                meta_file.write("# path\tattr\ttime\tdate\n")
                extracted, errors = extract_directory(
                    fp, bpb, fat, 0, part_dir, meta_file, "", args.verbose)

            print(f"  Files: {extracted} extracted"
                  + (f", {errors} errors" if errors else ""))
            print(f"  Metadata: -> partition_{part_idx}/.x68k_meta")

    print(f"\nExtraction complete -> {args.output_dir}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())

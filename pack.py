#!/usr/bin/env python3
"""
pack.py - X68000 SxSI Disk Image Packer

Reverse of unpack.py: takes one or more unpacked directories and recreates
a disk image. Supports multi-partition images.

Usage:
    pack.py <dir1> [<dir2> ...] <output_image>

SCSI header, IPL, and driver are taken from the first directory.
Each directory contributes one partition.
"""

import argparse
import json
import math
import os
import struct
import sys

import scsiformat


def compute_min_partition_records(tree, human_data, command_data, spc, root_entries):
    """Compute the minimum partition_records needed to hold the given data.

    Uses allocate_clusters on a copy of the tree to get exact cluster count,
    then iteratively solves for fat_recs.
    """
    cluster_size = spc * scsiformat.RECORD_SIZE
    root_dir_recs = root_entries * scsiformat.DIR_ENTRY_SIZE // scsiformat.RECORD_SIZE

    # Count data clusters needed using the same logic as allocate_clusters
    human_clusters = max(1, math.ceil(len(human_data) / cluster_size))
    command_clusters = max(1, math.ceil(len(command_data) / cluster_size))
    next_cluster = 2 + human_clusters + command_clusters
    next_cluster = scsiformat.allocate_clusters(tree, next_cluster, cluster_size)
    data_clusters = next_cluster - 2
    data_recs_needed = data_clusters * spc

    # Iteratively solve for fat_recs
    fat_recs = 1
    for _ in range(30):
        partition_records = 1 + 2 * fat_recs + root_dir_recs + data_recs_needed
        total_clusters = data_recs_needed // spc + 2
        needed_fat_recs = math.ceil(total_clusters * scsiformat.FAT_ENTRY_SIZE / scsiformat.RECORD_SIZE)
        if needed_fat_recs <= fat_recs:
            break
        fat_recs = needed_fat_recs

    return partition_records


def load_partition_data(extract_dir, part_info):
    """Load tree, HUMAN.SYS, COMMAND.X, and boot sector for a partition."""
    part_dir = os.path.join(extract_dir, f"partition_{part_info['index']}")
    bootsect_path = os.path.join(part_dir, "bootsect.bin")
    bootsect_data = scsiformat.load_file(bootsect_path, "Boot sector template")

    # Temporarily hide bootsect.bin from load_extra_tree
    bootsect_hidden = os.path.join(extract_dir, ".bootsect.bin.tmp")
    os.rename(bootsect_path, bootsect_hidden)
    try:
        tree, human_data, command_data, human_meta, command_meta = \
            scsiformat.load_extra_tree(part_dir)
    finally:
        os.rename(bootsect_hidden, bootsect_path)

    # Use defaults if HUMAN.SYS/COMMAND.X not found
    if human_data is None:
        human_data = scsiformat.load_file(
            os.path.join(scsiformat.DATA_DIR, "HUMAN.SYS"), "HUMAN.SYS")
        human_meta = None
    if command_data is None:
        command_data = scsiformat.load_file(
            os.path.join(scsiformat.DATA_DIR, "COMMAND.X"), "COMMAND.X")
        command_meta = None

    volume_label = part_info.get("volume_label")

    return bootsect_data, tree, human_data, command_data, human_meta, command_meta, volume_label


def main():
    parser = argparse.ArgumentParser(
        description="Pack X68000 SxSI disk image(s) from unpacked directories"
    )
    parser.add_argument("dirs_and_output", nargs="+", metavar="DIR_OR_OUTPUT",
                        help="One or more unpack directories followed by output image")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show detailed output")

    args = parser.parse_args()

    if len(args.dirs_and_output) < 2:
        print("Error: need at least one directory and an output image", file=sys.stderr)
        return 1

    extract_dirs = args.dirs_and_output[:-1]
    output_image = args.dirs_and_output[-1]

    for d in extract_dirs:
        if not os.path.isdir(d):
            print(f"Error: directory not found: {d}", file=sys.stderr)
            return 1

    # Load partition data from each directory
    partition_data = []
    for extract_dir in extract_dirs:
        ptable_path = os.path.join(extract_dir, "partitions.json")
        if not os.path.isfile(ptable_path):
            print(f"Error: partitions.json not found in {extract_dir}", file=sys.stderr)
            return 1
        with open(ptable_path) as f:
            ptable = json.load(f)

        for part_info in ptable["partitions"]:
            bootsect_data, tree, human_data, command_data, human_meta, command_meta, \
                volume_label = load_partition_data(extract_dir, part_info)

            spc = bootsect_data[0x14]
            root_entries = struct.unpack_from(">H", bootsect_data, 0x18)[0]

            min_records = compute_min_partition_records(
                tree, human_data, command_data, spc, root_entries)

            # Use original size if it's larger (preserves free space)
            orig_records = part_info["record_count"]
            partition_records = max(min_records, orig_records)

            partition_data.append({
                "extract_dir": extract_dir,
                "part_info": part_info,
                "bootsect_data": bootsect_data,
                "tree": tree,
                "human_data": human_data,
                "command_data": command_data,
                "human_meta": human_meta,
                "command_meta": command_meta,
                "partition_records": partition_records,
                "min_records": min_records,
                "volume_label": volume_label,
            })

    # Layout partitions sequentially
    partitions_layout = []
    next_start = scsiformat.PARTITION_START_RECORD
    for pd in partition_data:
        start = next_start
        count = pd["partition_records"]
        partitions_layout.append((scsiformat.PARTITION_NAME, start, count))
        pd["start_record"] = start
        next_start = start + count

    # Total image size: end of last partition + 1 record for rounding
    last_end = next_start
    total_records = last_end + 1
    image_size = total_records * scsiformat.RECORD_SIZE

    print(f"Image: {output_image}")
    print(f"  Size: {image_size} bytes ({total_records} records, "
          f"{image_size / (1024 * 1024):.1f} MB)")
    print(f"  Partitions: {len(partition_data)}")
    for i, pd in enumerate(partition_data):
        size_mb = pd["partition_records"] * scsiformat.RECORD_SIZE / (1024 * 1024)
        print(f"    [{i}] start={pd['start_record']}, records={pd['partition_records']}, "
              f"{size_mb:.1f} MB (from {pd['extract_dir']})")

    # Create zeroed output image
    print(f"\nCreating {image_size / (1024 * 1024):.1f} MB image...")
    with open(output_image, "wb") as f:
        # Write in chunks to avoid huge memory allocation
        chunk = b"\x00" * (1024 * 1024)
        remaining = image_size
        while remaining > 0:
            write_size = min(remaining, len(chunk))
            f.write(chunk[:write_size])
            remaining -= write_size

    with open(output_image, "r+b") as f:
        # Write IPL from first directory
        first_dir = extract_dirs[0]
        ipl_path = os.path.join(first_dir, "ipl.bin")
        if os.path.isfile(ipl_path):
            ipl_data = scsiformat.load_file(ipl_path, "IPL")
            scsiformat.write_ipl(f, ipl_data, args.verbose)
            print("IPL: written from ipl.bin")

        # Write SASI driver from first directory
        driver_path = os.path.join(first_dir, "driver.bin")
        if os.path.isfile(driver_path):
            driver_data = scsiformat.load_file(driver_path, "SASI driver")
            scsiformat.write_driver(f, driver_data, args.verbose)
            print(f"Driver: {len(driver_data)} bytes written")

        # Write partition table
        scsiformat.write_partition_table(f, total_records, partitions_layout, args.verbose)
        print(f"Partition table: {len(partitions_layout)} partition(s) written")

        # Format each partition
        for i, pd in enumerate(partition_data):
            print(f"\nPartition {i}:")
            bootsect_data = pd["bootsect_data"]
            spc = bootsect_data[0x14]
            root_entries = struct.unpack_from(">H", bootsect_data, 0x18)[0]
            partition_offset = pd["start_record"] * scsiformat.RECORD_SIZE
            ok = scsiformat.format_partition(
                f, partition_offset, pd["partition_records"], pd["start_record"],
                bootsect_data, spc, root_entries, pd["tree"],
                pd["human_data"], pd["command_data"],
                pd["human_meta"], pd["command_meta"], args.verbose,
                volume_label=pd["volume_label"])
            if not ok:
                return 1

    # SCSI header: overlay from first directory only for single-dir repack
    # (multi-dir combines different images so the old header has wrong size)
    scsi_header_path = os.path.join(first_dir, "scsi_header.bin")
    if len(extract_dirs) == 1 and os.path.isfile(scsi_header_path):
        header_data = scsiformat.load_file(scsi_header_path, "SCSI header")
        with open(output_image, "r+b") as f:
            f.seek(0)
            f.write(header_data)
        print(f"\nSCSI header: overlaid from scsi_header.bin")
    else:
        with open(output_image, "r+b") as f:
            scsiformat.write_scsi_header(f, total_records, args.verbose)
        print(f"\nSCSI header: generated")

    print(f"Assembled: {output_image}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

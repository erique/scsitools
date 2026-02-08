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

    Iteratively solves for fat_recs since FAT size depends on cluster count
    which depends on data_recs which depends on FAT size.
    """
    cluster_size = spc * scsiformat.RECORD_SIZE
    root_dir_recs = root_entries * scsiformat.DIR_ENTRY_SIZE // scsiformat.RECORD_SIZE

    # Count data clusters needed
    data_clusters = 0
    data_clusters += max(1, math.ceil(len(human_data) / cluster_size))
    data_clusters += max(1, math.ceil(len(command_data) / cluster_size))
    data_clusters += count_tree_clusters(tree, cluster_size)

    # data_clusters occupy data_clusters * spc records in the data area
    data_recs_needed = data_clusters * spc

    # Iteratively solve: partition_records = 1 + 2*fat_recs + root_dir_recs + data_recs
    # But fat_recs depends on total clusters = data_recs // spc + 2
    fat_recs = 1
    for _ in range(30):
        partition_records = 1 + 2 * fat_recs + root_dir_recs + data_recs_needed
        total_clusters = data_recs_needed // spc + 2
        needed_fat_recs = math.ceil(total_clusters * scsiformat.FAT_ENTRY_SIZE / scsiformat.RECORD_SIZE)
        if needed_fat_recs <= fat_recs:
            break
        fat_recs = needed_fat_recs

    return partition_records


def count_tree_clusters(entries, cluster_size):
    """Count total clusters needed for all entries in the tree."""
    total = 0
    for entry in entries:
        if isinstance(entry, scsiformat.DirEntry):
            subdir_bytes = (len(entry.children) + 2) * scsiformat.DIR_ENTRY_SIZE
            total += max(1, math.ceil(subdir_bytes / cluster_size))
            total += count_tree_clusters(entry.children, cluster_size)
        else:
            total += max(1, math.ceil(len(entry.data) / cluster_size))
    return total


def format_partition(f, partition_offset, partition_records, partition_start_record,
                     bootsect_data, tree, human_data, command_data,
                     human_meta, command_meta, verbose):
    """Format a single partition at the given offset.

    Writes boot sector, FAT, root directory, and all file data.
    """
    spc = bootsect_data[0x14]
    fat_recs = bootsect_data[0x1D]
    root_entries = struct.unpack_from(">H", bootsect_data, 0x18)[0]
    root_dir_recs = root_entries * scsiformat.DIR_ENTRY_SIZE // scsiformat.RECORD_SIZE
    cluster_size = spc * scsiformat.RECORD_SIZE

    # Recompute BPB from the actual partition_records we're using
    fat_recs, clusters = scsiformat.solve_fat_recs(partition_records, spc)

    data_recs = partition_records - 1 - 2 * fat_recs - root_dir_recs

    print(f"  BPB: SPC={spc}, FAT={fat_recs} recs/copy, {clusters} clusters, "
          f"root={root_entries}")

    scsiformat.write_boot_sector(f, partition_offset, bootsect_data, spc, fat_recs,
                                 partition_records, root_entries, partition_start_record,
                                 verbose)

    human_attr, human_time, human_date = human_meta if human_meta else (0x24, 0, 0)
    command_attr, command_time, command_date = command_meta if command_meta else (0x20, 0, 0)

    # Allocate clusters: HUMAN.SYS first, then COMMAND.X, then tree
    human_clusters = math.ceil(len(human_data) / cluster_size)
    human_start = 2
    command_start = human_start + human_clusters
    command_clusters = math.ceil(len(command_data) / cluster_size)
    next_cluster = command_start + command_clusters
    next_cluster = scsiformat.allocate_clusters(tree, next_cluster, cluster_size)

    used_clusters = next_cluster - 2
    if used_clusters > clusters - 2:
        print(f"  Error: need {used_clusters} data clusters but only {clusters - 2} available",
              file=sys.stderr)
        return False

    # Build and write FAT
    cluster_chains = [
        (human_start, human_clusters),
        (command_start, command_clusters),
    ]
    cluster_chains.extend(scsiformat.collect_cluster_chains(tree))
    scsiformat.write_fat(f, partition_offset, fat_recs, cluster_chains, verbose)

    # Build and write root directory
    root_entries_list = [
        scsiformat.make_dir_entry(b"HUMAN   ", b"SYS", b"\x00" * 10,
                                  human_attr, human_start, len(human_data),
                                  human_time, human_date),
        scsiformat.make_dir_entry(b"COMMAND ", b"X  ", b"\x00" * 10,
                                  command_attr, command_start, len(command_data),
                                  command_time, command_date),
    ]
    for entry in tree:
        if isinstance(entry, scsiformat.DirEntry):
            root_entries_list.append(
                scsiformat.make_dir_entry(entry.name_bytes, entry.ext_bytes,
                                          entry.name2_bytes, entry.attr,
                                          entry.start_cluster, 0,
                                          entry.dos_time, entry.dos_date))
        else:
            root_entries_list.append(
                scsiformat.make_dir_entry(entry.name_bytes, entry.ext_bytes,
                                          entry.name2_bytes, entry.attr,
                                          entry.start_cluster, len(entry.data),
                                          entry.dos_time, entry.dos_date))

    scsiformat.write_root_directory(f, partition_offset, fat_recs, root_dir_recs,
                                    root_entries_list, verbose)

    # Write file data
    data_offset = (partition_offset + scsiformat.RECORD_SIZE +
                   fat_recs * scsiformat.RECORD_SIZE * 2 +
                   root_dir_recs * scsiformat.RECORD_SIZE)
    scsiformat.write_file_data(f, data_offset, cluster_size, human_data,
                               human_start, verbose)
    scsiformat.write_file_data(f, data_offset, cluster_size, command_data,
                               command_start, verbose)
    scsiformat.write_tree_data(f, data_offset, cluster_size, tree, 0, verbose)

    total_files = 2 + scsiformat.count_all_entries(tree)
    print(f"  Files: {total_files} written ({used_clusters} clusters used)")
    return True


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

    return bootsect_data, tree, human_data, command_data, human_meta, command_meta


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
            bootsect_data, tree, human_data, command_data, human_meta, command_meta = \
                load_partition_data(extract_dir, part_info)

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
            partition_offset = pd["start_record"] * scsiformat.RECORD_SIZE
            ok = format_partition(
                f, partition_offset, pd["partition_records"], pd["start_record"],
                pd["bootsect_data"], pd["tree"], pd["human_data"], pd["command_data"],
                pd["human_meta"], pd["command_meta"], args.verbose)
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

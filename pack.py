#!/usr/bin/env python3
"""
pack.py - X68000 SxSI Disk Image Packer

Reverse of unpack.py: takes an unpacked directory and recreates the original
disk image. Imports scsiformat.py for all formatting logic.

Usage:
    pack.py <extract_dir> <output_image>
"""

import argparse
import json
import math
import os
import struct
import sys

import scsiformat


def main():
    parser = argparse.ArgumentParser(
        description="Pack an X68000 SxSI disk image from an unpacked directory"
    )
    parser.add_argument("extract_dir", help="Directory created by unpack.py")
    parser.add_argument("output_image", help="Output disk image file")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show detailed output")

    args = parser.parse_args()

    extract_dir = args.extract_dir
    if not os.path.isdir(extract_dir):
        print(f"Error: extract directory not found: {extract_dir}", file=sys.stderr)
        return 1

    # Read partition table metadata
    ptable_path = os.path.join(extract_dir, "partitions.json")
    if not os.path.isfile(ptable_path):
        print(f"Error: partitions.json not found in {extract_dir}", file=sys.stderr)
        return 1
    with open(ptable_path) as f:
        ptable = json.load(f)

    total_records_minus1 = ptable["total_records_minus1"]
    total_records = total_records_minus1 + 1
    image_size = total_records * scsiformat.RECORD_SIZE

    # Read BPB fields from extracted boot sector
    partition = ptable["partitions"][0]
    part_dir = os.path.join(extract_dir, f"partition_{partition['index']}")
    bootsect_path = os.path.join(part_dir, "bootsect.bin")
    bootsect_data = scsiformat.load_file(bootsect_path, "Boot sector template")
    orig_spc = bootsect_data[0x14]
    orig_fat_recs = bootsect_data[0x1D]
    root_entries = struct.unpack_from(">H", bootsect_data, 0x18)[0]
    partition_records = partition["record_count"]

    print(f"Image size: {image_size} bytes ({total_records} records, "
          f"{image_size / (1024 * 1024):.1f} MB)")
    print(f"Partition: {partition_records} records, root_entries={root_entries}")

    # Create zeroed output image
    with open(args.output_image, "wb") as f:
        f.write(b"\x00" * image_size)

    # Format the image using scsiformat.py functions
    with open(args.output_image, "r+b") as f:
        # Write IPL
        ipl_path = os.path.join(extract_dir, "ipl.bin")
        if os.path.isfile(ipl_path):
            ipl_data = scsiformat.load_file(ipl_path, "IPL")
            scsiformat.write_ipl(f, ipl_data, args.verbose)
            print("IPL: written from ipl.bin")

        # Write SASI driver
        driver_path = os.path.join(extract_dir, "driver.bin")
        if os.path.isfile(driver_path):
            driver_data = scsiformat.load_file(driver_path, "SASI driver")
            scsiformat.write_driver(f, driver_data, args.verbose)
            print(f"Driver: {len(driver_data)} bytes written from driver.bin")

        # Write partition table
        scsiformat.write_partition_table(f, total_records, partition_records, args.verbose)
        print("Partition table: written")

        # Use BPB values from original boot sector
        spc = orig_spc
        fat_recs = orig_fat_recs
        root_dir_recs = root_entries * scsiformat.DIR_ENTRY_SIZE // scsiformat.RECORD_SIZE
        data_recs = partition_records - 1 - 2 * fat_recs - root_dir_recs
        clusters = data_recs // spc + 2
        cluster_size = spc * scsiformat.RECORD_SIZE
        print(f"BPB: SPC={spc}, FAT={fat_recs} recs/copy, {clusters} clusters")

        # Write boot sector with extracted template
        partition_offset = scsiformat.PARTITION_START_RECORD * scsiformat.RECORD_SIZE
        scsiformat.write_boot_sector(f, partition_offset, bootsect_data, spc, fat_recs,
                                     partition_records, root_entries, args.verbose)

        # Load file tree from partition directory
        # Temporarily move bootsect.bin out so load_extra_tree doesn't include it
        bootsect_hidden = os.path.join(extract_dir, ".bootsect.bin.tmp")
        os.rename(bootsect_path, bootsect_hidden)
        try:
            tree, human_data, command_data, human_meta, command_meta = \
                scsiformat.load_extra_tree(part_dir)
        finally:
            os.rename(bootsect_hidden, bootsect_path)

        # Use defaults if HUMAN.SYS/COMMAND.X not found
        if human_data is None:
            print("Warning: HUMAN.SYS not found in extract, using default", file=sys.stderr)
            human_data = scsiformat.load_file(
                os.path.join(scsiformat.DATA_DIR, "HUMAN.SYS"), "HUMAN.SYS")
        if command_data is None:
            print("Warning: COMMAND.X not found in extract, using default", file=sys.stderr)
            command_data = scsiformat.load_file(
                os.path.join(scsiformat.DATA_DIR, "COMMAND.X"), "COMMAND.X")

        human_attr, human_time, human_date = human_meta if human_meta else (0x24, 0, 0)
        command_attr, command_time, command_date = command_meta if command_meta else (0x20, 0, 0)

        # Allocate clusters: HUMAN.SYS first, then COMMAND.X, then tree
        human_clusters = math.ceil(len(human_data) / cluster_size)
        human_start = 2
        command_start = human_start + human_clusters
        command_clusters = math.ceil(len(command_data) / cluster_size)
        next_cluster = command_start + command_clusters
        next_cluster = scsiformat.allocate_clusters(tree, next_cluster, cluster_size)

        # Build and write FAT
        cluster_chains = [
            (human_start, human_clusters),
            (command_start, command_clusters),
        ]
        cluster_chains.extend(scsiformat.collect_cluster_chains(tree))
        scsiformat.write_fat(f, partition_offset, fat_recs, cluster_chains, args.verbose)

        # Build and write root directory
        human_name = b"HUMAN   "
        human_ext = b"SYS"
        human_name2 = b"\x00" * 10
        command_name = b"COMMAND "
        command_ext = b"X  "
        command_name2 = b"\x00" * 10

        root_entries_list = [
            scsiformat.make_dir_entry(human_name, human_ext, human_name2,
                                      human_attr, human_start, len(human_data),
                                      human_time, human_date),
            scsiformat.make_dir_entry(command_name, command_ext, command_name2,
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
                                        root_entries_list, args.verbose)

        # Write file data
        data_offset = (partition_offset + scsiformat.RECORD_SIZE +
                       fat_recs * scsiformat.RECORD_SIZE * 2 +
                       root_dir_recs * scsiformat.RECORD_SIZE)
        scsiformat.write_file_data(f, data_offset, cluster_size, human_data,
                                   human_start, args.verbose)
        scsiformat.write_file_data(f, data_offset, cluster_size, command_data,
                                   command_start, args.verbose)
        scsiformat.write_tree_data(f, data_offset, cluster_size, tree, 0, args.verbose)

        total_files = 2 + scsiformat.count_all_entries(tree)
        print(f"Files: {total_files} written (HUMAN.SYS + COMMAND.X + "
              f"{scsiformat.count_all_entries(tree)} from tree)")

    # Overlay original SCSI header
    scsi_header_path = os.path.join(extract_dir, "scsi_header.bin")
    if os.path.isfile(scsi_header_path):
        header_data = scsiformat.load_file(scsi_header_path, "SCSI header")
        with open(args.output_image, "r+b") as f:
            f.seek(0)
            f.write(header_data)
        print(f"SCSI header: {len(header_data)} bytes overlaid from scsi_header.bin")
    else:
        # Fall back to generating a fresh header
        with open(args.output_image, "r+b") as f:
            scsiformat.write_scsi_header(f, total_records, args.verbose)
        print("SCSI header: generated (no scsi_header.bin found)")

    print(f"\nAssembled: {args.output_image}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

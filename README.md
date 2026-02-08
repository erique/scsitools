# scsitools - X68000 SxSI Disk Image Tools

## scsiformat.py

Formats an existing file as a bootable X68000 Human68k SxSI disk image.
The file size determines the disk geometry. Creates a single Human68k
partition with FAT16 filesystem and installs HUMAN.SYS + COMMAND.X for
a bootable system.

### Usage

```
scsiformat.py <image_file> [options]
```

The image file must already exist at the desired size (8 MB minimum).

### Options

| Option | Description |
|--------|-------------|
| `--ipl <file>` | Custom IPL binary (default: data/ipl.bin) |
| `--boot-sector <file>` | Custom partition boot sector template (default: data/bootsect.bin) |
| `--human-sys <file>` | Custom HUMAN.SYS (default: data/HUMAN.SYS) |
| `--command-x <file>` | Custom COMMAND.X (default: data/COMMAND.X) |
| `--driver <file>` | Custom SASI device driver (default: data/driver.bin) |
| `--no-ipl` | Don't write IPL code |
| `--root-entries <n>` | Root directory entries (default: 1024, must be multiple of 32) |
| `-v, --verbose` | Show detailed output |
| `-n, --dry-run` | Show what would be written without modifying the image |

### Example

```
# Create an empty 32 MB file and format it
truncate -s 32M disk.img
./scsiformat.py disk.img
```

### Disk Layout

```
Offset 0x0000  (record 0)     SCSI header ("X68SCSI1")
Offset 0x0400  (record 1)     IPL boot code
Offset 0x0800  (record 2)     Partition table ("X68K")
Offset 0x0C00  (records 3-13) SASI device driver
Offset 0x8000  (record 32+)   Partition 0 "Human68k"
  +0x0000                       Boot sector (BPB + loader code)
  +0x0400                       FAT #1
  +FAT1 end                     FAT #2 (copy)
  +FAT2 end                     Root directory
  +root end                     Data area (HUMAN.SYS, COMMAND.X)
```

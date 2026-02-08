# scsitools - X68000 SxSI Disk Image Tools

## scsiformat.py

Formats an existing file as a bootable X68000 Human68k SxSI disk image.
The file size determines the disk geometry. Creates a single Human68k
partition with FAT16 filesystem and installs HUMAN.SYS + COMMAND.X for
a bootable system.

Supports long filenames (Human68k 18+3 format via the fileName2 field),
recursive subdirectory creation, Shift-JIS filename handling (cp932 encoding),
and file attribute/timestamp preservation via `.x68k_meta` metadata files.

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
| `--extra-files <dir>` | Install additional files from directory into root |
| `-v, --verbose` | Show detailed output |
| `-n, --dry-run` | Show what would be written without modifying the image |

### Examples

```
# Create an empty 32 MB file and format it
truncate -s 32M disk.img
./scsiformat.py disk.img

# Format with additional files installed in the root directory
./scsiformat.py disk.img --extra-files myfiles/
```

The `--extra-files` directory is installed recursively with full support for
long filenames, subdirectories, and Shift-JIS encoded names. If a `.x68k_meta`
file is present (as written by `fsck.py extract`), file attributes and
timestamps are restored from it. HUMAN.SYS and COMMAND.X found in
`--extra-files` replace the default system files.

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

## fsck.py

X68000 filesystem checker and toolkit for SxSI/SCSI disk images.

### Usage

```
fsck.py [options] <command> image.hda [args...]
```

### Commands

| Command | Description |
|---------|-------------|
| `check` | Filesystem consistency check (default) |
| `info` | Show SCSI header, partition table, and BPB details |
| `tree` | List files in tree format with box-drawing characters |
| `ls` | List root directory in long format (attr, size, name) |
| `extract DIR` | Extract all files to DIR, writes `.x68k_meta` metadata |
| `add FILE DEST` | Add file to image (requires `-w`) |
| `mkdir PATH` | Create directory (requires `-w`) |
| `rm PATH` | Delete file or directory (requires `-w`) |

### Options

| Option | Description |
|--------|-------------|
| `--depth N` | Tree depth limit (default: 3, range 1-20) |
| `-w` | Enable write mode (required for add/mkdir/rm) |
| `-p N` | Partition index (default: 0) |
| `-v` | Verbose output (default: on) |
| `--force` | Force read/write past bad sectors |
| `--is2bytes` | Force 2-byte FAT interpretation |
| `--is1.5bytes` | Force 1.5-byte (12-bit) FAT interpretation |
| `--ignore-archive-attrib` | Ignore archive attribute check |

### Check Mode

Validates FAT link consistency (out-of-range pointers, loops, cross-links),
verifies file cluster chains match recorded sizes, and detects lost file chains.

### Extract Mode

Extracts all files and directories preserving the on-disk structure. Writes a
`.x68k_meta` tab-separated metadata file recording path, attribute (hex),
time (hex), and date (hex) for each entry. This metadata file is consumed by
`scsiformat.py` to recreate images with original attributes and timestamps.

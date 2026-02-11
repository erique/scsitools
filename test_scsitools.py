#!/usr/bin/env python3
"""
Test suite for scsitools: scsiformat.py, fsck.py, unpack.py, pack.py.

All tests are self-contained — no external disk images required.
Random file trees are generated as test data with fixed seeds for
reproducibility.

Run options:
    python3 -m pytest test_scsitools.py -v                  # all tests
    python3 -m pytest test_scsitools.py -v -m "not slow"    # fast only (~30s)
    python3 -m pytest test_scsitools.py -v -m slow          # large images only
"""

import filecmp
import math
import os
import random
import subprocess
import sys

import pytest

import scsiformat

slow = pytest.mark.slow

# ============================================================================
# Name pools for random tree generation
# ============================================================================

VOLUME_LABELS_ASCII = [
    "SYSTEM", "GAMES", "WORK", "BACKUP", "DATA", "TOOLS", "MUSIC",
    "HD0", "DISK01", "SRC",
]

VOLUME_LABELS_JAPANESE = [
    "\u30b2\u30fc\u30e0",      # ゲーム
    "\u30c7\u30fc\u30bf",      # データ
    "\u30c4\u30fc\u30eb",      # ツール
    "\u30e1\u30a4\u30f3",      # メイン
]

VOLUME_LABELS = VOLUME_LABELS_ASCII + VOLUME_LABELS_JAPANESE

ASCII_SHORT_NAMES = [
    "File", "Data", "ReadMe", "Config", "Setup", "Main", "Test", "Work",
    "Temp", "Log", "Src", "Lib", "Bin", "Doc", "Img", "Snd", "Gfx", "Map",
    "Util", "Prog",
]

ASCII_LONG_NAMES = [
    "LongFileName", "VeryLongName", "TestDataFile", "ProgramData",
    "BackupData", "SourceCode", "GameSave01", "HighScore",
]

JAPANESE_NAMES = [
    "\u30b2\u30fc\u30e0",      # ゲーム
    "\u30c6\u30b9\u30c8",      # テスト
    "\u30c7\u30fc\u30bf",      # データ
    "\u30c4\u30fc\u30eb",      # ツール
    "\u30ef\u30fc\u30af",      # ワーク
    "\u30c6\u30f3\u30d7",      # テンプ
    "\u30b5\u30f3\u30d7\u30eb",  # サンプル
    "\u30d7\u30ed\u30b0\u30e9\u30e0",  # プログラム
    "\u30e1\u30e2",            # メモ
]

EXTENSIONS = [".X", ".Dat", ".bin", ".TXT", ".Bat", ".sys", ".Ini", ".Doc",
              ".Bmp", ".pcm"]

DIR_NAMES = ["Games", "Tools", "System", "Data", "Backup", "Work",
             "\u30b2\u30fc\u30e0", "\u30c4\u30fc\u30eb", "\u30c7\u30fc\u30bf",
             "SrcCode", "MyFiles"]


# ============================================================================
# Random tree generator
# ============================================================================

def generate_random_tree(root_dir, seed, *, max_files=50,
                         max_total_bytes=2 * 1024 * 1024, max_depth=3,
                         japanese_ratio=0.3, max_file_size=None):
    """Generate a random directory tree for scsiformat --extra-files.

    Returns (file_count, dir_count, total_bytes).
    """
    rng = random.Random(seed)
    if max_file_size is None:
        max_file_size = min(max_total_bytes // 4, 256 * 1024)

    state = {"files": 0, "dirs": 0, "bytes": 0}
    meta_entries = []

    def pick_name(is_dir):
        if is_dir:
            return rng.choice(DIR_NAMES)
        if rng.random() < japanese_ratio:
            name = rng.choice(JAPANESE_NAMES)
        elif rng.random() < 0.3:
            name = rng.choice(ASCII_LONG_NAMES)
        else:
            name = rng.choice(ASCII_SHORT_NAMES)
        ext = rng.choice(EXTENSIONS)
        return name + ext

    def make_unique(name, used):
        if name not in used:
            return name
        for i in range(1, 100):
            candidate = f"{i}{name}" if len(name) < 15 else f"{name[:12]}{i}"
            # Ensure candidate is valid SJIS
            try:
                scsiformat.parse_human68k_filename(
                    candidate if "." in candidate else candidate + ".X")
                if candidate not in used:
                    return candidate
            except ValueError:
                continue
        return None

    def populate(dirpath, rel_prefix, depth):
        if state["files"] >= max_files or state["bytes"] >= max_total_bytes:
            return

        n_entries = rng.randint(2, 8)
        used_names = set()

        for _ in range(n_entries):
            if state["files"] >= max_files or state["bytes"] >= max_total_bytes:
                break

            is_dir = depth > 0 and rng.random() < 0.25
            raw_name = pick_name(is_dir)

            if is_dir:
                name = make_unique(raw_name, used_names)
                if name is None:
                    continue
                used_names.add(name)
                dpath = os.path.join(dirpath, name)
                os.makedirs(dpath, exist_ok=True)
                state["dirs"] += 1
                rel = rel_prefix + name + "/"
                attr = 0x10
                t = rng.randint(0, 0xFFFF)
                d = rng.randint(0, 0xFFFF)
                meta_entries.append((rel, attr, t, d))
                populate(dpath, rel, depth - 1)
            else:
                name = make_unique(raw_name, used_names)
                if name is None:
                    continue
                # Validate the name is encodable
                try:
                    scsiformat.parse_human68k_filename(name)
                except ValueError:
                    continue
                used_names.add(name)
                remaining = max_total_bytes - state["bytes"]
                size = min(rng.randint(0, max_file_size), remaining)
                fpath = os.path.join(dirpath, name)
                data = rng.randbytes(size)
                with open(fpath, "wb") as f:
                    f.write(data)
                state["files"] += 1
                state["bytes"] += size
                rel = rel_prefix + name
                attr = 0x20
                t = rng.randint(0, 0xFFFF)
                d = rng.randint(0, 0xFFFF)
                meta_entries.append((rel, attr, t, d))

    os.makedirs(root_dir, exist_ok=True)
    populate(root_dir, "", max_depth)

    # Write .x68k_meta
    meta_path = os.path.join(root_dir, ".x68k_meta")
    with open(meta_path, "w", encoding="utf-8") as mf:
        mf.write("# path\tattr\ttime\tdate\n")
        for path, attr, t, d in meta_entries:
            mf.write(f"{path}\t{attr:02x}\t{t:04x}\t{d:04x}\n")

    return state["files"], state["dirs"], state["bytes"]


def generate_large_tree(root_dir, seed, *, target_bytes, max_depth=3,
                        japanese_ratio=0.3):
    """Generate a large random tree targeting a specific total size.

    Uses a mix of large, medium, and small files to hit the target
    while stressing both data throughput and directory handling.

    Returns (file_count, dir_count, total_bytes).
    """
    rng = random.Random(seed)
    state = {"files": 0, "dirs": 0, "bytes": 0}
    meta_entries = []

    # File size distribution: 60% large, 25% medium, 15% small
    large_size = (4 * 1024 * 1024, 8 * 1024 * 1024)
    medium_size = (512 * 1024, 2 * 1024 * 1024)
    small_size = (1024, 64 * 1024)

    def pick_name(is_dir):
        if is_dir:
            return rng.choice(DIR_NAMES)
        if rng.random() < japanese_ratio:
            name = rng.choice(JAPANESE_NAMES)
        elif rng.random() < 0.3:
            name = rng.choice(ASCII_LONG_NAMES)
        else:
            name = rng.choice(ASCII_SHORT_NAMES)
        ext = rng.choice(EXTENSIONS)
        return name + ext

    def make_unique(name, used):
        if name not in used:
            return name
        for i in range(1, 200):
            candidate = f"{i}{name}" if len(name) < 15 else f"{name[:12]}{i}"
            try:
                scsiformat.parse_human68k_filename(
                    candidate if "." in candidate else candidate + ".X")
                if candidate not in used:
                    return candidate
            except ValueError:
                continue
        return None

    def pick_file_size():
        r = rng.random()
        remaining = target_bytes - state["bytes"]
        if remaining <= 0:
            return 0
        if r < 0.60:
            size = rng.randint(*large_size)
        elif r < 0.85:
            size = rng.randint(*medium_size)
        else:
            size = rng.randint(*small_size)
        return min(size, remaining)

    def populate(dirpath, rel_prefix, depth):
        if state["bytes"] >= target_bytes:
            return

        n_entries = rng.randint(3, 12)
        used_names = set()

        for _ in range(n_entries):
            if state["bytes"] >= target_bytes:
                break

            is_dir = depth > 0 and rng.random() < 0.2
            raw_name = pick_name(is_dir)

            if is_dir:
                name = make_unique(raw_name, used_names)
                if name is None:
                    continue
                used_names.add(name)
                dpath = os.path.join(dirpath, name)
                os.makedirs(dpath, exist_ok=True)
                state["dirs"] += 1
                rel = rel_prefix + name + "/"
                attr = 0x10
                t = rng.randint(0, 0xFFFF)
                d = rng.randint(0, 0xFFFF)
                meta_entries.append((rel, attr, t, d))
                populate(dpath, rel, depth - 1)
            else:
                name = make_unique(raw_name, used_names)
                if name is None:
                    continue
                try:
                    scsiformat.parse_human68k_filename(name)
                except ValueError:
                    continue
                used_names.add(name)
                size = pick_file_size()
                if size == 0:
                    break
                fpath = os.path.join(dirpath, name)
                data = rng.randbytes(size)
                with open(fpath, "wb") as f:
                    f.write(data)
                state["files"] += 1
                state["bytes"] += size
                rel = rel_prefix + name
                attr = 0x20
                t = rng.randint(0, 0xFFFF)
                d = rng.randint(0, 0xFFFF)
                meta_entries.append((rel, attr, t, d))

    os.makedirs(root_dir, exist_ok=True)
    populate(root_dir, "", max_depth)

    # Write .x68k_meta
    meta_path = os.path.join(root_dir, ".x68k_meta")
    with open(meta_path, "w", encoding="utf-8") as mf:
        mf.write("# path\tattr\ttime\tdate\n")
        for path, attr, t, d in meta_entries:
            mf.write(f"{path}\t{attr:02x}\t{t:04x}\t{d:04x}\n")

    return state["files"], state["dirs"], state["bytes"]


# ============================================================================
# Test helpers
# ============================================================================

def run_tool(name, *args, check=True):
    """Run a Python tool as subprocess, assert success."""
    cmd = [sys.executable, os.path.join(os.path.dirname(__file__), name)] + list(args)
    result = subprocess.run(cmd, capture_output=True, text=True)
    if check and result.returncode != 0:
        raise AssertionError(
            f"{name} failed (rc={result.returncode}):\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}")
    return result


def make_image(path, size_mb):
    """Create a zeroed file of given size in MB."""
    with open(path, "wb") as f:
        f.seek(size_mb * 1024 * 1024 - 1)
        f.write(b"\x00")


def format_image(path, extra_dir=None, verbose=False, volume_label=None):
    """Run scsiformat.py on an image."""
    args = [path]
    if extra_dir:
        args += ["--extra-files", extra_dir]
    if volume_label:
        args += ["--volume-label", volume_label]
    if verbose:
        args.append("-v")
    return run_tool("scsiformat.py", *args)


def fsck_check(image, partition=0):
    """Run fsck.py check, assert no errors."""
    result = run_tool("fsck.py", "check", image, "-p", str(partition))
    assert "No errors found." in result.stdout, \
        f"fsck check failed:\n{result.stdout}\n{result.stderr}"
    return result


def fsck_extract(image, dest, partition=0):
    """Run fsck.py extract to a directory."""
    return run_tool("fsck.py", "extract", image, dest, "-p", str(partition))


def fsck_info(image):
    """Run fsck.py info, return stdout."""
    return run_tool("fsck.py", "info", image).stdout


def fsck_ls(image, partition=0):
    """Run fsck.py ls, return stdout."""
    return run_tool("fsck.py", "ls", image, "-p", str(partition)).stdout


def compare_extractions(dir_a, dir_b):
    """Recursively compare two directories byte-for-byte.

    Ignores .x68k_meta files (metadata may differ in formatting).
    """
    errors = []

    def collect_files(base):
        result = {}
        for root, dirs, files in os.walk(base):
            for f in files:
                if f == ".x68k_meta":
                    continue
                full = os.path.join(root, f)
                rel = os.path.relpath(full, base)
                result[rel] = full
        return result

    files_a = collect_files(dir_a)
    files_b = collect_files(dir_b)

    only_a = set(files_a) - set(files_b)
    only_b = set(files_b) - set(files_a)
    if only_a:
        errors.append(f"Only in {dir_a}: {sorted(only_a)}")
    if only_b:
        errors.append(f"Only in {dir_b}: {sorted(only_b)}")

    for rel in sorted(set(files_a) & set(files_b)):
        if not filecmp.cmp(files_a[rel], files_b[rel], shallow=False):
            size_a = os.path.getsize(files_a[rel])
            size_b = os.path.getsize(files_b[rel])
            errors.append(f"Differs: {rel} ({size_a} vs {size_b} bytes)")

    if errors:
        raise AssertionError("Directory comparison failed:\n" + "\n".join(errors))


def compare_with_originals(extract_dir, original_dir):
    """Compare extracted files with the originals that were packed.

    Ignores .x68k_meta and system files (HUMAN.SYS, COMMAND.X) since
    those come from the data/ directory, not --extra-files.
    """
    errors = []
    skip = {".x68k_meta"}

    def collect_files(base):
        result = {}
        for root, dirs, files in os.walk(base):
            for f in files:
                if f in skip:
                    continue
                full = os.path.join(root, f)
                rel = os.path.relpath(full, base)
                result[rel] = full
        return result

    extracted = collect_files(extract_dir)
    originals = collect_files(original_dir)

    # System files are in extraction but not in originals
    system_files = {"HUMAN.SYS", "COMMAND.X"}

    for rel in sorted(originals):
        if rel not in extracted:
            errors.append(f"Missing from extraction: {rel}")
            continue
        if not filecmp.cmp(originals[rel], extracted[rel], shallow=False):
            size_o = os.path.getsize(originals[rel])
            size_e = os.path.getsize(extracted[rel])
            errors.append(f"Differs: {rel} ({size_o} original vs {size_e} extracted)")

    if errors:
        raise AssertionError(
            f"Extraction comparison failed ({len(errors)} errors):\n"
            + "\n".join(errors[:20]))


# ============================================================================
# Group 1: Unit tests (direct imports, no subprocess)
# ============================================================================

class TestCalculateBPB:
    def test_8mb(self):
        partition_records = (8 * 1024 * 1024 // scsiformat.RECORD_SIZE) - 33
        spc, fat_recs, clusters, root_dir_recs = scsiformat.calculate_bpb(
            partition_records)
        assert spc == 1
        assert fat_recs == 16
        assert clusters == 8096
        assert root_dir_recs == 32

    @pytest.mark.parametrize("size_mb", [8, 16, 32, 64, 128, 256, 512, 1024])
    def test_parametrized(self, size_mb):
        total_records = size_mb * 1024 * 1024 // scsiformat.RECORD_SIZE
        partition_records = total_records - 33
        spc, fat_recs, clusters, root_dir_recs = scsiformat.calculate_bpb(
            partition_records)

        # Basic constraints
        assert spc >= 1
        assert spc in (1, 2, 4, 8, 16, 32, 64, 128)
        assert clusters <= 65535
        assert fat_recs <= 255
        assert fat_recs >= 1
        assert root_dir_recs == 32

        # FAT must have enough entries for all clusters
        fat_entries = fat_recs * scsiformat.RECORD_SIZE // scsiformat.FAT_ENTRY_SIZE
        assert fat_entries >= clusters

        # Cluster count must be consistent
        reserved = 1
        data_recs = partition_records - reserved - 2 * fat_recs - root_dir_recs
        expected_clusters = data_recs // spc + 2
        assert clusters == expected_clusters


class TestSolveFatRecs:
    @pytest.mark.parametrize("size_mb", [8, 16, 32, 64, 128, 256, 512, 1024])
    def test_convergence(self, size_mb):
        total_records = size_mb * 1024 * 1024 // scsiformat.RECORD_SIZE
        partition_records = total_records - 33
        # Get spc from calculate_bpb
        spc = scsiformat.calculate_bpb(partition_records)[0]
        fat_recs, clusters = scsiformat.solve_fat_recs(partition_records, spc)

        # FAT must cover all clusters
        fat_entries = fat_recs * scsiformat.RECORD_SIZE // scsiformat.FAT_ENTRY_SIZE
        assert fat_entries >= clusters

        # Verify the solution is minimal (not over-allocated)
        needed = math.ceil(clusters * scsiformat.FAT_ENTRY_SIZE
                           / scsiformat.RECORD_SIZE)
        assert fat_recs == needed


class TestParseFilename:
    def test_short_human_sys(self):
        name, ext, name2 = scsiformat.parse_human68k_filename("HUMAN.SYS")
        assert name == b"HUMAN\x20\x20\x20"
        assert ext == b"SYS"
        assert name2 == b"\x00" * 10

    def test_short_command_x(self):
        name, ext, name2 = scsiformat.parse_human68k_filename("COMMAND.X")
        assert name == b"COMMAND\x20"
        assert ext == b"X\x20\x20"
        assert name2 == b"\x00" * 10

    def test_short_no_ext(self):
        name, ext, name2 = scsiformat.parse_human68k_filename("README")
        assert name == b"README\x20\x20"
        assert ext == b"\x20\x20\x20"
        assert name2 == b"\x00" * 10

    def test_long_roundtrip(self):
        original = "LongFileName.TXT"
        name, ext, name2 = scsiformat.parse_human68k_filename(original)
        # Name > 8 chars should overflow into name2
        assert name == b"LongFile"
        assert ext == b"TXT"
        assert name2[:4] == b"Name"
        # Roundtrip
        result = scsiformat.name_bytes_to_str(name, ext, name2)
        assert result == original

    def test_japanese_game(self):
        original = "\u30b2\u30fc\u30e0.X"  # ゲーム.X
        name, ext, name2 = scsiformat.parse_human68k_filename(original)
        result = scsiformat.name_bytes_to_str(name, ext, name2)
        assert result == original

    def test_japanese_test_dat(self):
        original = "\u30c6\u30b9\u30c8.DAT"  # テスト.DAT
        name, ext, name2 = scsiformat.parse_human68k_filename(original)
        result = scsiformat.name_bytes_to_str(name, ext, name2)
        assert result == original

    def test_e5_substitution(self):
        """First byte 0xE5 should be stored as 0x05 and roundtrip correctly."""
        # Use half-width katakana ｵ (0xB5 in cp932, single byte) to test
        # a name where the SJIS first byte happens to be 0xE5 won't work
        # because 0xE5 is a lead byte in cp932.  Instead, directly test
        # the substitution logic: craft name_bytes with 0xE5 first byte
        # and verify name_bytes_to_str restores it.
        name = bytearray(b"\xe5TEST\x20\x20\x20")
        ext = b"X\x20\x20"
        name2 = b"\x00" * 10

        # parse_human68k_filename would store 0xE5 as 0x05
        name_stored = bytearray(name)
        name_stored[0] = 0x05

        # name_bytes_to_str should restore 0xE5
        result = scsiformat.name_bytes_to_str(bytes(name_stored), ext, name2)
        # The restored name should start with the byte 0xE5
        restored = result.encode("cp932") if result.isascii() is False else result.encode("latin-1")
        assert restored[0] == 0xE5

    def test_too_long_name(self):
        # 19+ SJIS bytes in name part
        with pytest.raises(ValueError, match="Name too long"):
            scsiformat.parse_human68k_filename("A" * 19 + ".X")

    def test_too_long_ext(self):
        with pytest.raises(ValueError, match="Extension too long"):
            scsiformat.parse_human68k_filename("FOO.ABCD")


# ============================================================================
# Group 2: Small image integration tests
# ============================================================================

class TestFormatSmall:
    def test_basic(self, tmp_path):
        """8MB with random tree, fsck check passes, ls shows files."""
        tree_dir = tmp_path / "tree"
        nfiles, ndirs, nbytes = generate_random_tree(str(tree_dir), seed=1)
        assert nfiles > 0

        image = str(tmp_path / "test.hda")
        make_image(image, 8)
        format_image(image, extra_dir=str(tree_dir))
        fsck_check(image)

        ls_out = fsck_ls(image)
        # Should contain at least HUMAN.SYS and COMMAND.X
        assert "HUMAN.SYS" in ls_out or "HUMAN" in ls_out
        assert "COMMAND.X" in ls_out or "COMMAND" in ls_out

    def test_bare(self, tmp_path):
        """8MB no extra files, only system files present."""
        image = str(tmp_path / "bare.hda")
        make_image(image, 8)
        format_image(image)
        fsck_check(image)

        ls_out = fsck_ls(image)
        assert "HUMAN" in ls_out
        assert "COMMAND" in ls_out

    @pytest.mark.parametrize("size_mb", [8, 16, 32])
    def test_sizes(self, tmp_path, size_mb):
        """Multiple sizes all pass fsck check."""
        tree_dir = tmp_path / "tree"
        generate_random_tree(str(tree_dir), seed=size_mb)

        image = str(tmp_path / f"test_{size_mb}.hda")
        make_image(image, size_mb)
        format_image(image, extra_dir=str(tree_dir))
        fsck_check(image)

    def test_dry_run(self, tmp_path):
        """--dry-run leaves image all zeros."""
        image = str(tmp_path / "dry.hda")
        make_image(image, 8)

        result = run_tool("scsiformat.py", image, "-n")
        assert "Dry run" in result.stdout

        with open(image, "rb") as f:
            data = f.read()
        assert data == b"\x00" * len(data)

    def test_empty_extra(self, tmp_path):
        """Format with empty --extra-files, only system files."""
        tree_dir = tmp_path / "empty_tree"
        tree_dir.mkdir()
        # Write minimal meta
        (tree_dir / ".x68k_meta").write_text("# path\tattr\ttime\tdate\n",
                                             encoding="utf-8")

        image = str(tmp_path / "test.hda")
        make_image(image, 8)
        format_image(image, extra_dir=str(tree_dir))
        fsck_check(image)

    def test_deep_dirs(self, tmp_path):
        """Tree with max_depth=3, verify check passes."""
        tree_dir = tmp_path / "deep"
        generate_random_tree(str(tree_dir), seed=42, max_depth=3, max_files=30)

        image = str(tmp_path / "deep.hda")
        make_image(image, 16)
        format_image(image, extra_dir=str(tree_dir))
        fsck_check(image)

    def test_japanese_only(self, tmp_path):
        """Tree using only Japanese names."""
        tree_dir = tmp_path / "jp"
        nfiles, ndirs, nbytes = generate_random_tree(
            str(tree_dir), seed=7, japanese_ratio=1.0, max_files=20)
        assert nfiles > 0

        image = str(tmp_path / "jp.hda")
        make_image(image, 8)
        format_image(image, extra_dir=str(tree_dir))
        fsck_check(image)


# ============================================================================
# Group 3: Round-trip small (format → unpack → pack → verify)
# ============================================================================

class TestRoundtripSmall:
    def test_basic(self, tmp_path):
        """Format 8MB, unpack, pack, both pass fsck."""
        tree_dir = tmp_path / "tree"
        generate_random_tree(str(tree_dir), seed=100, max_files=20)

        # Format original
        orig = str(tmp_path / "orig.hda")
        make_image(orig, 8)
        format_image(orig, extra_dir=str(tree_dir))
        fsck_check(orig)

        # Unpack
        unpacked = str(tmp_path / "unpacked")
        run_tool("unpack.py", orig, unpacked)

        # Pack
        repacked = str(tmp_path / "repacked.hda")
        run_tool("pack.py", unpacked, repacked)
        fsck_check(repacked)

    def test_preserves_files(self, tmp_path):
        """Extract both images, compare byte-for-byte."""
        tree_dir = tmp_path / "tree"
        generate_random_tree(str(tree_dir), seed=101, max_files=25)

        orig = str(tmp_path / "orig.hda")
        make_image(orig, 8)
        format_image(orig, extra_dir=str(tree_dir))

        # Unpack + pack
        unpacked = str(tmp_path / "unpacked")
        run_tool("unpack.py", orig, unpacked)
        repacked = str(tmp_path / "repacked.hda")
        run_tool("pack.py", unpacked, repacked)

        # Extract both
        ext_orig = str(tmp_path / "ext_orig")
        ext_repacked = str(tmp_path / "ext_repacked")
        fsck_extract(orig, ext_orig)
        fsck_extract(repacked, ext_repacked)

        compare_extractions(ext_orig, ext_repacked)

    def test_unpack_structure(self, tmp_path):
        """Verify partitions.json, bootsect.bin, .x68k_meta exist."""
        image = str(tmp_path / "test.hda")
        make_image(image, 8)
        format_image(image)

        unpacked = str(tmp_path / "unpacked")
        run_tool("unpack.py", image, unpacked)

        assert os.path.isfile(os.path.join(unpacked, "partitions.json"))
        assert os.path.isfile(os.path.join(unpacked, "ipl.bin"))
        part0 = os.path.join(unpacked, "partition_0")
        assert os.path.isdir(part0)
        assert os.path.isfile(os.path.join(part0, "bootsect.bin"))
        assert os.path.isfile(os.path.join(part0, ".x68k_meta"))

    def test_roundtrip_metadata(self, tmp_path):
        """Verify .x68k_meta attrs/timestamps preserved through roundtrip."""
        tree_dir = tmp_path / "tree"
        generate_random_tree(str(tree_dir), seed=102, max_files=15)

        orig = str(tmp_path / "orig.hda")
        make_image(orig, 8)
        format_image(orig, extra_dir=str(tree_dir))

        # Extract and read meta
        ext1 = str(tmp_path / "ext1")
        fsck_extract(orig, ext1)

        # Unpack, pack, extract again
        unpacked = str(tmp_path / "unpacked")
        run_tool("unpack.py", orig, unpacked)
        repacked = str(tmp_path / "repacked.hda")
        run_tool("pack.py", unpacked, repacked)

        ext2 = str(tmp_path / "ext2")
        fsck_extract(repacked, ext2)

        # Parse and compare metadata
        def parse_meta(path):
            entries = {}
            meta = os.path.join(path, ".x68k_meta")
            with open(meta, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split("\t")
                    name = parts[0]
                    attr = parts[1] if len(parts) > 1 else "00"
                    time = parts[2] if len(parts) > 2 else "0000"
                    date = parts[3] if len(parts) > 3 else "0000"
                    entries[name] = (attr, time, date)
            return entries

        meta1 = parse_meta(ext1)
        meta2 = parse_meta(ext2)

        # All entries from original should be in repacked
        for name in meta1:
            assert name in meta2, f"Missing entry: {name}"
            assert meta1[name] == meta2[name], \
                f"Metadata differs for {name}: {meta1[name]} vs {meta2[name]}"


# ============================================================================
# Group 4: Large image tests
# ============================================================================

@slow
class TestLarge:
    def test_single_partition(self, tmp_path):
        """512MB image, ~450MB of files, Japanese+English names."""
        tree_dir = str(tmp_path / "tree")
        target = 450 * 1024 * 1024
        nfiles, ndirs, nbytes = generate_large_tree(
            tree_dir, seed=1000, target_bytes=target, max_depth=3,
            japanese_ratio=0.3)
        assert nfiles > 50
        assert nbytes > 300 * 1024 * 1024

        image = str(tmp_path / "large.hda")
        make_image(image, 512)
        format_image(image, extra_dir=tree_dir)
        fsck_check(image)

        # Extract and compare with originals
        ext_dir = str(tmp_path / "extracted")
        fsck_extract(image, ext_dir)
        compare_with_originals(ext_dir, tree_dir)

    def test_multi_partition(self, tmp_path):
        """5 partitions x 256MB, each with different random tree."""
        images = []
        tree_dirs = []

        for i in range(5):
            tree_dir = str(tmp_path / f"tree_{i}")
            target = 220 * 1024 * 1024
            generate_large_tree(tree_dir, seed=2000 + i, target_bytes=target,
                                max_depth=3, japanese_ratio=0.3)
            tree_dirs.append(tree_dir)

            img = str(tmp_path / f"part_{i}.hda")
            make_image(img, 256)
            format_image(img, extra_dir=tree_dir)
            images.append(img)

        # Unpack all
        unpacked_dirs = []
        for i, img in enumerate(images):
            unpacked = str(tmp_path / f"unpacked_{i}")
            run_tool("unpack.py", img, unpacked)
            unpacked_dirs.append(unpacked)

        # Pack into combined image
        combined = str(tmp_path / "combined.hda")
        run_tool("pack.py", *unpacked_dirs, combined)

        # Verify
        info = fsck_info(combined)
        assert "Partition 4" in info or "partition 4" in info.lower()

        for i in range(5):
            fsck_check(combined, partition=i)
            ext_dir = str(tmp_path / f"ext_combined_{i}")
            fsck_extract(combined, ext_dir, partition=i)
            compare_with_originals(ext_dir, tree_dirs[i])

    def test_large_roundtrip(self, tmp_path):
        """Format 5x256MB → unpack all → pack combined → verify full cycle."""
        images = []
        tree_dirs = []

        for i in range(5):
            tree_dir = str(tmp_path / f"tree_{i}")
            target = 200 * 1024 * 1024
            generate_large_tree(tree_dir, seed=3000 + i, target_bytes=target,
                                max_depth=3)
            tree_dirs.append(tree_dir)

            img = str(tmp_path / f"part_{i}.hda")
            make_image(img, 256)
            format_image(img, extra_dir=tree_dir)
            images.append(img)

        # Unpack all
        unpacked_dirs = []
        for i, img in enumerate(images):
            unpacked = str(tmp_path / f"unpacked_{i}")
            run_tool("unpack.py", img, unpacked)
            unpacked_dirs.append(unpacked)

        # Pack combined
        combined = str(tmp_path / "combined.hda")
        run_tool("pack.py", *unpacked_dirs, combined)

        # Verify all partitions
        for i in range(5):
            fsck_check(combined, partition=i)

        # Extract each partition and compare
        for i in range(5):
            ext_dir = str(tmp_path / f"ext_{i}")
            fsck_extract(combined, ext_dir, partition=i)
            compare_with_originals(ext_dir, tree_dirs[i])

        # Full cycle: unpack combined → repack → compare extractions
        unpacked_combined = str(tmp_path / "unpacked_combined")
        run_tool("unpack.py", combined, unpacked_combined)
        repacked = str(tmp_path / "repacked.hda")
        run_tool("pack.py", unpacked_combined, repacked)

        for i in range(5):
            fsck_check(repacked, partition=i)
            ext_a = str(tmp_path / f"ext_{i}")      # already extracted above
            ext_b = str(tmp_path / f"ext_repack_{i}")
            fsck_extract(repacked, ext_b, partition=i)
            compare_extractions(ext_a, ext_b)

    def test_nearly_full(self, tmp_path):
        """256MB image filled to ~95% capacity."""
        tree_dir = str(tmp_path / "tree")
        # 256MB image → ~243MB usable after overhead
        target = 230 * 1024 * 1024
        nfiles, ndirs, nbytes = generate_large_tree(
            tree_dir, seed=4000, target_bytes=target, max_depth=2)
        assert nbytes > 150 * 1024 * 1024

        image = str(tmp_path / "full.hda")
        make_image(image, 256)
        format_image(image, extra_dir=tree_dir)
        fsck_check(image)

        ext_dir = str(tmp_path / "extracted")
        fsck_extract(image, ext_dir)
        compare_with_originals(ext_dir, tree_dir)

    def test_everything(self, tmp_path):
        """Kitchen-sink test: 5x256MB, volume labels, Japanese+English, full roundtrip.

        Exercises every feature in one image suitable for MAME boot-testing.
        """
        import json

        rng = random.Random(5000)
        # Partition 2 has no label (None) to test the mixed case
        labels = [rng.choice(VOLUME_LABELS) for _ in range(5)]
        labels[2] = None

        images = []
        tree_dirs = []

        for i in range(5):
            tree_dir = str(tmp_path / f"tree_{i}")
            target = 200 * 1024 * 1024
            jp_ratio = 0.5 if i % 2 == 0 else 0.2
            generate_large_tree(tree_dir, seed=5000 + i, target_bytes=target,
                                max_depth=3, japanese_ratio=jp_ratio)
            tree_dirs.append(tree_dir)

            img = str(tmp_path / f"part_{i}.hda")
            make_image(img, 256)
            format_image(img, extra_dir=tree_dir, volume_label=labels[i])
            images.append(img)

        # Unpack all
        unpacked_dirs = []
        for i, img in enumerate(images):
            unpacked = str(tmp_path / f"unpacked_{i}")
            run_tool("unpack.py", img, unpacked)
            unpacked_dirs.append(unpacked)

        # Verify labels in partitions.json
        for i, udir in enumerate(unpacked_dirs):
            with open(os.path.join(udir, "partitions.json")) as f:
                ptable = json.load(f)
            got = ptable["partitions"][0].get("volume_label")
            assert got == labels[i], \
                f"Partition {i}: expected label {labels[i]!r}, got {got!r}"

        # Pack combined
        combined = str(tmp_path / "combined.hda")
        run_tool("pack.py", *unpacked_dirs, combined)

        # Verify all partitions pass check
        for i in range(5):
            fsck_check(combined, partition=i)

        # Verify labels in fsck info (skip None)
        info = fsck_info(combined)
        for i, label in enumerate(labels):
            if label is not None:
                assert label in info, \
                    f"Partition {i} label {label!r} not found in combined info"

        # Extract each partition and compare with originals
        for i in range(5):
            ext_dir = str(tmp_path / f"ext_{i}")
            fsck_extract(combined, ext_dir, partition=i)
            compare_with_originals(ext_dir, tree_dirs[i])

        # Full cycle: unpack combined → repack → verify everything again
        unpacked_combined = str(tmp_path / "unpacked_combined")
        run_tool("unpack.py", combined, unpacked_combined)

        with open(os.path.join(unpacked_combined, "partitions.json")) as f:
            ptable = json.load(f)
        for i in range(5):
            got = ptable["partitions"][i].get("volume_label")
            assert got == labels[i], \
                f"Partition {i}: expected {labels[i]!r}, got {got!r}"

        repacked = str(tmp_path / "repacked.hda")
        run_tool("pack.py", unpacked_combined, repacked)

        for i in range(5):
            fsck_check(repacked, partition=i)
            ext_a = str(tmp_path / f"ext_{i}")
            ext_b = str(tmp_path / f"ext_repack_{i}")
            fsck_extract(repacked, ext_b, partition=i)
            compare_extractions(ext_a, ext_b)

        info_repacked = fsck_info(repacked)
        for i, label in enumerate(labels):
            if label is not None:
                assert label in info_repacked, \
                    f"Partition {i} label {label!r} lost after repack"


# ============================================================================
# Group 5: Multi-partition small (fast)
# ============================================================================

class TestMultiPartitionSmall:
    def test_two_partitions(self, tmp_path):
        """Two 8MB with different trees → combined, both pass check."""
        images = []
        for i in range(2):
            tree_dir = str(tmp_path / f"tree_{i}")
            generate_random_tree(tree_dir, seed=200 + i, max_files=15)

            img = str(tmp_path / f"part_{i}.hda")
            make_image(img, 8)
            format_image(img, extra_dir=tree_dir)
            images.append(img)

        # Unpack both
        unpacked = []
        for i, img in enumerate(images):
            u = str(tmp_path / f"unpacked_{i}")
            run_tool("unpack.py", img, u)
            unpacked.append(u)

        # Pack combined
        combined = str(tmp_path / "combined.hda")
        run_tool("pack.py", *unpacked, combined)

        info = fsck_info(combined)
        assert "Partition 0" in info or "partition 0" in info.lower()
        assert "Partition 1" in info or "partition 1" in info.lower()

        fsck_check(combined, partition=0)
        fsck_check(combined, partition=1)

    def test_five_partitions(self, tmp_path):
        """Five 8MB → combined, all 5 pass check+extract."""
        images = []
        tree_dirs = []
        for i in range(5):
            tree_dir = str(tmp_path / f"tree_{i}")
            generate_random_tree(tree_dir, seed=300 + i, max_files=10)
            tree_dirs.append(tree_dir)

            img = str(tmp_path / f"part_{i}.hda")
            make_image(img, 8)
            format_image(img, extra_dir=tree_dir)
            images.append(img)

        # Unpack all
        unpacked = []
        for i, img in enumerate(images):
            u = str(tmp_path / f"unpacked_{i}")
            run_tool("unpack.py", img, u)
            unpacked.append(u)

        # Pack combined
        combined = str(tmp_path / "combined.hda")
        run_tool("pack.py", *unpacked, combined)

        for i in range(5):
            fsck_check(combined, partition=i)
            ext_dir = str(tmp_path / f"ext_{i}")
            fsck_extract(combined, ext_dir, partition=i)
            compare_with_originals(ext_dir, tree_dirs[i])


# ============================================================================
# Group 6: Volume label tests
# ============================================================================

class TestVolumeLabel:
    def test_make_volume_label_entry(self):
        """Unit test: verify 32-byte entry, attr=0x08, name padded."""
        entry = scsiformat.make_volume_label_entry("TESTDISK")
        assert len(entry) == 32
        assert entry[0x0B] == 0x08
        assert entry[0x00:0x0B] == b"TESTDISK   "
        # cluster and size must be zero
        assert entry[0x1A:0x1C] == b"\x00\x00"
        assert entry[0x1C:0x20] == b"\x00\x00\x00\x00"
        # name2 must be zero
        assert entry[0x0C:0x16] == b"\x00" * 10

    def test_make_volume_label_entry_japanese(self):
        """Unit test: Japanese label encodes correctly."""
        entry = scsiformat.make_volume_label_entry("\u30b2\u30fc\u30e0")  # ゲーム
        assert len(entry) == 32
        assert entry[0x0B] == 0x08
        sjis = "\u30b2\u30fc\u30e0".encode("cp932")  # 6 bytes
        padded = sjis.ljust(11, b"\x20")
        assert entry[0x00:0x0B] == padded

    def test_make_volume_label_entry_too_long(self):
        """Unit test: label >11 SJIS bytes raises ValueError."""
        with pytest.raises(ValueError, match="too long"):
            scsiformat.make_volume_label_entry("A" * 12)

    def test_make_volume_label_entry_empty(self):
        """Unit test: empty label raises ValueError."""
        with pytest.raises(ValueError, match="empty"):
            scsiformat.make_volume_label_entry("")

    def test_format_with_label(self, tmp_path):
        """8MB with --volume-label TESTDISK, fsck check passes, info shows label."""
        image = str(tmp_path / "labeled.hda")
        make_image(image, 8)
        format_image(image, volume_label="TESTDISK")
        fsck_check(image)

        info = fsck_info(image)
        assert "TESTDISK" in info

    def test_format_with_japanese_label(self, tmp_path):
        """Japanese label, fsck check passes, info shows label."""
        label = "\u30b2\u30fc\u30e0"  # ゲーム
        image = str(tmp_path / "jp_label.hda")
        make_image(image, 8)
        format_image(image, volume_label=label)
        fsck_check(image)

        info = fsck_info(image)
        assert label in info

    def test_format_with_label_and_files(self, tmp_path):
        """Volume label + extra files, all pass check."""
        tree_dir = tmp_path / "tree"
        generate_random_tree(str(tree_dir), seed=500, max_files=15)

        image = str(tmp_path / "label_files.hda")
        make_image(image, 8)
        format_image(image, extra_dir=str(tree_dir), volume_label="MYFILES")
        fsck_check(image)

        info = fsck_info(image)
        assert "MYFILES" in info

    def test_roundtrip_volume_label(self, tmp_path):
        """format → unpack → verify partitions.json has label → pack → check → unpack → label still there."""
        import json

        label = "TESTDISK"
        image = str(tmp_path / "orig.hda")
        make_image(image, 8)
        format_image(image, volume_label=label)
        fsck_check(image)

        # Unpack
        unpacked = str(tmp_path / "unpacked")
        run_tool("unpack.py", image, unpacked)

        # Verify partitions.json has the label
        with open(os.path.join(unpacked, "partitions.json")) as f:
            ptable = json.load(f)
        assert ptable["partitions"][0].get("volume_label") == label

        # Pack
        repacked = str(tmp_path / "repacked.hda")
        run_tool("pack.py", unpacked, repacked)
        fsck_check(repacked)

        info = fsck_info(repacked)
        assert label in info

        # Unpack again and verify label preserved
        unpacked2 = str(tmp_path / "unpacked2")
        run_tool("unpack.py", repacked, unpacked2)
        with open(os.path.join(unpacked2, "partitions.json")) as f:
            ptable2 = json.load(f)
        assert ptable2["partitions"][0].get("volume_label") == label

    def test_multi_partition_labels(self, tmp_path):
        """3 partitions with different labels, all preserved through unpack/pack cycle."""
        import json

        rng = random.Random(600)
        labels = [rng.choice(VOLUME_LABELS) for _ in range(3)]

        images = []
        for i in range(3):
            tree_dir = str(tmp_path / f"tree_{i}")
            generate_random_tree(tree_dir, seed=600 + i, max_files=10)

            img = str(tmp_path / f"part_{i}.hda")
            make_image(img, 8)
            format_image(img, extra_dir=tree_dir, volume_label=labels[i])
            images.append(img)

        # Unpack all
        unpacked = []
        for i, img in enumerate(images):
            u = str(tmp_path / f"unpacked_{i}")
            run_tool("unpack.py", img, u)
            unpacked.append(u)

        # Pack combined
        combined = str(tmp_path / "combined.hda")
        run_tool("pack.py", *unpacked, combined)

        # Verify each partition
        for i in range(3):
            fsck_check(combined, partition=i)

        # Verify fsck info shows all labels
        info = fsck_info(combined)
        for label in labels:
            assert label in info, f"Label {label!r} not found in info output"

        # Unpack combined and verify partitions.json
        unpacked_combined = str(tmp_path / "unpacked_combined")
        run_tool("unpack.py", combined, unpacked_combined)
        with open(os.path.join(unpacked_combined, "partitions.json")) as f:
            ptable = json.load(f)
        for i in range(3):
            assert ptable["partitions"][i].get("volume_label") == labels[i]


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))

#!/usr/bin/env python3
"""Create a disposable, pinned upstream tree with the MeshCore overlay."""

from pathlib import Path
import argparse
import binascii
import re
import shutil
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[3]
PIN = "c67f0bcf0fa8e841426335b1bbde91cda6ca1f50"
PIN_RELEASE = "0.11.0"
BOOTLOADER_VERSION = 0x00000B00
VERSION_SYMBOL = "__meshcore_vendor_bootloader_version"
DEFAULT_SOURCE = ROOT / ".tmp" / "Adafruit_nRF52_Bootloader"
OVERLAY = ROOT / "bootloader" / "xiao_nrf52840_ota"
UPSTREAM_BOARDS = {
    "xiao_nrf52840": "xiao_nrf52840_ble",
    "xiao_nrf52840_sense": "xiao_nrf52840_ble_sense",
    "sensecap_solar_p1": "xiao_nrf52840_ble",
}

# ghostfat.c infoUf2File flash-cost patch: named module-level constants (not
# inline literals in main()) so tests can import this module and reuse the
# EXACT same before/after text prepare_upstream.py itself patches with --
# no hand-retyped duplicate copy that could silently drift out of sync with
# the real patch logic below.
GHOSTFAT_INFO_DECL_OLD = (
    'char infoUf2File[128*3] =\n'
    '    "UF2 Bootloader " UF2_VERSION "\\r\\n"\n'
    '    "Model: " UF2_PRODUCT_NAME "\\r\\n"\n'
    '    "Board-ID: " UF2_BOARD_ID "\\r\\n"\n'
    '    "Date: " __DATE__ "\\r\\n";\n'
)
GHOSTFAT_INFO_DECL_NEW = (
    'static const char kInfoUf2FilePrefix[] =\n'
    '    "UF2 Bootloader " UF2_VERSION "\\r\\n"\n'
    '    "Model: " UF2_PRODUCT_NAME "\\r\\n"\n'
    '    "Board-ID: " UF2_BOARD_ID "\\r\\n"\n'
    '    "Date: " __DATE__ "\\r\\n";\n'
    'char infoUf2File[128*3];\n'
)
GHOSTFAT_UF2_INIT_OPEN_OLD = (
    'void uf2_init(void)\n{\n  strcat(infoUf2File, "SoftDevice: ");\n'
)
GHOSTFAT_UF2_INIT_OPEN_NEW = (
    'void uf2_init(void)\n'
    '{\n'
    '  strcpy(infoUf2File, kInfoUf2FilePrefix);\n'
    '  strcat(infoUf2File, "SoftDevice: ");\n'
)


# --work-dir is unconditionally shutil.rmtree()'d before a fresh copy, so
# it must live in a DEDICATED disposable-build namespace (never directly
# in ROOT/.tmp itself, and never using a name reserved for other owners'
# data), and any PRE-EXISTING non-empty directory there must first prove
# it was created by a prior run of THIS exact script/workspace via an
# ownership sentinel file -- otherwise a --work-dir that merely happens
# to resolve inside ROOT/.tmp (passing the older, narrower check) could
# still rmtree() an unrelated directory (another owner's archive, a
# differently-purposed build tree, etc.) that coincidentally lives there.
WORK_DIR_NAMESPACE = "ota-boot-builds"
RESERVED_WORK_DIR_PATH_COMPONENTS = frozenset({"ota-index"})
WORK_DIR_SENTINEL_NAME = ".xiao_ota_prepare_upstream_owner"
WORK_DIR_SENTINEL_VERSION = 1


def run(*args: str) -> str:
    return subprocess.check_output(args, text=True).strip()


def _work_dir_sentinel_path(work: Path) -> Path:
    return work / WORK_DIR_SENTINEL_NAME


def _work_dir_sentinel_contents(source: Path) -> str:
    return (
        f"xiao_ota_prepare_upstream_owner v{WORK_DIR_SENTINEL_VERSION}\n"
        f"root={ROOT.resolve()}\n"
        f"pin={PIN}\n"
        f"source={source.resolve()}\n"
    )


def validate_work_dir_namespace(resolved: Path, tmp_root: Path) -> None:
    """Enforce the dedicated disposable-build namespace geometry: WORK
    must contain WORK_DIR_NAMESPACE as one of its path components
    (relative to ROOT/.tmp) with at least one further, strict descendant
    component after it -- so it can never be the namespace root itself,
    an ancestor of it, or plainly anywhere else under ROOT/.tmp -- and
    must never use a path component reserved for other owners' data
    (e.g. a durable archive/index directory name)."""
    rel_parts = resolved.relative_to(tmp_root).parts
    reserved_hit = RESERVED_WORK_DIR_PATH_COMPONENTS.intersection(rel_parts)
    if reserved_hit:
        raise SystemExit(
            f"--work-dir must not use reserved path component(s) "
            f"{sorted(reserved_hit)} anywhere under {tmp_root}, got {resolved} "
            f"-- those names are reserved for other owners'/tools' data, "
            f"never this script's disposable build scratch"
        )
    if WORK_DIR_NAMESPACE not in rel_parts:
        raise SystemExit(
            f"--work-dir must be a descendant of the dedicated disposable "
            f"build namespace {tmp_root / WORK_DIR_NAMESPACE} (not just "
            f"anywhere under {tmp_root}), got {resolved}"
        )
    idx = rel_parts.index(WORK_DIR_NAMESPACE)
    if len(rel_parts) <= idx + 1:
        raise SystemExit(
            f"--work-dir must be a STRICT descendant of "
            f"{tmp_root / WORK_DIR_NAMESPACE} (not that directory itself or "
            f"an ancestor of it), got {resolved}"
        )


def check_work_dir_ownership(work: Path, source: Path) -> None:
    """If --work-dir already exists and is non-empty, it must contain a
    regular (non-symlink) ownership sentinel file, written by a PRIOR run
    of THIS exact script/workspace (matching sentinel format version,
    canonical ROOT, pinned upstream commit, and canonical SOURCE),
    before any git/copy/delete action touches it. A brand-new or already-
    empty directory needs no sentinel -- there is nothing to protect yet.
    This is the second half of the disposable-build-namespace fix: the
    namespace/geometry check alone only proves WORK's *location* is
    reserved for this purpose, not that any pre-existing content found
    there actually belongs to THIS script -- an unrelated directory
    (another owner's or another tool's data) could still coincidentally
    satisfy the geometry check."""
    if not work.exists():
        return
    if not any(work.iterdir()):
        return
    sentinel = _work_dir_sentinel_path(work)
    if sentinel.is_symlink() or not sentinel.is_file():
        raise SystemExit(
            f"--work-dir {work} already exists, is non-empty, and has no "
            f"valid ownership sentinel ({WORK_DIR_SENTINEL_NAME}) -- refusing "
            f"to delete unrecognized/unowned content. Use an empty or "
            f"not-yet-existing --work-dir, or confirm by hand that this is "
            f"really a prior run of THIS script before removing it yourself."
        )
    expected = _work_dir_sentinel_contents(source)
    actual = sentinel.read_text()
    if actual != expected:
        raise SystemExit(
            f"--work-dir {work} exists with an ownership sentinel that does "
            f"not match this exact script/workspace (format version, ROOT, "
            f"pinned upstream commit, and SOURCE must all match) -- refusing "
            f"to delete content that may belong to a different build/owner. "
            f"expected={expected!r} actual={actual!r}"
        )


def validate_tmp_scratch_path(path: Path, flag_name: str) -> Path:
    """Reject any --work-dir/--source-dir that is not a strict descendant
    of ROOT/.tmp, before any git/copy/delete action touches it. This must
    run first and must not be bypassable via a symlink (Path.resolve()
    follows them). Kept intentionally narrow to ROOT/.tmp even though
    --source-dir is never rmtree()'d (unlike WORK): this script must never
    be pointed at durable, Root-managed storage living outside build
    scratch (e.g. a persistent archive) -- only disposable, re-clonable
    build-scratch paths belong here."""
    tmp_root = (ROOT / ".tmp").resolve()
    resolved = path.resolve()
    if resolved == tmp_root or resolved == ROOT.resolve():
        raise SystemExit(f"--{flag_name} must not be {resolved} (reserved path)")
    try:
        resolved.relative_to(tmp_root)
    except ValueError:
        raise SystemExit(f"--{flag_name} must resolve inside {tmp_root}, got {resolved}")
    return resolved


def validate_work_dir(work: Path, source: Path) -> Path:
    """Reject any --work-dir that is not a strict descendant of ROOT/.tmp,
    or that overlaps the (possibly caller-relocated) pinned upstream clone
    directory IN EITHER DIRECTION, before any git/copy/delete action. WORK
    is shutil.rmtree()'d unconditionally below, so a caller-controlled
    path here would be a recursive-delete vulnerability -- not only when
    WORK is identical to or nested inside SOURCE (checked first below),
    but also the previously-unchecked reverse: a caller picking WORK as
    an ANCESTOR of SOURCE (e.g. --work-dir=.tmp/owner,
    --source-dir=.tmp/owner/source) would have rmtree(WORK) silently
    erase the pinned upstream clone (and anything else already present
    under that ancestor) before the copy ever runs. Both directions (and
    exact identity) must be rejected up front; this is a strict,
    non-overlapping scratch-boundary invariant between the two paths,
    not general host hardening."""
    resolved = validate_tmp_scratch_path(work, "work-dir")
    source_root = source.resolve()
    if resolved == source_root:
        raise SystemExit(f"--work-dir must not be {resolved} (reserved path)")
    try:
        resolved.relative_to(source_root)
        raise SystemExit(
            f"--work-dir must not be inside pinned upstream clone {source_root}, "
            f"got {resolved}")
    except ValueError:
        pass
    try:
        source_root.relative_to(resolved)
        raise SystemExit(
            f"--work-dir must not be an ancestor of pinned upstream clone "
            f"{source_root} (rmtree(work-dir) would erase it), got {resolved}")
    except ValueError:
        pass
    validate_work_dir_namespace(resolved, (ROOT / ".tmp").resolve())
    return resolved


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-ble", action="store_true",
                        help="build the stock-address UF2/CDC recovery variant")
    parser.add_argument("--board", choices=tuple(UPSTREAM_BOARDS),
                        default="xiao_nrf52840",
                        help="select the pinned vendor BSP, boot-info marker and install "
                             "policy target. xiao_nrf52840_sense uses the genuine Sense "
                             "BSP with the existing Xiao application family. "
                             "sensecap_solar_p1 is a real, "
                             "distinct target id sharing the same P25Q16H QSPI pinout "
                             "family, but has NOT been physically qualified on hardware "
                             "-- treat any such build as build-only until a real board "
                             "confirms it.")
    parser.add_argument("--role-id", type=int, choices=(0, 1), default=0,
                        help="compiled role identity (XIAO_OTA_COMPILED_ROLE_ID) to "
                             "bake into this build: 0 (companion, default) or 1 "
                             "(repeater). A role-1 binary's install-command policy "
                             "check and compiled-role policy both "
                             "require an exact match to this value, never a wildcard "
                             "or a role<=1 acceptance. Must agree with the same "
                             "--role-id passed to sign_image.py/verify_boot_info_"
                             "artifact.py for this exact artifact.")
    parser.add_argument("--work-dir", default=None,
                        help="disposable build tree to copy the pinned upstream into "
                             "and compile from. Defaults to "
                             ".tmp/ota-boot-builds/<board>_ota{_roleN}_{_noswd}_upstream "
                             "(selected by --board, --role-id and --no-ble). Pass a distinct --work-dir per "
                             "profile when building more than one --board in one "
                             "invocation, or they will clobber each other's "
                             "tree/artifacts. Must be a strict descendant of "
                             "ROOT/.tmp/ota-boot-builds (see "
                             "validate_work_dir_namespace) -- a plain ROOT/.tmp "
                             "descendant is no longer sufficient. If it already "
                             "exists and is non-empty, it must carry this script's own "
                             "ownership sentinel (see check_work_dir_ownership) or it "
                             "will be refused rather than deleted.")
    parser.add_argument("--source-dir", default=None,
                        help="pinned upstream git clone to check out PIN in and copy "
                             "from. Defaults to .tmp/Adafruit_nRF52_Bootloader. Pass "
                             "this (matching the Makefile's own $(XIAO_OTA_UPSTREAM)) "
                             "whenever invoking this script with a relocated/namespaced "
                             "TMPDIR, so this script's own clone follows that "
                             "relocation instead of silently falling back to the fixed "
                             "default path -- this never wipes or force-refetches an "
                             "already-present clone at either the default or an "
                             "explicit path (see the idempotent checkout/submodule "
                             "calls below); a fresh network clone only happens if "
                             "nothing at all exists yet at the resolved path. Must "
                             "resolve inside ROOT/.tmp, same as --work-dir.")
    args = parser.parse_args(argv)
    SOURCE = Path(args.source_dir).resolve() if args.source_dir else DEFAULT_SOURCE
    if not SOURCE.is_absolute():
        SOURCE = ROOT / SOURCE
    SOURCE = validate_tmp_scratch_path(SOURCE, "source-dir")
    BOARD_TARGET_MACRO = {
        "xiao_nrf52840": "XIAO_OTA_TARGET_XIAO_NRF52840",
        "xiao_nrf52840_sense": "XIAO_OTA_TARGET_XIAO_NRF52840",
        "sensecap_solar_p1": "XIAO_OTA_TARGET_SENSECAP_SOLAR_P1",
    }[args.board]
    # Must stay byte-for-byte identical to the same-named constants in
    # include/xiao_ota_record.h -- these numeric values are what actually get
    # compiled in (via -D below) and what the boot-info CRC patch step below
    # authenticates against.
    BOARD_TARGET_VALUE = {
        "xiao_nrf52840": 0x584E3430,
        "xiao_nrf52840_sense": 0x584E3430,
        "sensecap_solar_p1": 0x53435031,
    }[args.board]
    upstream_board = UPSTREAM_BOARDS[args.board]
    ROLE_SUFFIX = "" if args.role_id == 0 else f"_role{args.role_id}"
    WORK = Path(args.work_dir) if args.work_dir else ROOT / ".tmp" / WORK_DIR_NAMESPACE / (
        f"{args.board}_ota{ROLE_SUFFIX}_noswd_upstream" if args.no_ble
        else f"{args.board}_ota{ROLE_SUFFIX}_upstream"
    )
    if not WORK.is_absolute():
        WORK = ROOT / WORK
    WORK = validate_work_dir(WORK, SOURCE)
    # Ownership check must run before ANY git/copy/delete action touches
    # WORK, not just before the rmtree() call below -- see
    # check_work_dir_ownership()'s docstring.
    check_work_dir_ownership(WORK, SOURCE)

    if not (SOURCE / ".git").is_dir():
        SOURCE.parent.mkdir(parents=True, exist_ok=True)
        subprocess.check_call([
            "git", "clone", "https://github.com/adafruit/Adafruit_nRF52_Bootloader.git",
            str(SOURCE),
        ])
    subprocess.check_call(["git", "-C", str(SOURCE), "checkout", "--detach", PIN])
    if run("git", "-C", str(SOURCE), "rev-parse", "HEAD") != PIN:
        raise SystemExit("pinned upstream checkout mismatch")
    if run("git", "-C", str(SOURCE), "rev-parse", f"{PIN_RELEASE}^{{commit}}") != PIN:
        raise SystemExit("pinned upstream semantic release mismatch")
    # Idempotently re-asserted here (cheap no-op if the Makefile's fetch
    # target already did it) so this script is self-sufficient even on a
    # fresh non-recursive clone, where submodules like lib/nrfx (nrf.h)
    # would otherwise copy over empty and fail the build.
    subprocess.check_call([
        "git", "-C", str(SOURCE), "submodule", "update", "--init", "--recursive", "--quiet",
    ])
    for name in ("board.h", "board.mk", "pinconfig.c"):
        if not (SOURCE / "src" / "boards" / upstream_board / name).is_file():
            raise SystemExit(f"pinned vendor board {upstream_board} lacks {name}")

    if WORK.exists():
        shutil.rmtree(WORK)
    shutil.copytree(SOURCE, WORK, ignore=shutil.ignore_patterns(".git", "_build", "_bin"))
    # Written immediately after the fresh copy succeeds (before any later
    # overlay/patch step that could fail) so a repeat run of THIS exact
    # script/workspace is always recognized as owned and can safely
    # rmtree()+recreate, even if a later step previously failed partway.
    _work_dir_sentinel_path(WORK).write_text(_work_dir_sentinel_contents(SOURCE))

    custom = WORK / "src" / "xiao_ota"
    custom.mkdir(parents=True)
    for path in (OVERLAY / "include").glob("*.h"):
        shutil.copy2(path, custom / path.name)
    for path in (OVERLAY / "src").glob("*.[ch]"):
        shutil.copy2(path, custom / path.name)
    shutil.copy2(OVERLAY / "linker" / "nrf52840_xiao_ota.ld",
                 WORK / "linker" / "nrf52840_xiao_ota.ld")
    shutil.copy2(OVERLAY / "linker" / "nrf52840_xiao_ota_noswd.ld",
                 WORK / "linker" / "nrf52840_xiao_ota_noswd.ld")

    # xiao_ota_platform_layout_contract.h (just copied above, verbatim from
    # OVERLAY/include) is only a thin forwarding stub that reaches the real
    # canonical contract via a relative "../../../src/ota/platform/..."
    # #include -- correct for its FIXED location in the real repo, but that
    # relative traversal resolves to the wrong (or a nonexistent) path now
    # that the file lives inside this disposable, differently-nested WORK
    # tree. Overwrite the copy with the canonical header's actual, live
    # bytes instead of duplicating/hand-copying its constants -- this is
    # authoritative and re-read fresh on every prepare, so it can never go
    # stale; a missing canonical header is a hard error, never a silent
    # fallback to some older/duplicated literal set.
    canonical_layout_contract = ROOT / "src" / "ota" / "platform" / "Nrf52FlashLayoutContract.h"
    if not canonical_layout_contract.is_file():
        raise SystemExit(
            f"canonical shared layout contract missing: {canonical_layout_contract} "
            "-- refusing to fall back to a stale/duplicated copy"
        )
    shutil.copy2(canonical_layout_contract,
                 custom / "xiao_ota_platform_layout_contract.h")

    # Defense against BOARD_TARGET_VALUE silently drifting from the real
    # constants defined in xiao_ota_record.h (the one the compiled bootloader
    # and its install-command policy check actually use).
    record_header_text = (custom / "xiao_ota_record.h").read_text()
    expected_target_hex = f"UINT32_C(0x{BOARD_TARGET_VALUE:08X})"
    if not re.search(rf"#define\s+{re.escape(BOARD_TARGET_MACRO)}\s+{re.escape(expected_target_hex)}",
                     record_header_text):
        raise SystemExit(
            f"BOARD_TARGET_VALUE for --board {args.board} ({expected_target_hex}) no longer "
            f"matches {BOARD_TARGET_MACRO} in xiao_ota_record.h -- update prepare_upstream.py"
        )

    # Compute the real boot-info marker CRC-32 for the selected board profile
    # and patch it into the copied xiao_ota_boot_info.c, replacing the
    # deliberately-invalid placeholder committed in the repo. This must mirror
    # xiao_ota_crc32()'s exact algorithm (IEEE 802.3, reflected, init/final
    # 0xFFFFFFFF -- i.e. the same as binascii.crc32) over the packed struct's
    # exact little-endian byte layout (nRF52840/Cortex-M is little-endian), and
    # every field value here must be identical to the literal C initializer in
    # xiao_ota_boot_info.c below the placeholder (magic/format_version/
    # struct_bytes/role_id/capability_flags/key_id/algorithm_id), or the two
    # would silently diverge.
    public_key_header_text = (custom / "xiao_ota_public_key.h").read_text()
    key_match = re.search(
        r"XIAO_OTA_LAB_PUBLIC_KEY_ED25519_BYTES\s*\\((?:.|\n)*?)\n\n", public_key_header_text
    )
    if not key_match:
        raise SystemExit("could not locate XIAO_OTA_LAB_PUBLIC_KEY_ED25519_BYTES in "
                          "xiao_ota_public_key.h")
    key_bytes = bytes(int(tok, 16) for tok in re.findall(r"0x[0-9a-fA-F]{2}", key_match.group(1)))
    if len(key_bytes) != 32:
        raise SystemExit(f"expected 32 public key bytes, parsed {len(key_bytes)}")

    BOOT_INFO_MAGIC = 0x584F4249
    BOOT_INFO_FORMAT_VERSION = 1
    BOOT_INFO_STRUCT_BYTES = 60
    # Must be byte-for-byte identical to the compiled XIAO_OTA_COMPILED_
    # ROLE_ID (-D'd into the real ARM build below) -- the baked-in
    # immutable marker's role_id field and the live policy checks must
    # never drift from each other.
    BOOT_INFO_ROLE_ID = args.role_id
    BOOT_INFO_CAP_QSPI_INSTALL = 1
    BOOT_INFO_KEY_ID = 1
    BOOT_INFO_ALGORITHM_ED25519 = 1
    boot_info_bytes_before_crc = struct.pack(
        "<IHHIIIHH32s",
        BOOT_INFO_MAGIC,
        BOOT_INFO_FORMAT_VERSION,
        BOOT_INFO_STRUCT_BYTES,
        BOARD_TARGET_VALUE,
        BOOT_INFO_ROLE_ID,
        BOOT_INFO_CAP_QSPI_INSTALL,
        BOOT_INFO_KEY_ID,
        BOOT_INFO_ALGORITHM_ED25519,
        key_bytes,
    )
    if len(boot_info_bytes_before_crc) != BOOT_INFO_STRUCT_BYTES - 4:
        raise SystemExit(
            f"boot-info packed layout mismatch: expected "
            f"{BOOT_INFO_STRUCT_BYTES - 4} bytes before crc32, got "
            f"{len(boot_info_bytes_before_crc)} -- xiao_ota_boot_info_t layout changed?"
        )
    boot_info_crc = binascii.crc32(boot_info_bytes_before_crc) & 0xFFFFFFFF

    boot_info_c = custom / "xiao_ota_boot_info.c"
    boot_info_text = boot_info_c.read_text()
    placeholder = (
        ".crc32 = 0xFFFFFFFFu, /* XIAO_OTA_BOOT_INFO_CRC32_PLACEHOLDER: "
        "patched by prepare_upstream.py */"
    )
    if placeholder not in boot_info_text:
        raise SystemExit(
            "xiao_ota_boot_info.c CRC placeholder not found -- source format changed, "
            "update prepare_upstream.py's patch step"
        )
    boot_info_text = boot_info_text.replace(
        placeholder,
        f".crc32 = UINT32_C(0x{boot_info_crc:08X}), /* patched for --board {args.board} "
        f"by prepare_upstream.py */",
        1,
    )
    boot_info_c.write_text(boot_info_text)


    # ghostfat.c's INFO_UF2TXT buffer (infoUf2File[128*3]=384 bytes) is
    # declared WITH a non-empty string-literal initializer (the fixed
    # "UF2 Bootloader ..." prefix, built from UF2_VERSION/UF2_PRODUCT_NAME/
    # UF2_BOARD_ID/__DATE__), so the compiler must place the WHOLE 384-byte
    # array in .data -- costing 384 bytes of flash for its initial value --
    # even though only the short prefix (well under 384 bytes; the exact
    # length depends on the per-board/per-build macro expansion) is ever
    # non-zero; the remaining bytes are flash-stored zero padding that
    # exists purely because a single C object can't be split between
    # .data and .bss. Split it: keep the SAME prefix text as a separate
    # `static const` literal (only its own real length lands in flash,
    # in .rodata, not 384 bytes), declare infoUf2File itself with NO
    # initializer (so it becomes .bss -- zero flash cost, runtime content
    # is still identical), and copy the prefix into it as the very first
    # statement of uf2_init() -- strictly before the existing SoftDevice
    # strcat() calls and before tusb/USB init ever exposes the FAT
    # filesystem, so the file's final content and ordering are byte-for-
    # byte unchanged from what a host ever reads over USB.
    ghostfat_c = WORK / "src" / "usb" / "uf2" / "ghostfat.c"
    ghostfat_text = ghostfat_c.read_text()
    if GHOSTFAT_INFO_DECL_OLD not in ghostfat_text:
        raise SystemExit(
            "ghostfat.c infoUf2File declaration not found in the expected form -- "
            "upstream source changed, update prepare_upstream.py's patch step"
        )
    ghostfat_text = ghostfat_text.replace(GHOSTFAT_INFO_DECL_OLD, GHOSTFAT_INFO_DECL_NEW, 1)

    if GHOSTFAT_UF2_INIT_OPEN_OLD not in ghostfat_text:
        raise SystemExit(
            "ghostfat.c uf2_init() opening not found in the expected form -- "
            "upstream source changed, update prepare_upstream.py's patch step"
        )
    ghostfat_text = ghostfat_text.replace(GHOSTFAT_UF2_INIT_OPEN_OLD, GHOSTFAT_UF2_INIT_OPEN_NEW, 1)
    ghostfat_c.write_text(ghostfat_text)

    ed25519 = ROOT / "src" / "ota" / "trust" / "third_party" / "ed25519"
    for name in ("ed25519.h", "fixedint.h", "fe.h", "fe.c", "ge.h", "ge.c",
                 "sc.h", "sc.c", "sha512.h", "sha512.c", "verify.c",
                 "precomp_data.h", "LICENSE", "NOTICE.txt"):
        shutil.copy2(ed25519 / name, custom / name)

    if args.no_ble:
        tweetnacl = OVERLAY / "third_party" / "tweetnacl"
        shutil.copy2(tweetnacl / "tweetnacl.c", custom / "tweetnacl.c")
        shutil.copy2(tweetnacl / "tweetnacl.h", custom / "tweetnacl.h")

    main = WORK / "src" / "main.c"
    text = main.read_text()
    text = text.replace('#include "boards.h"\n', '#include "boards.h"\n#include "xiao_ota_boot.h"\n')
    version_store = '  BOOTLOADER_VERSION_REGISTER = (MK_BOOTLOADER_VERSION);\n'
    if text.count(version_store) != 1:
        raise SystemExit("pinned vendor version assignment changed")
    text = text.replace(
        version_store,
        f'  _Static_assert(MK_BOOTLOADER_VERSION == 0x{BOOTLOADER_VERSION:08X}u,\n'
        '                 "vendor version must match the pinned release");\n'
        + version_store,
        1,
    )
    needle = '  led_state(STATE_BOOTLOADER_STARTED);\n'
    text = text.replace(needle, needle + "\n  xiao_ota_boot_process();\n", 1)
    main.write_text(text)

    if args.no_ble:
        text = main.read_text()
        text = text.replace("static uint32_t ble_stack_init(void);\n", "", 1)
        text = text.replace(
            '  // Start Bootloader in BLE OTA mode\n'
            '  _ota_dfu = (gpregret == DFU_MAGIC_OTA_APPJUM) || '
            '(gpregret == DFU_MAGIC_OTA_RESET);\n',
            '  // BLE DFU is omitted. Legacy BLE reset requests enter CDC-only DFU.\n'
            '  _ota_dfu = false;\n',
            1,
        )
        text = text.replace(
            '  bool const serial_only_dfu = '
            '(gpregret == DFU_MAGIC_SERIAL_ONLY_RESET);\n',
            '  bool const serial_only_dfu = '
            '(gpregret == DFU_MAGIC_SERIAL_ONLY_RESET) ||\n'
            '                               '
            '(gpregret == DFU_MAGIC_OTA_APPJUM) ||\n'
            '                               '
            '(gpregret == DFU_MAGIC_OTA_RESET);\n',
            1,
        )
        text = text.replace(
            '    if (_ota_dfu) {\n'
            '      led_state(STATE_BLE_DISCONNECTED);\n'
            '      if (!_sd_inited) mbr_init_sd();\n'
            '      _sd_inited = true;\n'
            '      ble_stack_init();\n'
            '    } else {\n'
            '      led_state(STATE_USB_UNMOUNTED);\n'
            '      usb_init(serial_only_dfu);\n'
            '    }\n',
            '    led_state(STATE_USB_UNMOUNTED);\n'
            '    usb_init(serial_only_dfu);\n',
            1,
        )
        text = text.replace(
            '      bootloader_dfu_start(_ota_dfu, 3000, true);\n',
            '      bootloader_dfu_start(false, 3000, true);\n',
            1,
        )
        text = text.replace(
            '      bootloader_dfu_start(_ota_dfu, 0, false);\n',
            '      bootloader_dfu_start(false, 0, false);\n',
            1,
        )
        text = text.replace(
            '    if (_ota_dfu) {\n'
            '      disable_softdevice();\n'
            '    } else {\n'
            '      usb_teardown();\n'
            '    }\n',
            '    usb_teardown();\n',
            1,
        )
        ble_start = text.index(
            '//--------------------------------------------------------------------+\n'
            '// BLE\n'
            '//--------------------------------------------------------------------+\n'
        )
        error_start = text.index(
            '//--------------------------------------------------------------------+\n'
            '// Error Handler\n'
            '//--------------------------------------------------------------------+\n'
        )
        text = text[:ble_start] + text[error_start:]
        main.write_text(text)

    makefile = WORK / "Makefile"
    text = makefile.read_text()
    if "-include src/boards/$(BOARD)/board.mk\n" not in text:
        raise SystemExit("pinned Makefile board include not found; refusing unbound board preparation")
    text = text.replace(
        "GIT_VERSION := $(shell git describe --dirty --always --tags)",
        f"GIT_VERSION := {PIN_RELEASE}-{PIN[:12]}",
        1,
    )
    needle = "# all files in boards\n"
    addition = f"""# MeshCore XIAO external-QSPI OTA overlay
    C_SRC += \\
      src/xiao_ota/xiao_ota_boot.c \\
      src/xiao_ota/xiao_ota_boot_io.c \\
      src/xiao_ota/xiao_ota_record.c \\
      src/xiao_ota/xiao_ota_boot_info.c \\
      src/xiao_ota/xiao_ota_sha256.c \\
      src/xiao_ota/fe.c \\
      src/xiao_ota/ge.c \\
      src/xiao_ota/sc.c \\
      src/xiao_ota/sha512.c \\
      src/xiao_ota/verify.c
    IPATH += src/xiao_ota
    # --board {args.board}: selects the install-policy target check and the
    # baked-in boot-info marker's board_target_id (see xiao_ota_record.h /
    # xiao_ota_boot_info.c). sensecap_solar_p1 is NOT physically qualified --
    # build-only until real hardware confirms it.
    CFLAGS += -DXIAO_OTA_BOARD_TARGET=0x{BOARD_TARGET_VALUE:08X}u
    # --role-id {args.role_id}: this binary's compiled role identity
    # (XIAO_OTA_COMPILED_ROLE_ID, 0=companion/1=repeater). Checked by both
    # the install-command policy and the compiled-role policy
    # policy (xiao_ota_record.c / xiao_ota_boot_io.c), and baked into the
    # immutable boot-info marker's role_id field above by this same script.
    CFLAGS += -DXIAO_OTA_COMPILED_ROLE_ID={args.role_id}u
    LDFLAGS += -Wl,--defsym={VERSION_SYMBOL}=0x{BOOTLOADER_VERSION:08X}

    """
    text = text.replace(needle, addition + needle, 1)
    text = text.replace(
        "-include src/boards/$(BOARD)/board.mk\n",
        f"BOARD ?= {upstream_board}\n"
        f"ifneq ($(BOARD),{upstream_board})\n"
        f"$(error prepared --board {args.board} requires BOARD={upstream_board})\n"
        "endif\n"
        "-include src/boards/$(BOARD)/board.mk\n\n"
        f"ifeq ($(BOARD),{upstream_board})\n"
        "CFLAGS += -DBOOTLOADER_REGION_START=0xED000\n"
        "endif\n",
        1,
    )
    text = text.replace(
        "else\n  LD_FILE = linker/$(MCU_SUB_VARIANT).ld\nendif\n",
        "else\n  LD_FILE = linker/$(MCU_SUB_VARIANT).ld\nendif\n"
        f"ifeq ($(BOARD),{upstream_board})\n"
        "LD_FILE = linker/nrf52840_xiao_ota.ld\n"
        "endif\n",
        1,
    )
    if args.no_ble:
        for source in (
            "  src/dfu_ble_svc.c \\\n",
            "C_SRC += $(SDK11_PATH)/libraries/bootloader_dfu/dfu_transport_ble.c\n",
            "C_SRC += $(SDK11_PATH)/ble/ble_services/ble_dfu/ble_dfu.c\n",
            "C_SRC += $(SDK11_PATH)/ble/ble_services/ble_dis/ble_dis.c\n",
        ):
            text = text.replace(source, "", 1)
        for source in (
            "  src/xiao_ota/fe.c \\\n",
            "  src/xiao_ota/ge.c \\\n",
            "  src/xiao_ota/sc.c \\\n",
            "  src/xiao_ota/sha512.c \\\n",
            "  src/xiao_ota/verify.c\n",
        ):
            text = text.replace(source, "", 1)
        text = text.replace(
            "  src/xiao_ota/xiao_ota_boot.c \\\n",
            "  src/xiao_ota/xiao_ota_boot.c \\\n"
            "  src/xiao_ota/xiao_ota_no_ble.c \\\n",
            1,
        )
        text = text.replace(
            "  src/xiao_ota/xiao_ota_sha256.c \\\n",
            "  src/xiao_ota/xiao_ota_sha256.c \\\n"
            "  src/xiao_ota/xiao_ota_ed25519_tweetnacl.c \\\n"
            "  src/xiao_ota/tweetnacl.c\n",
            1,
        )
        text = text.replace(
            "CFLAGS += -DBOOTLOADER_REGION_START=0xED000\n",
            "CFLAGS += -DBOOTLOADER_REGION_START=0xF4000\n"
            "CFLAGS += -flto -fuse-linker-plugin\n",
            1,
        )
        text = text.replace(
            "LD_FILE = linker/nrf52840_xiao_ota.ld\n",
            "LD_FILE = linker/nrf52840_xiao_ota_noswd.ld\n",
            1,
        )
        text += (
            "\n# TweetNaCl is externally maintained compact public-domain C.\n"
            "CFLAGS += -Wno-unused-function -Wno-sign-compare -Wno-shadow "
            "-Wno-unterminated-string-initialization\n"
        )
    makefile.write_text(text)

    print(WORK)
    return WORK


if __name__ == "__main__":
    main()

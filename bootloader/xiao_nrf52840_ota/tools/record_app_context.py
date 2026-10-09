"""PlatformIO build-only target freezing actual XIAO APP compiler context and bytes."""
import json
import os
import argparse
from pathlib import Path
import shutil
import sys
import re


def selected_defines(values):
    selected = {}
    wanted = {"XIAO_NRF52", "MESHCORE_LORA_OTA", "XIAO_OTA_COMPILED_ROLE_ID",
              "LORA_FREQ", "LORA_BW", "LORA_SF", "LORA_CR", "LORA_TX_POWER"}
    for value in values:
        if isinstance(value, (list, tuple)):
            key, item = value
        else:
            key, _, item = str(value).partition("=")
            item = item or "1"
        if key not in wanted:
            continue
        text = str(item if item is not None else 1)
        if key in selected and selected[key] != text:
            raise ValueError("conflicting actual compiler define: " + key)
        selected[key] = text
    return selected


def freeze(source, target, env):
    sys.path.insert(0, str(Path(env.subst("$PROJECT_DIR")) /
                          "bootloader/xiao_nrf52840_ota/tools"))
    import package_pair as paired
    defines = selected_defines(env["CPPDEFINES"])
    board = os.environ["XIAO_OTA_APP_BOARD"]
    role = int(os.environ["XIAO_OTA_APP_ROLE"])
    output = Path(os.environ["XIAO_OTA_APP_FREEZE"]).resolve()
    compiler = {key: int(defines[key], 0) for key in
                ("XIAO_NRF52", "MESHCORE_LORA_OTA", "XIAO_OTA_COMPILED_ROLE_ID")}
    paired.require(board in ("xiao_nrf52840", "xiao_nrf52840_sense") and role in (0, 1) and
                   compiler == {"XIAO_NRF52": 1, "MESHCORE_LORA_OTA": 1,
                                "XIAO_OTA_COMPILED_ROLE_ID": role},
                   "actual compiler board/ROLE is not the selected installer")
    pio_board = env.GetProjectOption("board")
    mcu = env.BoardConfig().get("build.mcu")
    paired.require(pio_board == "seeed-xiao-afruitnrf52-nrf52840" and mcu == "nrf52840",
                   "actual compiler board is not the selected XIAO family")
    paired.require(output.is_relative_to(paired.build.ROOT / ".tmp/ota-boot-builds") and
                   not output.exists(), "requires a new project-owned APP freeze directory")
    build_dir = Path(env.subst("$BUILD_DIR"))
    name = env.subst("${PROGNAME}")
    zip_path, elf_path = build_dir / (name + ".zip"), build_dir / (name + ".elf")
    app, _ = paired.package_payload(zip_path, "application")
    context = dict(schema="xiao-ota-app-build-v1", board_profile=board, role=role,
        pio_board=pio_board, mcu=mcu, environment=env["PIOENV"], compiler=compiler,
        image_sha256=paired.digest(app), image_bytes=len(app),
        zip_sha256=paired.build.sha(zip_path), elf="firmware.elf",
        elf_sha256=paired.build.sha(elf_path),
        radio_defaults={key: float(defines[key]) for key in
                        ("LORA_FREQ", "LORA_BW", "LORA_SF", "LORA_TX_POWER")})
    context["radio_defaults"]["LORA_CR"] = float(defines.get("LORA_CR", "5"))
    output.mkdir(parents=True)
    shutil.copy2(zip_path, output / "firmware.zip")
    shutil.copy2(elf_path, output / "firmware.elf")
    (output / "firmware.bin").write_bytes(app)
    (output / "app-build.json").write_text(json.dumps(context, indent=2) + "\n")
    paired.verify_app_context(output / "app-build.json", output / "firmware.zip",
                              board=board, role=role)
    print("FROZEN actual APP build context:", output, context["radio_defaults"],
          "NO hardware accessed; NOT RF qualification")


if "Import" in globals():
    Import("env")
    env.AddCustomTarget("xiao-app-context",
        dependencies=["$BUILD_DIR/${PROGNAME}.zip", "$BUILD_DIR/${PROGNAME}.elf"],
        actions=freeze, title="Freeze XIAO OTA APP build context", always_build=True)
elif __name__ == "__main__":
    import package_pair as paired
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config-output", type=Path, required=True)
    parser.add_argument("--environment", required=True)
    args = parser.parse_args()
    output = args.config_output.resolve()
    paired.require(output.is_relative_to(paired.build.ROOT / ".tmp/ota-boot-builds") and
                   re.fullmatch(r"[A-Za-z0-9_.-]+", args.environment),
                   "requires a project-owned config and explicit environment name")
    output.parent.mkdir(parents=True, exist_ok=True)
    text = (paired.build.ROOT / "platformio.ini").read_text()
    text += (f"\n[env:{args.environment}]\nextra_scripts = create-uf2.py\n"
             "  post:bootloader/xiao_nrf52840_ota/tools/record_app_context.py\n")
    paired.require(not output.exists() or output.read_text() == text,
                   "refusing to overwrite a different build configuration")
    if not output.exists():
        output.write_text(text)

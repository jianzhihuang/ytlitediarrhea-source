#!/usr/bin/env python3
"""Update an AltStore/SideStore apps.json from a GitHub release IPA."""

from __future__ import annotations

import json
import os
import plistlib
import re
import shutil
import struct
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path
from typing import Any


API_ROOT = "https://api.github.com"
DEFAULT_ICON_URL = (
    "https://raw.githubusercontent.com/YTLitePlus/"
    "YTLitePlus-Altstore/main/Youtube_logo-512.png"
)
DEFAULT_TINT_COLOR = "e22a41"
IMPLICIT_ENTITLEMENTS = {
    "application-identifier",
    "com.app.developer.team-identifier",
    "com.apple.developer.team-identifier",
}


def env(name: str, default: str) -> str:
    value = os.environ.get(name)
    return value if value else default


def fetch_json(url: str) -> Any:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "ytlitediarrhea-source-updater",
        },
    )
    with urllib.request.urlopen(request) as response:
        return json.load(response)


def download_file(url: str, destination: Path) -> None:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "ytlitediarrhea-source-updater"},
    )
    with urllib.request.urlopen(request) as response, destination.open("wb") as handle:
        shutil.copyfileobj(response, handle)


def find_latest_ipa_release(owner: str, repo: str) -> dict[str, Any]:
    skip_name_regex = os.environ.get("SKIP_RELEASE_NAME_REGEX")
    releases = fetch_json(f"{API_ROOT}/repos/{owner}/{repo}/releases?per_page=20")
    for release in releases:
        if release.get("draft") or release.get("prerelease"):
            continue
        if skip_name_regex and re.search(skip_name_regex, release.get("name") or ""):
            continue
        for asset in release.get("assets", []):
            if asset.get("name", "").lower().endswith(".ipa"):
                return {"release": release, "asset": asset}
    raise RuntimeError(f"No stable release with an IPA asset found for {owner}/{repo}.")


def read_plist_from_zip(archive: zipfile.ZipFile, path: str) -> dict[str, Any]:
    return plistlib.loads(archive.read(path))


def find_main_app_info_path(names: list[str]) -> str:
    for name in names:
        if name.startswith("Payload/") and name.count("/") == 2 and name.endswith(".app/Info.plist"):
            return name
    raise RuntimeError("Could not find Payload/*.app/Info.plist in the IPA.")


def collect_privacy_keys(info: dict[str, Any]) -> dict[str, str]:
    return {
        key: value
        for key, value in sorted(info.items())
        if key.endswith("UsageDescription") and isinstance(value, str)
    }


def read_uint32(data: bytes, offset: int, endian: str) -> int:
    return struct.unpack_from(f"{endian}I", data, offset)[0]


def locate_code_signature(binary_path: Path) -> tuple[int, int]:
    data = binary_path.read_bytes()

    def macho_slice_offset_and_endian(blob: bytes, offset: int) -> tuple[int, str]:
        magic = struct.unpack_from(">I", blob, offset)[0]

        if magic == 0xCAFEBABE:
            nfat_arch = struct.unpack_from(">I", blob, offset + 4)[0]
            if nfat_arch < 1:
                raise RuntimeError("FAT binary has no architecture slices.")
            first_arch_offset = struct.unpack_from(">I", blob, offset + 16)[0]
            return first_arch_offset, ">"

        if magic == 0xCAFEBABF:
            nfat_arch = struct.unpack_from(">I", blob, offset + 4)[0]
            if nfat_arch < 1:
                raise RuntimeError("FAT64 binary has no architecture slices.")
            first_arch_offset = struct.unpack_from(">Q", blob, offset + 16)[0]
            return first_arch_offset, ">"

        if magic in {0xFEEDFACE, 0xFEEDFACF}:
            return offset, ">"

        if magic in {0xCEFAEDFE, 0xCFFAEDFE}:
            return offset, "<"

        raise RuntimeError(f"Unsupported Mach-O magic 0x{magic:08x} in {binary_path}.")

    slice_offset, endian = macho_slice_offset_and_endian(data, 0)
    magic = struct.unpack_from(f"{endian}I", data, slice_offset)[0]
    is_64 = magic in {0xFEEDFACF, 0xCFFAEDFE}
    header_size = 32 if is_64 else 28
    ncmds = read_uint32(data, slice_offset + 16, endian)

    cursor = slice_offset + header_size
    for _ in range(ncmds):
        cmd = read_uint32(data, cursor, endian)
        cmdsize = read_uint32(data, cursor + 4, endian)
        if cmd == 0x1D:
            dataoff = read_uint32(data, cursor + 8, endian)
            datasize = read_uint32(data, cursor + 12, endian)
            return slice_offset + dataoff, datasize
        cursor += cmdsize

    raise RuntimeError(f"LC_CODE_SIGNATURE not found in {binary_path}.")


def parse_entitlements_from_binary(binary_path: Path) -> set[str]:
    offset, size = locate_code_signature(binary_path)
    data = binary_path.read_bytes()[offset : offset + size]

    if data[:4] != bytes.fromhex("fade0cc0"):
        raise RuntimeError(f"Unsupported code signature superblob in {binary_path}.")

    count = int.from_bytes(data[8:12], byteorder="big")
    entitlements: set[str] = set()

    for index in range(count):
        start = 12 + index * 8
        blob_offset = int.from_bytes(data[start + 4 : start + 8], byteorder="big")
        blob_magic = int.from_bytes(data[blob_offset : blob_offset + 4], byteorder="big")

        if blob_magic != 0xFADE7171:
            continue

        blob_length = int.from_bytes(data[blob_offset + 4 : blob_offset + 8], byteorder="big")
        blob_data = data[blob_offset + 8 : blob_offset + blob_length]
        plist = plistlib.loads(blob_data)
        entitlements.update(str(key) for key in plist.keys())

    return {key for key in entitlements if key not in IMPLICIT_ENTITLEMENTS}


def extract_ipa_metadata(ipa_path: Path) -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as temp_dir:
        extract_root = Path(temp_dir)

        with zipfile.ZipFile(ipa_path, "r") as archive:
            names = archive.namelist()
            main_info_path = find_main_app_info_path(names)
            main_info = read_plist_from_zip(archive, main_info_path)
            archive.extract(main_info_path, extract_root)

            app_bundle_dir = Path(main_info_path).parent
            app_executable = main_info["CFBundleExecutable"]
            main_binary_path = extract_root / app_bundle_dir / app_executable
            archive.extract(main_binary_path.relative_to(extract_root).as_posix(), extract_root)
            binaries_to_check = [main_binary_path]

            for name in names:
                if not name.startswith(f"{app_bundle_dir.as_posix()}/PlugIns/") or not name.endswith(
                    ".appex/Info.plist"
                ):
                    continue
                archive.extract(name, extract_root)
                appex_info = read_plist_from_zip(archive, name)
                appex_dir = Path(name).parent
                appex_binary_path = extract_root / appex_dir / appex_info["CFBundleExecutable"]
                archive.extract(appex_binary_path.relative_to(extract_root).as_posix(), extract_root)
                binaries_to_check.append(appex_binary_path)

        entitlements: set[str] = set()
        for binary in binaries_to_check:
            entitlements.update(parse_entitlements_from_binary(binary))

        return {
            "bundleIdentifier": main_info["CFBundleIdentifier"],
            "displayName": main_info.get("CFBundleDisplayName") or main_info.get("CFBundleName"),
            "version": main_info["CFBundleShortVersionString"],
            "buildVersion": main_info["CFBundleVersion"],
            "minOSVersion": main_info.get("MinimumOSVersion"),
            "privacy": collect_privacy_keys(main_info),
            "entitlements": sorted(entitlements),
        }


def load_existing_apps_json(path: Path) -> dict[str, Any]:
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return {}


def make_release_notes(release: dict[str, Any]) -> str:
    lines = [f"GitHub release {release['tag_name']}"]
    body = (release.get("body") or "").strip()
    if body:
        lines.extend(["", body])
    return "\n".join(lines)


def default_source() -> dict[str, Any]:
    return {
        "name": env("SOURCE_NAME", "YTLiteDiarrhea"),
        "subtitle": env("SOURCE_SUBTITLE", "YouTubePlus source for SideStore"),
        "description": env(
            "SOURCE_DESCRIPTION",
            "SideStore source for YTLiteDiarrhea GitHub releases.",
        ),
        "website": env("SOURCE_WEBSITE", "https://github.com/diarrhea3/YTLiteDiarrhea"),
        "iconURL": env("ICON_URL", DEFAULT_ICON_URL),
        "tintColor": env("TINT_COLOR", DEFAULT_TINT_COLOR),
        "featuredApps": [],
        "apps": [],
        "news": [],
    }


def default_app() -> dict[str, Any]:
    return {
        "name": env("APP_NAME", "YouTubePlus"),
        "developerName": env("DEVELOPER_NAME", "diarrhea3"),
        "subtitle": env("APP_SUBTITLE", "YTLiteDiarrhea build"),
        "localizedDescription": env(
            "APP_DESCRIPTION",
            "YouTubePlus build from the YTLiteDiarrhea GitHub releases.",
        ),
        "iconURL": env("ICON_URL", DEFAULT_ICON_URL),
        "tintColor": env("TINT_COLOR", DEFAULT_TINT_COLOR),
        "category": env("APP_CATEGORY", "social"),
        "screenshots": [],
        "versions": [],
        "appPermissions": {"entitlements": [], "privacy": {}},
    }


def update_source_document(existing: dict[str, Any], metadata: dict[str, Any], release: dict[str, Any], asset: dict[str, Any]) -> dict[str, Any]:
    document = default_source()
    document.update({key: value for key, value in existing.items() if key != "apps"})

    apps = list(existing.get("apps") or [])
    app = apps[0] if apps else default_app()
    app_defaults = default_app()
    for key, value in app_defaults.items():
        app.setdefault(key, value)

    app["bundleIdentifier"] = metadata["bundleIdentifier"]
    app["developerName"] = env("DEVELOPER_NAME", app.get("developerName") or "diarrhea3")
    app["name"] = env("APP_NAME", app.get("name") or metadata["displayName"] or "YouTubePlus")
    app["subtitle"] = env("APP_SUBTITLE", app.get("subtitle") or "YTLiteDiarrhea build")
    app["localizedDescription"] = env(
        "APP_DESCRIPTION",
        app.get("localizedDescription") or "YouTubePlus build from the YTLiteDiarrhea GitHub releases.",
    )
    app["iconURL"] = env("ICON_URL", app.get("iconURL") or DEFAULT_ICON_URL)
    app["tintColor"] = env("TINT_COLOR", app.get("tintColor") or DEFAULT_TINT_COLOR)
    app["category"] = env("APP_CATEGORY", app.get("category") or "social")
    app["appPermissions"] = {
        "entitlements": metadata["entitlements"],
        "privacy": metadata["privacy"],
    }

    new_version = {
        "version": metadata["version"],
        "buildVersion": metadata["buildVersion"],
        "marketingVersion": release.get("name") or metadata["version"],
        "date": release["published_at"],
        "localizedDescription": make_release_notes(release),
        "downloadURL": asset["browser_download_url"],
        "size": asset["size"],
    }
    if metadata.get("minOSVersion"):
        new_version["minOSVersion"] = metadata["minOSVersion"]

    versions = list(app.get("versions") or [])
    skip_name_regex = os.environ.get("SKIP_RELEASE_NAME_REGEX")
    filtered_versions = [
        version
        for version in versions
        if not (
            version.get("version") == new_version["version"]
            and version.get("buildVersion") == new_version["buildVersion"]
        )
    ]
    if skip_name_regex:
        filtered_versions = [
            version
            for version in filtered_versions
            if not re.search(
                skip_name_regex,
                " ".join(
                    [
                        str(version.get("marketingVersion") or ""),
                        str(version.get("localizedDescription") or ""),
                    ]
                ),
            )
        ]
    filtered_versions.insert(0, new_version)
    app["versions"] = filtered_versions[: int(env("MAX_VERSION_HISTORY", "10"))]

    document["apps"] = [app]
    document["featuredApps"] = [metadata["bundleIdentifier"]]
    document.setdefault("news", [])
    return document


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main() -> int:
    owner = env("SOURCE_OWNER", "diarrhea3")
    repo = env("SOURCE_REPO", "YTLiteDiarrhea")
    output_path = Path(env("OUTPUT_PATH", "apps.json"))

    release_info = find_latest_ipa_release(owner, repo)
    release = release_info["release"]
    asset = release_info["asset"]

    with tempfile.TemporaryDirectory() as temp_dir:
        ipa_path = Path(temp_dir) / asset["name"]
        download_file(asset["browser_download_url"], ipa_path)
        metadata = extract_ipa_metadata(ipa_path)

    existing = load_existing_apps_json(output_path)
    updated = update_source_document(existing, metadata, release, asset)
    write_json(output_path, updated)

    print(
        f"Updated {output_path} to {metadata['version']} ({metadata['buildVersion']}) "
        f"from {owner}/{repo} release {release['tag_name']}."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

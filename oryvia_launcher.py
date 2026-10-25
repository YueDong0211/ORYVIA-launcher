"""MIT-licensed launcher for a separately authorized ORYVIA Unix package.

The launcher contains no ORYVIA analysis code, models, data or environments.
Registration verifies an author-supplied archive checksum and its full manifest;
it never downloads a package or executes package code.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unicodedata
import zipfile

__version__ = "2026.10.24.3"
SUPPORTED_APPLICATION_VERSION = "2026.10.24.3"
MANIFEST_SCHEMA = "ORYVIA_PRIVATE_DELIVERY_MANIFEST_V1"
REGISTRATION_SCHEMA = "ORYVIA_AUTHORIZED_UNIX_REGISTRATION_V1"
MARKER = ".oryvia-registration.json"
PREFIX = "ORYVIA_Studio"
MAX_MEMBERS = 20000
MAX_EXPANDED_BYTES = 8 * 1024**3
MAX_MANIFEST_BYTES = 16 * 1024**2
REQUIRED = ("SETUP.sh", "START.sh", "STOP.sh", "CHECK_ENVIRONMENT.sh",
            "runtime_shell.sh", "isolated_entry.py", "setup_runtime.py",
            "start_source.py", "stop.py")
SCRIPTS = {"setup": "SETUP.sh", "start": "START.sh", "stop": "STOP.sh",
           "check": "CHECK_ENVIRONMENT.sh"}
_HEX = re.compile(r"[0-9a-fA-F]{64}\Z")
_RESERVED = re.compile(r"(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?\Z", re.I)


class RegistrationError(RuntimeError):
    """A package or workspace does not satisfy the import contract."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _json(data: bytes):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise RegistrationError("Duplicate JSON key: " + key)
            result[key] = value
        return result
    def invalid(value):
        raise RegistrationError("Non-finite JSON value: " + value)
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=unique,
                          parse_constant=invalid)
    except (UnicodeError, ValueError, TypeError) as exc:
        raise RegistrationError("Invalid UTF-8 JSON document") from exc


def _relative(value: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or ":" in value:
        raise RegistrationError("Invalid relative member path")
    if value.startswith("/") or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise RegistrationError("Absolute or control-character path rejected")
    parts = value.split("/")
    if any(p in ("", ".", "..") or p.endswith((" ", ".")) or _RESERVED.fullmatch(p)
           for p in parts):
        raise RegistrationError("Unsafe or non-portable member path: " + value)
    if str(PurePosixPath(value)) != value:
        raise RegistrationError("Non-canonical member path")
    return value


def _alias(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


def _remember_prefixes(known: dict[str, str], value: str):
    parts = value.split("/")
    for i in range(1, len(parts) + 1):
        prefix = "/".join(parts[:i])
        key = _alias(prefix)
        if key in known and known[key] != prefix:
            raise RegistrationError("Case or Unicode-normalization path alias rejected: " + value)
        known[key] = prefix


def _linked(path: Path) -> bool:
    if path.is_symlink():
        return True
    if path.exists():
        info = path.lstat()
        return bool(getattr(info, "st_file_attributes", 0) & 0x400)
    return False


def _plain_ancestors(path: Path):
    for part in (path, *path.parents):
        if _linked(part):
            raise RegistrationError("Linked workspace path rejected: " + str(part))


def _workspace(path: Path, *, new: bool = False) -> Path:
    path = Path(os.path.abspath(os.path.expanduser(str(path))))
    _plain_ancestors(path)
    if path == Path(path.anchor):
        raise RegistrationError("A filesystem root is not a workspace")
    prefix = Path(sys.prefix).resolve()
    resolved = path.resolve()
    if resolved == prefix or prefix in resolved.parents or resolved in prefix.parents:
        raise RegistrationError("Use a workspace outside the Python/Conda installation")
    if new:
        if path.exists():
            raise RegistrationError("Registration requires a new, nonexistent workspace")
        if not path.parent.is_dir():
            raise RegistrationError("The workspace parent must already exist")
    elif not path.is_dir():
        raise RegistrationError("Workspace directory not found")
    return path


def _manifest(data: bytes) -> tuple[dict, dict[str, dict]]:
    if len(data) > MAX_MANIFEST_BYTES:
        raise RegistrationError("Manifest exceeds the 16 MiB resource limit")
    doc = _json(data)
    if not isinstance(doc, dict) or doc.get("schema") != MANIFEST_SCHEMA:
        raise RegistrationError("Unsupported delivery manifest schema")
    if doc.get("platform") != "unix" or doc.get("version") != SUPPORTED_APPLICATION_VERSION:
        raise RegistrationError("Expected the authorized Unix application " + SUPPORTED_APPLICATION_VERSION)
    identity = doc.get("source_identity")
    if not isinstance(identity, dict) or not re.fullmatch(r"[0-9a-f]{40}", str(identity.get("git_commit", ""))):
        raise RegistrationError("Missing application source identity")
    rows = doc.get("files")
    if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_MEMBERS:
        raise RegistrationError("Invalid manifest file list")
    if doc.get("file_count_without_manifest") != len(rows):
        raise RegistrationError("Manifest file count does not match its file list")
    files, folded, prefixes, total = {}, set(), {}, 0
    for row in rows:
        if not isinstance(row, dict):
            raise RegistrationError("Malformed manifest member")
        name = _relative(row.get("path"))
        if _alias(name) == _alias("DELIVERY_MANIFEST.json") or _alias(name) in folded:
            raise RegistrationError("Duplicate or reserved manifest member: " + name)
        _remember_prefixes(prefixes, name)
        size, digest = row.get("size"), row.get("sha256")
        if type(size) is not int or size < 0 or not isinstance(digest, str) or not _HEX.fullmatch(digest):
            raise RegistrationError("Invalid member size or SHA-256: " + name)
        total += size
        files[name] = {"size": size, "sha256": digest.lower()}
        folded.add(_alias(name))
    if total > MAX_EXPANDED_BYTES:
        raise RegistrationError("Package exceeds the 8 GiB expanded resource limit")
    for name in REQUIRED:
        if name not in files:
            raise RegistrationError("Missing application entry: " + name)
    # Files and directories cannot occupy the same path, even on case-insensitive systems.
    for name in files:
        for parent in PurePosixPath(name).parents:
            if str(parent) != "." and _alias(str(parent)) in folded:
                raise RegistrationError("File/directory collision in manifest")
    return doc, files


def _zip_members(package: zipfile.ZipFile) -> dict[str, zipfile.ZipInfo]:
    infos = package.infolist()
    if len(infos) > MAX_MEMBERS * 2:
        raise RegistrationError("Too many ZIP members")
    members, names, prefixes, total = {}, set(), {}, 0
    for info in infos:
        value = info.filename
        if info.orig_filename != value or info.flag_bits & ~(0x800 | 0x8 | 0x6):
            raise RegistrationError("Unsupported ZIP flags or truncated member name")
        if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            raise RegistrationError("Unsupported ZIP compression method")
        mode = info.external_attr >> 16
        kind = stat.S_IFMT(mode)
        if kind not in (0, stat.S_IFREG, stat.S_IFDIR) or (info.external_attr & 0x400):
            raise RegistrationError("Links and special ZIP members are rejected")
        clean = value[:-1] if info.is_dir() else value
        _relative(clean)
        if _alias(clean) in names:
            raise RegistrationError("Duplicate or case-aliased ZIP member")
        _remember_prefixes(prefixes, clean)
        names.add(_alias(clean))
        parts = clean.split("/", 1)
        if parts[0] != PREFIX or (len(parts) == 1 and not info.is_dir()):
            raise RegistrationError("Expected a single ORYVIA_Studio ZIP root")
        if info.is_dir():
            continue
        name = parts[1]
        total += info.file_size
        if total > MAX_EXPANDED_BYTES:
            raise RegistrationError("ZIP exceeds the 8 GiB expanded resource limit")
        members[name] = info
    return members


def inspect_archive(archive: Path, expected_sha256: str) -> dict:
    """Validate the whole archive and all payload members without executing them."""
    if not _HEX.fullmatch(expected_sha256):
        raise RegistrationError("Supply the 64-character SHA-256 from the authorized delivery receipt")
    archive = Path(archive)
    if not archive.is_file() or _linked(archive):
        raise RegistrationError("Archive must be a regular, unlinked file")
    actual = sha256_file(archive)
    if actual != expected_sha256.lower():
        raise RegistrationError("Whole-archive SHA-256 mismatch")
    try:
        with zipfile.ZipFile(archive) as package:
            members = _zip_members(package)
            if "DELIVERY_MANIFEST.json" not in members:
                raise RegistrationError("Delivery manifest is missing")
            info = members["DELIVERY_MANIFEST.json"]
            if info.file_size > MAX_MANIFEST_BYTES:
                raise RegistrationError("Manifest exceeds the 16 MiB resource limit")
            manifest_data = package.read(info)
            manifest, files = _manifest(manifest_data)
            if set(members) != set(files) | {"DELIVERY_MANIFEST.json"}:
                raise RegistrationError("ZIP and manifest file sets differ")
            for name, row in files.items():
                if members[name].file_size != row["size"]:
                    raise RegistrationError("Member size mismatch: " + name)
                digest, count = hashlib.sha256(), 0
                with package.open(members[name]) as source:
                    for block in iter(lambda: source.read(1024 * 1024), b""):
                        digest.update(block)
                        count += len(block)
                if count != row["size"] or digest.hexdigest() != row["sha256"]:
                    raise RegistrationError("Member SHA-256 mismatch: " + name)
    except (zipfile.BadZipFile, RuntimeError, OSError) as exc:
        if isinstance(exc, RegistrationError):
            raise
        raise RegistrationError("ZIP validation failed: " + str(exc)) from exc
    return {"archive_sha256": actual, "manifest_sha256": hashlib.sha256(manifest_data).hexdigest(),
            "application_version": manifest["version"], "source_commit": manifest["source_identity"]["git_commit"],
            "file_count": len(files), "expanded_bytes": sum(r["size"] for r in files.values())}


def register(archive: Path, expected_sha256: str, workspace: Path, *, authorized: bool = False) -> dict:
    if not authorized:
        raise RegistrationError("Confirm that you are authorized to use this package with --accept-authorized-package")
    workspace = _workspace(workspace, new=True)
    report = inspect_archive(archive, expected_sha256)
    # O_EXCL directory creation prevents replacing any existing workspace.
    workspace.mkdir(mode=0o700)
    staging = None
    try:
        staging = Path(tempfile.mkdtemp(prefix=".import-", dir=workspace))
        with zipfile.ZipFile(archive) as package:
            members = _zip_members(package)
            manifest_data = package.read(members["DELIVERY_MANIFEST.json"])
            _, files = _manifest(manifest_data)
            if hashlib.sha256(manifest_data).hexdigest() != report["manifest_sha256"]:
                raise RegistrationError("Archive changed during registration")
            for name, info in members.items():
                target = staging.joinpath(*name.split("/"))
                target.parent.mkdir(parents=True, exist_ok=True)
                digest, count = hashlib.sha256(), 0
                with package.open(info) as source, target.open("xb") as dest:
                    for block in iter(lambda: source.read(1024 * 1024), b""):
                        dest.write(block); digest.update(block); count += len(block)
                expected = {"sha256": report["manifest_sha256"], "size": len(manifest_data)} if name == "DELIVERY_MANIFEST.json" else files[name]
                if count != expected["size"] or digest.hexdigest() != expected["sha256"]:
                    raise RegistrationError("Archive changed during extraction: " + name)
                target.chmod(0o700 if name.endswith(".sh") else 0o600)
        if sha256_file(archive) != report["archive_sha256"]:
            raise RegistrationError("Archive changed during registration")
        staging.rename(workspace / "application")
        record = {"schema": REGISTRATION_SCHEMA, "launcher_version": __version__,
                  "application_directory": "application", "authorized_package_acknowledged": True,
                  **report}
        (workspace / MARKER).write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        (workspace / MARKER).chmod(0o600)
        return record
    except Exception:
        # This directory was created exclusively by this registration attempt.
        if workspace.is_dir() and not _linked(workspace):
            shutil.rmtree(workspace)
        raise


def registration(workspace: Path) -> tuple[Path, dict, dict[str, dict]]:
    workspace = _workspace(workspace)
    marker = workspace / MARKER
    if _linked(marker) or not marker.is_file() or marker.stat().st_size > MAX_MANIFEST_BYTES:
        raise RegistrationError("Registration receipt is missing or linked")
    record = _json(marker.read_bytes())
    if not isinstance(record, dict) or record.get("schema") != REGISTRATION_SCHEMA or record.get("application_directory") != "application":
        raise RegistrationError("Unsupported registration receipt")
    app = workspace / "application"
    if not app.is_dir() or _linked(app):
        raise RegistrationError("Registered application directory is missing or linked")
    manifest = app / "DELIVERY_MANIFEST.json"
    if _linked(manifest) or not manifest.is_file() or manifest.stat().st_size > MAX_MANIFEST_BYTES:
        raise RegistrationError("Registered manifest is missing or linked")
    raw = manifest.read_bytes()
    if hashlib.sha256(raw).hexdigest() != record.get("manifest_sha256"):
        raise RegistrationError("Registered manifest was modified")
    doc, files = _manifest(raw)
    if doc["version"] != record.get("application_version") or doc["source_identity"]["git_commit"] != record.get("source_commit"):
        raise RegistrationError("Registration identity mismatch")
    return app, record, files


def verify(workspace: Path, *, full: bool = True) -> dict:
    app, record, files = registration(workspace)
    targets = files if full else {name: files[name] for name in REQUIRED}
    for name, expected in targets.items():
        path = app.joinpath(*name.split("/"))
        _plain_ancestors(path)
        if not path.is_file() or path.stat().st_size != expected["size"] or sha256_file(path) != expected["sha256"]:
            raise RegistrationError("Registered application member differs: " + name)
    return {**record, "verified_files": len(targets), "verification": "full" if full else "entrypoints"}


def run_script(workspace: Path, command: str, arguments: list[str]) -> int:
    if os.name == "nt":
        raise RegistrationError("This launcher targets native Linux/macOS; use the authorized Windows workstation on Windows")
    # Verify the complete shipped source before executing its entry scripts.
    verify(workspace, full=True)
    app, _, _ = registration(workspace)
    bash = shutil.which("bash")
    if not bash:
        raise RegistrationError("Bash is required for the Unix application entry scripts")
    if command == "check" and arguments:
        raise RegistrationError("check takes no forwarded arguments")
    env = dict(os.environ)
    for key in list(env):
        if key.upper().startswith("PYTHON") or key.upper() in ("VIRTUAL_ENV", "HAP_PYTHON"):
            env.pop(key)
    env.update(ORYVIA_NO_PAUSE="1", ORYVIA_LAUNCHER_VERSION=__version__)
    # The application uses its own .venv after setup. Conda's minimal launcher
    # Python is used only to create it or perform explicit environment setup.
    if command in ("setup", "check"):
        env["HAP_PYTHON"] = sys.executable
    result = subprocess.run([bash, str(app / SCRIPTS[command]), *arguments],
                            cwd=app, env=env, check=False)
    return result.returncode


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Register and launch a separately authorized ORYVIA Unix package. No analysis code or models are included.")
    parser.add_argument("--version", action="version", version="ORYVIA launcher " + __version__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("register", help="Verify and import an authorized package into a new workspace")
    p.add_argument("--archive", type=Path, required=True)
    p.add_argument("--sha256", required=True)
    p.add_argument("--workspace", type=Path, required=True)
    p.add_argument("--accept-authorized-package", action="store_true")
    p = sub.add_parser("inspect-archive", help="Verify an archive without importing or executing it")
    p.add_argument("--archive", type=Path, required=True); p.add_argument("--sha256", required=True)
    for name in ("info", "verify", *SCRIPTS):
        p = sub.add_parser(name)
        p.add_argument("--workspace", type=Path, required=True)
        if name in SCRIPTS:
            p.add_argument("arguments", nargs=argparse.REMAINDER, help="Arguments after -- go to the authorized application entry script")
    args = parser.parse_args(argv)
    try:
        if args.command == "register":
            value = register(args.archive, args.sha256, args.workspace, authorized=args.accept_authorized_package)
        elif args.command == "inspect-archive":
            value = inspect_archive(args.archive, args.sha256)
        elif args.command == "info":
            _, value, _ = registration(args.workspace)
        elif args.command == "verify":
            value = verify(args.workspace)
        else:
            forwarded = args.arguments[1:] if args.arguments[:1] == ["--"] else args.arguments
            return run_script(args.workspace, args.command, forwarded)
        print(json.dumps(value, ensure_ascii=False, indent=2)); return 0
    except (RegistrationError, OSError, zipfile.BadZipFile) as exc:
        print("ORYVIA launcher: " + str(exc), file=sys.stderr); return 2


if __name__ == "__main__":
    raise SystemExit(main())

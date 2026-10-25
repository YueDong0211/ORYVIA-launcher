"""Synthetic public fixtures only; no ORYVIA analysis source or user data."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import oryvia_launcher as launcher


def fixture(path, *, edit=None, entries=None):
    files = {name: b"# synthetic launcher test fixture\n" for name in launcher.REQUIRED}
    for name in launcher.SCRIPTS.values():
        files[name] = ("#!/usr/bin/env bash\nprintf '%s\\n' '" + name + "' \"$@\"\n").encode()
    files["docs/read me.txt"] = "Synthetic text: 水稻\n".encode()
    manifest = {"schema": launcher.MANIFEST_SCHEMA, "platform": "unix",
                "version": launcher.SUPPORTED_APPLICATION_VERSION,
                "source_identity": {"git_commit": "a" * 40},
                "files": [{"path": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                          for name, data in files.items()], "file_count_without_manifest": len(files)}
    payload = {launcher.PREFIX + "/" + name: data for name, data in files.items()}
    if edit:
        edit(manifest, payload)
    payload[launcher.PREFIX + "/DELIVERY_MANIFEST.json"] = json.dumps(manifest, ensure_ascii=False).encode()
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for name, data in payload.items():
            z.writestr(name, data)
        for item, data in entries or []:
            z.writestr(item, data)
    return launcher.sha256_file(path)


class LauncherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.archive = self.base / "authorized.zip"
        self.digest = fixture(self.archive)
        self.work = self.base / "new workspace"

    def tearDown(self):
        self.temp.cleanup()

    def register(self):
        return launcher.register(self.archive, self.digest, self.work, authorized=True)

    def reject_fixture(self, *, edit=None, entries=None):
        digest = fixture(self.archive, edit=edit, entries=entries)
        with self.assertRaises(launcher.RegistrationError):
            launcher.register(self.archive, digest, self.work, authorized=True)
        self.assertFalse(self.work.exists())

    def test_inspect_and_register_all_members(self):
        report = launcher.inspect_archive(self.archive, self.digest)
        self.assertEqual(report["file_count"], len(launcher.REQUIRED) + 1)
        self.assertFalse(self.work.exists())
        record = self.register()
        verified = launcher.verify(self.work)
        self.assertEqual(verified["verified_files"], record["file_count"])
        self.assertTrue((self.work / "application" / "docs" / "read me.txt").is_file())

    def test_authorization_required(self):
        with self.assertRaises(launcher.RegistrationError):
            launcher.register(self.archive, self.digest, self.work)
        self.assertFalse(self.work.exists())

    def test_checksum_required_and_mismatch(self):
        for digest in ["bad", "0" * 64]:
            with self.subTest(digest=digest), self.assertRaises(launcher.RegistrationError):
                launcher.inspect_archive(self.archive, digest)

    def test_existing_empty_directory_not_overwritten(self):
        self.work.mkdir()
        with self.assertRaises(launcher.RegistrationError):
            self.register()
        self.assertEqual(list(self.work.iterdir()), [])

    def test_existing_user_data_not_overwritten(self):
        self.work.mkdir(); (self.work / "my-data.txt").write_text("preserve")
        with self.assertRaises(launcher.RegistrationError):
            self.register()
        self.assertEqual((self.work / "my-data.txt").read_text(), "preserve")

    def test_missing_parent_rejected(self):
        self.work = self.base / "missing" / "target"
        with self.assertRaises(launcher.RegistrationError):
            self.register()
        self.assertFalse(self.work.parent.exists())

    def test_install_prefix_rejected(self):
        with self.assertRaises(launcher.RegistrationError):
            launcher._workspace(Path(sys.prefix) / "new-app", new=True)

    def test_manifest_version_and_platform(self):
        for key, value in [("schema", "unknown"), ("version", "2026.10.17.2"), ("platform", "windows")]:
            with self.subTest(key=key):
                self.reject_fixture(edit=lambda m, p: m.update({key: value}))

    def test_missing_required_entry(self):
        def edit(m, p):
            m["files"] = m["files"][1:]; m["file_count_without_manifest"] -= 1
            p.pop(launcher.PREFIX + "/" + launcher.REQUIRED[0])
        self.reject_fixture(edit=edit)

    def test_manifest_member_hash_and_size(self):
        for key, value in [("sha256", "0" * 64), ("size", 999), ("size", True)]:
            with self.subTest(key=key, value=value):
                self.reject_fixture(edit=lambda m, p: m["files"][0].update({key: value}))

    def test_extra_unmanifested_member(self):
        self.reject_fixture(entries=[(launcher.PREFIX + "/extra.py", b"not authorized")])

    def test_missing_member(self):
        self.reject_fixture(edit=lambda m, p: p.pop(launcher.PREFIX + "/START.sh"))

    def test_path_traversal_absolute_and_windows_paths(self):
        for name in ["../outside", "/tmp/absolute", "C:/escape", launcher.PREFIX + "/../escape",
                     launcher.PREFIX + "/dir/../../escape", launcher.PREFIX + "/back\\slash",
                     launcher.PREFIX + "/CON", launcher.PREFIX + "/name."]:
            with self.subTest(name=name):
                self.reject_fixture(entries=[(name, b"malicious")])
        self.assertFalse((self.base / "outside").exists())

    def test_symlink_zip_member(self):
        entry = zipfile.ZipInfo(launcher.PREFIX + "/linked")
        entry.create_system = 3; entry.external_attr = (stat.S_IFLNK | 0o777) << 16
        self.reject_fixture(entries=[(entry, b"../../outside")])

    def test_special_zip_member(self):
        entry = zipfile.ZipInfo(launcher.PREFIX + "/pipe")
        entry.create_system = 3; entry.external_attr = (stat.S_IFIFO | 0o600) << 16
        self.reject_fixture(entries=[(entry, b"")])

    def test_duplicate_and_case_alias(self):
        for name in [launcher.PREFIX + "/START.sh", launcher.PREFIX + "/start.SH"]:
            with self.subTest(name=name):
                self.reject_fixture(entries=[(name, b"alias")])

    def test_manifest_duplicate_path(self):
        def edit(m, p):
            m["files"].append(m["files"][0]); m["file_count_without_manifest"] += 1
        self.reject_fixture(edit=edit)

    def test_manifest_file_directory_collision(self):
        def edit(m, p):
            data = b"x"; p[launcher.PREFIX + "/START.sh/child"] = data
            m["files"].append({"path": "START.sh/child", "size": 1, "sha256": hashlib.sha256(data).hexdigest()})
            m["file_count_without_manifest"] += 1
        self.reject_fixture(edit=edit)

    def test_implicit_directory_and_unicode_aliases(self):
        for left, right in [("Data/a", "data/b"), ("café/a", "cafe\u0301/b"), ("café.txt", "cafe\u0301.txt")]:
            with self.subTest(left=left, right=right):
                self.reject_fixture(entries=[(launcher.PREFIX + "/" + left, b"a"), (launcher.PREFIX + "/" + right, b"b")])

    def test_resource_limit_rejects_before_write(self):
        with mock.patch.object(launcher, "MAX_EXPANDED_BYTES", 2):
            with self.assertRaises(launcher.RegistrationError):
                self.register()
        self.assertFalse(self.work.exists())

    def test_modified_file_and_manifest_rejected(self):
        self.register()
        entry = self.work / "application" / "START.sh"
        entry.write_text("modified")
        with self.assertRaises(launcher.RegistrationError):
            launcher.verify(self.work)
        manifest = self.work / "application" / "DELIVERY_MANIFEST.json"
        manifest.write_text("{}")
        with self.assertRaises(launcher.RegistrationError):
            launcher.registration(self.work)

    def test_user_state_allowed_without_changing_code(self):
        self.register()
        path = self.work / "application" / "runs"; path.mkdir()
        (path / "user-result.tsv").write_text("user\tdata\n")
        self.assertEqual(launcher.verify(self.work)["verification"], "full")

    def test_linked_workspace_or_entry_rejected(self):
        self.register()
        original = self.work / "application" / "START.sh"
        linked = self.base / "start-original.sh"; original.rename(linked)
        try:
            original.symlink_to(linked)
        except OSError:
            self.skipTest("Platform does not allow unprivileged symbolic links")
        with self.assertRaises(launcher.RegistrationError):
            launcher.verify(self.work)

    def test_script_bridge_forwards_literal_args_and_sanitizes_env(self):
        self.register()
        fake_os = types.SimpleNamespace(name="posix", environ={**os.environ, "PYTHONPATH": "bad", "HAP_PYTHON": "bad", "VIRTUAL_ENV": "bad"})
        with mock.patch.object(launcher, "os", fake_os), mock.patch.object(launcher, "_workspace", return_value=self.work), mock.patch.object(launcher.shutil, "which", return_value="/bin/bash"), mock.patch.object(launcher.subprocess, "run") as run:
            run.return_value.returncode = 7
            result = launcher.run_script(self.work, "setup", ["--python", "--wheelhouse", "folder;$(literal)"])
            self.assertEqual(result, 7)
            args, kwargs = run.call_args
            self.assertEqual(args[0][-3:], ["--python", "--wheelhouse", "folder;$(literal)"])
            self.assertFalse(kwargs.get("shell", False))
            self.assertNotIn("PYTHONPATH", kwargs["env"])
            self.assertEqual(kwargs["env"]["HAP_PYTHON"], sys.executable)
            launcher.run_script(self.work, "start", ["--no-browser"])
            self.assertNotIn("HAP_PYTHON", run.call_args.kwargs["env"])

    def test_cli_version_inspection_registration_and_verify(self):
        def cli(*args):
            return subprocess.run([sys.executable, "-I", str(Path(launcher.__file__)), *map(str, args)], capture_output=True, text=True)
        self.assertIn(launcher.__version__, cli("--version").stdout)
        result = cli("register", "--archive", self.archive, "--sha256", self.digest, "--workspace", self.work, "--accept-authorized-package")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(cli("verify", "--workspace", self.work).returncode, 0)

    def test_real_synthetic_bash_entry_scripts(self):
        self.register()
        bash = shutil.which("bash")
        if not bash and os.name == "nt":
            possible = Path(r"D:\Git\bin\bash.exe")
            bash = str(possible) if possible.is_file() else None
        if not bash:
            self.skipTest("Bash unavailable")
        for command, name in launcher.SCRIPTS.items():
            result = subprocess.run([bash, str(self.work / "application" / name), "literal input"], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.splitlines(), [name, "literal input"])


if __name__ == "__main__":
    unittest.main()

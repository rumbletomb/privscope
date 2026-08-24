import argparse
import json
import os
import pathlib
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


PROJECT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))

import privscope  # noqa: E402


def args(**overrides):
    values = dict(
        command_timeout=2,
        scan_timeout=5,
        all_filesystems=False,
        checks=None,
    )
    values.update(overrides)
    return argparse.Namespace(**values)


class ParserTests(unittest.TestCase):
    def test_parse_sudo_rules_multiline(self):
        output = """Matching Defaults entries for alice on host:
    env_reset

User alice may run the following commands on host:
    (root) NOPASSWD: /usr/bin/systemctl restart demo
    (backup) /usr/bin/rsync --server *
"""
        self.assertEqual(
            privscope.Auditor.parse_sudo_rules(output),
            [
                "(root) NOPASSWD: /usr/bin/systemctl restart demo",
                "(backup) /usr/bin/rsync --server *",
            ],
        )

    def test_risky_sudo_binary(self):
        self.assertEqual(privscope.Auditor._sudo_risky_binary("(root) NOPASSWD: /usr/bin/find /tmp"), "find")
        self.assertIsNone(privscope.Auditor._sudo_risky_binary("(root) /usr/bin/id"))

    def test_cron_parser(self):
        self.assertEqual(
            privscope.Auditor._cron_command("*/5 * * * * root /opt/job.sh --quiet"),
            ("root", "/opt/job.sh --quiet"),
        )
        self.assertEqual(privscope.Auditor._cron_command("@reboot root /opt/start.sh"), ("root", "/opt/start.sh"))
        self.assertIsNone(privscope.Auditor._cron_command("PATH=/usr/bin:/bin"))
        self.assertIsNone(privscope.Auditor._cron_command("# comment"))

    def test_first_command_path_skips_wrapper(self):
        self.assertEqual(privscope.Auditor._first_command_path("FOO=1 nice -n 5 /opt/job.py"), "/opt/job.py")

    def test_secret_classification(self):
        self.assertEqual(privscope.Auditor._secret_kind("/root/.ssh/id_ed25519"), "private-key-or-certificate-material")
        self.assertEqual(privscope.Auditor._secret_kind("/etc/krb5.keytab"), "kerberos-keytab")
        self.assertEqual(privscope.Auditor._secret_kind("/srv/app/.env.prod"), "environment-secret-file")


class PermissionTests(unittest.TestCase):
    def setUp(self):
        self.auditor = privscope.Auditor(args())

    def test_permission_bit_evaluator(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "config")
            pathlib.Path(path).write_text("x", encoding="utf-8")
            os.chmod(path, 0o400)
            self.assertIsNone(self.auditor.writable_reason(path, replace_counts=False))
            os.chmod(path, 0o600)
            self.assertIn("writable object", self.auditor.writable_reason(path, replace_counts=False))

    def test_replaceable_file_via_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "config")
            pathlib.Path(path).write_text("x", encoding="utf-8")
            os.chmod(path, 0o400)
            os.chmod(directory, 0o700)
            self.assertIn("replaceable via writable parent", self.auditor.writable_reason(path))


class DetectionTests(unittest.TestCase):
    def test_writable_root_cron_definition_becomes_critical_finding(self):
        auditor = privscope.Auditor(args())
        with tempfile.TemporaryDirectory() as directory:
            cron = os.path.join(directory, "root-job")
            script = os.path.join(directory, "job.sh")
            pathlib.Path(script).write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            pathlib.Path(cron).write_text(f"* * * * * root {script}\n", encoding="utf-8")
            os.chmod(directory, 0o700)
            os.chmod(cron, 0o600)
            os.chmod(script, 0o700)
            with mock.patch.object(auditor, "iter_files", return_value=iter([cron])), \
                 mock.patch("privscope.os.path.isdir", return_value=False):
                auditor.check_scheduled_tasks()
        ids = [finding.id for finding in auditor.findings]
        self.assertIn("CRON-FILE-WRITABLE", ids)
        self.assertIn("CRON-COMMAND-WRITABLE", ids)
        self.assertTrue(all(f.severity == "critical" for f in auditor.findings))


class RenderingTests(unittest.TestCase):
    def sample_report(self):
        finding = privscope.Finding(
            id="TEST-1",
            title="Unsafe <file>",
            severity="high",
            category="test",
            evidence=["/tmp/a&b"],
            attack_path="A path.",
            prerequisites=["One"],
            validation=["stat /tmp/a"],
            detection=["Monitor it"],
            remediation=["Fix it"],
            mitre_attack=["T0000"],
        ).to_dict()
        return {
            "tool": {"version": privscope.VERSION},
            "target": {"user": "alice", "hostname": "host", "uid": 1000, "kernel": "test"},
            "scan": {"timestamp_utc": "2026-01-01T00:00:00Z"},
            "summary": {"counts": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0}},
            "findings": [finding],
            "notes": [],
            "errors": [],
        }

    def test_text_contains_defensive_fields(self):
        rendered = privscope.text_report(self.sample_report(), color=False)
        self.assertIn("Attack path", rendered)
        self.assertIn("Safe validation", rendered)
        self.assertIn("Detection", rendered)
        self.assertIn("MITRE ATT&CK", rendered)

    def test_html_escapes_evidence(self):
        rendered = privscope.html_report(self.sample_report())
        self.assertIn("Unsafe &lt;file&gt;", rendered)
        self.assertIn("/tmp/a&amp;b", rendered)
        self.assertNotIn("Unsafe <file>", rendered)


class CliTests(unittest.TestCase):
    def test_json_smoke(self):
        proc = subprocess.run(
            [
                sys.executable,
                str(PROJECT / "privscope.py"),
                "--checks",
                "context",
                "--format",
                "json",
                "--fail-on",
                "never",
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
            check=False,
        )
        self.assertIn(proc.returncode, (0, 2), proc.stderr)
        report = json.loads(proc.stdout)
        self.assertEqual(report["tool"]["mode"], "read-only")
        self.assertEqual(report["scan"]["checks"], ["context"])
        self.assertIn("secret_candidates", report)

    def test_unknown_check_rejected(self):
        with self.assertRaises(SystemExit):
            privscope.parse_args(["--checks", "does_not_exist"])


if __name__ == "__main__":
    unittest.main()

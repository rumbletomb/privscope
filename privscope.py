#!/usr/bin/env python3
"""PrivScope: read-only Linux privilege-escalation exposure auditor.

PrivScope identifies local conditions that could form a path from the current
user to root.  It never executes an exploit, changes a file, opens a shell, or
prompts for credentials.
"""

from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import grp
import hashlib
import html
import json
import os
import pathlib
import platform
import pwd
import re
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
from dataclasses import asdict, dataclass, field
from typing import Callable, Iterable, Optional


VERSION = "0.1.0"
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_COLORS = {
    "info": "\033[36m",
    "low": "\033[34m",
    "medium": "\033[33m",
    "high": "\033[31m",
    "critical": "\033[1;31m",
}
RESET = "\033[0m"


@dataclass
class CommandResult:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    category: str
    evidence: list[str]
    attack_path: str
    prerequisites: list[str]
    validation: list[str]
    detection: list[str]
    remediation: list[str]
    mitre_attack: list[str] = field(default_factory=list)
    confidence: str = "medium"
    references: list[str] = field(default_factory=list)

    def fingerprint(self) -> str:
        raw = self.id + "\0" + "\0".join(sorted(self.evidence))
        return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:16]

    def to_dict(self) -> dict:
        result = asdict(self)
        result["fingerprint"] = self.fingerprint()
        return result


class Auditor:
    """Collects findings without modifying the audited host."""

    CHECK_ORDER = [
        "context",
        "sudo",
        "groups",
        "path",
        "sensitive_files",
        "suid_sgid",
        "capabilities",
        "scheduled_tasks",
        "systemd",
        "processes",
        "containers",
        "mounts",
        "kernel",
        "secrets_metadata",
    ]

    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.uid = os.geteuid()
        self.gid = os.getegid()
        self.groups = set(os.getgroups()) | {self.gid}
        self.username = self._username(self.uid)
        self.hostname = socket.gethostname()
        self.started = time.monotonic()
        self.findings: list[Finding] = []
        self.errors: list[str] = []
        self.notes: list[str] = []
        self.secret_candidates: list[dict] = []
        self._seen: set[tuple[str, tuple[str, ...]]] = set()

    @staticmethod
    def _username(uid: int) -> str:
        try:
            return pwd.getpwuid(uid).pw_name
        except KeyError:
            return str(uid)

    def run_command(self, argv: list[str], timeout: Optional[int] = None) -> CommandResult:
        timeout = timeout or self.args.command_timeout
        try:
            proc = subprocess.run(
                argv,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
                env={**os.environ, "LC_ALL": "C", "LANG": "C"},
            )
            return CommandResult(argv, proc.returncode, proc.stdout, proc.stderr)
        except subprocess.TimeoutExpired as exc:
            return CommandResult(
                argv,
                124,
                exc.stdout or "" if isinstance(exc.stdout, str) else "",
                exc.stderr or "" if isinstance(exc.stderr, str) else "",
                True,
            )
        except (FileNotFoundError, PermissionError, OSError) as exc:
            return CommandResult(argv, 127, "", str(exc))

    def add(self, finding: Finding) -> None:
        key = (finding.id, tuple(sorted(finding.evidence)))
        if key not in self._seen:
            self._seen.add(key)
            self.findings.append(finding)

    def error(self, check: str, message: str) -> None:
        self.errors.append(f"{check}: {message}")

    def _mode_allows_write(self, st: os.stat_result, directory: bool = False) -> bool:
        required = stat.S_IWUSR | (stat.S_IXUSR if directory else 0)
        if st.st_uid == self.uid and (st.st_mode & required) == required:
            return True
        required = stat.S_IWGRP | (stat.S_IXGRP if directory else 0)
        if st.st_gid in self.groups and (st.st_mode & required) == required:
            return True
        required = stat.S_IWOTH | (stat.S_IXOTH if directory else 0)
        return (st.st_mode & required) == required

    def writable_reason(self, path: str, replace_counts: bool = True) -> Optional[str]:
        """Return why current identity can alter path, or None.

        This permission-bit evaluator intentionally does not treat uid 0 as a
        universal bypass. Running as root is separately marked as unreliable.
        """
        try:
            st = os.stat(path)
            if self._mode_allows_write(st, stat.S_ISDIR(st.st_mode)):
                return f"writable object ({stat.filemode(st.st_mode)}, owner {st.st_uid}:{st.st_gid})"
            if replace_counts and not stat.S_ISDIR(st.st_mode):
                parent = os.path.dirname(path) or "."
                pst = os.stat(parent)
                if self._mode_allows_write(pst, True):
                    return f"replaceable via writable parent {parent} ({stat.filemode(pst.st_mode)})"
        except (FileNotFoundError, PermissionError, OSError):
            return None
        return None

    def path_components_writable(self, path: str) -> list[str]:
        result: list[str] = []
        current = pathlib.Path(os.path.abspath(path))
        for parent in [current.parent, *current.parents]:
            reason = self.writable_reason(str(parent), replace_counts=False)
            if reason:
                result.append(f"{parent}: {reason}")
        return result

    @staticmethod
    def safe_read(path: str, max_bytes: int = 1024 * 1024) -> Optional[str]:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                return handle.read(max_bytes)
        except (FileNotFoundError, PermissionError, IsADirectoryError, OSError):
            return None

    @staticmethod
    def iter_files(paths: Iterable[str], patterns: tuple[str, ...] = ("*",)) -> Iterable[str]:
        for raw in paths:
            path = pathlib.Path(raw)
            if path.is_file() or path.is_symlink():
                yield str(path)
            elif path.is_dir():
                try:
                    for item in path.iterdir():
                        if item.is_file() and any(fnmatch.fnmatch(item.name, p) for p in patterns):
                            yield str(item)
                except (PermissionError, OSError):
                    continue

    def check_context(self) -> None:
        if self.uid == 0:
            self.add(Finding(
                id="CTX-ROOT-RUN",
                title="Audit executed as root; user-path results are not representative",
                severity="medium",
                category="execution-context",
                evidence=["effective UID is 0"],
                attack_path="No escalation path is demonstrated. Root can read and modify objects that the intended unprivileged account cannot.",
                prerequisites=["The scanner was launched with sudo or from a root shell."],
                validation=["id -u", "Run PrivScope again as the target user without sudo."],
                detection=["Record which identity launched the assessment and compare reports only for the same identity."],
                remediation=["Re-run as the exact unprivileged user whose exposure is being assessed."],
                confidence="high",
            ))
        try:
            os_info = self.safe_read("/etc/os-release", 64 * 1024) or "unavailable"
            pretty = re.search(r'^PRETTY_NAME=["\']?(.*?)["\']?$', os_info, re.M)
            self.notes.append(f"OS: {pretty.group(1) if pretty else platform.platform()}")
        except Exception as exc:  # defensive metadata only
            self.error("context", str(exc))

    def check_sudo(self) -> None:
        if not shutil.which("sudo"):
            self.notes.append("sudo not installed or not in PATH")
            return
        result = self.run_command(["sudo", "-n", "-l"], timeout=min(10, self.args.command_timeout))
        combined = "\n".join(x for x in (result.stdout, result.stderr) if x).strip()
        if result.timed_out:
            self.error("sudo", "sudo -n -l timed out")
            return
        if result.returncode != 0:
            if "password is required" in combined.lower() or "a password is required" in combined.lower():
                self.notes.append("sudo requires authentication; PrivScope did not prompt for a password")
            else:
                self.notes.append("No non-interactive sudo permissions observed")
            return

        rules = self.parse_sudo_rules(result.stdout)
        if not rules:
            self.notes.append("sudo -n -l succeeded, but no executable rule was parsed")
            return
        for idx, rule in enumerate(rules, 1):
            upper = rule.upper()
            nopasswd = "NOPASSWD:" in upper
            setenv = "SETENV:" in upper
            command_part = rule.split(":", 1)[-1].strip()
            unrestricted = re.search(r"(^|[,\s])ALL($|[,\s])", command_part) is not None
            risky_name = self._sudo_risky_binary(command_part)
            severity = "critical" if unrestricted and nopasswd else "high"
            if not nopasswd and not setenv and not risky_name:
                severity = "medium"
            abuse = (
                "An attacker controlling this account can invoke the permitted command with elevated identity. "
                "If the command can launch child processes, load attacker-controlled files, invoke an editor/pager, "
                "or accepts an unsafe wildcard, that control may cross the sudo boundary and become root execution."
            )
            self.add(Finding(
                id=f"SUDO-RULE-{idx}",
                title="Potentially escalation-relevant sudo rule",
                severity=severity,
                category="sudo",
                evidence=[rule],
                attack_path=abuse,
                prerequisites=[
                    "Attacker has a shell as the audited user.",
                    "The allowed command or one of its inputs exposes an escape, file-write, plugin, environment, or wildcard primitive.",
                    "Authentication is unnecessary when NOPASSWD is present; otherwise a valid sudo authentication context may be needed.",
                ],
                validation=["sudo -n -l", f"Resolve and review the permitted executable and every writable input: {command_part}"],
                detection=[
                    "Monitor /var/log/auth.log, /var/log/secure, or journald for COMMAND= records involving this rule.",
                    "Alert when a sudo-launched process creates an unexpected shell, interpreter, editor, pager, compiler, or network client.",
                    "With auditd, correlate execve events where auid is the user but euid becomes 0.",
                ],
                remediation=[
                    "Replace broad commands with a purpose-built root helper that validates all input.",
                    "Use absolute command paths, fixed arguments, NOEXEC where applicable, and avoid SETENV/wildcards.",
                    "Remove NOPASSWD unless it is operationally necessary and independently constrained.",
                ],
                mitre_attack=["T1548.003 - Sudo and Sudo Caching"],
                confidence="high" if unrestricted or risky_name else "medium",
                references=["https://www.sudo.ws/docs/man/sudoers.man/"],
            ))

    @staticmethod
    def parse_sudo_rules(output: str) -> list[str]:
        rules: list[str] = []
        in_rules = False
        current = ""
        for raw in output.splitlines():
            line = raw.rstrip()
            if "may run the following commands" in line.lower():
                in_rules = True
                continue
            if not in_rules:
                continue
            stripped = line.strip()
            if not stripped:
                continue
            if re.match(r"^\([^)]*\)\s+", stripped):
                if current:
                    rules.append(current)
                current = stripped
            elif current and line[:1].isspace():
                current += " " + stripped
        if current:
            rules.append(current)
        return rules

    @staticmethod
    def _sudo_risky_binary(rule: str) -> Optional[str]:
        risky = {
            "bash", "sh", "dash", "zsh", "fish", "python", "python3", "perl", "ruby", "lua",
            "vim", "vi", "nvim", "less", "more", "man", "find", "awk", "sed", "tar", "zip",
            "rsync", "cp", "mv", "tee", "dd", "mount", "env", "docker", "podman", "systemctl",
            "journalctl", "git", "make", "gcc", "gdb", "node", "php", "socat", "nc", "ncat",
        }
        words = re.findall(r"(?:^|[\s,/])([A-Za-z0-9_.+-]+)(?=$|[\s,*])", rule)
        return next((w for w in words if w in risky), None)

    def check_groups(self) -> None:
        dangerous = {
            "docker": ("critical", "control the Docker daemon and start or modify privileged containers"),
            "lxd": ("critical", "create containers that map or mount host resources"),
            "lxc": ("critical", "control local containers and potentially expose host resources"),
            "disk": ("critical", "read or alter raw block devices, bypassing filesystem permissions"),
            "root": ("high", "receive group permissions intended for root-managed objects"),
            "libvirt": ("high", "control virtual machines and host-backed devices or files"),
            "kvm": ("high", "access virtualization devices; impact depends on local helpers and policy"),
            "adm": ("medium", "read privileged logs that may disclose credentials or operational secrets"),
            "systemd-journal": ("medium", "read privileged journal data that may disclose secrets"),
            "shadow": ("high", "read password-hash material when group permissions allow it"),
        }
        memberships: list[str] = []
        for gid in sorted(self.groups):
            try:
                memberships.append(grp.getgrgid(gid).gr_name)
            except KeyError:
                continue
        for name in memberships:
            if name not in dangerous:
                continue
            severity, primitive = dangerous[name]
            self.add(Finding(
                id=f"GROUP-{name.upper()}",
                title=f"Membership in escalation-relevant group: {name}",
                severity=severity,
                category="groups-and-delegation",
                evidence=[f"{self.username} is a member of {name}"],
                attack_path=f"The group can {primitive}. An attacker may use that delegated primitive to cross into root-controlled resources.",
                prerequisites=["The group-backed device, socket, file, or service is present and accessible."],
                validation=["id", f"getent group {shlex.quote(name)}"],
                detection=[
                    "Alert on membership changes to privileged local groups.",
                    "Correlate use of the associated daemon/socket/device with interactive user sessions.",
                ],
                remediation=[f"Remove unnecessary users from {name}; use narrowly scoped brokered operations instead."],
                mitre_attack=["T1098 - Account Manipulation", "T1548 - Abuse Elevation Control Mechanism"],
                confidence="high",
            ))

    def check_path(self) -> None:
        raw = os.environ.get("PATH", "")
        entries = raw.split(":")
        problems: list[str] = []
        for idx, entry in enumerate(entries):
            path = entry or os.getcwd()
            if not os.path.isabs(path):
                problems.append(f"PATH[{idx}] is relative: {entry!r}")
                continue
            reason = self.writable_reason(path, replace_counts=False)
            if reason:
                problems.append(f"PATH[{idx}] {path}: {reason}")
        if problems:
            self.add(Finding(
                id="PATH-WRITABLE",
                title="Current PATH contains attacker-writable or relative directories",
                severity="medium",
                category="path-hijacking",
                evidence=problems[:50],
                attack_path="If a privileged script or sudo rule invokes a command without an absolute path while inheriting this search path, an attacker can place a same-named executable earlier in PATH and obtain elevated execution.",
                prerequisites=["A privileged execution context inherits the unsafe PATH.", "That context invokes a command by name rather than an absolute, trusted path."],
                validation=["printf '%s\\n' \"$PATH\" | tr ':' '\\n'", "Review privileged scripts for commands lacking absolute paths."],
                detection=["Monitor creation and execution of new files in writable PATH directories.", "Alert when root executes a binary from /tmp, a user home, or another user-writable location."],
                remediation=["Set a minimal secure_path for sudo and services.", "Use absolute paths in privileged scripts and make every parent directory root-owned and non-writable."],
                mitre_attack=["T1574.007 - PATH Environment Variable Hijacking"],
                confidence="medium",
            ))

    def check_sensitive_files(self) -> None:
        targets = {
            "/etc/passwd": ("critical", "alter account identity or add a UID 0 principal"),
            "/etc/shadow": ("critical", "alter password hashes or authentication state"),
            "/etc/group": ("high", "add the account to privileged groups"),
            "/etc/gshadow": ("high", "alter protected group membership or credentials"),
            "/etc/sudoers": ("critical", "grant unrestricted sudo rights"),
            "/etc/ld.so.preload": ("critical", "force privileged dynamic processes to load attacker-controlled code"),
            "/etc/environment": ("high", "inject environment settings into later login contexts"),
            "/etc/profile": ("high", "inject commands into shell login initialization"),
            "/etc/bash.bashrc": ("high", "inject commands into interactive shell initialization"),
            "/etc/crontab": ("critical", "change commands executed by the system scheduler"),
            "/etc/fstab": ("high", "influence privileged mount behavior on a later mount or boot"),
            "/etc/pam.conf": ("critical", "alter system authentication policy"),
        }
        for path, (severity, primitive) in targets.items():
            if not os.path.lexists(path):
                continue
            reason = self.writable_reason(path)
            if reason:
                self.add(Finding(
                    id="SENSITIVE-WRITABLE",
                    title=f"Sensitive root configuration can be modified: {path}",
                    severity=severity,
                    category="sensitive-file-permissions",
                    evidence=[f"{path}: {reason}"],
                    attack_path=f"An attacker can {primitive}. The change is then consumed by authentication, a privileged process, or the next boot/login cycle.",
                    prerequisites=["The audited identity retains write or replacement access to the file.", "The affected subsystem reads the modified file."],
                    validation=[f"namei -l {shlex.quote(path)}", f"stat -Lc '%A %U:%G %n' {shlex.quote(path)}"],
                    detection=[f"Add an audit watch for writes and attribute changes to {path}.", "Alert on unexpected ownership, mode, checksum, or package-integrity changes."],
                    remediation=[f"Restore root ownership and restrictive permissions on {path} and all parent directories.", "Validate the file against a trusted package or configuration baseline."],
                    mitre_attack=["T1222.002 - Linux and Mac File and Directory Permissions Modification", "T1548 - Abuse Elevation Control Mechanism"],
                    confidence="high",
                ))

        dirs = {
            "/etc/sudoers.d": ("critical", "sudo policy fragments"),
            "/etc/cron.d": ("critical", "system cron entries"),
            "/etc/systemd/system": ("critical", "system service definitions"),
            "/etc/ld.so.conf.d": ("high", "dynamic linker search configuration"),
            "/etc/pam.d": ("critical", "PAM authentication policy"),
            "/etc/polkit-1/rules.d": ("critical", "polkit authorization rules"),
            "/root/.ssh": ("critical", "root SSH trust and credentials"),
        }
        for path, (severity, purpose) in dirs.items():
            if os.path.isdir(path):
                reason = self.writable_reason(path, replace_counts=False)
                if reason:
                    self.add(Finding(
                        id="SENSITIVE-DIR-WRITABLE",
                        title=f"Sensitive configuration directory is writable: {path}",
                        severity=severity,
                        category="sensitive-file-permissions",
                        evidence=[f"{path}: {reason}"],
                        attack_path=f"The user can plant or replace {purpose}. A privileged subsystem may later trust and process the attacker-controlled entry.",
                        prerequisites=["The subsystem accepts a new or replaced file in this directory."],
                        validation=[f"namei -l {shlex.quote(path)}", f"find {shlex.quote(path)} -maxdepth 1 -printf '%M %u:%g %p\\n'"],
                        detection=[f"Monitor create, rename, unlink, chmod and chown events below {path}."],
                        remediation=[f"Make {path} and its parents root-owned and non-writable to unprivileged users."],
                        mitre_attack=["T1222.002 - Linux and Mac File and Directory Permissions Modification"],
                        confidence="high",
                    ))

        result = self.run_command(["find", "/etc", "-xdev", "-type", "f", "-writable", "-print"], timeout=self.args.scan_timeout)
        files = [p for p in result.stdout.splitlines() if p and not p.startswith("/etc/mtab")]
        if files:
            self.add(Finding(
                id="ETC-WRITABLE-FILES",
                title="Additional writable files found below /etc",
                severity="high",
                category="sensitive-file-permissions",
                evidence=files[:100] + ([f"... {len(files)-100} more"] if len(files) > 100 else []),
                attack_path="A root-owned service, login flow, package hook, or scheduled task may consume one of these files, converting a file-write primitive into privileged execution or policy tampering.",
                prerequisites=["A privileged consumer must parse or execute the writable file."],
                validation=["Review owner, mode, parent directories, package provenance, and consumers for every listed path."],
                detection=["Use auditd/FIM to monitor writable configuration files and compare them with the package-manager baseline."],
                remediation=["Remove unintended write permissions and repair ownership; reinstall or verify the owning package where appropriate."],
                mitre_attack=["T1222.002 - Linux and Mac File and Directory Permissions Modification"],
                confidence="medium",
            ))

    def check_suid_sgid(self) -> None:
        argv = ["find", "/"]
        if not self.args.all_filesystems:
            argv.append("-xdev")
        argv += ["-type", "f", "(", "-perm", "-4000", "-o", "-perm", "-2000", ")", "-print"]
        result = self.run_command(argv, timeout=self.args.scan_timeout)
        if result.timed_out:
            self.notes.append("SUID/SGID scan reached its time limit; results may be partial")
        paths = sorted(set(p for p in result.stdout.splitlines() if p.startswith("/")))
        risky = {
            "bash", "dash", "sh", "zsh", "find", "vim", "vi", "nvim", "less", "more", "nano",
            "python", "python3", "perl", "ruby", "lua", "php", "node", "awk", "gawk", "sed", "tar",
            "cp", "mv", "dd", "tee", "env", "make", "gdb", "strace", "socat", "ncat", "nc",
            "busybox", "systemctl", "journalctl", "docker", "podman",
        }
        unusual: list[str] = []
        for path in paths:
            try:
                st = os.stat(path)
            except OSError:
                continue
            flags = []
            if st.st_mode & stat.S_ISUID:
                flags.append(f"SUID owner={self._username(st.st_uid)}")
            if st.st_mode & stat.S_ISGID:
                try:
                    group_name = grp.getgrgid(st.st_gid).gr_name
                except KeyError:
                    group_name = str(st.st_gid)
                flags.append(f"SGID group={group_name}")
            reason = self.writable_reason(path)
            base = os.path.basename(path)
            if reason:
                self.add(Finding(
                    id="SUID-WRITABLE",
                    title=f"Privileged executable can be modified: {path}",
                    severity="critical",
                    category="suid-sgid",
                    evidence=[f"{path}: {', '.join(flags)}; {reason}"],
                    attack_path="An attacker can replace or alter the privileged executable. When any user invokes it, the kernel applies its SUID/SGID identity to attacker-controlled code.",
                    prerequisites=["The filesystem honors SUID/SGID on this mount.", "The file remains privileged after replacement or can be modified in place."],
                    validation=[f"findmnt -T {shlex.quote(path)} -o TARGET,FSTYPE,OPTIONS", f"namei -l {shlex.quote(path)}"],
                    detection=[f"Monitor write, rename, unlink and metadata changes to {path}.", "Alert on SUID/SGID files executed from non-standard paths."],
                    remediation=["Immediately remove the privilege bit or execution access, restore from a trusted package/source, and correct ownership and parent permissions."],
                    mitre_attack=["T1548.001 - Setuid and Setgid"],
                    confidence="high",
                ))
            elif base in risky and (st.st_mode & stat.S_ISUID) and st.st_uid == 0:
                self.add(Finding(
                    id="SUID-RISKY-BINARY",
                    title=f"Root-SUID binary exposes a broad execution primitive: {path}",
                    severity="high",
                    category="suid-sgid",
                    evidence=[f"{path}: {', '.join(flags)}; mode {stat.filemode(st.st_mode)}"],
                    attack_path="Broad interpreters, editors, file utilities, debuggers, and shell-capable tools often provide a documented path to execute another program or overwrite a protected file while retaining effective UID 0.",
                    prerequisites=["The installed build retains the relevant feature and does not drop privileges.", "The mount is not nosuid and no LSM policy blocks the action."],
                    validation=[f"{shlex.quote(path)} --version 2>/dev/null || true", f"findmnt -T {shlex.quote(path)} -o OPTIONS", "Compare the exact binary/version and invocation constraints with vendor documentation and GTFOBins."],
                    detection=[f"Audit execve of {path} and alert when euid=0 but auid is an unprivileged user.", "Inspect child-process creation and protected-file writes originating from this binary."],
                    remediation=["Remove SUID unless strictly required; replace it with a narrow capability or brokered service and verify package integrity."],
                    mitre_attack=["T1548.001 - Setuid and Setgid"],
                    confidence="high",
                    references=["https://gtfobins.github.io/"],
                ))
            elif st.st_uid != 0 and (st.st_mode & stat.S_ISUID):
                unusual.append(f"{path}: {', '.join(flags)}")
        if unusual:
            self.add(Finding(
                id="SUID-NONROOT",
                title="Non-root SUID executables require review",
                severity="low",
                category="suid-sgid",
                evidence=unusual[:100],
                attack_path="These files do not directly grant root, but may enable lateral movement into a service identity that owns a stronger escalation primitive.",
                prerequisites=["The target service account has privileges or access not held by the current user."],
                validation=["Confirm package ownership and business need for each SUID bit."],
                detection=["Baseline all SUID/SGID files and alert on additions or changes."],
                remediation=["Remove unnecessary SUID bits and restore package-default permissions."],
                mitre_attack=["T1548.001 - Setuid and Setgid"],
                confidence="medium",
            ))

    def check_capabilities(self) -> None:
        if not shutil.which("getcap"):
            self.notes.append("getcap not available; file-capability check skipped")
            return
        argv = ["getcap", "-r", "/"]
        result = self.run_command(argv, timeout=self.args.scan_timeout)
        if result.timed_out:
            self.notes.append("Capability scan reached its time limit; results may be partial")
        for line in result.stdout.splitlines():
            if "=" not in line or not line.split():
                continue
            try:
                path, caps = line.split(None, 1)
            except ValueError:
                continue
            path, caps = path.strip(), caps.strip()
            dangerous = any(c in caps for c in ("cap_setuid", "cap_setgid", "cap_dac_override", "cap_dac_read_search", "cap_sys_admin", "cap_sys_ptrace", "cap_sys_module"))
            if not dangerous:
                continue
            reason = self.writable_reason(path)
            severity = "critical" if reason else "high"
            self.add(Finding(
                id="FILE-CAP-DANGEROUS",
                title=f"Executable has escalation-relevant Linux capabilities: {path}",
                severity=severity,
                category="file-capabilities",
                evidence=[f"{path} = {caps}" + (f"; {reason}" if reason else "")],
                attack_path="The executable receives kernel privileges without full SUID root. Depending on its features, it may change identity, bypass file permissions, trace privileged processes, administer namespaces/mounts, or load kernel code.",
                prerequisites=["The capability is effective/permitted for the executed file.", "The program exposes a feature that can exercise the granted capability."],
                validation=[f"getcap -v {shlex.quote(path)}", f"stat -Lc '%A %U:%G %n' {shlex.quote(path)}", "Review the exact program/version and whether it drops capabilities before processing user input."],
                detection=[f"Baseline capabilities with getcap and monitor security.capability xattr changes on {path}.", "Alert on execution by interactive users followed by UID changes, protected-file access, ptrace, mounts, or module operations."],
                remediation=["Remove unnecessary capabilities with the package/configuration mechanism; use the narrowest capability set and sandbox the service."],
                mitre_attack=["T1548 - Abuse Elevation Control Mechanism"],
                confidence="high",
            ))

    @staticmethod
    def _cron_command(line: str) -> Optional[tuple[str, str]]:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" in stripped.split()[0]:
            return None
        parts = stripped.split()
        if not parts:
            return None
        if parts[0].startswith("@"):
            if len(parts) >= 3:
                return parts[1], " ".join(parts[2:])
            return None
        if len(parts) >= 7:
            return parts[5], " ".join(parts[6:])
        return None

    @staticmethod
    def _first_command_path(command: str) -> Optional[str]:
        try:
            tokens = shlex.split(command, comments=True, posix=True)
        except ValueError:
            return None
        while tokens and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tokens[0]):
            tokens.pop(0)
        wrappers = {"nice", "nohup", "timeout", "ionice", "chrt", "env", "sudo", "su", "runuser"}
        options_with_values = {
            "nice": {"-n", "--adjustment"},
            "timeout": {"-k", "--kill-after", "-s", "--signal"},
            "ionice": {"-c", "--class", "-n", "--classdata", "-t", "--ignore"},
            "chrt": {"-p", "--pid", "-T", "--sched-runtime", "-P", "--sched-period", "-D", "--sched-deadline"},
            "env": {"-u", "--unset", "-C", "--chdir", "-S", "--split-string"},
            "sudo": {"-u", "--user", "-g", "--group", "-h", "--host", "-C", "--close-from", "-T", "--command-timeout", "-R", "--chroot", "-D", "--chdir"},
            "su": {"-c", "--command", "-s", "--shell", "-g", "--group", "-G", "--supp-group"},
            "runuser": {"-u", "--user", "-g", "--group", "-G", "--supp-group", "-s", "--shell", "-c", "--command"},
        }
        while tokens and os.path.basename(tokens[0]) in wrappers:
            wrapper = os.path.basename(tokens.pop(0))
            while tokens and tokens[0].startswith("-"):
                option = tokens.pop(0)
                option_name = option.split("=", 1)[0]
                if option_name in options_with_values.get(wrapper, set()) and "=" not in option and tokens:
                    tokens.pop(0)
            if wrapper == "timeout" and tokens:
                tokens.pop(0)  # duration
            while tokens and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tokens[0]):
                tokens.pop(0)
        return tokens[0] if tokens else None

    def check_scheduled_tasks(self) -> None:
        paths = ["/etc/crontab", "/etc/cron.d"]
        for path in self.iter_files(paths):
            reason = self.writable_reason(path)
            if reason:
                self.add(Finding(
                    id="CRON-FILE-WRITABLE",
                    title=f"System cron definition can be modified: {path}",
                    severity="critical",
                    category="scheduled-tasks",
                    evidence=[f"{path}: {reason}"],
                    attack_path="The user can alter a scheduler definition that is normally evaluated by root, causing an attacker-selected command to run as a privileged account at the next matching schedule.",
                    prerequisites=["cron/crond is active and reads this file.", "Syntax, ownership, and mode are accepted by the implementation."],
                    validation=[f"namei -l {shlex.quote(path)}", "systemctl is-active cron 2>/dev/null || systemctl is-active crond 2>/dev/null"],
                    detection=[f"Audit all writes and metadata changes to {path}.", "Correlate cron-launched root processes with recent configuration changes."],
                    remediation=["Restore root ownership and restrictive permissions; verify the file contents against configuration management."],
                    mitre_attack=["T1053.003 - Cron"],
                    confidence="high",
                ))
            content = self.safe_read(path)
            if content is None:
                continue
            for lineno, line in enumerate(content.splitlines(), 1):
                parsed = self._cron_command(line)
                if not parsed:
                    continue
                user, command = parsed
                if user != "root":
                    continue
                executable = self._first_command_path(command)
                if not executable:
                    continue
                if os.path.isabs(executable) and os.path.exists(executable):
                    cmd_reason = self.writable_reason(executable)
                    if cmd_reason:
                        self.add(Finding(
                            id="CRON-COMMAND-WRITABLE",
                            title=f"Root cron task executes a modifiable file: {executable}",
                            severity="critical",
                            category="scheduled-tasks",
                            evidence=[f"{path}:{lineno}: {line.strip()}", f"{executable}: {cmd_reason}"],
                            attack_path="An attacker changes the scheduled executable or replaces it through a writable parent. Cron later executes the modified content as root.",
                            prerequisites=["The cron entry is active and reaches the command.", "The file remains modifiable until execution."],
                            validation=[f"namei -l {shlex.quote(executable)}", f"stat -Lc '%A %U:%G %n' {shlex.quote(path)} {shlex.quote(executable)}"],
                            detection=[f"Monitor writes to {executable} and root execution whose parent is cron/crond.", "Alert if hashes change outside an approved deployment."],
                            remediation=["Make the executable and every parent directory root-owned and non-writable; deploy it from a trusted package or immutable build."],
                            mitre_attack=["T1053.003 - Cron"],
                            confidence="high",
                        ))

        periodic = ["/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"]
        for directory in periodic:
            if not os.path.isdir(directory):
                continue
            reason = self.writable_reason(directory, replace_counts=False)
            if reason:
                self.add(Finding(
                    id="CRON-DIR-WRITABLE",
                    title=f"Periodic root task directory is writable: {directory}",
                    severity="critical",
                    category="scheduled-tasks",
                    evidence=[f"{directory}: {reason}"],
                    attack_path="An attacker can plant or replace a task in a directory commonly executed by root through run-parts or an equivalent scheduler.",
                    prerequisites=["The system scheduler processes this directory and accepts the planted filename/mode."],
                    validation=[f"namei -l {shlex.quote(directory)}", "Review /etc/crontab and systemd timers for run-parts usage."],
                    detection=[f"Monitor file creation, rename, chmod and deletion below {directory}."],
                    remediation=["Restore root ownership and remove group/other write permissions."],
                    mitre_attack=["T1053.003 - Cron"],
                    confidence="high",
                ))

    def check_systemd(self) -> None:
        if not shutil.which("systemctl") or not os.path.isdir("/run/systemd/system"):
            self.notes.append("systemd is not the active service manager; systemd service check skipped")
            return
        listing = self.run_command(["systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "--plain"], timeout=self.args.command_timeout)
        units = [line.split()[0] for line in listing.stdout.splitlines() if line.split()][:200]
        for unit in units:
            show = self.run_command(["systemctl", "show", unit, "-p", "User", "-p", "FragmentPath", "-p", "ExecStart", "--value"], timeout=self.args.command_timeout)
            lines = show.stdout.splitlines()
            if len(lines) < 3:
                continue
            user, fragment, exec_start = lines[0].strip(), lines[1].strip(), "\n".join(lines[2:]).strip()
            if user not in {"", "root"}:
                continue
            evidence: list[str] = []
            if fragment and os.path.exists(fragment):
                reason = self.writable_reason(fragment)
                if reason:
                    evidence.append(f"unit {unit}; fragment {fragment}: {reason}")
            executables = re.findall(r"path=([^ ;}]+)", exec_start)
            if not executables:
                match = re.search(r"argv\[\]=([^ ;}]+)", exec_start)
                if match:
                    executables = [match.group(1)]
            for executable in executables[:5]:
                if os.path.exists(executable):
                    reason = self.writable_reason(executable)
                    if reason:
                        evidence.append(f"unit {unit}; executable {executable}: {reason}")
            if evidence:
                self.add(Finding(
                    id="SYSTEMD-ROOT-WRITABLE",
                    title=f"Root systemd service {unit} depends on modifiable content",
                    severity="critical",
                    category="services",
                    evidence=evidence,
                    attack_path="An attacker modifies the unit definition or service executable. The payload runs as root when the service starts, restarts, reloads, or the host boots.",
                    prerequisites=["The service is restarted/reloaded or the executable is invoked again.", "systemd accepts the modified unit and no integrity policy blocks it."],
                    validation=[f"systemctl cat {shlex.quote(unit)}", f"systemctl show {shlex.quote(unit)} -p User -p FragmentPath -p ExecStart"],
                    detection=["Monitor unit-file and service-binary writes plus systemctl daemon-reload/start/restart events.", "Alert on root services executing from user-writable paths or changing executable hashes."],
                    remediation=["Restore root ownership and permissions on unit files, drop-ins, executable files, and all parent directories; verify with package/configuration management."],
                    mitre_attack=["T1543.002 - Systemd Service"],
                    confidence="high",
                ))

    def check_processes(self) -> None:
        evidence: list[str] = []
        script_evidence: list[str] = []
        library_evidence: list[str] = []
        try:
            proc_entries = [p for p in os.listdir("/proc") if p.isdigit()]
        except OSError as exc:
            self.error("processes", str(exc))
            return
        for pid in proc_entries:
            status_text = self.safe_read(f"/proc/{pid}/status", 64 * 1024)
            if not status_text:
                continue
            uid_match = re.search(r"^Uid:\s+(\d+)", status_text, re.M)
            if not uid_match or int(uid_match.group(1)) != 0:
                continue
            try:
                exe = os.readlink(f"/proc/{pid}/exe")
            except (PermissionError, FileNotFoundError, OSError):
                continue
            exe = exe.removesuffix(" (deleted)")
            if not os.path.exists(exe):
                continue
            reason = self.writable_reason(exe)
            if reason:
                comm = (self.safe_read(f"/proc/{pid}/comm", 4096) or "").strip()
                evidence.append(f"pid={pid} comm={comm!r} exe={exe}: {reason}")
            try:
                with open(f"/proc/{pid}/cmdline", "rb") as handle:
                    argv = [x.decode("utf-8", "replace") for x in handle.read(256 * 1024).split(b"\0") if x]
            except (FileNotFoundError, PermissionError, OSError):
                argv = []
            for argument in argv[1:20]:
                candidate = argument[1:] if argument.startswith("@") else argument
                if not os.path.isabs(candidate) or not os.path.isfile(candidate):
                    continue
                if candidate == exe:
                    continue
                if candidate.endswith((".sh", ".py", ".pl", ".rb", ".php", ".js", ".lua")):
                    arg_reason = self.writable_reason(candidate)
                    if arg_reason:
                        script_evidence.append(f"pid={pid} interpreter={exe} script={candidate}: {arg_reason}")
            maps = self.safe_read(f"/proc/{pid}/maps", 4 * 1024 * 1024)
            if maps:
                loaded_paths = set()
                for map_line in maps.splitlines():
                    fields = map_line.split(None, 5)
                    if len(fields) == 6 and fields[5].startswith("/"):
                        loaded_paths.add(fields[5].removesuffix(" (deleted)"))
                for loaded in sorted(loaded_paths):
                    if loaded == exe or not os.path.isfile(loaded):
                        continue
                    loaded_reason = self.writable_reason(loaded)
                    if loaded_reason:
                        library_evidence.append(f"pid={pid} exe={exe} loaded={loaded}: {loaded_reason}")
        if evidence:
            self.add(Finding(
                id="ROOT-PROCESS-WRITABLE-EXE",
                title="Running root process uses a modifiable executable",
                severity="critical",
                category="processes",
                evidence=evidence[:100],
                attack_path="An attacker alters the executable backing a root process. The modified code gains root when the process is restarted, respawned, updated in place, or invoked by another privileged component.",
                prerequisites=["A restart or fresh execution occurs after modification.", "No package integrity, IMA, read-only mount, or LSM control blocks execution."],
                validation=["For each PID, compare /proc/PID/exe with package ownership and inspect all path permissions using namei -l."],
                detection=["Alert on writes to executables currently mapped by root processes.", "Correlate root service restarts with preceding writes by unprivileged auid values."],
                remediation=["Stop the affected service, restore the executable from a trusted source, repair ownership/permissions, and investigate prior modifications."],
                mitre_attack=["T1543 - Create or Modify System Process"],
                confidence="high",
            ))
        if script_evidence:
            self.add(Finding(
                id="ROOT-PROCESS-WRITABLE-SCRIPT",
                title="Running root interpreter references a modifiable script",
                severity="critical",
                category="processes",
                evidence=script_evidence[:100],
                attack_path="An attacker changes the script supplied to a root-owned interpreter. The modified statements execute with root privileges when the process restarts or the script is invoked again.",
                prerequisites=["The command line reflects a real executable script rather than a non-executed data argument.", "A restart or repeat execution occurs."],
                validation=["Inspect /proc/PID/cmdline and the service definition; use namei -l on the script and interpreter."],
                detection=["Monitor writes to scripts referenced by root processes and alert on interpreter executions with user-writable script arguments."],
                remediation=["Make the script and every parent directory root-owned and non-writable; deploy from a trusted artifact."],
                mitre_attack=["T1059 - Command and Scripting Interpreter", "T1543 - Create or Modify System Process"],
                confidence="high",
            ))
        if library_evidence:
            self.add(Finding(
                id="ROOT-PROCESS-WRITABLE-LIBRARY",
                title="Root process has mapped a modifiable file or shared library",
                severity="critical",
                category="dynamic-linking",
                evidence=library_evidence[:100],
                attack_path="An attacker modifies a library or mapped executable component used by a root process. A later process start or library load executes attacker-controlled code with root privileges.",
                prerequisites=["The file is executable code or otherwise interpreted as code by the process.", "The process reloads it or starts again after modification."],
                validation=["Inspect /proc/PID/maps, package ownership, hashes, and every path component without changing the file."],
                detection=["Monitor writes to libraries mapped by privileged processes and alert on root loading libraries from user-writable paths."],
                remediation=["Stop the process, restore affected files from trusted packages, repair ownership/modes, and investigate prior access."],
                mitre_attack=["T1574.006 - Dynamic Linker Hijacking"],
                confidence="high",
            ))

    def check_containers(self) -> None:
        sockets = [
            "/var/run/docker.sock", "/run/docker.sock", "/run/podman/podman.sock",
            "/var/lib/lxd/unix.socket", "/var/snap/lxd/common/lxd/unix.socket",
            "/run/containerd/containerd.sock", "/run/crio/crio.sock",
        ]
        for path in sockets:
            if not os.path.exists(path):
                continue
            reason = self.writable_reason(path, replace_counts=False)
            if reason:
                self.add(Finding(
                    id="CONTAINER-SOCKET-WRITABLE",
                    title=f"Container-management socket is writable: {path}",
                    severity="critical",
                    category="containers",
                    evidence=[f"{path}: {reason}"],
                    attack_path="The socket may permit creation or modification of a privileged workload with host filesystem/device access. That control is commonly equivalent to root on the host even though no sudo rule is involved.",
                    prerequisites=["The daemon accepts commands from this socket identity.", "Daemon policy permits privileged mounts, devices, namespaces, or workload changes."],
                    validation=[f"stat -Lc '%A %U:%G %n' {shlex.quote(path)}", "Identify the daemon and authorization plugin; inspect access without creating a container."],
                    detection=["Monitor socket connections and daemon API events from interactive users.", "Alert on privileged containers, host-root bind mounts, host PID/network namespaces, added devices, or elevated capabilities."],
                    remediation=["Remove direct socket access; use a constrained remote API/proxy, rootless containers, or an authorization plugin with least privilege."],
                    mitre_attack=["T1611 - Escape to Host", "T1548 - Abuse Elevation Control Mechanism"],
                    confidence="high",
                ))

    def check_mounts(self) -> None:
        exports = self.safe_read("/etc/exports", 1024 * 1024)
        if exports:
            lines = []
            for idx, line in enumerate(exports.splitlines(), 1):
                stripped = line.strip()
                if stripped and not stripped.startswith("#") and "no_root_squash" in stripped:
                    lines.append(f"/etc/exports:{idx}: {stripped}")
            if lines:
                self.add(Finding(
                    id="NFS-NO-ROOT-SQUASH",
                    title="NFS export permits remote root identity",
                    severity="high",
                    category="mounts-and-storage",
                    evidence=lines,
                    attack_path="A root-controlled NFS client may create files retaining UID 0 or privileged mode bits on the export. If the server later executes or trusts those files, remote control can become local root impact.",
                    prerequisites=["The attacker can mount the export from an allowed client/network.", "The exported filesystem and server workflow preserve a usable privileged artifact."],
                    validation=["exportfs -v 2>/dev/null", "Review client restrictions and whether the export contains executable or trusted content."],
                    detection=["Monitor mountd/NFS client activity and creation of UID 0 or SUID files in exported paths.", "Alert on export configuration changes."],
                    remediation=["Use root_squash, restrict clients and write access, and separate exports from executable/trusted server paths."],
                    mitre_attack=["T1021 - Remote Services", "T1548.001 - Setuid and Setgid"],
                    confidence="high",
                ))
        fstab_reason = self.writable_reason("/etc/fstab") if os.path.exists("/etc/fstab") else None
        if fstab_reason:
            # Already reported by sensitive-files; keep mount-specific detail out of duplicate findings.
            self.notes.append("Writable /etc/fstab also affects privileged mount behavior")

        mounts = self.safe_read("/proc/self/mounts", 4 * 1024 * 1024) or ""
        risky_mounts: list[str] = []
        for line in mounts.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            source, target, fstype, opts = parts[:4]
            option_set = set(opts.split(","))
            if target in {"/tmp", "/var/tmp", "/home"} and "nosuid" not in option_set:
                risky_mounts.append(f"{target} ({fstype}) lacks nosuid; options={opts}")
        if risky_mounts:
            self.add(Finding(
                id="USER-WRITABLE-MOUNT-SUID",
                title="User-writable filesystem may honor SUID/SGID",
                severity="low",
                category="mounts-and-storage",
                evidence=risky_mounts,
                attack_path="This is a hardening gap rather than a standalone escalation. It increases the impact of another primitive that can create or preserve a privileged file on the mount.",
                prerequisites=["Another flaw allows a privileged identity or trusted remote source to create a SUID/SGID file here."],
                validation=["findmnt -o TARGET,FSTYPE,OPTIONS /tmp /var/tmp /home 2>/dev/null"],
                detection=["Baseline and monitor SUID/SGID files on user-writable mounts."],
                remediation=["Add nosuid where compatible; also consider nodev and noexec based on workload requirements."],
                mitre_attack=["T1548.001 - Setuid and Setgid"],
                confidence="medium",
            ))

    def check_kernel(self) -> None:
        sysctls = {
            "/proc/sys/kernel/unprivileged_bpf_disabled": ("1", "Unprivileged BPF is not fully restricted", "Set kernel.unprivileged_bpf_disabled=1 or 2 according to kernel/vendor guidance."),
            "/proc/sys/kernel/yama/ptrace_scope": ("1", "ptrace restrictions are permissive", "Set kernel.yama.ptrace_scope=1 or stricter where compatible."),
            "/proc/sys/kernel/dmesg_restrict": ("1", "Unprivileged users can read kernel logs", "Set kernel.dmesg_restrict=1."),
            "/proc/sys/kernel/kptr_restrict": ("1", "Kernel pointer exposure is permissive", "Set kernel.kptr_restrict=1 or 2."),
            "/proc/sys/fs/protected_hardlinks": ("1", "Hardlink protection is disabled", "Set fs.protected_hardlinks=1."),
            "/proc/sys/fs/protected_symlinks": ("1", "Symlink protection is disabled", "Set fs.protected_symlinks=1."),
        }
        evidence: list[str] = []
        remedies: list[str] = []
        for path, (minimum, description, remedy) in sysctls.items():
            value = (self.safe_read(path, 128) or "").strip()
            if not value:
                continue
            try:
                weak = int(value) < int(minimum)
            except ValueError:
                weak = value != minimum
            if weak:
                evidence.append(f"{path}={value}: {description}")
                remedies.append(remedy)
        userns_path = "/proc/sys/kernel/unprivileged_userns_clone"
        userns = (self.safe_read(userns_path, 128) or "").strip()
        if userns == "1":
            evidence.append(f"{userns_path}=1: unprivileged user namespaces are enabled (context-dependent attack-surface increase)")
            remedies.append("Disable unprivileged user namespaces only if workloads do not require them; otherwise patch promptly and constrain with LSM/seccomp.")
        if evidence:
            self.add(Finding(
                id="KERNEL-HARDENING",
                title="Kernel hardening settings increase local exploitation surface",
                severity="low",
                category="kernel-hardening",
                evidence=evidence,
                attack_path="These settings do not independently grant root. They can make a separate kernel or privileged-process vulnerability easier to exploit, stabilize, or turn into useful information disclosure.",
                prerequisites=["A separate vulnerable kernel interface, driver, privileged process, or race condition exists."],
                validation=["sysctl kernel.unprivileged_bpf_disabled kernel.yama.ptrace_scope kernel.dmesg_restrict kernel.kptr_restrict fs.protected_hardlinks fs.protected_symlinks 2>/dev/null", "Compare the running kernel and distribution patch level with the vendor security tracker."],
                detection=["Monitor changes to security-relevant sysctls and use kernel/runtime telemetry for unexpected BPF, ptrace, namespace, keyring, io_uring, or module activity."],
                remediation=sorted(set(remedies)),
                mitre_attack=["T1068 - Exploitation for Privilege Escalation"],
                confidence="high",
            ))
        self.notes.append(f"Kernel: {platform.release()} (PrivScope does not infer CVEs from version strings alone)")

    def check_secrets_metadata(self) -> None:
        """Inventory likely credential files by metadata only; never read contents."""
        roots = ["/etc", "/opt", "/srv", "/var/lib", "/home", "/root"]
        names = [
            "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "*.pem", "*.key", "*.p12", "*.pfx",
            "*.keytab", ".env", ".env.*", "credentials", "credentials.json",
            "application_default_credentials.json", ".netrc", ".pgpass", ".my.cnf", "kubeconfig",
            "admin.conf", ".htpasswd", "htpasswd", "secrets.yml", "secrets.yaml", "secrets.json",
        ]
        candidates: set[str] = {
            "/etc/krb5.keytab",
            "/etc/shadow",
            "/etc/gshadow",
        }
        find_argv = ["find", *[r for r in roots if os.path.exists(r)]]
        if len(find_argv) > 1:
            find_argv += ["-xdev", "-type", "f", "("]
            for idx, name in enumerate(names):
                if idx:
                    find_argv.append("-o")
                find_argv += ["-name", name]
            find_argv += [")", "-print"]
            result = self.run_command(find_argv, timeout=self.args.scan_timeout)
            if result.timed_out:
                self.notes.append("Secret-candidate metadata scan reached its time limit; inventory may be partial")
            candidates.update(p for p in result.stdout.splitlines() if p.startswith("/"))

        # Add files in credential-specific directories even when their names are generic.
        credential_dirs = [
            "/root/.ssh", "/etc/wireguard", "/etc/NetworkManager/system-connections",
            "/etc/openvpn/client", "/etc/openvpn/server",
        ]
        for directory in credential_dirs:
            try:
                for item in pathlib.Path(directory).iterdir():
                    if item.is_file():
                        candidates.add(str(item))
            except (FileNotFoundError, PermissionError, OSError):
                continue

        exposed: list[str] = []
        inventory_evidence: list[str] = []
        for path in sorted(candidates)[:1000]:
            try:
                st = os.stat(path)
            except (FileNotFoundError, PermissionError, OSError):
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            try:
                owner = pwd.getpwuid(st.st_uid).pw_name
            except KeyError:
                owner = str(st.st_uid)
            try:
                group = grp.getgrgid(st.st_gid).gr_name
            except KeyError:
                group = str(st.st_gid)
            if st.st_uid == self.uid:
                readable = bool(st.st_mode & stat.S_IRUSR)
                relation = "own-user"
            elif st.st_gid in self.groups and st.st_mode & stat.S_IRGRP:
                readable = True
                relation = "other-identity/group-readable"
            elif st.st_mode & stat.S_IROTH:
                readable = True
                relation = "other-identity/world-readable"
            else:
                readable = False
                relation = "not-readable-by-audited-user"
            writable = self.writable_reason(path)
            kind = self._secret_kind(path)
            item = {
                "path": path,
                "probable_type": kind,
                "owner": owner,
                "group": group,
                "mode": stat.filemode(st.st_mode),
                "size_bytes": st.st_size,
                "relation": relation,
                "readable_by_audited_user": readable,
                "modifiable_by_audited_user": bool(writable),
                "content_inspected": False,
            }
            self.secret_candidates.append(item)
            inventory_evidence.append(
                f"{path}: type={kind}; {stat.filemode(st.st_mode)} {owner}:{group}; "
                f"readable={'yes' if readable else 'no'}; modifiable={'yes' if writable else 'no'}"
            )
            if readable and st.st_uid != self.uid:
                exposed.append(f"{path}: {stat.filemode(st.st_mode)} {owner}:{group}; probable type={kind} (contents not read)")

        if inventory_evidence:
            self.add(Finding(
                id="SECRET-CANDIDATE-INVENTORY",
                title="Metadata-only inventory of possible credential/secret files",
                severity="info",
                category="credential-inventory",
                evidence=inventory_evidence[:500] + ([f"... {len(inventory_evidence)-500} more in JSON report"] if len(inventory_evidence) > 500 else []),
                attack_path="This inventory is not itself an escalation finding. A candidate becomes relevant when it belongs to a more privileged identity, is reusable, and is readable or modifiable by the audited user.",
                prerequisites=["The filename/path heuristic may produce false positives; contents were deliberately not inspected."],
                validation=["Review metadata as an administrator and inspect only the candidates relevant to an authorized investigation."],
                detection=["Monitor reads and changes to confirmed credential files; alert when the accessing auid is outside the expected service/user set."],
                remediation=["Move confirmed secrets into an appropriate secret store, restrict owner/group/mode, and rotate any material that was exposed."],
                mitre_attack=["T1552.001 - Credentials In Files", "T1552.004 - Private Keys"],
                confidence="low",
            ))
        if exposed:
            self.add(Finding(
                id="PRIV-CREDENTIAL-METADATA",
                title="Privileged credential-bearing files appear readable",
                severity="high",
                category="credential-exposure",
                evidence=exposed,
                attack_path="An attacker may copy authentication material belonging to root or a service identity, then authenticate as that principal or pivot to a context with stronger local privileges. PrivScope did not read the contents.",
                prerequisites=["The file contains a valid reusable secret and the corresponding authentication path is reachable."],
                validation=["As an administrator, inspect ownership/mode and rotate rather than displaying suspected secret values."],
                detection=["Monitor reads of privileged keytabs, private keys, VPN keys, and network credentials by unexpected auid values.", "Alert on subsequent authentication using newly exposed credentials."],
                remediation=["Restrict file and parent-directory access, rotate potentially exposed credentials, and use a managed secret store where possible."],
                mitre_attack=["T1552.004 - Private Keys", "T1552.001 - Credentials In Files"],
                confidence="medium",
            ))

    @staticmethod
    def _secret_kind(path: str) -> str:
        name = os.path.basename(path).lower()
        if name.startswith("id_") or name.endswith((".pem", ".key")):
            return "private-key-or-certificate-material"
        if name.endswith((".p12", ".pfx")):
            return "certificate-key-container"
        if name.endswith(".keytab"):
            return "kerberos-keytab"
        if name in {"shadow", "gshadow"}:
            return "authentication-database"
        if name in {".env"} or name.startswith(".env."):
            return "environment-secret-file"
        if "credential" in name:
            return "credential-configuration"
        if name in {".netrc", ".pgpass", ".my.cnf"}:
            return "client-authentication-file"
        if "secret" in name:
            return "secret-configuration"
        if "kube" in name or name == "admin.conf":
            return "cluster-client-configuration"
        if "htpasswd" in name:
            return "password-hash-file"
        return "credential-candidate"

    def run(self) -> dict:
        selected = self.args.checks or self.CHECK_ORDER
        for check in self.CHECK_ORDER:
            if check not in selected:
                continue
            method: Callable[[], None] = getattr(self, f"check_{check}")
            try:
                method()
            except KeyboardInterrupt:
                raise
            except Exception as exc:
                self.error(check, f"unexpected {type(exc).__name__}: {exc}")
        self.findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.category, f.id, f.title))
        counts = {severity: 0 for severity in SEVERITY_ORDER}
        for finding in self.findings:
            counts[finding.severity] += 1
        return {
            "schema_version": "1.0",
            "tool": {"name": "PrivScope", "version": VERSION, "mode": "read-only"},
            "target": {
                "hostname": self.hostname,
                "user": self.username,
                "uid": self.uid,
                "gid": self.gid,
                "kernel": platform.release(),
                "architecture": platform.machine(),
            },
            "scan": {
                "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                "duration_seconds": round(time.monotonic() - self.started, 3),
                "checks": list(selected),
                "all_filesystems": self.args.all_filesystems,
                "limitations": [
                    "No exploits or modifying payloads were executed.",
                    "No password prompt was displayed and no secret values were read or reported.",
                    "Version strings alone are not used to claim kernel/package CVEs.",
                    "A clean report does not prove that privilege escalation is impossible.",
                ],
            },
            "summary": {"counts": counts, "total": len(self.findings)},
            "findings": [f.to_dict() for f in self.findings],
            "secret_candidates": self.secret_candidates,
            "notes": self.notes,
            "errors": self.errors,
        }


def text_report(report: dict, color: bool = True, min_severity: str = "info") -> str:
    lines = [
        f"PrivScope {report['tool']['version']} — read-only Linux privilege-escalation audit",
        f"Target: {report['target']['user']}@{report['target']['hostname']} uid={report['target']['uid']} kernel={report['target']['kernel']}",
        "",
    ]
    counts = report["summary"]["counts"]
    lines.append("Summary: " + ", ".join(f"{s}={counts[s]}" for s in ("critical", "high", "medium", "low", "info")))
    lines.append("")
    threshold = SEVERITY_ORDER[min_severity]
    visible = [f for f in report["findings"] if SEVERITY_ORDER[f["severity"]] >= threshold]
    for idx, finding in enumerate(visible, 1):
        sev = finding["severity"].upper()
        if color:
            sev = f"{SEVERITY_COLORS[finding['severity']]}{sev}{RESET}"
        lines += [
            f"[{idx}] {sev} {finding['id']} — {finding['title']}",
            f"    Category: {finding['category']} | Confidence: {finding['confidence']} | Fingerprint: {finding['fingerprint']}",
            "    Evidence:",
        ]
        lines += [f"      - {item}" for item in finding["evidence"]]
        lines += ["    Attack path:", *textwrap.wrap(finding["attack_path"], width=108, initial_indent="      ", subsequent_indent="      ")]
        for label, key in (("Prerequisites", "prerequisites"), ("Safe validation", "validation"), ("Detection", "detection"), ("Remediation", "remediation"), ("MITRE ATT&CK", "mitre_attack")):
            if finding.get(key):
                lines.append(f"    {label}:")
                lines += [f"      - {item}" for item in finding[key]]
        lines.append("")
    if report["notes"]:
        lines.append("Notes:")
        lines += [f"  - {n}" for n in report["notes"]]
        lines.append("")
    if report["errors"]:
        lines.append("Check errors / visibility limits:")
        lines += [f"  - {e}" for e in report["errors"]]
        lines.append("")
    lines.append("This is evidence for defensive review, not proof of exploitability or a guarantee of safety.")
    return "\n".join(lines)


def html_report(report: dict, min_severity: str = "info") -> str:
    threshold = SEVERITY_ORDER[min_severity]
    findings = [f for f in report["findings"] if SEVERITY_ORDER[f["severity"]] >= threshold]
    counts = report["summary"]["counts"]

    def list_html(items: Iterable[str]) -> str:
        return "<ul>" + "".join(f"<li>{html.escape(str(x))}</li>" for x in items) + "</ul>"

    cards = []
    for finding in findings:
        cards.append(f"""
<article class="finding {html.escape(finding['severity'])}">
  <header><span class="badge">{html.escape(finding['severity'].upper())}</span><h2>{html.escape(finding['title'])}</h2></header>
  <p class="meta">{html.escape(finding['id'])} · {html.escape(finding['category'])} · confidence {html.escape(finding['confidence'])} · {html.escape(finding['fingerprint'])}</p>
  <h3>Evidence</h3>{list_html(finding['evidence'])}
  <h3>Attack path</h3><p>{html.escape(finding['attack_path'])}</p>
  <h3>Prerequisites</h3>{list_html(finding['prerequisites'])}
  <h3>Safe validation</h3>{list_html(finding['validation'])}
  <h3>Detection</h3>{list_html(finding['detection'])}
  <h3>Remediation</h3>{list_html(finding['remediation'])}
  <h3>MITRE ATT&amp;CK</h3>{list_html(finding['mitre_attack'])}
</article>""")
    generated = html.escape(report["scan"]["timestamp_utc"])
    target = report["target"]
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PrivScope report — {html.escape(target['hostname'])}</title>
<style>
:root{{--bg:#0b1020;--panel:#151c2f;--text:#e8edf8;--muted:#a8b3cf;--line:#2a3552;--critical:#ff4269;--high:#ff704d;--medium:#ffbf47;--low:#5aa9ff;--info:#49d7c4}}
*{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 system-ui,sans-serif}} main{{max-width:1080px;margin:auto;padding:32px 20px 80px}}
h1{{margin-bottom:4px}} h2{{font-size:1.15rem;margin:0}} h3{{font-size:.82rem;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin:20px 0 6px}}
.subtitle,.meta{{color:var(--muted)}} .summary{{display:flex;flex-wrap:wrap;gap:10px;margin:24px 0}} .count{{background:var(--panel);border:1px solid var(--line);padding:10px 14px;border-radius:10px}}
.finding{{background:var(--panel);border:1px solid var(--line);border-left:5px solid var(--info);border-radius:12px;padding:20px;margin:16px 0;box-shadow:0 8px 28px #0003}}
.finding.critical{{border-left-color:var(--critical)}} .finding.high{{border-left-color:var(--high)}} .finding.medium{{border-left-color:var(--medium)}} .finding.low{{border-left-color:var(--low)}}
header{{display:flex;gap:12px;align-items:center}} .badge{{font-weight:800;font-size:.72rem;letter-spacing:.06em;border:1px solid currentColor;border-radius:99px;padding:3px 8px}} code{{white-space:pre-wrap}} li{{margin:4px 0}}
</style></head><body><main>
<h1>PrivScope report</h1><p class="subtitle">{html.escape(target['user'])}@{html.escape(target['hostname'])} · uid {target['uid']} · kernel {html.escape(target['kernel'])} · {generated}</p>
<section class="summary">{''.join(f'<div class="count"><strong>{counts[s]}</strong> {s}</div>' for s in ('critical','high','medium','low','info'))}</section>
{''.join(cards) or '<p>No findings at the selected severity threshold.</p>'}
<p class="subtitle">Read-only evidence. No exploit was executed. A clean report is not proof that escalation is impossible.</p>
</main></body></html>"""


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Read-only Linux local privilege-escalation exposure auditor",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--format", choices=("text", "json", "html"), default="text", help="report format")
    parser.add_argument("--output", help="write report to this path instead of stdout")
    parser.add_argument("--checks", type=lambda x: [p.strip() for p in x.split(",") if p.strip()], help="comma-separated checks")
    parser.add_argument("--list-checks", action="store_true", help="list available checks and exit")
    parser.add_argument("--all-filesystems", action="store_true", help="cross filesystem boundaries during SUID/capability scans")
    parser.add_argument("--command-timeout", type=int, default=15, help="timeout for individual commands")
    parser.add_argument("--scan-timeout", type=int, default=120, help="timeout for filesystem-wide scans")
    parser.add_argument("--min-severity", choices=tuple(SEVERITY_ORDER), default="info", help="minimum finding severity displayed")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colors in text output")
    parser.add_argument("--fail-on", choices=("never", "medium", "high", "critical"), default="high", help="exit 1 when a finding at/above this level exists")
    parser.add_argument("--version", action="version", version=f"PrivScope {VERSION}")
    args = parser.parse_args(argv)
    if args.checks:
        invalid = sorted(set(args.checks) - set(Auditor.CHECK_ORDER))
        if invalid:
            parser.error(f"unknown checks: {', '.join(invalid)}")
    if args.command_timeout < 1 or args.scan_timeout < 1:
        parser.error("timeouts must be positive")
    return args


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    if args.list_checks:
        print("\n".join(Auditor.CHECK_ORDER))
        return 0
    report = Auditor(args).run()
    if args.format == "json":
        payload = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    elif args.format == "html":
        payload = html_report(report, args.min_severity)
    else:
        color = not args.no_color and not args.output and sys.stdout.isatty()
        payload = text_report(report, color=color, min_severity=args.min_severity) + "\n"

    if args.output:
        output = os.path.abspath(args.output)
        parent = os.path.dirname(output) or "."
        os.makedirs(parent, exist_ok=True)
        fd, temp_path = tempfile.mkstemp(prefix=".privscope-", dir=parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
            os.replace(temp_path, output)
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
    else:
        sys.stdout.write(payload)

    if args.fail_on != "never":
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[f["severity"]] >= threshold for f in report["findings"]):
            return 1
    return 2 if report["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())

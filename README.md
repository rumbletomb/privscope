# PrivScope

PrivScope is a dependency-free, read-only Linux auditor that looks for local conditions an unprivileged user could potentially chain into `root` access. It is designed for defensive assessment and detection engineering: every finding explains the abuse path, the conditions that must be true, safe validation steps, likely telemetry, MITRE ATT&CK mapping, and remediation.

It does **not** execute exploits, create payloads, change permissions, open a privileged shell, prompt for passwords, or print secret values.

## What it checks

| Area | Examples of evidence |
|---|---|
| Sudo | Non-interactive rules, `NOPASSWD`, `SETENV`, broad commands and escape-capable utilities |
| Identity/delegation | Docker/LXD/disk/libvirt and other privilege-relevant groups |
| SUID/SGID | Modifiable privileged files and broad root-SUID utilities |
| Linux capabilities | `cap_setuid`, `cap_dac_override`, `cap_sys_admin`, `cap_sys_ptrace`, and similar grants |
| PATH | Relative or user-writable search directories |
| Sensitive configuration | Writable passwd/shadow/sudoers/PAM/systemd/cron/linker configuration and directories |
| Scheduled execution | Writable root cron definitions, task directories, or referenced scripts |
| Services/processes | Writable executables, scripts, unit files, and mapped libraries used by root processes |
| Containers | Writable Docker, Podman, LXD, containerd and CRI sockets |
| Storage | NFS `no_root_squash`, SUID-capable user-writable mounts and writable mount configuration |
| Kernel hardening | BPF, ptrace, user namespaces, dmesg/pointer exposure, symlink/hardlink protections |
| Credential metadata | Probable private keys, keytabs, `.env`, client-auth and cluster config paths—without reading contents |

No finite script can cover *every* Linux escalation. Custom kernel drivers, application-specific logic, unknown vulnerabilities, race conditions, distributed identity systems, MAC policy mistakes, and multi-step paths may require manual review. PrivScope therefore avoids claiming that a clean report proves safety.

## Requirements

- Linux with Python 3.9 or later; Python 3.11+ is recommended.
- Standard tools such as `find`, `stat`, `systemctl`, `sudo`, and `getcap` improve coverage but are optional.
- Run as the exact user being assessed—**not with `sudo`**. Root execution makes user-writability results misleading.

The scanner uses the Python standard library only. It is suitable for Debian/Ubuntu, Raspberry Pi OS, Kali, Fedora/RHEL-family, Arch-family, and other conventional Linux distributions, although paths and service-manager coverage vary.

## Quick start

```bash
chmod +x privscope.py
./privscope.py --no-color
```

Generate machine-readable and human-readable reports:

```bash
./privscope.py --format json --output privscope-report.json --fail-on never
./privscope.py --format html --output privscope-report.html --fail-on never
```

Run only selected checks:

```bash
./privscope.py --checks sudo,groups,containers,scheduled_tasks,systemd --no-color
```

Scan mounted filesystems as well as `/` for SUID/SGID artifacts:

```bash
./privscope.py --all-filesystems --scan-timeout 300 --format json --output full-report.json --fail-on never
```

This can be slow on large or remote mounts. The default keeps the filesystem-wide SUID/SGID scan on the root filesystem.

## Reading a finding

Each finding contains:

- **Evidence:** the observed rule, path, permission, capability, group or socket.
- **Attack path:** how an attacker would conceptually turn that primitive into stronger privileges.
- **Prerequisites:** the conditions required before treating it as exploitable.
- **Safe validation:** read-only commands and review actions; no root-spawning payloads.
- **Detection:** logs, process relationships, file changes and daemon/API events to monitor.
- **Remediation:** concrete permission, policy and architecture changes.
- **MITRE ATT&CK:** the closest applicable Enterprise technique.
- **Confidence:** how directly the evidence supports the claimed path.

The JSON `fingerprint` is stable for the finding ID and evidence set, making it useful for diffing scans or suppressing accepted risk.

## Secret candidate inventory

PrivScope searches common system and application locations for filenames that often contain credentials, including private-key names, keytabs, `.env*`, credential JSON, kubeconfig, client authentication files, and secret configuration files.

For every visible candidate, JSON includes:

```json
{
  "path": "/srv/example/.env",
  "probable_type": "environment-secret-file",
  "owner": "svc-example",
  "group": "svc-example",
  "mode": "-rw-r-----",
  "size_bytes": 392,
  "relation": "other-identity/group-readable",
  "readable_by_audited_user": true,
  "modifiable_by_audited_user": false,
  "content_inspected": false
}
```

The inventory is filename-based and can contain false positives. A path hidden by directory permissions cannot be discovered by an unprivileged process. PrivScope never opens candidate files to identify or display tokens, passwords, private keys, hashes, or connection strings.

## Detection-engineering use

Recommended workflow:

1. Run PrivScope as each representative account class: normal user, operator, service account and developer.
2. Export JSON and retain it as a baseline.
3. Triage `critical` and `high` findings by verifying their prerequisites.
4. Turn each validated path into telemetry requirements. Useful correlations include:
   - file write/rename/chmod by an unprivileged `auid`, followed by execution as `euid=0`;
   - root process creation whose parent is `sudo`, `cron`, `systemd`, an interpreter, or a container daemon;
   - new SUID/SGID bits or `security.capability` xattrs;
   - root loading a library or script from a user-writable path;
   - privileged container creation, host-root bind mounts, host namespaces, devices, or excessive capabilities;
   - reads of privileged credential files by an unexpected `auid`.
5. Fix the primitive, rerun the same checks, and compare fingerprints.

The `detections/` directory contains:

- `auditd-privscope.rules`: a non-installed starter policy for privileged identity/configuration changes, root execution, xattrs, metadata and kernel modules;
- `loki-logql.md`: LogQL starting points and correlation logic for Alloy/Loki environments.

The templates must be tailored to the distribution, architecture, existing EDR, log volume, and paths validated on that host. PrivScope never installs them automatically.

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | Completed and no finding met `--fail-on` |
| `1` | Completed and at least one finding met `--fail-on` |
| `2` | No threshold finding, but one or more checks had visibility/runtime errors |

Default `--fail-on high` makes the tool useful in CI or golden-image validation. Use `--fail-on never` for inventory-only runs.

## Tests

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile privscope.py
```

Tests cover parsers, permission evaluation, secret classification, output escaping, defensive report fields, CLI validation and a JSON smoke run.

## Safety and authorization

Use PrivScope only on systems you own or are explicitly authorized to assess. The tool only reads metadata and ordinary configuration visible to the current account, with three deliberate exceptions that remain non-destructive: it asks `sudo -n -l` for non-interactive policy, reads root-process metadata only where the kernel already permits it, and inventories likely secret paths without opening their contents.

## License

MIT. See `LICENSE`.

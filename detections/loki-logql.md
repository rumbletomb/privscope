# Loki / LogQL triage templates

These templates assume `auditd`, sudo/auth logs, journald, and container-daemon logs are already collected by Alloy. Replace the label selectors with those used in your Loki deployment. They are intentionally broad starting points; validate fields and volume before creating alerts.

## Root execution attributed to an interactive user

```logql
{job=~".*(audit|journald).*"} |~ "privscope_root_exec|type=EXECVE" |~ "euid=0|UID=\"root\""
```

Correlate the `auid`/login UID with the effective UID. Root-owned daemons normally have an unset login UID; a human `auid` combined with `euid=0` is much more interesting, though legitimate `sudo` remains common.

## Sudo command review

```logql
{job=~".*(auth|secure|journald).*"} |~ "sudo.*COMMAND="
```

High-signal refinements include unexpected users, commands outside an allowlist, execution from `/tmp` or a home directory, interpreters/editors/pagers, and a child shell or network client.

## Privileged configuration changes

```logql
{job=~".*audit.*"} |~ "privscope_(identity|sudo_policy|auth_policy|scheduled_task|systemd|linker)"
```

Useful fields for alert grouping are host, `auid`, executable, watched path, syscall, success, and terminal/session identifier.

## New capabilities or file metadata changes

```logql
{job=~".*audit.*"} |~ "privscope_(xattr|metadata)"
```

Prioritize `security.capability` changes, SUID/SGID mode additions, ownership changes to UID 0, and activity against executables or service paths. The starter audit policy cannot filter the xattr name at the syscall rule itself, so downstream parsing is important.

## Root service or scheduled-task execution after a write

```logql
{job=~".*audit.*"} |~ "privscope_(scheduled_task|systemd|root_exec)"
```

The valuable detection is a sequence, not a single event:

1. an unprivileged `auid` writes/renames/chmods a watched file;
2. `cron`, `systemd`, or an interpreter subsequently executes the affected path as root;
3. the child process is new, unusual, or inconsistent with the baseline.

## Container-daemon escalation indicators

```logql
{job=~".*(docker|containerd|podman|lxd|crio).*"} |~ "privileged|/var/run/docker.sock|/run/docker.sock|hostPID|hostNetwork|/host|CapAdd"
```

Alert candidates include privileged workloads, bind mounts of `/`, host PID/network namespaces, host devices, sensitive sockets mounted into containers, or broad capabilities such as `SYS_ADMIN`.

## Operational notes

- Use the PrivScope finding fingerprint as the suppression/exception reference in your case-management process.
- Prefer correlations over raw syscall alerts; otherwise legitimate administration will create excessive noise.
- Keep `auid` (original login identity) distinct from real/effective UID.
- Test every alert in a staging host with a benign administrative action before enabling paging.

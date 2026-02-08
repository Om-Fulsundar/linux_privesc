#!/usr/bin/env python3
import os
import json
import stat
import pwd
from datetime import datetime

OUTPUT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "report", "output", "perms_scan_output.json"
)

# Directories that are noisy or not relevant for PE (skip entirely)
SKIP_ROOTS = {
    "/proc", "/sys", "/dev", "/run", "/tmp", "/var/tmp", "/var/log",
    "/snap", "/lost+found"
}

# Critical system roots to scan (bounded scope for performance + relevance)
SCAN_ROOTS = [
    "/etc", "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/lib", "/lib64"
]

# Sensitive execution/parse locations (include even if not executable)
SENSITIVE_DIRS = [
    "/etc/cron",           # cron.* folders
    "/etc/init.d",         # SysV init scripts
    "/etc/sudoers.d",      # sudo rules
    "/etc/sudoers",        # main sudoers
    "/lib/systemd/system", # systemd unit files
    "/etc/systemd/system"  # local systemd unit overrides
]

# Non-executable extensions to ignore (data-only, not exploitable directly)
IGNORE_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".svg",
    ".txt", ".log", ".csv", ".json", ".yaml", ".yml", ".xml",
    ".conf", ".ini", ".md", ".rst",
    ".cache", ".db", ".sqlite", ".lock",
}

# Executable/script extensions that matter even if +x is missing
SCRIPT_EXTS = {".sh", ".bash", ".py", ".pl", ".service", ".timer"}


def safe_lstat(path):
    try:
        return os.lstat(path)
    except Exception:
        return None


def is_world_writable(st):
    return bool(st.st_mode & stat.S_IWOTH)


def is_root_owned(st):
    try:
        return st.st_uid == 0
    except Exception:
        return False


def is_executable(st):
    # Executable by any (user/group/other)
    return bool(st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))


def in_sensitive_dir(path):
    for d in SENSITIVE_DIRS:
        if path.startswith(d):
            return True
    return False


def has_ext(path, exts):
    _, ext = os.path.splitext(path.lower())
    return ext in exts


def likely_exploitable(path, st):
    """
    Decide if a writable, root-owned item is realistically exploitable.
    - Executables or scripts: exploitable (binary/script replacement).
    - Sensitive dirs: exploitable (cron/systemd/sudo rules).
    - Ignore common data files (images, logs, text, configs) unless in sensitive dirs.
    """
    if in_sensitive_dir(path):
        return True

    # If it's a regular file:
    if stat.S_ISREG(st.st_mode):
        if has_ext(path, SCRIPT_EXTS):
            return True
        if is_executable(st):
            return True
        if has_ext(path, IGNORE_EXTS):
            return False
        # Default: non-executable regular files are not exploitable
        return False

    # Directories: world-writable root-owned directories in sensitive paths can be abused
    if stat.S_ISDIR(st.st_mode):
        # Directories themselves: only flag if in sensitive dirs
        return in_sensitive_dir(path)

    # Symlinks and others: usually low-value; skip
    return False


def exploitation_hint(path, st):
    if in_sensitive_dir(path):
        if "/cron" in path:
            return "Writable cron script or directory; attacker can inject commands executed by root."
        if "systemd" in path:
            return "Writable systemd unit or override; attacker can hijack service execution as root."
        if "sudoers" in path:
            return "Writable sudoers rules; attacker can grant arbitrary root privileges."
        if "/init.d" in path:
            return "Writable init script; attacker can insert commands executed with elevated privileges."
        return "Writable file in sensitive execution path; likely abusable by privileged services."
    if stat.S_ISREG(st.st_mode):
        if has_ext(path, SCRIPT_EXTS):
            return "Writable script; attacker can modify it to execute malicious code."
        if is_executable(st):
            return "Writable executable; attacker can replace the binary to gain root when invoked."
    return "Potentially writable but not directly exploitable; review context of use."


def should_skip_root(root_path):
    # Skip entire trees starting at SKIP_ROOTS
    for s in SKIP_ROOTS:
        if root_path.startswith(s):
            return True
    return False


def scan_permissions() -> dict:
    findings = []
    seen_paths = set()

    for base in SCAN_ROOTS:
        if should_skip_root(base) or not os.path.exists(base):
            continue

        for root, dirs, files in os.walk(base, topdown=True, followlinks=False):
            # Prune noisy subpaths
            dirs[:] = [d for d in dirs if not should_skip_root(os.path.join(root, d))]

            # Files
            for name in files:
                path = os.path.join(root, name)
                if path in seen_paths:
                    continue
                st = safe_lstat(path)
                if not st:
                    continue
                if not is_world_writable(st):
                    continue
                if not is_root_owned(st):
                    continue
                if not likely_exploitable(path, st):
                    continue

                seen_paths.add(path)
                findings.append({
                    "path": path,
                    "type": "file",
                    "owner": "root",
                    "mode_octal": oct(st.st_mode & 0o777),
                    "issue": "World-writable root-owned file",
                    "severity": "High",
                    "exploitation": exploitation_hint(path, st),
                    "mitigation": "Restrict permissions (chmod), correct ownership (chown), and move scripts/configs out of writable locations."
                })

            # Directories (limited: only sensitive dirs matter)
            for d in dirs:
                path = os.path.join(root, d)
                if path in seen_paths:
                    continue
                st = safe_lstat(path)
                if not st:
                    continue
                if not stat.S_ISDIR(st.st_mode):
                    continue
                if not is_world_writable(st):
                    continue
                if not is_root_owned(st):
                    continue
                if not likely_exploitable(path, st):
                    continue

                seen_paths.add(path)
                findings.append({
                    "path": path,
                    "type": "directory",
                    "owner": "root",
                    "mode_octal": oct(st.st_mode & 0o777),
                    "issue": "World-writable root-owned directory in sensitive path",
                    "severity": "High",
                    "exploitation": exploitation_hint(path, st),
                    "mitigation": "Restrict directory permissions and ownership; ensure only privileged processes can modify contents."
                })

    summary = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "count": len(findings),
        "high": len(findings),
        "medium": 0,
        "low": 0
    }
    return {"summary": summary, "findings": findings}


def ensure_output_dir(path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)


def save_output(data: dict, path: str):
    ensure_output_dir(path)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def main():
    results = scan_permissions()
    save_output(results, OUTPUT_PATH)
    print(f"[+] Permissions scan complete. Exploitable findings: {results['summary']['count']}")
    print(f"[+] Output written to: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()

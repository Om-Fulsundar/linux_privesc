#!/usr/bin/env python3
import os
import re
import json
import stat
from datetime import datetime

OUTPUT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "report", "output", "cron_scan_output.json"
)

# Canonical cron locations (system-wide)
CRON_DIRS = [
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/etc/cron.yearly",  # rare but seen
]

# System crontabs and anacron
CRONTAB_FILES = [
    "/etc/crontab",
    "/etc/anacrontab",
]

# Root’s interactive crontab file (if saved on disk; not always present)
ROOT_USER_CRONTAB = "/var/spool/cron/crontabs/root"

# Extensions that suggest executable scripts (even if +x missing sometimes executed by sh)
SCRIPT_EXTS = {".sh", ".bash", ".py", ".pl", ".rb"}

# Strict: only consider regular files (no symlinks noise)
def is_regular(path):
    try:
        return stat.S_ISREG(os.stat(path).st_mode)  # follow symlink
    except Exception:
        return False

def is_directory(path):
    try:
        return stat.S_ISDIR(os.stat(path).st_mode)
    except Exception:
        return False

def target_stat(path):
    try:
        return os.stat(path)  # follow symlink to real file
    except Exception:
        return None

def root_owned(st):
    return st and st.st_uid == 0

def writable_by_group_or_others(st):
    if not st:
        return False
    m = st.st_mode
    return bool(m & stat.S_IWOTH) or bool(m & stat.S_IWGRP)

def is_executable(st):
    if not st:
        return False
    return bool(st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))

def has_script_ext(path):
    _, ext = os.path.splitext(path.lower())
    return ext in SCRIPT_EXTS

def exploitation_hint_for_script(path):
    if path.endswith(".sh") or has_script_ext(path):
        return "Writable cron script; attacker can inject commands executed automatically by root."
    return "Writable cron target; attacker can replace/modify file to execute arbitrary code via cron."

# Parse cron lines to extract command targets (very conservative)
CRON_LINE_RE = re.compile(r"^\s*(?:\#.*)?$")

# System crontab format: m h dom mon dow user command
SYSTEM_CRON_RE = re.compile(r"""
    ^\s*
    (?P<m>\S+)\s+(?P<h>\S+)\s+(?P<dom>\S+)\s+(?P<mon>\S+)\s+(?P<dow>\S+)\s+
    (?P<user>\S+)\s+
    (?P<cmd>.+)$
""", re.VERBOSE)

# /etc/cron.d format similar to system crontab (includes user column)
CROND_LINE_RE = SYSTEM_CRON_RE

# user crontab format: m h dom mon dow command
USER_CRON_RE = re.compile(r"""
    ^\s*
    (?P<m>\S+)\s+(?P<h>\S+)\s+(?P<dom>\S+)\s+(?P<mon>\S+)\s+(?P<dow>\S+)\s+
    (?P<cmd>.+)$
""", re.VERBOSE)

def read_lines(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.readlines()
    except Exception:
        return []

def extract_command_targets(cmd):
    """
    Heuristics:
    - Split on '&&', ';' to get individual commands
    - First token is the binary/script path when absolute
    - Also capture absolute script paths appearing anywhere
    """
    targets = set()
    parts = re.split(r'[;&]{1,2}', cmd)
    for part in parts:
        token = part.strip().split()
        if not token:
            continue
        first = token[0]
        # Absolute path as first token
        if first.startswith("/"):
            targets.add(first)
        # Search for absolute paths elsewhere (scripts passed to sh -c or similar)
        for t in token[1:]:
            if t.startswith("/"):
                targets.add(t)
    return list(targets)

def scan_cron_directories():
    findings = []
    for base in CRON_DIRS:
        if not os.path.isdir(base):
            continue
        # Flag writable directories themselves (root-owned)
        st_dir = target_stat(base)
        if root_owned(st_dir) and writable_by_group_or_others(st_dir):
            findings.append({
                "path": base,
                "type": "directory",
                "issue": "Writable cron directory (root-owned)",
                "severity": "High",
                "mode_octal": oct(st_dir.st_mode & 0o777),
                "exploitation": "Attacker can drop or alter cron jobs to execute as root on schedule.",
                "mitigation": "Set directory permissions to 0755 root:root; restrict write access."
            })
        # Inspect files inside
        for name in sorted(os.listdir(base)):
            path = os.path.join(base, name)
            if not is_regular(path):
                continue
            st = target_stat(path)
            if not root_owned(st):
                continue
            if not writable_by_group_or_others(st):
                continue
            mode_oct = oct(st.st_mode & 0o777)
            findings.append({
                "path": path,
                "type": "file",
                "issue": "Writable cron job file (root-owned)",
                "severity": "High",
                "mode_octal": mode_oct,
                "exploitation": "Attacker can edit job definitions to run malicious commands as root.",
                "mitigation": "Set file permissions to 0644 root:root; ensure only privileged users can modify."
            })
    return findings

def scan_crontab_files():
    findings = []
    # System-wide /etc/crontab and /etc/cron.d entries
    for cf in CRONTAB_FILES + [ROOT_USER_CRONTAB]:
        if not os.path.isfile(cf):
            continue
        for line in read_lines(cf):
            if not line.strip() or line.strip().startswith("#"):
                continue
            # Choose parser based on file
            m = None
            if cf in ("/etc/crontab", "/etc/anacrontab"):
                m = SYSTEM_CRON_RE.match(line)
            elif cf == ROOT_USER_CRONTAB:
                m = USER_CRON_RE.match(line)
            else:
                m = None
            if not m:
                # Try generic /etc/cron.d style matching
                m = CROND_LINE_RE.match(line)
                if not m:
                    continue

            cmd = m.group("cmd")
            user = m.groupdict().get("user", "root" if cf == ROOT_USER_CRONTAB else "unknown")
            targets = extract_command_targets(cmd)
            risky_targets = []

            for t in targets:
                st = target_stat(t)
                if not st:
                    continue
                # Only flag root-owned writable targets
                if not root_owned(st):
                    continue
                if not writable_by_group_or_others(st):
                    continue
                risky_targets.append({
                    "target": t,
                    "mode_octal": oct(st.st_mode & 0o777),
                    "is_executable": is_executable(st),
                    "has_script_ext": has_script_ext(t)
                })

            if risky_targets:
                findings.append({
                    "source": cf,
                    "user": user,
                    "schedule": f"{m.group('m')} {m.group('h')} {m.group('dom')} {m.group('mon')} {m.group('dow')}",
                    "cmd": cmd.strip(),
                    "issue": "Cron job executes writable root-owned target(s)",
                    "severity": "High",
                    "targets": risky_targets,
                    "exploitation": "Writable cron targets allow command injection or binary replacement executed as root.",
                    "mitigation": "Lock down target file permissions to 0644/0755 root:root; do not reference writable paths in cron."
                })
    return findings

def run_scan():
    dir_findings = scan_cron_directories()
    job_findings = scan_crontab_files()
    all_findings = dir_findings + job_findings
    summary = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "count": len(all_findings),
        "high": sum(1 for f in all_findings if f["severity"] == "High"),
        "medium": sum(1 for f in all_findings if f["severity"] == "Medium"),
        "low": sum(1 for f in all_findings if f["severity"] == "Low"),
    }
    return {"summary": summary, "findings": all_findings}

def ensure_output_dir(path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)

def save_output(data: dict, path: str):
    ensure_output_dir(path)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def main():
    results = run_scan()
    save_output(results, OUTPUT_PATH)
    print(f"[+] Cron scan complete. Exploitable findings: {results['summary']['count']}")
    print(f"[+] Output written to: {OUTPUT_PATH}")

if __name__ == "__main__":
    main()

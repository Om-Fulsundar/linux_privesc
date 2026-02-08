#!/usr/bin/env python3
import os, re, json, stat
from datetime import datetime

OUTPUT_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "report", "output", "services_scan_output.json")

SUDOERS_MAIN = "/etc/sudoers"
SUDOERS_DIR  = "/etc/sudoers.d"
SYSTEMD_DIRS = ["/etc/systemd/system", "/lib/systemd/system"]

DANGEROUS_BASENAMES = {
    "vim","vi","nano",
    "bash","sh","zsh",
    "python","python3","perl","ruby",
    "find","less","more","tee",
    "tar","zip","unzip","rsync",
    "nmap","awk","sed",
    "openssl","gdb"
}

UNIT_EXTS_STRICT = {".service",".timer",".socket"}  # exploitable-priority

COMMENT_RE  = re.compile(r'^\s*(#|$)')
INCLUDE_RE  = re.compile(r'^\s*@?include(dir)?\b', re.IGNORECASE)
SUDO_ENTRY_RE = re.compile(r"""
    ^\s*
    (?P<subject>[%@]?\S+)           # user/group (rough but robust)
    \s+
    (?P<hosts>[^=]+?)
    \s*=\s*
    \((?P<runas>[^)]+)\)
    \s*
    (?P<options>(?:NOPASSWD|PASSWD))?:
    \s*
    (?P<cmds>.+)$
""", re.VERBOSE)

def read_lines(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.readlines()
    except Exception:
        return []

def normalize_cmd(cmd):
    return cmd.strip().split()[0]

def basename_is_dangerous(cmd):
    return os.path.basename(normalize_cmd(cmd)) in DANGEROUS_BASENAMES

def parse_sudoers_file(path):
    findings = []
    for line in read_lines(path):
        if COMMENT_RE.match(line) or INCLUDE_RE.match(line):
            continue
        m = SUDO_ENTRY_RE.match(line)
        if not m:
            continue
        options = (m.group("options") or "PASSWD").strip()
        if options != "NOPASSWD":
            continue  # strict: only NOPASSWD

        subject = m.group("subject").strip()
        runas   = m.group("runas").strip()
        cmds_raw = m.group("cmds").strip()
        cmds = [c.strip() for c in cmds_raw.split(",") if c.strip()]
        if any(c.upper() == "ALL" for c in cmds):
            findings.append({
                "source": path, "subject": subject, "runas": runas, "options": "NOPASSWD", "cmds": ["ALL"],
                "issue": "NOPASSWD ALL (any command as elevated)",
                "severity": "Critical",
                "exploitation": "Subject can execute arbitrary commands as runas without password; trivial root shell.",
                "mitigation": "Remove NOPASSWD or restrict to specific safe commands; enforce least privilege."
            })
            continue

        dangerous = [c for c in cmds if basename_is_dangerous(c)]
        if not dangerous:
            # Non-dangerous NOPASSWD entries can be Medium if you want; strict mode skips:
            continue

        findings.append({
            "source": path, "subject": subject, "runas": runas, "options": "NOPASSWD", "cmds": dangerous,
            "issue": "NOPASSWD for shell-escape capable command(s)",
            "severity": "High",
            "exploitation": f"Subject can run {', '.join(os.path.basename(normalize_cmd(c)) for c in dangerous)} as elevated without password; GTFOBins shell escape.",
            "mitigation": "Remove NOPASSWD or constrain to non-interactive, argument-locked commands."
        })
    return findings

def scan_sudoers():
    findings = []
    findings.extend(parse_sudoers_file(SUDOERS_MAIN))
    if os.path.isdir(SUDOERS_DIR):
        for name in sorted(os.listdir(SUDOERS_DIR)):
            p = os.path.join(SUDOERS_DIR, name)
            if os.path.isfile(p):
                findings.extend(parse_sudoers_file(p))
    return findings

def is_regular(path):
    try:
        return stat.S_ISREG(os.stat(path).st_mode)  # follow symlink
    except Exception:
        return False

def target_stat(path):
    try:
        return os.stat(path)  # follow symlink to real file
    except Exception:
        return None

def root_owned(st):
    return st and st.st_uid == 0

def writable_by_others_or_group(st):
    if not st: return False
    m = st.st_mode
    return bool(m & stat.S_IWOTH) or bool(m & stat.S_IWGRP)

def unit_is_strict_type(name):
    _, ext = os.path.splitext(name.lower())
    return ext in UNIT_EXTS_STRICT

def unit_exec_lines(text):
    lines = []
    for line in text.splitlines():
        l = line.strip()
        if l.startswith(("ExecStart=","ExecStartPre=","ExecStartPost=","ExecStop=","ExecReload=")):
            lines.append(l)
    return lines

def read_text(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""

def scan_systemd_units():
    findings = []
    seen = set()
    for base in SYSTEMD_DIRS:
        if not os.path.isdir(base):
            continue
        for root, _, files in os.walk(base, topdown=True, followlinks=False):
            for name in files:
                if not unit_is_strict_type(name):
                    continue
                path = os.path.join(root, name)
                if path in seen:
                    continue
                seen.add(path)

                if not is_regular(path):  # skip symlinks or non-regular
                    continue
                st = target_stat(path)
                if not root_owned(st):
                    continue
                if not writable_by_others_or_group(st):
                    continue  # strict: only writable units
                mode_oct = oct(st.st_mode & 0o777)

                text = read_text(path)
                execs = unit_exec_lines(text)

                findings.append({
                    "path": path,
                    "type": "systemd_unit",
                    "issue": "Writable systemd unit (root-owned)",
                    "severity": "High",
                    "mode_octal": mode_oct,
                    "exec_lines": execs[:6],
                    "exploitation": "Attacker can modify ExecStart/commands to run arbitrary code as root.",
                    "mitigation": "Set 0644 root:root; ensure unit files and drop-ins are not writable by unprivileged users."
                })
    return findings

def run_scan():
    sudo_findings = scan_sudoers()
    unit_findings = scan_systemd_units()
    all_findings = sudo_findings + unit_findings
    summary = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "count": len(all_findings),
        "critical": sum(1 for f in all_findings if f["severity"] == "Critical"),
        "high": sum(1 for f in all_findings if f["severity"] == "High"),
        "medium": sum(1 for f in all_findings if f["severity"] == "Medium"),
        "low": sum(1 for f in all_findings if f["severity"] == "Low"),
    }
    return {"summary": summary, "findings": all_findings}

def ensure_output_dir(p): os.makedirs(os.path.dirname(p), exist_ok=True)
def save_output(data, p):
    ensure_output_dir(p)
    with open(p, "w", encoding="utf-8") as f: json.dump(data, f, indent=2)

def main():
    results = run_scan()
    save_output(results, OUTPUT_PATH)
    print(f"[+] Services scan complete. Findings: {results['summary']['count']} (Critical: {results['summary']['critical']}, High: {results['summary']['high']})")
    print(f"[+] Output written to: {OUTPUT_PATH}")

if __name__ == "__main__":
    main()

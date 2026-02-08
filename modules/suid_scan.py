#!/usr/bin/env python3
import json
import os
import pwd
import grp
import stat
import subprocess
import shlex
from datetime import datetime
from typing import List, Dict, Optional, Tuple

# Paths we avoid traversing for performance/noise
PRUNE_DIRS = ["/proc", "/sys", "/dev", "/run", "/var/run", "/var/tmp", "/tmp/mnt"]

DATA_GTF0BINS = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "gtfobins.json")
OUTPUT_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "report", "output", "suid_scan_output.json")

def load_gtfobins(path: str) -> List[str]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            bins = data.get("binaries", [])
            # Normalize to basename (e.g., /usr/bin/vim -> vim)
            return [b.strip().lower() for b in bins if isinstance(b, str)]
    except FileNotFoundError:
        return []
    except Exception:
        return []

def _build_prune_expr() -> str:
    # Find prune expression: \( -path /proc -o -path /sys ... \) -prune -o ...
    parts = []
    for p in PRUNE_DIRS:
        parts.extend(["-path", shlex.quote(p)])
        parts.append("-o")
    if parts:
        parts = parts[:-1]  # remove last -o
    return "\\( " + " ".join(parts) + " \\) -prune -o " if parts else ""

def run_find_sbits() -> Tuple[List[str], List[str]]:
    """
    Returns (suid_paths, sgid_paths) using one find call each, limited to local fs.
    """
    prune = _build_prune_expr()
    base = f"find / -xdev {prune}"
    # SUID
    cmd_suid = base + "-type f -perm -4000 -print 2>/dev/null"
    # SGID
    cmd_sgid = base + "-type f -perm -2000 -print 2>/dev/null"
    suid = _safe_shell_list(cmd_suid)
    sgid = _safe_shell_list(cmd_sgid)
    return suid, sgid

def _safe_shell_list(cmd: str, timeout: int = 40) -> List[str]:
    try:
        out = subprocess.run(cmd, shell=True, check=False, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, text=True, timeout=timeout)
        lines = [l.strip() for l in out.stdout.splitlines() if l.strip()]
        # Deduplicate while preserving order
        seen, result = set(), []
        for l in lines:
            if l not in seen:
                seen.add(l)
                result.append(l)
        return result
    except subprocess.TimeoutExpired:
        return []
    except Exception:
        return []

def collect_capabilities(paths: List[str]) -> Dict[str, str]:
    """
    Batch capability collection using `getcap`. If unavailable, returns empty dict.
    """
    caps = {}
    if not paths:
        return caps
    # If getcap is missing, skip gracefully
    if subprocess.run(["which", "getcap"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
        return caps
    # getcap does not support passing multiple args safely for big lists; use -r and filter.
    try:
        out = subprocess.run(["getcap", "-r", "/"],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=40)
        for line in out.stdout.splitlines():
            line = line.strip()
            if " = " in line:
                path, cap = line.split(" = ", 1)
                if path in paths:
                    caps[path] = cap.strip()
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass
    return caps

def stat_info(path: str) -> Optional[Dict[str, str]]:
    try:
        st = os.lstat(path)
        mode = stat.S_IMODE(st.st_mode)
        perm_str = _perm_string(mode)
        owner = pwd.getpwuid(st.st_uid).pw_name
        group = grp.getgrgid(st.st_gid).gr_name
        return {
            "owner": owner,
            "group": group,
            "mode_octal": f"{mode:04o}",
            "permissions": perm_str,
        }
    except Exception:
        return None

def _perm_string(mode: int) -> str:
    # rwxrwxrwx style
    chars = []
    for who in (stat.S_IRUSR, stat.S_IWUSR, stat.S_IXUSR,
                stat.S_IRGRP, stat.S_IWGRP, stat.S_IXGRP,
                stat.S_IROTH, stat.S_IWOTH, stat.S_IXOTH):
        chars.append('r' if mode & who and 'R' in stat.filemode(mode)[1:] else '')
    # Simple: use stat.filemode for readability
    return stat.filemode(mode)

def assess_risk(path: str, info: Dict[str, str], capabilities: Optional[str], gtfobins: List[str],
                is_suid: bool, is_sgid: bool) -> Tuple[str, str]:
    base = os.path.basename(path).lower()
    # High if known GTFOBin and SUID or SGID
    if base in gtfobins and (is_suid or is_sgid):
        return ("High", f"{base} is a known privilege escalation binary with {'SUID' if is_suid else 'SGID'} bit set.")
    # Medium if world/group writable (dangerous with privilege bits)
    perms = info.get("permissions", "")
    mode_oct = info.get("mode_octal", "")
    if any(x in perms[-3:] for x in ['w']) or mode_oct.endswith(("2", "3", "6", "7")):
        return ("Medium", "Writable by group/others while having SUID/SGID set.")
    # Medium if capabilities are present (may allow escalation)
    if capabilities:
        return ("Medium", f"Has Linux capabilities: {capabilities}")
    # Low default
    return ("Low", "Privilege bit set but no known exploit indicators detected.")

def find_entries(paths: List[str], gtfobins: List[str], caps_map: Dict[str, str], label: str) -> List[Dict]:
    results = []
    for p in paths:
        info = stat_info(p)
        if not info:
            continue
        capabilities = caps_map.get(p)
        sev, rationale = assess_risk(
            p, info, capabilities, gtfobins,
            is_suid=(label == "SUID"),
            is_sgid=(label == "SGID")
        )
        results.append({
            "path": p,
            "binary": os.path.basename(p),
            "owner": info["owner"],
            "group": info["group"],
            "permissions": info["permissions"],
            "mode_octal": info["mode_octal"],
            "type": label,
            "capabilities": capabilities or "",
            "severity": sev,
            "rationale": rationale,
            "mitigation": mitigation_for(label, sev)
        })
    return results

def mitigation_for(label: str, severity: str) -> str:
    if severity == "High":
        return "Evaluate necessity; remove SUID/SGID bit or replace with safer alternative. Restrict access and monitor."
    if severity == "Medium":
        return "Harden permissions; ensure non-root ownership; consider removing privilege bits. Audit capabilities."
    return "Review necessity periodically; keep package updated; monitor for changes."

def run_scan() -> Dict:
    gtfobins = load_gtfobins(DATA_GTF0BINS)
    suid_paths, sgid_paths = run_find_sbits()
    # Batch capabilities once; filter by discovered paths
    caps_map = collect_capabilities(suid_paths + sgid_paths)

    suid_results = find_entries(suid_paths, gtfobins, caps_map, "SUID")
    sgid_results = find_entries(sgid_paths, gtfobins, caps_map, "SGID")

    summary = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "counts": {
            "suid": len(suid_results),
            "sgid": len(sgid_results),
            "high": sum(1 for r in suid_results + sgid_results if r["severity"] == "High"),
            "medium": sum(1 for r in suid_results + sgid_results if r["severity"] == "Medium"),
            "low": sum(1 for r in suid_results + sgid_results if r["severity"] == "Low"),
        }
    }

    return {
        "summary": summary,
        "findings": suid_results + sgid_results
    }

def ensure_output_dir(path: str) -> None:
    out_dir = os.path.dirname(path)
    os.makedirs(out_dir, exist_ok=True)

def save_output(data: Dict, path: str) -> None:
    ensure_output_dir(path)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def main():
    results = run_scan()
    save_output(results, OUTPUT_PATH)
    print(f"[+] SUID/SGID scan complete. Findings: {results['summary']['counts']}.")
    print(f"[+] Output written to: {OUTPUT_PATH}")

if __name__ == "__main__":
    main()
    
  

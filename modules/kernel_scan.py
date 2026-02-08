#!/usr/bin/env python3
import os
import re
import json
import platform
import argparse
from datetime import datetime

OUTPUT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "report", "output", "kernel_scan_output.json"
)

# =========================
# Version helpers
# =========================

def parse_kernel_version(ver: str):
    """
    Parse Linux kernel version string into a comparable 4-tuple of ints.
    E.g., "6.6.7-parrot1-amd64" -> (6, 6, 7, 0)
    """
    base = ver.split("-")[0]
    parts = base.split(".")
    nums = []
    for p in parts:
        m = re.match(r"(\d+)", p)
        nums.append(int(m.group(1)) if m else 0)
    while len(nums) < 4:
        nums.append(0)
    return tuple(nums[:4])

def version_ge(a, b): return a >= b
def version_le(a, b): return a <= b
def version_lt(a, b): return a < b
def version_gt(a, b): return a > b

def kernel_is_rc(ver_str: str):
    return "-rc" in ver_str

# =========================
# Curated CVE Database
# =========================
# Notes:
# - Ranges are conservative to avoid false positives.
# - Some distros backport fixes; we mark all matches with "confidence: version_match".
# - Medium severity entries are context-dependent; shown only in verbose mode.

CVE_DB = [
    # DirtyPipe (CVE-2022-0847)
    {
        "cve": "CVE-2022-0847",
        "name": "DirtyPipe",
        "ranges": [
            {"min": (5, 8, 0, 0), "max": (5, 16, 11, 0), "end_exclusive": True},
            {"min": (5, 17, 0, 0), "max": (5, 17, 0, 0), "is_rc": True}
        ],
        "severity": "High",
        "exploitation": "Local users can overwrite cached file data to escalate to root.",
        "mitigation": "Upgrade to 5.16.11+ or 5.17.1+; ensure vendor patches applied."
    },
    # DirtyCow (CVE-2016-5195)
    {
        "cve": "CVE-2016-5195",
        "name": "DirtyCow",
        "ranges": [{"min": (2, 6, 22, 0), "max": (3, 9, 0, 0)}],
        "severity": "High",
        "exploitation": "Race in copy-on-write allows modification of read-only mappings → root.",
        "mitigation": "Use patched kernels beyond conservative cutoff or confirm backports."
    },
    # Overlayfs privesc (CVE-2015-8660)
    {
        "cve": "CVE-2015-8660",
        "name": "Overlayfs privilege escalation",
        "ranges": [{"min": (3, 18, 0, 0), "max": (4, 4, 0, 0)}],
        "severity": "High",
        "exploitation": "Faulty permission handling enables escalation via crafted overlay mounts.",
        "mitigation": "Upgrade; restrict unprivileged user namespaces if possible."
    },
    # eBPF verifier bugs (CVE-2021-3490)
    {
        "cve": "CVE-2021-3490",
        "name": "eBPF privilege escalation",
        "ranges": [{"min": (5, 7, 0, 0), "max": (5, 12, 14, 0), "end_exclusive": True}],
        "severity": "High",
        "exploitation": "BPF verifier bug enables arbitrary kernel memory write/ROP.",
        "mitigation": "Upgrade; set kernel.unprivileged_bpf_disabled=1 to reduce exposure."
    },
    # eBPF type confusion (CVE-2020-8835)
    {
        "cve": "CVE-2020-8835",
        "name": "eBPF verifier type confusion",
        "ranges": [{"min": (4, 14, 0, 0), "max": (5, 5, 19, 0), "end_exclusive": True}],
        "severity": "High",
        "exploitation": "Type confusion in verifier permits kernel code execution.",
        "mitigation": "Upgrade; disable unprivileged BPF where feasible."
    },
    # Overlayfs recent (CVE-2023-0386)
    {
        "cve": "CVE-2023-0386",
        "name": "Overlayfs copy-up bug",
        "ranges": [{"min": (5, 15, 0, 0), "max": (6, 3, 0, 0), "end_exclusive": True}],
        "severity": "High",
        "exploitation": "Overlayfs copy-up mishandling allows privilege escalation.",
        "mitigation": "Upgrade to 6.3+ or patched vendor kernels."
    },
    # AF_PACKET race condition (CVE-2016-8655)
    {
        "cve": "CVE-2016-8655",
        "name": "AF_PACKET race condition",
        "ranges": [{"min": (3, 2, 0, 0), "max": (4, 8, 14, 0), "end_exclusive": True}],
        "severity": "High",
        "exploitation": "Race in packet_set_ring leads to kernel R/W → root.",
        "mitigation": "Upgrade; restrict CAP_NET_RAW for unprivileged users."
    },
    # Keyring refcount (CVE-2016-0728)
    {
        "cve": "CVE-2016-0728",
        "name": "Keyring refcount overflow",
        "ranges": [{"min": (3, 8, 0, 0), "max": (4, 4, 0, 0)}],
        "severity": "High",
        "exploitation": "Keyring bug enables code execution in kernel context.",
        "mitigation": "Upgrade to fixed kernels or verify vendor backports."
    },
    # perf_event (CVE-2013-2094)
    {
        "cve": "CVE-2013-2094",
        "name": "perf_event local root",
        "ranges": [{"min": (2, 6, 39, 0), "max": (3, 8, 9, 0)}],
        "severity": "High",
        "exploitation": "perf_event allows arbitrary write into kernel memory.",
        "mitigation": "Upgrade; disable perf for unprivileged users."
    },
    # DirtyCred (CVE-2022-2588) — context dependent, keep Medium
    {
        "cve": "CVE-2022-2588",
        "name": "DirtyCred (Netfilter UAF)",
        "ranges": [{"min": (5, 4, 0, 0), "max": (5, 19, 2, 0), "end_exclusive": True}],
        "severity": "Medium",
        "exploitation": "Use-after-free in Netfilter enables credential reuse for root.",
        "mitigation": "Update kernel; reduce unprivileged Netfilter exposure."
    },
    # io_uring representative (keep Medium to avoid overclaims)
    {
        "cve": "CVE-2021-4104",
        "name": "io_uring privilege escalation (representative)",
        "ranges": [{"min": (5, 1, 0, 0), "max": (5, 15, 0, 0)}],
        "severity": "Medium",
        "exploitation": "Multiple io_uring bugs historically allowed kernel access.",
        "mitigation": "Upgrade; limit unprivileged io_uring if configurable."
    },
    # pkexec (userland, not kernel) — Medium, contextual
    {
        "cve": "CVE-2021-4034",
        "name": "Polkit pkexec overflow (userland)",
        "ranges": [{"min": (2, 6, 0, 0), "max": (6, 99, 99, 99)}],
        "severity": "Medium",
        "exploitation": "Argument handling leads to root; depends on polkit version, not kernel.",
        "mitigation": "Update polkit; remove SUID from pkexec if policy permits."
    },
]

# =========================
# Matching logic
# =========================

def range_matches(kver_tuple, kver_str, r):
    if r.get("is_rc"):
        return kernel_is_rc(kver_str) and kver_tuple[:3] == r["min"][:3]
    minv = r["min"]
    maxv = r["max"]
    if r.get("end_exclusive"):
        return version_ge(kver_tuple, minv) and version_lt(kver_tuple, maxv)
    return version_ge(kver_tuple, minv) and version_le(kver_tuple, maxv)

def match_cve(kver_tuple, kver_str, cve_entry):
    return any(range_matches(kver_tuple, kver_str, r) for r in cve_entry["ranges"])

def build_finding(cve_entry):
    return {
        "cve": cve_entry["cve"],
        "name": cve_entry["name"],
        "severity": cve_entry["severity"],
        "issue": f"Kernel version falls in vulnerable range for {cve_entry['name']}",
        "exploitation": cve_entry["exploitation"],
        "mitigation": cve_entry["mitigation"],
        "confidence": "version_match"
    }

# =========================
# Scanner
# =========================

def scan_kernel(verbose: bool = False):
    findings = []
    kver_str = platform.release()
    kver = parse_kernel_version(kver_str)
    arch = platform.machine()

    for cve in CVE_DB:
        # In strict mode: include only High severity. In verbose: include Medium too.
        if not verbose and cve["severity"] != "High":
            continue
        if match_cve(kver, kver_str, cve):
            findings.append(build_finding(cve))

    # Sort by severity (High first) then CVE
    severity_rank = {"High": 0, "Medium": 1, "Low": 2}
    findings.sort(key=lambda f: (severity_rank.get(f["severity"], 9), f["cve"]))

    summary = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "kernel": kver_str,
        "kernel_tuple": list(kver),
        "arch": arch,
        "count": len(findings),
        "high": sum(1 for f in findings if f["severity"] == "High"),
        "medium": sum(1 for f in findings if f["severity"] == "Medium"),
        "low": sum(1 for f in findings if f["severity"] == "Low"),
        "mode": "verbose" if verbose else "strict"
    }
    return {"summary": summary, "findings": findings}

# =========================
# I/O
# =========================

def ensure_output_dir(path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)

def save_output(data: dict, path: str):
    ensure_output_dir(path)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

# =========================
# CLI / entrypoint
# =========================

def main():
    parser = argparse.ArgumentParser(description="Kernel CVE scanner (curated, strict by default).")
    parser.add_argument("--verbose", action="store_true", help="Include Medium findings (context-dependent CVEs).")
    args = parser.parse_args()

    results = scan_kernel(verbose=args.verbose)
    save_output(results, OUTPUT_PATH)
    print(f"[+] Kernel CVE scan complete. Findings: {results['summary']['count']} (High: {results['summary']['high']}, Medium: {results['summary']['medium']})")
    print(f"[+] Output written to: {OUTPUT_PATH}")

if __name__ == "__main__":
    main()

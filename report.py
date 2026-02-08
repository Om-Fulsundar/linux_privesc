#!/usr/bin/env python3
import os
import json
from datetime import datetime

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "report", "output")
FINAL_REPORT = os.path.join(OUTPUT_DIR, "final_report.txt")

COLORS = {
    "HEADER": "\033[95m",
    "OKBLUE": "\033[94m",
    "OKCYAN": "\033[96m",
    "OKGREEN": "\033[92m",
    "WARNING": "\033[93m",
    "FAIL": "\033[91m",
    "ENDC": "\033[0m",
    "BOLD": "\033[1m",
    "UNDERLINE": "\033[4m"
}

def load_json_files():
    reports = {}
    for fname in os.listdir(OUTPUT_DIR):
        if fname.endswith("_output.json"):
            path = os.path.join(OUTPUT_DIR, fname)
            with open(path, "r", encoding="utf-8") as f:
                reports[fname.replace("_output.json", "")] = json.load(f)
    return reports

def summarize(reports):
    summary = {
        "total_findings": 0,
        "high": 0,
        "medium": 0,
        "low": 0
    }
    for module, data in reports.items():
        s = data.get("summary", {})
        counts = s.get("counts", {})

        if module == "suid_scan":
            summary["total_findings"] += counts.get("suid", 0) + counts.get("sgid", 0)
            summary["high"] += counts.get("high", s.get("high", 0))
            summary["medium"] += counts.get("medium", s.get("medium", 0))
            summary["low"] += counts.get("low", s.get("low", 0))
        else:
            summary["total_findings"] += s.get("count", 0)
            summary["high"] += s.get("high", 0)
            summary["medium"] += s.get("medium", 0)
            summary["low"] += s.get("low", 0)
    return summary

def print_report(reports, summary):
    print(COLORS["HEADER"] + COLORS["BOLD"] + "\n=== Linux PrivEsc Toolkit Final Report ===\n" + COLORS["ENDC"])
    print(f"Generated: {datetime.utcnow().isoformat()}Z\n")

    print(COLORS["BOLD"] + "Overall Findings:" + COLORS["ENDC"])
    print(f"  Total Findings: {summary['total_findings']}")
    print(COLORS['FAIL'] + f"  High: {summary['high']}" + COLORS['ENDC'])
    print(COLORS['WARNING'] + f"  Medium: {summary['medium']}" + COLORS['ENDC'])
    print(COLORS['OKBLUE'] + f"  Low: {summary['low']}" + COLORS['ENDC'])
    print("\n")

    for module, data in reports.items():
        print(COLORS["BOLD"] + f"[{module.upper()}]" + COLORS["ENDC"])
        s = data.get("summary", {})
        counts = s.get("counts", {})

        if module == "suid_scan":
            suid_count = counts.get("suid", 0)
            sgid_count = counts.get("sgid", 0)
            print(f"  SUID Findings: {suid_count}")
            print(f"  SGID Findings: {sgid_count}")
            print(f"  Severity -> High: {counts.get('high', 0)}, Medium: {counts.get('medium', 0)}, Low: {counts.get('low', 0)}")
        else:
            print(f"  Findings: {s.get('count', 0)} (High: {s.get('high', 0)}, Medium: {s.get('medium', 0)}, Low: {s.get('low', 0)})")

        if "findings" in data and data["findings"]:
            for f in data["findings"][:5]:
                sev_color = COLORS['FAIL'] if f.get("severity") == "High" else COLORS['WARNING'] if f.get("severity") == "Medium" else COLORS['OKBLUE']
                label = f.get("path") or f.get("issue") or f.get("cve") or f.get("binary") or "Unknown"
                print(sev_color + f"    - {label} ({f.get('severity','Unknown')})" + COLORS['ENDC'])
        else:
            print("    No exploitable findings.")
        print("\n")

def save_text_report(reports, summary):
    with open(FINAL_REPORT, "w", encoding="utf-8") as f:
        f.write("=== Linux PrivEsc Toolkit Final Report ===\n")
        f.write(f"Generated: {datetime.utcnow().isoformat()}Z\n\n")
        f.write("Overall Findings:\n")
        f.write(f"  Total Findings: {summary['total_findings']}\n")
        f.write(f"  High: {summary['high']}\n")
        f.write(f"  Medium: {summary['medium']}\n")
        f.write(f"  Low: {summary['low']}\n\n")

        for module, data in reports.items():
            f.write(f"[{module.upper()}]\n")
            s = data.get("summary", {})
            counts = s.get("counts", {})

            if module == "suid_scan":
                suid_count = counts.get("suid", 0)
                sgid_count = counts.get("sgid", 0)
                f.write(f"  SUID Findings: {suid_count}\n")
                f.write(f"  SGID Findings: {sgid_count}\n")
                f.write(f"  Severity -> High: {counts.get('high', 0)}, Medium: {counts.get('medium', 0)}, Low: {counts.get('low', 0)}\n")
            else:
                f.write(f"  Findings: {s.get('count', 0)} (High: {s.get('high', 0)}, Medium: {s.get('medium', 0)}, Low: {s.get('low', 0)})\n")

            if "findings" in data and data["findings"]:
                for fnd in data["findings"][:5]:
                    label = fnd.get("path") or fnd.get("issue") or fnd.get("cve") or fnd.get("binary") or "Unknown"
                    f.write(f"    - {label} ({fnd.get('severity','Unknown')})\n")
            else:
                f.write("    No exploitable findings.\n")
            f.write("\n")

def main():
    reports = load_json_files()
    summary = summarize(reports)
    print_report(reports, summary)
    save_text_report(reports, summary)
    print(COLORS["OKGREEN"] + f"[+] Final report saved to {FINAL_REPORT}" + COLORS["ENDC"])

if __name__ == "__main__":
    main()

# Linux Privilege Escalation Toolkit

## Overview
This toolkit automates the process of scanning Linux systems for privilege escalation opportunities. It focuses on detection only—no exploits are executed. The goal is to identify misconfigurations, weak permissions, and exploitable binaries using real-world techniques from penetration testing and security auditing.

## Features
- **SUID/SGID Binary Discovery**: Detects binaries with special permission bits and flags risky ones.  
- **Weak Permission Detection**: Finds world-writable files, misconfigured directories, and insecure service scripts.  
- **Service Misconfiguration Checks**: Identifies systemd services and sudo rules that may allow escalation.  
- **Cron Job Analysis**: Detects writable scripts executed by root and highlights timing-based risks.  
- **Kernel Vulnerability Awareness**: Matches kernel version against known CVEs and flags outdated versions.  

## Workflow
1. Run `main.py` to execute all scanning modules.  
2. Each module generates a JSON output in the `report/output/` directory.  
3. `report.py` consolidates findings and produces a final text report.  
4. Results are printed to the terminal and saved as `final_report.txt`.  

## Tech Stack
- **Language**: Python 3  
- **Linux Utilities**: `find`, `ls`, `systemctl`, `getcap`, `sudo -l`, `crontab`, `uname`, `grep`, `awk`, `sed`  

## Repository Structure
```
linux_privesc/
│── .gitignore
│── main.py
│── report.py
│
├── modules/
│   ├── suid_scan.py
│   ├── perms_scan.py
│   ├── services_scan.py
│   ├── cron_scan.py
│   └── kernel_scan.py
│
└── report/                        # it will create once you run the tool
│    └── output/
│        ├── suid_scan_output.json
│        ├── perms_scan_output.json
│        ├── services_scan_output.json
│        ├── cron_scan_output.json
│        ├── kernel_scan_output.json
│        └── final_report.txt     
│
└── docs/
    └── screenshots/
    └── linux privesc diagram    # flowchart and workflow diagram
    └── linux-privesc ppt
    └── Linux Privesc doc
```

## Usage
Clone the repository and run the main script:
```bash
git clone https://github.com/Om-Fulsundar/linux_privesc.git
cd linux_privesc
python3 main.py
```

Reports and outputs will be available in:
```
report/output/
```

## Limitations
- **Detection Only**: The toolkit does not attempt exploitation or privilege escalation; it only flags potential vectors.  
- **Static Analysis**: Relies on file system and service inspection, not runtime behavior.  
- **Local Execution**: Must be run on the target system; no remote scanning support.  
- **Kernel CVE Matching**: Based on static kernel version checks, may miss patched or custom builds.  

## Future Improvements
- **Exploit Suggestion Engine**: Integrate GTFOBins mappings or PoCs for flagged binaries.  
- **Live Process Analysis**: Inspect running processes and privileges.  
- **Network PrivEsc Checks**: Extend scanning to NFS, Docker, SSH misconfigs.  

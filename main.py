#!/usr/bin/env python3
# script by Om Fulsundar (https://github.com/Om-Fulsundar)


import importlib
import sys
import subprocess

def run_module(mod_name: str):
    try:
        mod = importlib.import_module(mod_name)
        if hasattr(mod, "main"):
            mod.main()
            return True
        print(f"[!] Module {mod_name} has no main()")
        return False
    except Exception as e:
        print(f"[!] Error running {mod_name}: {e}")
        return False

def main():
    print("[*] Toolkit initialized.")

    ok = run_module("modules.suid_scan")
    if not ok:
        sys.exit(1)

    ok = run_module("modules.perms_scan")
    if not ok:
        sys.exit(1)
    
    ok = run_module("modules.services_scan")
    if not ok:
        sys.exit(1)
        
    ok = run_module("modules.cron_scan")
    if not ok:
        sys.exit(1)
        
    ok = run_module("modules.kernel_scan")
    if not ok:
        sys.exit(1)
        
    print("[*] All modules completed successfully.")
    print("\n[+] Generating consolidated final report...\n")
    subprocess.run(["python3", "report.py"])



if __name__ == "__main__":
    main()
 

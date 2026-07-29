#!/usr/bin/env python3
"""
Aegis Vanguard Agent Healthcheck

Verifies all security tools are installed and the ASM bridge is configured.
Run with --quick for a fast binary-only check (used by Docker HEALTHCHECK),
or without flags for a full report.
"""

import os
import shutil
import sys
import json

CORE_TOOLS = [
    ("subfinder",    "Subdomain enumeration"),
    ("dnsx",         "DNS resolution"),
    ("naabu",        "Port scanning"),
    ("httpx",        "HTTP probing"),
    ("nuclei",       "Vulnerability scanning"),
    ("katana",       "Web crawling"),
    ("tlsx",         "TLS analysis"),
]

EXTENDED_TOOLS = [
    ("amass",        "Subdomain enumeration (alt)"),
    ("nmap",         "Service detection"),
    ("masscan",      "Fast port scanning"),
    ("nikto",        "Web server scanner"),
    ("sqlmap",       "SQL injection testing"),
    ("whatweb",      "Technology fingerprinting"),
    ("wafw00f",      "WAF detection"),
    ("testssl.sh",   "SSL/TLS testing"),
    ("sslyze",       "SSL/TLS analysis"),
    ("waybackurls",  "Historical URL discovery"),
    ("gau",          "URL aggregation"),
    ("ffuf",         "Directory fuzzing"),
    ("arjun",        "Parameter discovery"),
    ("gitleaks",     "Secret scanning"),
    ("wpscan",       "WordPress scanning"),
]

PATH_TOOLS = [
    ("/opt/xsstrike/xsstrike.py",  "XSS detection (XSStrike)"),
    ("/opt/cmseek/cmseek.py",      "CMS detection (CMSeeK)"),
]


def check_tools(quick=False):
    results = {"core": [], "extended": [], "path": [], "bridge": {}}
    all_ok = True

    for name, desc in CORE_TOOLS:
        found = shutil.which(name) is not None
        results["core"].append({"tool": name, "description": desc, "installed": found})
        if not found:
            all_ok = False

    if not quick:
        for name, desc in EXTENDED_TOOLS:
            found = shutil.which(name) is not None
            results["extended"].append({"tool": name, "description": desc, "installed": found})
            if not found:
                all_ok = False

        for path, desc in PATH_TOOLS:
            found = os.path.exists(path)
            results["path"].append({"path": path, "description": desc, "installed": found})
            if not found:
                all_ok = False

    api_url = os.environ.get("ASM_API_URL", "")
    api_key = os.environ.get("ASM_API_KEY", "")
    agent_id = os.environ.get("ASM_AGENT_ID", "")
    results["bridge"] = {
        "api_url_set": bool(api_url),
        "api_key_set": bool(api_key),
        "agent_id": agent_id or "(default)",
    }

    return results, all_ok


def print_report(results, all_ok):
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    print(f"\n{BOLD}Aegis Vanguard Agent - Tool Inventory{RESET}\n")

    print(f"{BOLD}Core Tools (required):{RESET}")
    for t in results["core"]:
        icon = f"{GREEN}OK{RESET}" if t["installed"] else f"{RED}MISSING{RESET}"
        print(f"  [{icon}] {t['tool']:16s} {t['description']}")

    if results["extended"]:
        print(f"\n{BOLD}Extended Tools (recommended):{RESET}")
        for t in results["extended"]:
            icon = f"{GREEN}OK{RESET}" if t["installed"] else f"{YELLOW}MISSING{RESET}"
            print(f"  [{icon}] {t['tool']:16s} {t['description']}")

    if results["path"]:
        print(f"\n{BOLD}Path-based Tools:{RESET}")
        for t in results["path"]:
            icon = f"{GREEN}OK{RESET}" if t["installed"] else f"{YELLOW}MISSING{RESET}"
            print(f"  [{icon}] {t['path']:40s} {t['description']}")

    b = results["bridge"]
    print(f"\n{BOLD}ASM Bridge Configuration:{RESET}")
    print(f"  API URL:    {'set' if b['api_url_set'] else RED + 'NOT SET' + RESET}")
    print(f"  API Key:    {'set' if b['api_key_set'] else RED + 'NOT SET' + RESET}")
    print(f"  Agent ID:   {b['agent_id']}")

    core_count = sum(1 for t in results["core"] if t["installed"])
    ext_count = sum(1 for t in results.get("extended", []) if t["installed"])
    path_count = sum(1 for t in results.get("path", []) if t["installed"])
    total = core_count + ext_count + path_count
    expected = len(results["core"]) + len(results.get("extended", [])) + len(results.get("path", []))
    print(f"\n{BOLD}Summary:{RESET} {total}/{expected} tools installed", end="")
    if all_ok:
        print(f" {GREEN}ALL OK{RESET}")
    else:
        print(f" {RED}SOME MISSING{RESET}")
    print()


def main():
    quick = "--quick" in sys.argv
    json_out = "--json" in sys.argv

    results, all_ok = check_tools(quick=quick)

    if json_out:
        print(json.dumps(results, indent=2))
    elif quick:
        if not all_ok:
            missing = [t["tool"] for t in results["core"] if not t["installed"]]
            print(f"UNHEALTHY: missing core tools: {', '.join(missing)}", file=sys.stderr)
            sys.exit(1)
        print("OK")
    else:
        print_report(results, all_ok)

    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()

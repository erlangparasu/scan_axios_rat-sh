# scan_axios_rat-sh

# Axios Supply Chain Threat Scanner

[![Bash](https://img.shields.io/badge/Script-Bash-4EAA25?logo=gnu-bash&logoColor=white)](#)
[![Status](https://img.shields.io/badge/Status-Incident_Response-red)](#)

A lightweight, zero-dependency incident response script designed to detect the `axios` + `plain-crypto-js` supply chain attack. 

In late March 2026, compromised npm credentials belonging to an Axios maintainer were used to publish malicious packages (`axios@1.14.1` and `axios@0.30.4`). These packages injected a hidden dependency (`plain-crypto-js@4.2.1`), which utilizes a post-install script to drop a Remote Access Trojan (RAT) tailored to the host operating system.

Because the malware dropper cleans up its own manifest post-infection, standard tools like `npm audit` may fail to detect the compromise. This script performs a hard scan of your repository manifests and checks local system paths for known Indicators of Compromise (IOCs).

## Features

1. **Manifest & Lockfile Scanning:** Uses regex to hunt for compromised versions across `package.json`, `package-lock.json`, `yarn.lock`, and `pnpm-lock.yaml`.
2. **System-Level IOC Detection:** Checks for the presence of the dropped RAT payloads based on the host operating system:
   - **macOS:** `/Library/Caches/com.apple.act.mond`
   - **Linux:** `/tmp/ld.py`
   - **Windows (Bash environments):** `C:/ProgramData/wt`
3. **CI/CD Ready:** Fails fast with a non-zero exit code (`exit 1`) if any vulnerabilities or IOCs are detected, making it safe to drop into automated pipelines.

## Usage

Download and make executable:**

```bash
chmod +x scan_axios_rat.sh
```

Run against the current directory:
Bash

```bash
./scan_axios_rat.sh
```

Run against a specific path (e.g., a monorepo or build server workspace):
Bash

```bash
./scan_axios_rat.sh /path/to/your/workspace
```

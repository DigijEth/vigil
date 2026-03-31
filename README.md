# Vigil — Anti-Surveillance Shield

**KernelSU-Next / Magisk / APatch module for journalists, activists, and at-risk users.**

Vigil detects stalkerware, government spyware (Pegasus, Predator, Hermit), forensic extraction tools (Cellebrite UFED), silent SMS tracking, and IMSI catchers. It provides real-time protection with file integrity monitoring, encryption key eviction, and network-level threat blocking.

Developed by **Setec Labs**.

---

## Features

### Threat Scanner
- Scans installed packages, signing certificates, APK hashes, running processes, accessibility services, and device admins against a curated IOC database
- 11,000+ indicators sourced from CitizenLab, MVT, EFF, Meta Threat Research, and stalkerware-indicators
- Detects Pegasus, Predator, Hermit, Chrysaor, commercial stalkerware, and trojans

### FrostGuard — File Integrity Monitor
- SHA256 baseline of system partitions, boot images, and critical binaries
- Continuous monitoring for unauthorized modifications
- Heuristic detection: SUID anomalies, staging directory implants, SELinux tampering, injection frameworks
- Pseudo-locked-bootloader protection for rooted devices

### Key Wiper / BFU Mode
- Evicts FBE (File-Based Encryption) credential keys from memory
- Moves the device to a "Before First Unlock" equivalent state
- Runs TRIM to prevent NAND flash recovery of deleted data
- Disables ADB, developer settings, and minimizes system logging
- Effectively defeats AFU-mode forensic extraction

### Forensic Shield
- Real-time USB monitoring for forensic tool staging
- 71 known Cellebrite UFED binary hashes
- Exploit binary name detection (dirtycow, zergRush, pingroot, etc.)
- Frida injection detection
- Automatic lockdown on forensic tool detection (opt-in)

### SMS Shield
- Detects Type-0 (silent) and Class-0 (flash) SMS pings used for location tracking
- Monitors RIL/telephony layer via logcat with root access
- WAP Push and binary SMS detection
- Optional delivery receipt suppression

### Network Monitor
- Hosts-based domain blocking (4,400+ C2 and tracker domains)
- iptables IP blocking (139+ known malicious IPs)
- Live connection monitoring against threat indicators
- DNS resolution watchdog

---

## Installation

Flash the ZIP via KernelSU-Next, Magisk, or APatch manager.

Requires:
- Android 9+ (API 28)
- Root access (KernelSU-Next, Magisk, or APatch)

## Usage

```sh
# Show protection status
vigil status

# Run full threat scan
vigil scan

# Run quick scan (packages + processes only)
vigil scan quick

# Enter BFU lockdown mode
vigil lockdown

# Check file integrity
vigil integrity verify

# Create new integrity baseline
vigil integrity baseline

# View alerts
vigil alerts

# Forensic shield scan
vigil forensic scan

# SMS shield status
vigil sms status

# Start SMS monitoring
vigil sms monitor

# Install/update network blocklists
vigil network install

# Update threat indicators
vigil update-ioc

# View logs
vigil log
```

## Configuration

Edit `/data/adb/vigil/vigil.conf` on the device. Key settings:

| Setting | Default | Description |
|---------|---------|-------------|
| `SCANNER_INTERVAL` | 3600 | Seconds between automatic scans |
| `FROSTGUARD_ENABLED` | 1 | File integrity monitoring |
| `FORENSIC_AUTO_LOCKDOWN` | 0 | Auto-lockdown on forensic tool detection |
| `SMS_BLOCK_SILENT` | 1 | Block silent SMS delivery receipts |
| `NETWORK_BLOCK_C2` | 1 | Block known C2 domains |
| `KEYWIPER_TRIM_ON_LOCKDOWN` | 1 | TRIM storage on lockdown |
| `VIGIL_BACKEND_URL` | (empty) | Reporting server URL |

## Threat Indicator Sources

- [CitizenLab Malware Indicators](https://github.com/citizenlab/malware-indicators)
- [AssoEchap Stalkerware Indicators](https://github.com/AssoEchap/stalkerware-indicators)
- [MVT — Mobile Verification Toolkit](https://github.com/mvt-project/mvt)
- [Meta Threat Research](https://github.com/facebook/threat-research)
- [EFF Rayhunter](https://github.com/EFForg/rayhunter)
- [Lockup Anti-Forensics](https://github.com/levlesec/lockup)
- [Costin Raiu Mobile Trackers](https://github.com/craiu/mobiletrackers)
- [Palo Alto Unit42](https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel)

## Architecture

```
vigil/
├── module.prop              # KernelSU/Magisk module metadata
├── customize.sh             # Installation script
├── service.sh               # Boot service (starts vigild)
├── post-fs-data.sh          # Early boot (integrity check, lockdown enforcement)
├── vigil/
│   ├── bin/
│   │   ├── vigil            # CLI interface
│   │   └── vigild           # Main daemon
│   ├── config/
│   │   ├── vigil.conf       # Default configuration
│   │   └── exclusions.conf  # User exclusions
│   ├── ioc/                 # Threat indicator database
│   └── lib/
│       ├── scanner.sh       # Threat scanner engine
│       ├── integrity.sh     # FrostGuard file integrity
│       ├── key_wiper.sh     # BFU mode / key eviction
│       ├── forensic_shield.sh  # Anti-Cellebrite
│       ├── sms_shield.sh    # Silent SMS detection
│       └── network_monitor.sh  # C2/tracker blocking
└── tools/
    └── build_ioc_db.py      # IOC database builder
```

## License

Copyright (c) 2025 Setec Labs. All rights reserved.

## Disclaimer

This tool is intended for defensive security use by journalists, activists, human rights defenders, and security researchers. It is designed to detect and defend against unauthorized surveillance. Use responsibly and in accordance with applicable laws.

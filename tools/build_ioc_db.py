#!/usr/bin/env python3
"""
Vigil IOC Database Builder
Extracts Indicators of Compromise from research repositories and writes
unified indicator files for the Vigil anti-surveillance module.
"""

import csv
import io
import os
import re
import sys
from collections import OrderedDict

RESEARCH = "/home/snake/research/repos"
OUT_DIR = "/home/snake/vigil/vigil/ioc"

os.makedirs(OUT_DIR, exist_ok=True)

# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────

def dedup_sorted(lines):
    """Return sorted, deduplicated list (case-sensitive)."""
    return sorted(set(l for l in lines if l.strip()))


def write_ioc(filename, lines, header=""):
    path = os.path.join(OUT_DIR, filename)
    lines = dedup_sorted(lines)
    with open(path, "w") as f:
        if header:
            f.write(header + "\n")
        for line in lines:
            f.write(line + "\n")
    return len(lines)


def read_file(path):
    if not os.path.isfile(path):
        return ""
    with open(path, "r", errors="replace") as f:
        return f.read()


# ──────────────────────────────────────────────────────────────────────
# YAML parser (no pyyaml dependency -- simple state-machine parser)
# Parses stalkerware-indicators/ioc.yaml
# ──────────────────────────────────────────────────────────────────────

def parse_stalkerware_yaml(path):
    """
    Parse the stalkerware-indicators ioc.yaml which has a known structure:
    - name: ThreatName
      type: stalkerware
      packages:
      - com.example.pkg
      certificates:
      - DEADBEEF...
      websites:
      - example.com
      distribution:
        - dist.example.com
      c2:
        ips:
        - 1.2.3.4
        domains:
        - c2.example.com
    Returns lists of: packages, certificates, domains (with category), ips
    """
    text = read_file(path)
    if not text:
        return [], [], [], []

    packages = []      # (pkg, threat_name, type)
    certificates = []  # (hash, threat_name)
    domains = []       # (domain, threat_name, category)
    ips = []           # (ip, threat_name)

    current_name = None
    current_type = "stalkerware"
    current_section = None  # packages, certificates, websites, distribution, c2_ips, c2_domains
    in_c2 = False

    for line in text.splitlines():
        stripped = line.rstrip()
        if not stripped or stripped.startswith("#"):
            continue

        # Top-level entry
        m = re.match(r'^- name:\s*(.+)', stripped)
        if m:
            current_name = m.group(1).strip()
            current_section = None
            in_c2 = False
            continue

        # type field
        m = re.match(r'^\s+type:\s*(.+)', stripped)
        if m:
            current_type = m.group(1).strip()
            continue

        # names field (aliases) -- skip
        if re.match(r'^\s+names:\s*$', stripped):
            current_section = "names"
            continue

        # Section headers
        if re.match(r'^\s+packages:\s*$', stripped):
            current_section = "packages"
            in_c2 = False
            continue
        if re.match(r'^\s+certificates:\s*$', stripped):
            current_section = "certificates"
            in_c2 = False
            continue
        if re.match(r'^\s+websites:\s*$', stripped):
            current_section = "websites"
            in_c2 = False
            continue
        if re.match(r'^\s+distribution:\s*$', stripped):
            current_section = "distribution"
            in_c2 = False
            continue
        if re.match(r'^\s+c2:\s*$', stripped):
            in_c2 = True
            current_section = None
            continue
        if in_c2 and re.match(r'^\s+ips:\s*$', stripped):
            current_section = "c2_ips"
            continue
        if in_c2 and re.match(r'^\s+domains:\s*$', stripped):
            current_section = "c2_domains"
            continue

        # List items
        m = re.match(r'^\s+- (.+)', stripped)
        if m and current_name:
            val = m.group(1).strip()
            if current_section == "packages":
                packages.append((val, current_name, current_type))
            elif current_section == "certificates":
                certificates.append((val, current_name))
            elif current_section == "websites":
                domains.append((val, current_name, "tracking"))
            elif current_section == "distribution":
                domains.append((val, current_name, "distribution"))
            elif current_section == "c2_domains":
                domains.append((val, current_name, "c2"))
            elif current_section == "c2_ips":
                ips.append((val, current_name))
            # skip "names" items

    return packages, certificates, domains, ips


# ──────────────────────────────────────────────────────────────────────
# 1. PACKAGES
# ──────────────────────────────────────────────────────────────────────

def build_packages():
    lines = []

    # Source 1: stalkerware-indicators
    pkgs, _, _, _ = parse_stalkerware_yaml(
        os.path.join(RESEARCH, "stalkerware-indicators/ioc.yaml"))
    for pkg, name, typ in pkgs:
        lines.append(f"{pkg}|{name}|{typ}")

    # Source 2: threat-research indicators -- look for android_package_name in CSVs
    tr_csv_dir = os.path.join(RESEARCH, "threat-research/indicators/csv")
    if os.path.isdir(tr_csv_dir):
        for root, dirs, files in os.walk(tr_csv_dir):
            for fn in files:
                if not fn.endswith(".csv"):
                    continue
                fpath = os.path.join(root, fn)
                try:
                    content = read_file(fpath)
                    reader = csv.DictReader(io.StringIO(content))
                    for row in reader:
                        itype = (row.get("indicator_type") or row.get("type") or "").strip().lower()
                        val = (row.get("indicator_value") or row.get("value") or "").strip()
                        comment = (row.get("comment") or "").strip()
                        if "android" in itype and "package" in itype and val:
                            threat = comment if comment else os.path.basename(fn).replace(".csv", "")
                            lines.append(f"{val}|{threat}|spyware")
                except Exception:
                    pass

    # Source 3: isdi app-flags.csv -- extract appId where flag is spyware
    isdi_path = os.path.join(RESEARCH, "isdi/static_data/app-flags.csv")
    if os.path.isfile(isdi_path):
        content = read_file(isdi_path)
        reader = csv.DictReader(io.StringIO(content))
        for row in reader:
            flag = (row.get("flag") or "").strip().lower()
            app_id = (row.get("appId") or "").strip()
            if flag == "spyware" and app_id:
                title = (row.get("title") or "").strip()
                threat = title.split(",")[0].split("|")[0].strip() if title else "Unknown"
                lines.append(f"{app_id}|{threat}|stalkerware")

    # Source 4: MVT ROOT_PACKAGES
    mvt_utils = os.path.join(RESEARCH, "mvt/src/mvt/android/utils.py")
    if os.path.isfile(mvt_utils):
        content = read_file(mvt_utils)
        # Extract ROOT_PACKAGES list
        m = re.search(r'ROOT_PACKAGES.*?\[(.*?)\]', content, re.DOTALL)
        if m:
            for pkg in re.findall(r'"([^"]+)"', m.group(1)):
                lines.append(f"{pkg}|MVT_RootDetection|forensic")

    return write_ioc("packages.txt", lines,
                      "# Vigil IOC: Malicious/stalkerware Android packages\n"
                      "# Format: package_name|threat_name|category")


# ──────────────────────────────────────────────────────────────────────
# 2. CERTIFICATES
# ──────────────────────────────────────────────────────────────────────

def build_certificates():
    lines = []
    _, certs, _, _ = parse_stalkerware_yaml(
        os.path.join(RESEARCH, "stalkerware-indicators/ioc.yaml"))
    for h, name in certs:
        # Determine hash type by length
        h_clean = h.strip()
        if len(h_clean) == 40:
            htype = "SHA1"
        elif len(h_clean) == 64:
            htype = "SHA256"
        elif len(h_clean) == 32:
            htype = "MD5"
        else:
            htype = "unknown"
        lines.append(f"{h_clean}|{name}|{htype}")

    return write_ioc("certificates.txt", lines,
                      "# Vigil IOC: Malicious signing certificate hashes\n"
                      "# Format: hash|threat_name|hash_type")


# ──────────────────────────────────────────────────────────────────────
# 3. DOMAINS
# ──────────────────────────────────────────────────────────────────────

def build_domains():
    lines = []

    # Source 1: stalkerware-indicators
    _, _, doms, _ = parse_stalkerware_yaml(
        os.path.join(RESEARCH, "stalkerware-indicators/ioc.yaml"))
    for d, name, cat in doms:
        lines.append(f"{d}|{name}|{cat}")

    # Source 2: mobiletrackers list.txt
    mt_path = os.path.join(RESEARCH, "mobiletrackers/list.txt")
    if os.path.isfile(mt_path):
        for line in read_file(mt_path).splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Should be a domain
            if re.match(r'^[a-zA-Z0-9][\w.-]+\.[a-zA-Z]{2,}$', line):
                lines.append(f"{line}|MobileTracker|tracking")

    # Source 3: malware-indicators CSVs -- domain types
    mi_dir = os.path.join(RESEARCH, "malware-indicators")
    if os.path.isdir(mi_dir):
        for root, dirs, files in os.walk(mi_dir):
            # Skip .git
            dirs[:] = [d for d in dirs if d != ".git"]
            for fn in files:
                if not fn.endswith(".csv"):
                    continue
                fpath = os.path.join(root, fn)
                # Determine threat from directory name
                parent = os.path.basename(os.path.dirname(fpath))
                try:
                    content = read_file(fpath)
                    reader = csv.DictReader(io.StringIO(content))
                    for row in reader:
                        itype = (row.get("type") or row.get("indicator_type") or "").strip().lower()
                        val = (row.get("value") or row.get("indicator_value") or "").strip().strip('"')
                        if itype == "domain" and val:
                            lines.append(f"{val}|{parent}|c2")
                        elif itype == "domain_name" and val:
                            lines.append(f"{val}|{parent}|c2")
                except Exception:
                    pass

    # Source 4: threat-research CSVs -- domain_name types
    tr_csv_dir = os.path.join(RESEARCH, "threat-research/indicators/csv")
    if os.path.isdir(tr_csv_dir):
        for root, dirs, files in os.walk(tr_csv_dir):
            for fn in files:
                if not fn.endswith(".csv"):
                    continue
                fpath = os.path.join(root, fn)
                try:
                    content = read_file(fpath)
                    reader = csv.DictReader(io.StringIO(content))
                    for row in reader:
                        itype = (row.get("indicator_type") or row.get("type") or "").strip().lower()
                        val = (row.get("indicator_value") or row.get("value") or "").strip().strip('"')
                        if itype in ("domain_name", "domain") and val:
                            threat = os.path.basename(fn).replace(".csv", "")
                            lines.append(f"{val}|{threat}|c2")
                except Exception:
                    pass

    return write_ioc("domains.txt", lines,
                      "# Vigil IOC: C2 and tracking domains\n"
                      "# Format: domain|threat_name|category")


# ──────────────────────────────────────────────────────────────────────
# 4. IPS
# ──────────────────────────────────────────────────────────────────────

def build_ips():
    lines = []

    # Source 1: stalkerware-indicators
    _, _, _, ip_list = parse_stalkerware_yaml(
        os.path.join(RESEARCH, "stalkerware-indicators/ioc.yaml"))
    for ip, name in ip_list:
        lines.append(f"{ip}|{name}|c2")

    # Source 2: malware-indicators CSVs -- ip-dst types
    mi_dir = os.path.join(RESEARCH, "malware-indicators")
    if os.path.isdir(mi_dir):
        for root, dirs, files in os.walk(mi_dir):
            dirs[:] = [d for d in dirs if d != ".git"]
            for fn in files:
                if not fn.endswith(".csv"):
                    continue
                fpath = os.path.join(root, fn)
                parent = os.path.basename(os.path.dirname(fpath))
                try:
                    content = read_file(fpath)
                    reader = csv.DictReader(io.StringIO(content))
                    for row in reader:
                        itype = (row.get("type") or "").strip().lower()
                        val = (row.get("value") or "").strip().strip('"')
                        if itype in ("ip-dst", "ip-src") and val:
                            lines.append(f"{val}|{parent}|c2")
                except Exception:
                    pass

    # Source 3: threat-research CSVs
    tr_csv_dir = os.path.join(RESEARCH, "threat-research/indicators/csv")
    if os.path.isdir(tr_csv_dir):
        for root, dirs, files in os.walk(tr_csv_dir):
            for fn in files:
                if not fn.endswith(".csv"):
                    continue
                fpath = os.path.join(root, fn)
                try:
                    content = read_file(fpath)
                    reader = csv.DictReader(io.StringIO(content))
                    for row in reader:
                        itype = (row.get("indicator_type") or row.get("type") or "").strip().lower()
                        val = (row.get("indicator_value") or row.get("value") or "").strip().strip('"')
                        if itype in ("ip_address", "ip-dst", "ip-src") and val:
                            threat = os.path.basename(fn).replace(".csv", "")
                            lines.append(f"{val}|{threat}|c2")
                except Exception:
                    pass

    return write_ioc("ips.txt", lines,
                      "# Vigil IOC: Malicious IPs\n"
                      "# Format: ip|threat_name|category")


# ──────────────────────────────────────────────────────────────────────
# 5. HASHES
# ──────────────────────────────────────────────────────────────────────

def build_hashes():
    lines = []

    # Source 1: stalkerware-indicators generated -- look for samples/hashes
    gen_dir = os.path.join(RESEARCH, "stalkerware-indicators/generated")
    if os.path.isdir(gen_dir):
        for fn in os.listdir(gen_dir):
            if not fn.endswith(".csv"):
                continue
            fpath = os.path.join(gen_dir, fn)
            try:
                content = read_file(fpath)
                reader = csv.DictReader(io.StringIO(content))
                for row in reader:
                    # Look for hash-like columns
                    for key in row:
                        kl = key.lower()
                        val = (row[key] or "").strip()
                        if "sha256" in kl and len(val) == 64 and re.match(r'^[0-9a-fA-F]+$', val):
                            app = row.get("app", row.get("name", fn))
                            lines.append(f"{val}|{app}|SHA256")
                        elif "sha1" in kl and len(val) == 40 and re.match(r'^[0-9a-fA-F]+$', val):
                            app = row.get("app", row.get("name", fn))
                            lines.append(f"{val}|{app}|SHA1")
                        elif "md5" in kl and len(val) == 32 and re.match(r'^[0-9a-fA-F]+$', val):
                            app = row.get("app", row.get("name", fn))
                            lines.append(f"{val}|{app}|MD5")
            except Exception:
                pass

    # Source 2: malware-indicators CSVs -- sha256, md5 types
    mi_dir = os.path.join(RESEARCH, "malware-indicators")
    if os.path.isdir(mi_dir):
        for root, dirs, files in os.walk(mi_dir):
            dirs[:] = [d for d in dirs if d != ".git"]
            for fn in files:
                if not fn.endswith(".csv"):
                    continue
                fpath = os.path.join(root, fn)
                parent = os.path.basename(os.path.dirname(fpath))
                try:
                    content = read_file(fpath)
                    reader = csv.DictReader(io.StringIO(content))
                    fields = reader.fieldnames or []
                    for row in reader:
                        itype = (row.get("type") or "").strip().lower()
                        val = (row.get("value") or "").strip().strip('"')
                        if itype == "sha256" and len(val) == 64:
                            lines.append(f"{val}|{parent}|SHA256")
                        elif itype == "md5" and len(val) == 32:
                            lines.append(f"{val}|{parent}|MD5")
                        elif itype == "sha1" and len(val) == 40:
                            lines.append(f"{val}|{parent}|SHA1")
                        # Also check named columns (like hashes.csv)
                        if "MD5" in fields:
                            md5 = (row.get("MD5") or "").strip()
                            if len(md5) == 32 and re.match(r'^[0-9a-fA-F]+$', md5):
                                lines.append(f"{md5}|{parent}|MD5")
                except Exception:
                    pass

    # Source 3: threat-research CSVs
    tr_csv_dir = os.path.join(RESEARCH, "threat-research/indicators/csv")
    if os.path.isdir(tr_csv_dir):
        for root, dirs, files in os.walk(tr_csv_dir):
            for fn in files:
                if not fn.endswith(".csv"):
                    continue
                fpath = os.path.join(root, fn)
                try:
                    content = read_file(fpath)
                    reader = csv.DictReader(io.StringIO(content))
                    for row in reader:
                        itype = (row.get("indicator_type") or row.get("type") or "").strip().lower()
                        val = (row.get("indicator_value") or row.get("value") or "").strip().strip('"')
                        if itype in ("sha256", "hash_sha256") and len(val) == 64:
                            threat = os.path.basename(fn).replace(".csv", "")
                            lines.append(f"{val}|{threat}|SHA256")
                        elif itype in ("md5", "hash_md5") and len(val) == 32:
                            threat = os.path.basename(fn).replace(".csv", "")
                            lines.append(f"{val}|{threat}|MD5")
                except Exception:
                    pass

    return write_ioc("hashes.txt", lines,
                      "# Vigil IOC: Malicious file hashes\n"
                      "# Format: hash|threat_name|hash_type")


# ──────────────────────────────────────────────────────────────────────
# 6. HOSTS (blocklist format)
# ──────────────────────────────────────────────────────────────────────

def build_hosts():
    """Build hosts file from all domains in domains.txt."""
    domains_path = os.path.join(OUT_DIR, "domains.txt")
    lines = []
    if os.path.isfile(domains_path):
        for line in open(domains_path):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("|")
            domain = parts[0].strip()
            if domain and re.match(r'^[a-zA-Z0-9][\w.-]+\.[a-zA-Z]{2,}$', domain):
                lines.append(f"0.0.0.0 {domain}")

    return write_ioc("hosts.txt", lines,
                      "# Vigil IOC: Hosts blocklist (C2 + tracking domains)\n"
                      "# Format: 0.0.0.0 domain")


# ──────────────────────────────────────────────────────────────────────
# 7. CELLEBRITE HASHES
# ──────────────────────────────────────────────────────────────────────

def build_cellebrite_hashes():
    lines = []

    lockup_service = os.path.join(
        RESEARCH, "lockup/app/src/main/java/com/lockup/LockUpService.java")
    if os.path.isfile(lockup_service):
        content = read_file(lockup_service)

        # Extract CB_ELEVATOR_HASHES array
        m = re.search(r'CB_ELEVATOR_HASHES\s*=\s*new\s+String\[\]\s*\{(.*?)\}', content, re.DOTALL)
        if m:
            for h in re.findall(r'"([0-9a-fA-F]{64})"', m.group(1)):
                lines.append(f"{h}|Cellebrite_UFED_Elevator|SHA256")

        # Extract bannedKeys array
        m = re.search(r'bannedKeys\s*=\s*new\s+String\[\]\s*\{(.*?)\}', content, re.DOTALL)
        if m:
            for h in re.findall(r'"([0-9a-fA-F]{64})"', m.group(1)):
                lines.append(f"{h}|Cellebrite_BannedKey|SHA256")

    return write_ioc("cellebrite_hashes.txt", lines,
                      "# Vigil IOC: Cellebrite forensic tool hashes\n"
                      "# Format: hash|threat_name|hash_type")


# ──────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("Vigil IOC Database Builder")
    print("=" * 60)

    counts = {}
    counts["packages.txt"] = build_packages()
    counts["certificates.txt"] = build_certificates()
    counts["domains.txt"] = build_domains()
    counts["ips.txt"] = build_ips()
    counts["hashes.txt"] = build_hashes()
    counts["hosts.txt"] = build_hosts()
    counts["cellebrite_hashes.txt"] = build_cellebrite_hashes()

    print()
    total = 0
    for fn, count in counts.items():
        print(f"  {fn:30s} {count:>6d} indicators")
        total += count
    print(f"  {'TOTAL':30s} {total:>6d} indicators")
    print()
    print(f"Output directory: {OUT_DIR}")
    print("Done.")


if __name__ == "__main__":
    main()

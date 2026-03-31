#!/system/bin/sh
# Vigil — Threat Scanner Engine
# Scans installed packages, processes, certificates, accessibility services
# against the IOC database
# (c) Setec Labs

VIGIL_DATA="/data/adb/vigil"
VIGIL_LOG="$VIGIL_DATA/vigil.log"
IOC_DIR="$VIGIL_DATA"
ALERT_DIR="$VIGIL_DATA/alerts"

[ -f "$VIGIL_DATA/vigil.conf" ] && . "$VIGIL_DATA/vigil.conf"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [scanner] $1" >> "$VIGIL_LOG"
}

alert() {
    local severity="$1"
    local message="$2"
    local timestamp=$(date +%s)
    echo "${severity}|${timestamp}|scanner|${message}" >> "$ALERT_DIR/pending"
    log "ALERT [$severity]: $message"
}

load_exclusions() {
    EXCLUDED_PACKAGES=""
    if [ -f "$VIGIL_DATA/exclusions.conf" ]; then
        EXCLUDED_PACKAGES=$(grep -v '^#' "$VIGIL_DATA/exclusions.conf" | grep -v '^$')
    fi
}

is_excluded() {
    local pkg="$1"
    echo "$EXCLUDED_PACKAGES" | grep -qx "$pkg" 2>/dev/null
}

# ── PACKAGE SCAN: Check installed apps against IOC package list ──
scan_packages() {
    log "Scanning installed packages..."
    local hits=0
    local checked=0
    local ioc_file="$IOC_DIR/packages.txt"

    if [ ! -f "$ioc_file" ]; then
        log "WARNING: packages.txt IOC file not found"
        return 0
    fi

    # Get installed packages
    local installed=$(pm list packages 2>/dev/null | sed 's/^package://')

    for pkg in $installed; do
        checked=$((checked + 1))

        # Skip exclusions
        is_excluded "$pkg" && continue

        # Check against IOC database
        local match=$(grep "^${pkg}|" "$ioc_file" 2>/dev/null | head -1)
        if [ -n "$match" ]; then
            local threat_name=$(echo "$match" | cut -d'|' -f2)
            local category=$(echo "$match" | cut -d'|' -f3)
            hits=$((hits + 1))

            case "$category" in
                pegasus|government)
                    alert "CRITICAL" "STATE-LEVEL SPYWARE: $pkg ($threat_name) [$category]"
                    ;;
                spyware|stalkerware)
                    alert "HIGH" "STALKERWARE DETECTED: $pkg ($threat_name) [$category]"
                    ;;
                trojan)
                    alert "HIGH" "TROJAN DETECTED: $pkg ($threat_name) [$category]"
                    ;;
                tracker)
                    alert "MEDIUM" "TRACKER APP: $pkg ($threat_name) [$category]"
                    ;;
                *)
                    alert "HIGH" "THREAT DETECTED: $pkg ($threat_name) [$category]"
                    ;;
            esac
        fi
    done

    log "Package scan complete: $checked checked, $hits threats found"
    echo "  Packages: $checked scanned, $hits threats"
    return $hits
}

# ── CERTIFICATE SCAN: Check app signing certs against IOC cert list ──
scan_certificates() {
    log "Scanning app certificates..."
    local hits=0
    local checked=0
    local ioc_file="$IOC_DIR/certificates.txt"

    if [ ! -f "$ioc_file" ]; then
        log "WARNING: certificates.txt IOC file not found"
        return 0
    fi

    # Get certificate info for each package
    pm list packages 2>/dev/null | sed 's/^package://' | while read -r pkg; do
        # Extract signing certificate hash from package info
        local cert_info=$(dumpsys package "$pkg" 2>/dev/null | grep -A1 "signatures=" | grep -oE '[0-9a-fA-F]{40}')

        for cert_hash in $cert_info; do
            checked=$((checked + 1))
            local cert_upper=$(echo "$cert_hash" | tr 'a-f' 'A-F')
            local cert_lower=$(echo "$cert_hash" | tr 'A-F' 'a-f')

            local match=$(grep -i "^${cert_lower}\|^${cert_upper}" "$ioc_file" 2>/dev/null | head -1)
            if [ -n "$match" ]; then
                local threat_name=$(echo "$match" | cut -d'|' -f2)
                hits=$((hits + 1))
                alert "HIGH" "MALICIOUS CERTIFICATE on $pkg: $cert_hash ($threat_name)"
            fi
        done
    done

    log "Certificate scan complete: $checked checked, $hits threats found"
    echo "  Certificates: $checked checked, $hits threats"
    return $hits
}

# ── PROCESS SCAN: Check running processes for suspicious activity ──
scan_processes() {
    log "Scanning running processes..."
    local hits=0

    # Known suspicious process patterns
    local suspicious_patterns="pegasus\|predator\|chrysaor\|hermit\|candiru\|sourgum\|quadream\|cytrox\|cellebrite\|ufed\|graykey\|magnet.forensic\|oxygen.forensic\|frida-server\|objection"

    # Check running processes
    ps -A -o PID,NAME 2>/dev/null | while read -r pid name; do
        if echo "$name" | grep -qi "$suspicious_patterns"; then
            hits=$((hits + 1))
            alert "CRITICAL" "SUSPICIOUS PROCESS: $name (PID: $pid)"
        fi
    done

    # Check for hidden processes (processes that don't show in normal ps)
    # Compare /proc entries with ps output
    local ps_pids=$(ps -A -o PID 2>/dev/null | tail -n +2 | sort -n)
    for pid_dir in /proc/[0-9]*; do
        local pid=$(basename "$pid_dir")
        if ! echo "$ps_pids" | grep -qx "$pid" 2>/dev/null; then
            local cmdline=$(cat "/proc/$pid/cmdline" 2>/dev/null | tr '\0' ' ')
            if [ -n "$cmdline" ]; then
                alert "HIGH" "HIDDEN PROCESS: PID $pid ($cmdline)"
                hits=$((hits + 1))
            fi
        fi
    done

    log "Process scan complete: $hits suspicious processes"
    echo "  Processes: $hits suspicious"
    return $hits
}

# ── ACCESSIBILITY SCAN: Check for stalkerware abusing accessibility ──
scan_accessibility() {
    log "Scanning accessibility services..."
    local hits=0
    local ioc_file="$IOC_DIR/packages.txt"

    # Get enabled accessibility services
    local enabled=$(settings get secure enabled_accessibility_services 2>/dev/null)

    if [ -n "$enabled" ] && [ "$enabled" != "null" ]; then
        # Split by colon
        echo "$enabled" | tr ':' '\n' | while read -r service; do
            local pkg=$(echo "$service" | cut -d'/' -f1)

            # Check if this package is in our IOC database
            if [ -f "$ioc_file" ]; then
                local match=$(grep "^${pkg}|" "$ioc_file" 2>/dev/null | head -1)
                if [ -n "$match" ]; then
                    local threat_name=$(echo "$match" | cut -d'|' -f2)
                    hits=$((hits + 1))
                    alert "CRITICAL" "STALKERWARE ACCESSIBILITY SERVICE: $service ($threat_name)"
                fi
            fi

            # Heuristic: check if accessibility service belongs to a non-system app
            local is_system=$(pm dump "$pkg" 2>/dev/null | grep -c "SYSTEM")
            if [ "$is_system" = "0" ]; then
                # Non-system app with accessibility — suspicious
                local app_name=$(pm dump "$pkg" 2>/dev/null | grep "applicationInfo" | head -1)
                alert "MEDIUM" "Non-system accessibility service: $service"
                hits=$((hits + 1))
            fi
        done
    fi

    log "Accessibility scan complete: $hits suspicious services"
    echo "  Accessibility: $hits suspicious"
    return $hits
}

# ── DEVICE ADMIN SCAN: Check for malicious device admins ──
scan_device_admin() {
    log "Scanning device administrators..."
    local hits=0
    local ioc_file="$IOC_DIR/packages.txt"

    # Get active device admins
    dumpsys device_policy 2>/dev/null | grep "Active Admins" -A 100 | grep "ComponentInfo" | while read -r line; do
        local component=$(echo "$line" | grep -oE '\{[^}]+\}' | tr -d '{}')
        local pkg=$(echo "$component" | cut -d'/' -f1)

        if [ -f "$ioc_file" ]; then
            local match=$(grep "^${pkg}|" "$ioc_file" 2>/dev/null | head -1)
            if [ -n "$match" ]; then
                local threat_name=$(echo "$match" | cut -d'|' -f2)
                hits=$((hits + 1))
                alert "CRITICAL" "MALICIOUS DEVICE ADMIN: $component ($threat_name)"
            fi
        fi
    done

    log "Device admin scan complete: $hits suspicious"
    echo "  Device admins: $hits suspicious"
    return $hits
}

# ── APK HASH SCAN: Check APK file hashes (slow, thorough) ──
scan_hashes() {
    log "Scanning APK hashes (this may take a while)..."
    local hits=0
    local checked=0
    local ioc_file="$IOC_DIR/hashes.txt"

    if [ ! -f "$ioc_file" ]; then
        log "WARNING: hashes.txt IOC file not found"
        return 0
    fi

    # Scan non-system APKs
    pm list packages -f 2>/dev/null | sed 's/^package://' | while IFS='=' read -r apk_path pkg; do
        # Skip system apps for speed (focus on user-installed)
        case "$apk_path" in
            /system/*|/vendor/*|/product/*) continue ;;
        esac

        checked=$((checked + 1))
        local apk_hash=$(sha256sum "$apk_path" 2>/dev/null | cut -d' ' -f1)

        if [ -n "$apk_hash" ]; then
            local match=$(grep "^${apk_hash}|" "$ioc_file" 2>/dev/null | head -1)
            if [ -n "$match" ]; then
                local threat_name=$(echo "$match" | cut -d'|' -f2)
                hits=$((hits + 1))
                alert "CRITICAL" "MALICIOUS APK HASH: $pkg ($apk_path) matches $threat_name"
            fi
        fi
    done

    log "Hash scan complete: $checked APKs checked, $hits threats found"
    echo "  APK hashes: $checked checked, $hits threats"
    return $hits
}

# ── FULL SCAN ──
cmd_full_scan() {
    log "=== FULL THREAT SCAN STARTED ==="
    load_exclusions

    local total_hits=0
    echo ""
    echo "Vigil Threat Scan Report"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Time: $(date)"
    echo ""

    [ "${SCANNER_CHECK_PACKAGES:-1}" = "1" ] && {
        scan_packages
        total_hits=$((total_hits + $?))
    }

    [ "${SCANNER_CHECK_CERTS:-1}" = "1" ] && {
        scan_certificates
        total_hits=$((total_hits + $?))
    }

    [ "${SCANNER_CHECK_PROCESSES:-1}" = "1" ] && {
        scan_processes
        total_hits=$((total_hits + $?))
    }

    [ "${SCANNER_CHECK_ACCESSIBILITY:-1}" = "1" ] && {
        scan_accessibility
        total_hits=$((total_hits + $?))
    }

    [ "${SCANNER_CHECK_DEVICE_ADMIN:-1}" = "1" ] && {
        scan_device_admin
        total_hits=$((total_hits + $?))
    }

    [ "${SCANNER_CHECK_HASHES:-1}" = "1" ] && {
        scan_hashes
        total_hits=$((total_hits + $?))
    }

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━"
    if [ $total_hits -gt 0 ]; then
        echo "⚠ THREATS DETECTED: $total_hits"
        echo "Run 'vigil alerts' for details"
    else
        echo "✓ No threats detected"
    fi
    echo ""

    log "=== FULL SCAN COMPLETE: $total_hits threats ==="
    return $total_hits
}

# ── QUICK SCAN (packages + processes only) ──
cmd_quick_scan() {
    log "=== QUICK SCAN STARTED ==="
    load_exclusions

    local total_hits=0
    echo "Vigil Quick Scan..."

    scan_packages
    total_hits=$((total_hits + $?))

    scan_processes
    total_hits=$((total_hits + $?))

    scan_accessibility
    total_hits=$((total_hits + $?))

    if [ $total_hits -gt 0 ]; then
        echo "⚠ $total_hits threats detected — run 'vigil scan' for full scan"
    else
        echo "✓ Quick scan clean"
    fi

    log "=== QUICK SCAN COMPLETE: $total_hits threats ==="
    return $total_hits
}

# ── DISPATCH ──
case "$1" in
    full)          cmd_full_scan ;;
    quick)         cmd_quick_scan ;;
    packages)      load_exclusions; scan_packages ;;
    certificates)  scan_certificates ;;
    processes)     scan_processes ;;
    accessibility) scan_accessibility ;;
    device-admin)  scan_device_admin ;;
    hashes)        scan_hashes ;;
    *)
        echo "Vigil Threat Scanner"
        echo "Usage: scanner.sh {full|quick|packages|certificates|processes|accessibility|device-admin|hashes}"
        ;;
esac

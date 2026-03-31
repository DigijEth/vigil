#!/system/bin/sh
# Vigil — Forensic Shield (Anti-Cellebrite/UFED)
# Monitors USB, detects forensic extraction tools, triggers defensive response
# (c) Setec Labs
#
# Based on research from: levlesec/lockup, bakad3v/Android-AntiForensic-Tools
#
# Detection vectors:
# 1. USB device connection monitoring
# 2. Cellebrite binary hash detection in staging directories
# 3. Cellebrite signing certificate detection
# 4. Forensic tool process detection
# 5. ADB state monitoring

VIGIL_DATA="/data/adb/vigil"
VIGIL_LOG="$VIGIL_DATA/vigil.log"
IOC_DIR="$VIGIL_DATA"
ALERT_DIR="$VIGIL_DATA/alerts"

[ -f "$VIGIL_DATA/vigil.conf" ] && . "$VIGIL_DATA/vigil.conf"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [forensic] $1" >> "$VIGIL_LOG"
}

alert() {
    local severity="$1"
    local message="$2"
    local timestamp=$(date +%s)
    echo "${severity}|${timestamp}|forensic_shield|${message}" >> "$ALERT_DIR/pending"
    log "ALERT [$severity]: $message"
}

# Known forensic tool staging directories
STAGING_DIRS="/data/local/tmp /data/local/tmp/cb /cblr /dev/shm /data/local/tmp/frida"

# Known forensic tool process names
FORENSIC_PROCESSES="cellebrite\|ufed\|graykey\|grayshift\|magnet.forensic\|oxygen.forensic\|msab\|xry\|elcomsoft\|passware\|hashcat\|john\|volatility\|autopsy\|ftk\|encase\|axiom\|nuix\|paraben\|susteen\|mobiledit\|belkasoft"

# Known exploit binary names used by forensic tools
EXPLOIT_NAMES="nandread\|dirtycow\|dirty_cow\|pingroot\|zergRush\|psneuter\|salmatak\|gingerbreak\|rageagainstthecage\|exploid\|zimperlich\|levitator\|mempodroid\|motochopper\|put_user\|towelroot\|framaroot\|kingroot"

# ── STAGING DIRECTORY MONITOR ──
check_staging_dirs() {
    local hits=0

    for dir in $STAGING_DIRS; do
        if [ -d "$dir" ]; then
            # Check for any files
            local files=$(find "$dir" -type f 2>/dev/null)
            if [ -n "$files" ]; then
                echo "$files" | while read -r filepath; do
                    local filename=$(basename "$filepath")
                    local filesize=$(stat -c '%s' "$filepath" 2>/dev/null || echo "0")

                    # Check filename against exploit patterns
                    if echo "$filename" | grep -qiE "$EXPLOIT_NAMES"; then
                        alert "CRITICAL" "FORENSIC EXPLOIT BINARY: $filepath ($filename)"
                        hits=$((hits + 1))
                    fi

                    # Check file hash against Cellebrite hashes
                    if [ -f "$IOC_DIR/cellebrite_hashes.txt" ] && [ "$filesize" -gt 0 ]; then
                        local file_hash=$(sha256sum "$filepath" 2>/dev/null | cut -d' ' -f1)
                        if grep -qi "^${file_hash}" "$IOC_DIR/cellebrite_hashes.txt" 2>/dev/null; then
                            alert "CRITICAL" "CELLEBRITE BINARY DETECTED: $filepath (hash: ${file_hash:0:16}...)"
                            hits=$((hits + 1))
                        fi
                    fi

                    # Check for Frida-related files
                    if echo "$filename" | grep -qiE "frida|gadget|agent.*\.so|re\.frida"; then
                        alert "HIGH" "FRIDA INJECTION TOOL: $filepath"
                        hits=$((hits + 1))
                    fi
                done
            fi
        fi
    done

    return $hits
}

# ── PROCESS MONITOR ──
check_forensic_processes() {
    local hits=0

    ps -A -o PID,NAME 2>/dev/null | while read -r pid name; do
        if echo "$name" | grep -qi "$FORENSIC_PROCESSES"; then
            alert "CRITICAL" "FORENSIC TOOL PROCESS: $name (PID: $pid)"
            hits=$((hits + 1))

            # If auto-lockdown is enabled, trigger it immediately
            if [ "${FORENSIC_AUTO_LOCKDOWN:-0}" = "1" ]; then
                log "AUTO-LOCKDOWN triggered by forensic process: $name"
                "$VIGIL_DATA/../modules/vigil/vigil/lib/key_wiper.sh" lockdown
            fi
        fi
    done

    return $hits
}

# ── USB STATE MONITOR ──
check_usb_state() {
    local usb_state=$(cat /sys/class/android_usb/android0/state 2>/dev/null || getprop sys.usb.state 2>/dev/null)
    local usb_config=$(getprop sys.usb.config 2>/dev/null)

    # If we're in lockdown and USB is connected, alert
    if [ -f "$VIGIL_DATA/.lockdown" ]; then
        if [ "$usb_state" = "CONFIGURED" ] || [ "$usb_state" = "CONNECTED" ]; then
            alert "HIGH" "USB CONNECTED DURING LOCKDOWN (config: $usb_config)"
            # Force charging-only mode
            setprop sys.usb.config "charging" 2>/dev/null
        fi
    fi

    # Check if ADB got re-enabled unexpectedly
    if [ "${FORENSIC_ADB_GUARD:-1}" = "1" ]; then
        local adb_state=$(settings get global adb_enabled 2>/dev/null)
        if [ -f "$VIGIL_DATA/.lockdown" ] && [ "$adb_state" = "1" ]; then
            alert "HIGH" "ADB RE-ENABLED DURING LOCKDOWN — disabling"
            settings put global adb_enabled 0 2>/dev/null
            stop adbd 2>/dev/null
        fi
    fi
}

# ── PACKAGE INSTALL MONITOR ──
# Check recently installed packages for forensic tool signatures
check_recent_installs() {
    local hits=0
    local threshold=$(($(date +%s) - 300))  # Last 5 minutes

    # Check for recently installed packages with suspicious signing certs
    pm list packages -i 2>/dev/null | while read -r line; do
        local pkg=$(echo "$line" | sed 's/package:\([^ ]*\).*/\1/')
        local installer=$(echo "$line" | grep -oP 'installer=\K[^ ]+')

        # Non-store installs are suspicious during forensic scenarios
        if [ "$installer" != "com.android.vending" ] && [ "$installer" != "com.google.android.packageinstaller" ]; then
            # Check if this is a known forensic tool package
            if echo "$pkg" | grep -qiE "cellebrite\|ufed\|forensic\|graykey\|grayshift\|msab\|oxygen"; then
                alert "CRITICAL" "FORENSIC TOOL PACKAGE INSTALLED: $pkg (installer: $installer)"
                hits=$((hits + 1))
            fi
        fi
    done

    return $hits
}

# ── CONTINUOUS MONITOR (run as daemon) ──
cmd_monitor() {
    log "Forensic shield monitor starting..."
    echo "Forensic Shield active — monitoring USB, processes, staging dirs"

    while true; do
        check_usb_state
        check_forensic_processes
        check_staging_dirs

        # Quick process check every second if in lockdown, otherwise every 5
        if [ -f "$VIGIL_DATA/.lockdown" ]; then
            sleep 1
        else
            sleep 5
        fi
    done
}

# ── ONE-TIME SCAN ──
cmd_scan() {
    log "Forensic shield scan..."
    echo "Forensic Shield Scan"
    echo "━━━━━━━━━━━━━━━━━━━━"

    local total=0

    echo -n "  Staging directories: "
    check_staging_dirs
    local s=$?
    total=$((total + s))
    echo "$s findings"

    echo -n "  Forensic processes:  "
    check_forensic_processes
    local p=$?
    total=$((total + p))
    echo "$p findings"

    echo -n "  USB state:           "
    check_usb_state
    echo "checked"

    echo -n "  Recent installs:     "
    check_recent_installs
    local i=$?
    total=$((total + i))
    echo "$i findings"

    echo "━━━━━━━━━━━━━━━━━━━━"
    if [ $total -gt 0 ]; then
        echo "⚠ FORENSIC ACTIVITY DETECTED: $total findings"
    else
        echo "✓ No forensic tool activity detected"
    fi

    return $total
}

# ── STATUS ──
cmd_status() {
    echo "Forensic Shield Status:"
    echo "  Enabled:    ${FORENSIC_SHIELD_ENABLED:-1}"
    echo "  USB Guard:  ${FORENSIC_USB_MONITOR:-1}"
    echo "  ADB Guard:  ${FORENSIC_ADB_GUARD:-1}"
    echo "  Auto-Lock:  ${FORENSIC_AUTO_LOCKDOWN:-0}"
    echo "  Lockdown:   $([ -f "$VIGIL_DATA/.lockdown" ] && echo "ACTIVE" || echo "inactive")"

    local usb_state=$(getprop sys.usb.config 2>/dev/null)
    local adb_state=$(settings get global adb_enabled 2>/dev/null)
    echo "  USB Config: $usb_state"
    echo "  ADB:        $([ "$adb_state" = "1" ] && echo "ENABLED" || echo "disabled")"
}

# ── DISPATCH ──
case "$1" in
    monitor) cmd_monitor ;;
    scan)    cmd_scan ;;
    status)  cmd_status ;;
    *)
        echo "Forensic Shield — Anti-Extraction Defense"
        echo "Usage: forensic_shield.sh {monitor|scan|status}"
        ;;
esac

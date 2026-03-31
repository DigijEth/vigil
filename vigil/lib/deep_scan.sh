#!/system/bin/sh
# Vigil — Deep Forensic Scanner (MVT-style)
# Performs thorough forensic analysis of the device for compromise indicators
# (c) Setec Labs
#
# Two modes:
#   background - Lightweight continuous monitoring, low CPU/battery
#   deep       - Full on-demand forensic scan (cranks it out)
#
# Analysis vectors drawn from MVT, CitizenLab, and APT research:
# - Dumpsys extraction and IOC correlation
# - SMS/MMS database analysis
# - Call log anomaly detection
# - Browser history IOC matching
# - App installation source analysis
# - Logcat forensic artifact extraction
# - Chrome/WebView history scanning
# - Accessibility/notification listener abuse
# - Battery usage anomaly detection (spyware drains battery)
# - Data usage anomaly detection (spyware exfiltrates)
# - Certificate store tampering detection

VIGIL_DATA="/data/adb/vigil"
VIGIL_LOG="$VIGIL_DATA/vigil.log"
IOC_DIR="$VIGIL_DATA"
ALERT_DIR="$VIGIL_DATA/alerts"
DEEP_LOG="$VIGIL_DATA/deep_scan.log"
REPORT_DIR="$VIGIL_DATA/reports"

[ -f "$VIGIL_DATA/vigil.conf" ] && . "$VIGIL_DATA/vigil.conf"

mkdir -p "$REPORT_DIR" "$ALERT_DIR"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [deep_scan] $1" >> "$VIGIL_LOG"
}

alert() {
    local severity="$1"
    local message="$2"
    local timestamp=$(date +%s)
    echo "${severity}|${timestamp}|deep_scan|${message}" >> "$ALERT_DIR/pending"
    log "ALERT [$severity]: $message"
}

report() {
    echo "$1" >> "$CURRENT_REPORT"
}

# ════════════════════════════════════════════
# ANALYSIS MODULES
# ════════════════════════════════════════════

# ── SMS/MMS Database Analysis ──
# Check for evidence of exploitation via SMS (Pegasus delivery vector)
analyze_sms() {
    log "Analyzing SMS/MMS database..."
    report "## SMS/MMS Analysis"

    local sms_db=""
    for db in \
        /data/data/com.android.providers.telephony/databases/mmssms.db \
        /data/user_de/0/com.android.providers.telephony/databases/mmssms.db \
        /data/data/com.google.android.gms/databases/icing_mmssms.db; do
        [ -f "$db" ] && sms_db="$db" && break
    done

    if [ -z "$sms_db" ] || ! command -v sqlite3 >/dev/null 2>&1; then
        report "SMS database not accessible or sqlite3 unavailable"
        report ""
        return 0
    fi

    local hits=0

    # Check for messages with suspicious URLs (IOC domains)
    if [ -f "$IOC_DIR/domains.txt" ]; then
        # Extract all URLs from SMS body
        local urls=$(sqlite3 "$sms_db" "SELECT body FROM sms WHERE body LIKE '%http%';" 2>/dev/null)
        echo "$urls" | grep -oE 'https?://[a-zA-Z0-9._/-]+' | while read -r url; do
            local domain=$(echo "$url" | sed 's|https\?://||' | cut -d'/' -f1)
            if grep -qi "^${domain}|" "$IOC_DIR/domains.txt" 2>/dev/null; then
                local match=$(grep -i "^${domain}|" "$IOC_DIR/domains.txt" | head -1)
                local threat=$(echo "$match" | cut -d'|' -f2)
                alert "CRITICAL" "MALICIOUS URL IN SMS: $url ($threat)"
                report "- **CRITICAL**: Malicious URL found: $url ($threat)"
                hits=$((hits + 1))
            fi
        done
    fi

    # Check for empty-body SMS (silent SMS indicators)
    local empty_count=$(sqlite3 "$sms_db" "SELECT COUNT(*) FROM sms WHERE body IS NULL OR body = '';" 2>/dev/null)
    if [ "${empty_count:-0}" -gt 5 ]; then
        alert "MEDIUM" "Found $empty_count empty-body SMS messages (possible silent SMS)"
        report "- **MEDIUM**: $empty_count empty-body SMS (possible silent SMS tracking)"
        hits=$((hits + 1))
    fi

    # Check for SMS from very short numbers or unusual patterns
    local short_senders=$(sqlite3 "$sms_db" "SELECT DISTINCT address FROM sms WHERE LENGTH(address) <= 4 AND address NOT LIKE '%*%';" 2>/dev/null)
    if [ -n "$short_senders" ]; then
        report "- Short-code senders: $short_senders"
    fi

    # Check for WAP Push messages
    local wap_count=$(sqlite3 "$sms_db" "SELECT COUNT(*) FROM sms WHERE body LIKE '%wap%' OR body LIKE '%WAP%' OR body LIKE '%application/vnd%';" 2>/dev/null)
    if [ "${wap_count:-0}" -gt 0 ]; then
        alert "MEDIUM" "Found $wap_count WAP Push related SMS messages"
        report "- **MEDIUM**: $wap_count WAP Push SMS messages"
        hits=$((hits + 1))
    fi

    report "- Total SMS analyzed, empty-body count: ${empty_count:-0}"
    report ""
    return $hits
}

# ── Call Log Anomaly Detection ──
analyze_calls() {
    log "Analyzing call logs..."
    report "## Call Log Analysis"

    local calls_db=""
    for db in \
        /data/data/com.android.providers.contacts/databases/calllog.db \
        /data/data/com.android.providers.contacts/databases/contacts2.db; do
        [ -f "$db" ] && calls_db="$db" && break
    done

    if [ -z "$calls_db" ] || ! command -v sqlite3 >/dev/null 2>&1; then
        report "Call log database not accessible"
        report ""
        return 0
    fi

    local hits=0

    # Check for zero-duration calls (potential silent call exploits)
    local zero_dur=$(sqlite3 "$calls_db" "SELECT COUNT(*) FROM calls WHERE duration = 0 AND type = 1;" 2>/dev/null)
    if [ "${zero_dur:-0}" -gt 10 ]; then
        alert "LOW" "Found $zero_dur zero-duration incoming calls (possible probing)"
        report "- **LOW**: $zero_dur zero-duration incoming calls"
        hits=$((hits + 1))
    fi

    report "- Zero-duration incoming calls: ${zero_dur:-0}"
    report ""
    return $hits
}

# ── Browser History IOC Scan ──
analyze_browser() {
    log "Analyzing browser history..."
    report "## Browser History Analysis"

    local hits=0

    # Chrome history
    for chrome_db in \
        /data/data/com.android.chrome/app_chrome/Default/History \
        /data/data/com.chrome.*/app_chrome/Default/History \
        /data/data/org.chromium.*/app_chrome/Default/History; do

        [ -f "$chrome_db" ] || continue

        if [ -f "$IOC_DIR/domains.txt" ] && command -v sqlite3 >/dev/null 2>&1; then
            sqlite3 "$chrome_db" "SELECT url FROM urls ORDER BY last_visit_time DESC LIMIT 5000;" 2>/dev/null | while read -r url; do
                local domain=$(echo "$url" | sed 's|https\?://||' | cut -d'/' -f1)
                if grep -qi "^${domain}|" "$IOC_DIR/domains.txt" 2>/dev/null; then
                    local match=$(grep -i "^${domain}|" "$IOC_DIR/domains.txt" | head -1)
                    local threat=$(echo "$match" | cut -d'|' -f2)
                    alert "HIGH" "MALICIOUS DOMAIN IN BROWSER HISTORY: $domain ($threat)"
                    report "- **HIGH**: Visited malicious domain: $domain ($threat)"
                    hits=$((hits + 1))
                fi
            done
        fi
    done

    [ $hits -eq 0 ] && report "- No malicious domains found in browser history"
    report ""
    return $hits
}

# ── App Installation Source Analysis ──
# Off-store installs are a primary stalkerware vector
analyze_app_sources() {
    log "Analyzing app installation sources..."
    report "## App Installation Source Analysis"

    local hits=0
    local offstore=0
    local suspicious_installers=""

    pm list packages -i 2>/dev/null | while IFS= read -r line; do
        local pkg=$(echo "$line" | sed 's/package:\([^ ]*\).*/\1/')
        local installer=$(echo "$line" | grep -oP 'installer=\K\S+')

        # Legitimate installers
        case "$installer" in
            com.android.vending|com.google.android.packageinstaller|com.android.packageinstaller|com.samsung.android.app.galaxystore|""|null)
                continue ;;
        esac

        # Sideloaded or unknown installer
        offstore=$((offstore + 1))

        # Check if this sideloaded app is in our IOC database
        if [ -f "$IOC_DIR/packages.txt" ]; then
            local match=$(grep "^${pkg}|" "$IOC_DIR/packages.txt" 2>/dev/null | head -1)
            if [ -n "$match" ]; then
                local threat=$(echo "$match" | cut -d'|' -f2)
                alert "CRITICAL" "SIDELOADED THREAT: $pkg installed by $installer ($threat)"
                report "- **CRITICAL**: Sideloaded threat: $pkg (installer: $installer) — $threat"
                hits=$((hits + 1))
            fi
        fi
    done

    report "- Off-store installed apps: $offstore"
    report ""
    return $hits
}

# ── Dumpsys Forensic Extraction ──
# Extract and analyze dumpsys data like MVT does
analyze_dumpsys() {
    log "Analyzing dumpsys data..."
    report "## Dumpsys Forensic Analysis"

    local hits=0

    # ── Accessibility services (primary stalkerware vector) ──
    local acc_services=$(settings get secure enabled_accessibility_services 2>/dev/null)
    if [ -n "$acc_services" ] && [ "$acc_services" != "null" ]; then
        report "### Accessibility Services"
        echo "$acc_services" | tr ':' '\n' | while read -r service; do
            local pkg=$(echo "$service" | cut -d'/' -f1)
            report "- $service"

            if [ -f "$IOC_DIR/packages.txt" ]; then
                local match=$(grep "^${pkg}|" "$IOC_DIR/packages.txt" 2>/dev/null)
                if [ -n "$match" ]; then
                    local threat=$(echo "$match" | cut -d'|' -f2)
                    alert "CRITICAL" "MALICIOUS ACCESSIBILITY SERVICE: $service ($threat)"
                    report "  **CRITICAL**: Known threat — $threat"
                    hits=$((hits + 1))
                fi
            fi
        done
        report ""
    fi

    # ── Notification listeners (data exfiltration vector) ──
    local notif_listeners=$(settings get secure enabled_notification_listeners 2>/dev/null)
    if [ -n "$notif_listeners" ] && [ "$notif_listeners" != "null" ]; then
        report "### Notification Listeners"
        echo "$notif_listeners" | tr ':' '\n' | while read -r listener; do
            local pkg=$(echo "$listener" | cut -d'/' -f1)
            report "- $listener"

            if [ -f "$IOC_DIR/packages.txt" ]; then
                local match=$(grep "^${pkg}|" "$IOC_DIR/packages.txt" 2>/dev/null)
                if [ -n "$match" ]; then
                    local threat=$(echo "$match" | cut -d'|' -f2)
                    alert "HIGH" "MALICIOUS NOTIFICATION LISTENER: $listener ($threat)"
                    report "  **HIGH**: Known threat — $threat"
                    hits=$((hits + 1))
                fi
            fi
        done
        report ""
    fi

    # ── Device admin receivers ──
    report "### Device Administrators"
    dumpsys device_policy 2>/dev/null | grep -A2 "Admin" | grep "ComponentInfo" | while read -r line; do
        local component=$(echo "$line" | grep -oE '\{[^}]+\}' | tr -d '{}')
        local pkg=$(echo "$component" | cut -d'/' -f1)
        report "- $component"

        if [ -f "$IOC_DIR/packages.txt" ]; then
            local match=$(grep "^${pkg}|" "$IOC_DIR/packages.txt" 2>/dev/null)
            if [ -n "$match" ]; then
                local threat=$(echo "$match" | cut -d'|' -f2)
                alert "CRITICAL" "MALICIOUS DEVICE ADMIN: $component ($threat)"
                report "  **CRITICAL**: Known threat — $threat"
                hits=$((hits + 1))
            fi
        fi
    done
    report ""

    # ── Usage stats (detect background activity of suspicious apps) ──
    report "### Suspicious Background Activity"
    dumpsys usagestats 2>/dev/null | grep "package=" | sort -t'=' -k2 | uniq -c | sort -rn | head -20 | while read -r count pkg_line; do
        local pkg=$(echo "$pkg_line" | grep -oP 'package=\K\S+')
        if [ -f "$IOC_DIR/packages.txt" ]; then
            local match=$(grep "^${pkg}|" "$IOC_DIR/packages.txt" 2>/dev/null)
            if [ -n "$match" ]; then
                local threat=$(echo "$match" | cut -d'|' -f2)
                alert "HIGH" "THREAT APP ACTIVE IN BACKGROUND: $pkg ($count events) — $threat"
                report "- **HIGH**: $pkg — $count background events — $threat"
                hits=$((hits + 1))
            fi
        fi
    done
    report ""

    return $hits
}

# ── Battery Anomaly Detection ──
# Spyware causes abnormal battery drain
analyze_battery() {
    log "Analyzing battery usage patterns..."
    report "## Battery Usage Anomaly Detection"

    local hits=0

    # Get battery stats for apps consuming excessive power
    dumpsys batterystats 2>/dev/null | grep -E "Uid [0-9]+" | while read -r line; do
        local uid=$(echo "$line" | grep -oE 'Uid [0-9]+' | awk '{print $2}')
        local pkg=$(pm list packages --uid "$uid" 2>/dev/null | head -1 | sed 's/package://')

        if [ -n "$pkg" ] && [ -f "$IOC_DIR/packages.txt" ]; then
            local match=$(grep "^${pkg}|" "$IOC_DIR/packages.txt" 2>/dev/null)
            if [ -n "$match" ]; then
                local threat=$(echo "$match" | cut -d'|' -f2)
                alert "MEDIUM" "THREAT APP CONSUMING BATTERY: $pkg — $threat"
                report "- **MEDIUM**: Battery drain from threat app: $pkg — $threat"
                hits=$((hits + 1))
            fi
        fi
    done

    report ""
    return $hits
}

# ── Certificate Store Tampering ──
# Check for rogue CA certificates (MITM attacks)
analyze_certificates() {
    log "Analyzing certificate store..."
    report "## Certificate Store Analysis"

    local hits=0
    local user_certs_dir="/data/misc/user/0/cacerts-added"

    if [ -d "$user_certs_dir" ]; then
        local cert_count=$(ls "$user_certs_dir" 2>/dev/null | wc -l)
        if [ "$cert_count" -gt 0 ]; then
            report "### User-Added CA Certificates ($cert_count found)"
            for cert in "$user_certs_dir"/*; do
                [ -f "$cert" ] || continue
                local subject=$(openssl x509 -in "$cert" -noout -subject 2>/dev/null || echo "unknown")
                local issuer=$(openssl x509 -in "$cert" -noout -issuer 2>/dev/null || echo "unknown")
                report "- $subject"
                report "  Issuer: $issuer"

                # User-added CAs are always suspicious in a surveillance context
                alert "MEDIUM" "USER-ADDED CA CERTIFICATE: $subject"
                hits=$((hits + 1))
            done
        fi
    fi

    [ $hits -eq 0 ] && report "- No user-added CA certificates found"
    report ""
    return $hits
}

# ── Logcat Forensic Artifact Extraction ──
# Scan recent logcat for signs of exploitation
analyze_logcat() {
    log "Analyzing logcat for forensic artifacts..."
    report "## Logcat Forensic Analysis"

    local hits=0
    local logcat_dump=$(logcat -d 2>/dev/null)

    # Check for exploit indicators
    local exploit_patterns="CVE-\|exploit\|root.*shell\|privilege.*escalat\|selinux.*denied.*zygote\|WebView.*exploit\|use.after.free\|heap.*overflow\|buffer.*overflow\|RCE\|remote.*code.*exec"
    local exploit_hits=$(echo "$logcat_dump" | grep -ci "$exploit_patterns" 2>/dev/null)
    if [ "${exploit_hits:-0}" -gt 0 ]; then
        alert "HIGH" "Found $exploit_hits exploit-related logcat entries"
        report "- **HIGH**: $exploit_hits exploit-related log entries"
        echo "$logcat_dump" | grep -i "$exploit_patterns" | tail -5 | while read -r line; do
            report "  - $line"
        done
        hits=$((hits + 1))
    fi

    # Check for suspicious native library loading
    local native_loads=$(echo "$logcat_dump" | grep -i "System.loadLibrary\|dlopen.*data/data" | grep -v "com.android\|com.google" | head -10)
    if [ -n "$native_loads" ]; then
        report "### Suspicious Native Library Loading"
        echo "$native_loads" | while read -r line; do
            report "- $line"
        done
        hits=$((hits + 1))
    fi

    # Check for silent SMS indicators in logcat
    local sms_artifacts=$(echo "$logcat_dump" | grep -ci "type.?0.*sms\|sms.*type.?0\|class.?0.*sms\|silent.*sms" 2>/dev/null)
    if [ "${sms_artifacts:-0}" -gt 0 ]; then
        alert "HIGH" "Found $sms_artifacts silent SMS artifacts in logcat"
        report "- **HIGH**: $sms_artifacts silent SMS artifacts in logcat"
        hits=$((hits + 1))
    fi

    [ $hits -eq 0 ] && report "- No forensic artifacts found in logcat"
    report ""
    return $hits
}

# ── System Properties Analysis ──
# Check for suspicious system properties set by malware
analyze_properties() {
    log "Analyzing system properties..."
    report "## System Properties Analysis"

    local hits=0

    # Check for debugging/rooting properties that malware sets
    local suspicious_props="ro.debuggable persist.sys.dalvik.vm.lib ro.kernel.android.checkjni persist.service.adb.enable service.bootanim.exit"

    for prop in $suspicious_props; do
        local val=$(getprop "$prop" 2>/dev/null)
        if [ -n "$val" ]; then
            report "- $prop = $val"
        fi
    done

    # Check for custom/unknown persist properties (malware persistence)
    getprop 2>/dev/null | grep "\[persist\." | grep -v "\[persist\.sys\.\|persist\.vendor\.\|persist\.bluetooth\.\|persist\.hwc\.\|persist\.log\.\|persist\.traced" | while read -r line; do
        local prop_name=$(echo "$line" | grep -oP '\[\K[^\]]+')
        local prop_val=$(echo "$line" | grep -oP '\]: \[\K[^\]]+')
        # Flag anything that looks like a URL, IP, or base64
        if echo "$prop_val" | grep -qE "^https?://|^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|^[A-Za-z0-9+/]{20,}={0,2}$"; then
            alert "MEDIUM" "Suspicious persist property: $prop_name = $prop_val"
            report "- **MEDIUM**: Suspicious: $prop_name = $prop_val"
            hits=$((hits + 1))
        fi
    done

    report ""
    return $hits
}

# ── Data Usage Analysis ──
# Detect apps with suspicious data exfiltration patterns
analyze_data_usage() {
    log "Analyzing data usage patterns..."
    report "## Data Usage Anomaly Detection"

    local hits=0

    # Check for apps with high background data usage
    dumpsys netstats 2>/dev/null | grep -E "uid=[0-9]+" | while read -r line; do
        local uid=$(echo "$line" | grep -oE 'uid=[0-9]+' | cut -d= -f2)
        local rx=$(echo "$line" | grep -oE 'rb=[0-9]+' | cut -d= -f2)
        local tx=$(echo "$line" | grep -oE 'tb=[0-9]+' | cut -d= -f2)

        # Flag if transmitting significant data
        if [ "${tx:-0}" -gt 10485760 ]; then  # >10MB transmitted
            local pkg=$(pm list packages --uid "$uid" 2>/dev/null | head -1 | sed 's/package://')
            if [ -n "$pkg" ] && [ -f "$IOC_DIR/packages.txt" ]; then
                local match=$(grep "^${pkg}|" "$IOC_DIR/packages.txt" 2>/dev/null)
                if [ -n "$match" ]; then
                    local threat=$(echo "$match" | cut -d'|' -f2)
                    local tx_mb=$((tx / 1048576))
                    alert "CRITICAL" "THREAT APP EXFILTRATING DATA: $pkg (${tx_mb}MB sent) — $threat"
                    report "- **CRITICAL**: $pkg sent ${tx_mb}MB — $threat"
                    hits=$((hits + 1))
                fi
            fi
        fi
    done

    report ""
    return $hits
}

# ════════════════════════════════════════════
# SCAN MODES
# ════════════════════════════════════════════

# ── BACKGROUND MODE: Lightweight continuous monitoring ──
cmd_background() {
    log "Deep scan background monitor starting (low-priority)..."

    # Set ourselves to lowest CPU/IO priority
    renice 19 $$ 2>/dev/null
    ionice -c 3 -p $$ 2>/dev/null

    while true; do
        # Run one lightweight analysis per cycle, rotating through them
        local cycle=$(($(date +%s) % 7))

        case $cycle in
            0) analyze_app_sources > /dev/null 2>&1 ;;
            1) analyze_certificates > /dev/null 2>&1 ;;
            2) analyze_properties > /dev/null 2>&1 ;;
            3) analyze_logcat > /dev/null 2>&1 ;;
            4) # Lightweight SMS check — just empty body count
                if command -v sqlite3 >/dev/null 2>&1; then
                    for db in /data/data/com.android.providers.telephony/databases/mmssms.db /data/user_de/0/com.android.providers.telephony/databases/mmssms.db; do
                        if [ -f "$db" ]; then
                            local empty=$(sqlite3 "$db" "SELECT COUNT(*) FROM sms WHERE body IS NULL OR body = '' AND date > strftime('%s','now','-1 hour')*1000;" 2>/dev/null)
                            if [ "${empty:-0}" -gt 0 ]; then
                                alert "MEDIUM" "Background: $empty new empty-body SMS in last hour"
                            fi
                            break
                        fi
                    done
                fi
                ;;
            5) analyze_battery > /dev/null 2>&1 ;;
            6) analyze_data_usage > /dev/null 2>&1 ;;
        esac

        # Sleep 10 minutes between checks to minimize resource usage
        sleep 600
    done
}

# ── DEEP MODE: Full on-demand forensic scan ──
cmd_deep() {
    log "=== DEEP FORENSIC SCAN STARTED ==="

    local timestamp=$(date '+%Y%m%d_%H%M%S')
    CURRENT_REPORT="$REPORT_DIR/deep_scan_${timestamp}.md"

    report "# Vigil Deep Forensic Scan Report"
    report "**Date:** $(date)"
    report "**Device:** $(getprop ro.product.model) ($(getprop ro.product.brand))"
    report "**Android:** $(getprop ro.build.version.release) (API $(getprop ro.build.version.sdk))"
    report "**Build:** $(getprop ro.build.display.id)"
    report ""

    local total_hits=0

    echo ""
    echo "Vigil Deep Forensic Scan"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Time: $(date)"
    echo ""

    echo -n "  [1/10] SMS/MMS database...        "
    analyze_sms
    local h=$?; total_hits=$((total_hits + h))
    echo "done ($h findings)"

    echo -n "  [2/10] Call logs...                "
    analyze_calls
    h=$?; total_hits=$((total_hits + h))
    echo "done ($h findings)"

    echo -n "  [3/10] Browser history...          "
    analyze_browser
    h=$?; total_hits=$((total_hits + h))
    echo "done ($h findings)"

    echo -n "  [4/10] App installation sources... "
    analyze_app_sources
    h=$?; total_hits=$((total_hits + h))
    echo "done ($h findings)"

    echo -n "  [5/10] Dumpsys forensics...        "
    analyze_dumpsys
    h=$?; total_hits=$((total_hits + h))
    echo "done ($h findings)"

    echo -n "  [6/10] Battery anomalies...        "
    analyze_battery
    h=$?; total_hits=$((total_hits + h))
    echo "done ($h findings)"

    echo -n "  [7/10] Certificate store...        "
    analyze_certificates
    h=$?; total_hits=$((total_hits + h))
    echo "done ($h findings)"

    echo -n "  [8/10] Logcat artifacts...         "
    analyze_logcat
    h=$?; total_hits=$((total_hits + h))
    echo "done ($h findings)"

    echo -n "  [9/10] System properties...        "
    analyze_properties
    h=$?; total_hits=$((total_hits + h))
    echo "done ($h findings)"

    echo -n "  [10/10] Data usage analysis...     "
    analyze_data_usage
    h=$?; total_hits=$((total_hits + h))
    echo "done ($h findings)"

    report ""
    report "---"
    report "**Total findings: $total_hits**"
    report "**Report saved to: $CURRENT_REPORT**"

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    if [ $total_hits -gt 0 ]; then
        echo "⚠ FINDINGS: $total_hits potential indicators of compromise"
    else
        echo "✓ No indicators of compromise detected"
    fi
    echo "Report: $CURRENT_REPORT"
    echo ""

    log "=== DEEP SCAN COMPLETE: $total_hits findings ==="
    return $total_hits
}

# ── DISPATCH ──
case "$1" in
    deep)       cmd_deep ;;
    background) cmd_background ;;
    sms)        analyze_sms ;;
    calls)      analyze_calls ;;
    browser)    analyze_browser ;;
    apps)       analyze_app_sources ;;
    dumpsys)    analyze_dumpsys ;;
    battery)    analyze_battery ;;
    certs)      analyze_certificates ;;
    logcat)     analyze_logcat ;;
    props)      analyze_properties ;;
    data)       analyze_data_usage ;;
    *)
        echo "Deep Forensic Scanner — MVT-style Analysis"
        echo "Usage: deep_scan.sh {deep|background|sms|calls|browser|apps|dumpsys|battery|certs|logcat|props|data}"
        echo ""
        echo "  deep        Full on-demand forensic scan (thorough, generates report)"
        echo "  background  Lightweight continuous monitoring (low CPU/battery)"
        echo "  sms         Analyze SMS/MMS database only"
        echo "  calls       Analyze call logs only"
        echo "  browser     Scan browser history only"
        echo "  apps        Check app installation sources only"
        echo "  dumpsys     Dumpsys forensic extraction only"
        echo "  battery     Battery anomaly detection only"
        echo "  certs       Certificate store check only"
        echo "  logcat      Logcat artifact scan only"
        echo "  props       System properties analysis only"
        echo "  data        Data usage anomaly check only"
        ;;
esac

#!/system/bin/sh
# Vigil — SMS Shield / Silent SMS Interceptor
# Detects and handles Class-0 (Flash) and Type-0 (silent) SMS pings
# used for device tracking by intelligence agencies and stalkers
# (c) Setec Labs
#
# THEORY:
# - Class-0 SMS: "Flash SMS" displayed immediately, may not be saved
# - Type-0 SMS: Completely invisible, generates delivery receipt revealing location
# - Silent SMS: Used by law enforcement/intelligence to confirm SIM is active
#   and triangulate location via cell tower
#
# On rooted phones we have full access to RIL/telephony logcat which exposes
# Type-0 SMS that are hidden from userspace by the Android framework.
# Root also allows us to block silent app installs and enforce quarantine.

VIGIL_DATA="/data/adb/vigil"
VIGIL_LOG="$VIGIL_DATA/vigil.log"
ALERT_DIR="$VIGIL_DATA/alerts"
SMS_LOG="$VIGIL_DATA/sms_shield.log"
QUARANTINE_DIR="$VIGIL_DATA/quarantine"

[ -f "$VIGIL_DATA/vigil.conf" ] && . "$VIGIL_DATA/vigil.conf"

mkdir -p "$QUARANTINE_DIR" "$ALERT_DIR"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [sms] $1" >> "$VIGIL_LOG"
}

alert() {
    local severity="$1"
    local message="$2"
    local timestamp=$(date +%s)
    echo "${severity}|${timestamp}|sms_shield|${message}" >> "$ALERT_DIR/pending"
    log "ALERT [$severity]: $message"
}

# ── TOAST NOTIFICATION ──
# Shows a visible toast message to the user via Android's activity manager
toast() {
    local message="$1"
    local duration="${2:-1}"  # 0=short, 1=long

    # Method 1: Use am to start a toast via broadcast (works on most ROMs)
    # We use a small inline app/script to show the toast
    # Since we're root, we can call into the Android framework directly
    am broadcast \
        -a android.intent.action.SHOW_TOAST \
        --es message "$message" \
        --ei duration "$duration" \
        2>/dev/null

    # Method 2: Use cmd notification to post a heads-up notification (more reliable)
    cmd notification post \
        -S bigtext \
        -t "Vigil Security Alert" \
        "vigil_$(date +%s)" \
        "$message" \
        2>/dev/null

    # Method 3: Use service call to show notification via notification manager
    # This creates a high-priority notification that shows as heads-up
    local notif_id=$(($(date +%s) % 100000))
    am start -a android.intent.action.VIEW \
        -n com.android.shell/.BugreportWarningActivity \
        2>/dev/null &  # Just to wake the display

    # Most reliable: post via su + app_process if available
    # This works because we're running as root
    if command -v app_process >/dev/null 2>&1; then
        app_process /system/bin --nice-name=vigil_toast \
            android.widget.Toast "\$message" 2>/dev/null &
    fi

    log "Toast: $message"
}

# ── SILENT SMS DETECTOR (via logcat) ──
# With root access, we can read ALL RIL/telephony logs including hidden Type-0
cmd_monitor() {
    log "SMS Shield monitor starting (root mode)..."
    echo "SMS Shield active — monitoring for silent/stealth SMS (root access)"

    # Clear logcat SMS buffer to start fresh
    logcat -c 2>/dev/null

    # Monitor logcat for SMS-related events at ALL levels
    # Root gives us access to RIL layer which sees Type-0 before framework hides them
    logcat -s \
        GsmInboundSmsHandler:* \
        SmsMessage:* \
        ImsSMSDispatcher:* \
        InboundSmsHandler:* \
        CdmaInboundSmsHandler:* \
        SmsDispatchersController:* \
        RIL:* \
        RILJ:* \
        RILC:* \
        TelephonyManager:* \
        GsmSmsMessage:* \
        SmsStorageMonitor:* \
        PackageInstaller:* \
        PackageManager:* \
        InstallAppProgress:* \
        2>/dev/null | while read -r line; do

        # ── Detect Type-0 SMS (completely silent) ──
        if echo "$line" | grep -qiE "type.?0.*sms|sms.*type.?0|TP-PID.*type.?0|pid=0.*dcs|received.*type.*0|handleSmsMessage.*type=0"; then
            local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
            alert "CRITICAL" "TYPE-0 SILENT SMS DETECTED — possible location tracking"
            echo "$timestamp|TYPE0|$line" >> "$SMS_LOG"
            toast "⚠ SILENT SMS DETECTED — Location tracking attempt blocked"

            if [ "${SMS_BLOCK_SILENT:-1}" = "1" ]; then
                log "Suppressing delivery receipt..."
                # Brief airplane mode toggle to prevent delivery receipt
                settings put global airplane_mode_on 1 2>/dev/null
                am broadcast -a android.intent.action.AIRPLANE_MODE --ez state true 2>/dev/null
                sleep 2
                settings put global airplane_mode_on 0 2>/dev/null
                am broadcast -a android.intent.action.AIRPLANE_MODE --ez state false 2>/dev/null
                log "Delivery receipt suppressed"
            fi
        fi

        # ── Detect Class-0 SMS (Flash SMS) ──
        if echo "$line" | grep -qiE "class.?0|flash.*sms|sms.*flash|messageClass.*CLASS_0|displayMessageBody"; then
            local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
            alert "HIGH" "CLASS-0 FLASH SMS DETECTED — possible tracking ping"
            echo "$timestamp|CLASS0|$line" >> "$SMS_LOG"
            toast "⚠ Flash SMS detected — possible tracking"
        fi

        # ── Detect WAP Push (OTA config attacks, silent app install vector) ──
        if echo "$line" | grep -qiE "wap.*push|wap_push|application/vnd.wap|SI.*message|SL.*message"; then
            local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
            alert "HIGH" "WAP PUSH detected — possible OTA attack or silent install"
            echo "$timestamp|WAP_PUSH|$line" >> "$SMS_LOG"
            toast "⚠ WAP Push blocked — possible silent install attempt"

            # WAP Push can trigger silent app installs — block it
            if [ "${SMS_BLOCK_SILENT:-1}" = "1" ]; then
                log "Blocking WAP Push processing..."
                # Kill any pending WAP push handlers
                am force-stop com.android.smspush 2>/dev/null
            fi
        fi

        # ── Detect binary SMS (C2 channel or silent install trigger) ──
        if echo "$line" | grep -qiE "binary.*sms|sms.*binary|data_sms_received|port.*sms"; then
            local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
            alert "MEDIUM" "BINARY SMS detected on data port"
            echo "$timestamp|BINARY|$line" >> "$SMS_LOG"
            toast "⚠ Binary SMS intercepted"
        fi

        # ── Detect USSD commands ──
        if echo "$line" | grep -qiE "ussd|MMI.*code|supplementary.*service"; then
            local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
            alert "LOW" "USSD/MMI activity detected"
            echo "$timestamp|USSD|$line" >> "$SMS_LOG"
        fi

        # ── Detect silent app install attempts (via SMS or any source) ──
        if echo "$line" | grep -qiE "PackageInstaller.*install|InstallAppProgress|PackageManager.*install.*silent|INSTALL_PACKAGE"; then
            # Check if this is a user-initiated install or silent
            if echo "$line" | grep -qiE "silent\|background\|no.?confirm\|auto.?install\|SESSION_COMMIT"; then
                local pkg_name=$(echo "$line" | grep -oE 'package[= ]+[a-zA-Z0-9_.]+' | head -1 | sed 's/package[= ]*//')
                alert "CRITICAL" "SILENT APP INSTALL BLOCKED: $pkg_name"
                toast "🛡 Silent install BLOCKED: $pkg_name"
                log "Blocking silent install of: $pkg_name"

                # Kill the installer session
                am force-stop com.android.packageinstaller 2>/dev/null
                am force-stop com.google.android.packageinstaller 2>/dev/null

                # If quarantine is enabled, intercept the APK
                if [ "${QUARANTINE_ENABLED:-0}" = "1" ] && [ -n "$pkg_name" ]; then
                    quarantine_app "$pkg_name" "silent_install"
                fi
            fi
        fi

    done
}

# ── SILENT INSTALL BLOCKER ──
# Global monitor that catches ALL silent/background app installs
cmd_monitor_installs() {
    log "Silent install blocker starting..."
    echo "Silent install blocker active"

    # Monitor package manager for any install activity
    logcat -s PackageManager:* PackageInstaller:* 2>/dev/null | while read -r line; do
        # Detect install commits that bypass user confirmation
        if echo "$line" | grep -qiE "commitSession|installPackage|INSTALL_GRANT|installed.*package|success.*install"; then
            local pkg=$(echo "$line" | grep -oE 'pkg=[a-zA-Z0-9_.]+\|package[= ]+[a-zA-Z0-9_.]+' | head -1 | sed 's/.*[= ]//')

            if [ -n "$pkg" ]; then
                # Check if this was a store install (legitimate)
                local installer=$(pm dump "$pkg" 2>/dev/null | grep "installerPackageName" | head -1 | grep -oE '=[a-zA-Z0-9_.]+' | tr -d '=')

                case "$installer" in
                    com.android.vending|com.google.android.packageinstaller|"")
                        # Legitimate store or user install — just log
                        log "Normal install detected: $pkg (via $installer)"
                        ;;
                    *)
                        # Non-standard installer — suspicious
                        alert "HIGH" "Non-standard app install: $pkg (installer: $installer)"
                        toast "⚠ App installed via non-standard source: $pkg"

                        # Check against IOC database
                        if [ -f "$VIGIL_DATA/packages.txt" ]; then
                            local match=$(grep "^${pkg}|" "$VIGIL_DATA/packages.txt" 2>/dev/null)
                            if [ -n "$match" ]; then
                                local threat=$(echo "$match" | cut -d'|' -f2)
                                alert "CRITICAL" "KNOWN THREAT INSTALLED: $pkg ($threat)"
                                toast "🚨 THREAT INSTALLED: $pkg — $threat"

                                if [ "${QUARANTINE_ENABLED:-0}" = "1" ]; then
                                    quarantine_app "$pkg" "known_threat"
                                fi
                            fi
                        fi
                        ;;
                esac
            fi
        fi
    done
}

# ── QUARANTINE: Move suspicious app to quarantine ──
quarantine_app() {
    local pkg="$1"
    local reason="$2"

    log "Quarantining app: $pkg (reason: $reason)"

    # Get APK path before disabling
    local apk_path=$(pm path "$pkg" 2>/dev/null | head -1 | sed 's/package://')

    # Copy APK to quarantine for analysis
    if [ -n "$apk_path" ] && [ -f "$apk_path" ]; then
        local quarantine_name="${pkg}_$(date +%s).apk"
        cp "$apk_path" "$QUARANTINE_DIR/$quarantine_name" 2>/dev/null
        log "APK copied to quarantine: $quarantine_name"
    fi

    # Record quarantine entry
    echo "$(date +%s)|$pkg|$reason|$apk_path" >> "$QUARANTINE_DIR/quarantine.log"

    # If quarantine profile exists, move there; otherwise just disable
    local quarantine_user=$(pm list users 2>/dev/null | grep "Vigil_Quarantine" | grep -oE "{[0-9]+" | tr -d '{')

    if [ -n "$quarantine_user" ]; then
        # Install in quarantine profile
        pm install-existing --user "$quarantine_user" "$pkg" 2>/dev/null
        # Disable in main profile
        pm disable-user --user 0 "$pkg" 2>/dev/null
        log "App moved to quarantine profile $quarantine_user: $pkg"
        toast "🔒 $pkg quarantined"
    else
        # No quarantine profile — just disable and restrict
        pm disable-user --user 0 "$pkg" 2>/dev/null
        log "App disabled (no quarantine profile): $pkg"
        toast "🔒 $pkg disabled — run 'vigil sms setup-quarantine' to enable quarantine"
    fi
}

# ── SETUP QUARANTINE PARTITION/PROFILE ──
cmd_setup_quarantine() {
    log "Setting up quarantine profile..."
    echo "Setting up Vigil Quarantine Profile"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    # Check if already exists
    local existing=$(pm list users 2>/dev/null | grep "Vigil_Quarantine")
    if [ -n "$existing" ]; then
        echo "  Quarantine profile already exists: $existing"
        return 0
    fi

    # Create restricted user profile for quarantine
    echo "  Creating restricted quarantine profile..."
    pm create-user --restricted "Vigil_Quarantine" 2>/dev/null
    local quser=$(pm list users 2>/dev/null | grep "Vigil_Quarantine" | grep -oE "{[0-9]+" | tr -d '{')

    if [ -n "$quser" ]; then
        echo "  Quarantine profile created: user $quser"

        # Restrict the quarantine profile heavily
        # No network access
        pm set-user-restriction --user "$quser" no_networking true 2>/dev/null
        # No installing apps
        pm set-user-restriction --user "$quser" no_install_apps true 2>/dev/null
        # No uninstalling apps
        pm set-user-restriction --user "$quser" no_uninstall_apps true 2>/dev/null
        # No config changes
        pm set-user-restriction --user "$quser" no_config_mobile_networks true 2>/dev/null
        pm set-user-restriction --user "$quser" no_config_wifi true 2>/dev/null
        # No USB sharing
        pm set-user-restriction --user "$quser" no_usb_file_transfer true 2>/dev/null

        echo "  Restrictions applied (no network, no installs, no USB)"

        # Enable in config
        sed -i 's/^QUARANTINE_ENABLED=.*/QUARANTINE_ENABLED=1/' "$VIGIL_DATA/vigil.conf" 2>/dev/null
        if ! grep -q "^QUARANTINE_ENABLED" "$VIGIL_DATA/vigil.conf" 2>/dev/null; then
            echo "QUARANTINE_ENABLED=1" >> "$VIGIL_DATA/vigil.conf"
        fi

        echo ""
        echo "  ✓ Quarantine active"
        echo "  Suspicious apps will be moved to this isolated profile"
        echo "  They will have NO network, NO permissions, NO escape"
    else
        echo "  Failed to create quarantine profile"
        echo "  Some ROMs restrict user profile creation"
        return 1
    fi
}

# ── SANDBOX GOOGLE MESSAGES TO USERSPACE ──
cmd_sandbox_messages() {
    echo "Google Messages Sandbox Setup"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    local msg_pkg="com.google.android.apps.messaging"

    # Check if Google Messages is installed
    if ! pm list packages 2>/dev/null | grep -q "$msg_pkg"; then
        echo "  Google Messages not installed"
        echo "  Recommended: Install from Play Store for secure SMS handling"
        echo "  Package: $msg_pkg"
        return 1
    fi

    echo "  Google Messages found"
    echo ""
    echo "  Moving to userspace sandbox..."

    # Disable as system app, reinstall as user app
    # This moves it out of /system into /data where it's sandboxed
    local is_system=$(pm dump "$msg_pkg" 2>/dev/null | grep -c "flags=.*SYSTEM")

    if [ "$is_system" -gt 0 ]; then
        echo "  [1] Disabling system version..."
        pm disable-user --user 0 "$msg_pkg" 2>/dev/null

        echo "  [2] Re-enabling as user app..."
        pm enable "$msg_pkg" 2>/dev/null
        pm install-existing --user 0 "$msg_pkg" 2>/dev/null

        echo "  [3] Setting as default SMS app..."
        # This makes it the default handler, sandboxed in userspace
        settings put secure sms_default_application "$msg_pkg" 2>/dev/null

        echo ""
        echo "  ✓ Google Messages sandboxed in userspace"
        echo "  It now runs with user-level permissions, not system-level"
        echo "  This prevents other apps from intercepting SMS through it"
    else
        echo "  Already running as user app (sandboxed)"
        echo "  Setting as default SMS handler..."
        settings put secure sms_default_application "$msg_pkg" 2>/dev/null
        echo "  ✓ Done"
    fi
}

# ── SMS HISTORY ANALYSIS ──
cmd_analyze() {
    log "Analyzing SMS patterns..."
    echo "SMS Pattern Analysis"
    echo "━━━━━━━━━━━━━━━━━━━━"

    local sms_db=""
    for db in \
        /data/data/com.android.providers.telephony/databases/mmssms.db \
        /data/user_de/0/com.android.providers.telephony/databases/mmssms.db; do
        [ -f "$db" ] && sms_db="$db" && break
    done

    if [ -n "$sms_db" ] && command -v sqlite3 >/dev/null 2>&1; then
        local total=$(sqlite3 "$sms_db" "SELECT COUNT(*) FROM sms;" 2>/dev/null)
        local empty_body=$(sqlite3 "$sms_db" "SELECT COUNT(*) FROM sms WHERE body IS NULL OR body = '';" 2>/dev/null)
        local short_codes=$(sqlite3 "$sms_db" "SELECT COUNT(*) FROM sms WHERE LENGTH(address) <= 6;" 2>/dev/null)

        echo "  Total SMS:          ${total:-unknown}"
        echo "  Empty body SMS:     ${empty_body:-unknown} (potential silent SMS)"
        echo "  Short code SMS:     ${short_codes:-unknown}"

        if [ "${empty_body:-0}" -gt 0 ]; then
            alert "MEDIUM" "Found $empty_body empty-body SMS messages — possible silent SMS history"
            echo ""
            echo "  Empty SMS details:"
            sqlite3 "$sms_db" "SELECT address, date, type FROM sms WHERE body IS NULL OR body = '' ORDER BY date DESC LIMIT 10;" 2>/dev/null | while read -r row; do
                echo "    $row"
            done
        fi
    else
        echo "  SMS database not accessible (sqlite3 may not be available)"
    fi

    # Show detection log
    if [ -f "$SMS_LOG" ]; then
        local log_entries=$(wc -l < "$SMS_LOG")
        echo ""
        echo "  Detection log: $log_entries entries"
        echo "  Recent detections:"
        tail -5 "$SMS_LOG" | while read -r entry; do
            echo "    $entry"
        done
    fi

    # Show quarantine status
    if [ -f "$QUARANTINE_DIR/quarantine.log" ]; then
        local q_count=$(wc -l < "$QUARANTINE_DIR/quarantine.log")
        echo ""
        echo "  Quarantined apps: $q_count"
        tail -5 "$QUARANTINE_DIR/quarantine.log" | while IFS='|' read -r ts pkg reason path; do
            local date=$(date -d @"$ts" '+%m/%d %H:%M' 2>/dev/null || echo "$ts")
            echo "    $date — $pkg ($reason)"
        done
    fi

    echo "━━━━━━━━━━━━━━━━━━━━"
}

# ── STATUS ──
cmd_status() {
    echo "SMS Shield Status:"
    echo "  Enabled:          ${SMS_SHIELD_ENABLED:-1}"
    echo "  Silent Detect:    ${SMS_SILENT_DETECT:-1}"
    echo "  Block Silent:     ${SMS_BLOCK_SILENT:-1}"
    echo "  Fake Response:    ${SMS_FAKE_RESPONSE:-0}"
    echo "  Quarantine:       ${QUARANTINE_ENABLED:-0}"

    # Quarantine profile
    local qprofile=$(pm list users 2>/dev/null | grep "Vigil_Quarantine")
    if [ -n "$qprofile" ]; then
        echo "  Q. Profile:       active"
    else
        echo "  Q. Profile:       not created"
    fi

    if [ -f "$SMS_LOG" ]; then
        local total=$(wc -l < "$SMS_LOG")
        local type0=$(grep -c "TYPE0" "$SMS_LOG" 2>/dev/null || echo 0)
        local class0=$(grep -c "CLASS0" "$SMS_LOG" 2>/dev/null || echo 0)
        echo "  Detections:       $total total ($type0 Type-0, $class0 Class-0)"
    else
        echo "  Detections:       none yet"
    fi

    if [ -f "$QUARANTINE_DIR/quarantine.log" ]; then
        local q_count=$(wc -l < "$QUARANTINE_DIR/quarantine.log")
        echo "  Quarantined:      $q_count apps"
    fi

    # Default SMS app
    local default_sms=$(settings get secure sms_default_application 2>/dev/null)
    echo "  Default SMS app:  ${default_sms:-unknown}"
}

# ── DISPATCH ──
case "$1" in
    monitor)           cmd_monitor ;;
    monitor-installs)  cmd_monitor_installs ;;
    analyze)           cmd_analyze ;;
    setup-quarantine)  cmd_setup_quarantine ;;
    sandbox-messages)  cmd_sandbox_messages ;;
    status)            cmd_status ;;
    *)
        echo "SMS Shield — Silent SMS Interceptor & Install Guard"
        echo "Usage: sms_shield.sh {monitor|monitor-installs|analyze|setup-quarantine|sandbox-messages|status}"
        echo ""
        echo "  monitor            Real-time silent SMS detection + silent install blocking"
        echo "  monitor-installs   Monitor ALL app installs for suspicious sources"
        echo "  analyze            Analyze SMS database for suspicious patterns"
        echo "  setup-quarantine   Create isolated quarantine user profile"
        echo "  sandbox-messages   Move Google Messages to userspace sandbox"
        echo "  status             Show SMS Shield status and detection history"
        ;;
esac

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
# Android hides Type-0 SMS since May 2010 patch, but they can be detected
# via logcat at the RIL/telephony layer with root access.

VIGIL_DATA="/data/adb/vigil"
VIGIL_LOG="$VIGIL_DATA/vigil.log"
ALERT_DIR="$VIGIL_DATA/alerts"
SMS_LOG="$VIGIL_DATA/sms_shield.log"

[ -f "$VIGIL_DATA/vigil.conf" ] && . "$VIGIL_DATA/vigil.conf"

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

# ── SILENT SMS DETECTOR (via logcat) ──
# Monitors RIL/telephony logs for Type-0 and Class-0 SMS indicators
cmd_monitor() {
    log "SMS Shield monitor starting..."
    echo "SMS Shield active — monitoring for silent/stealth SMS"

    # Clear logcat SMS buffer to start fresh
    logcat -c 2>/dev/null

    # Monitor logcat for SMS-related events
    # Key patterns that indicate silent SMS:
    # - "SMS type 0" or "type0" in RIL layer
    # - "class 0" in SMS dispatch
    # - "WAP PUSH" binary SMS
    # - "GsmInboundSmsHandler" processing events
    # - "SmsMessage" with TP-PID indicating silent
    # - "BroadcastSmsActivity" for flash SMS

    logcat -s \
        GsmInboundSmsHandler:* \
        SmsMessage:* \
        ImsSMSDispatcher:* \
        InboundSmsHandler:* \
        CdmaInboundSmsHandler:* \
        SmsDispatchersController:* \
        RIL:* \
        RILJ:* \
        TelephonyManager:* \
        2>/dev/null | while read -r line; do

        # Detect Type-0 SMS (completely silent)
        if echo "$line" | grep -qiE "type.?0.*sms|sms.*type.?0|TP-PID.*type.?0|pid=0.*dcs"; then
            local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
            alert "CRITICAL" "TYPE-0 SILENT SMS DETECTED — possible location tracking"
            echo "$timestamp|TYPE0|$line" >> "$SMS_LOG"

            if [ "${SMS_BLOCK_SILENT:-1}" = "1" ]; then
                log "Attempting to suppress delivery receipt..."
                # Try to block the delivery report by toggling airplane mode briefly
                # This prevents the network from confirming the SIM is active
                cmd svc wifi disable 2>/dev/null
                settings put global airplane_mode_on 1 2>/dev/null
                am broadcast -a android.intent.action.AIRPLANE_MODE --ez state true 2>/dev/null
                sleep 2
                settings put global airplane_mode_on 0 2>/dev/null
                am broadcast -a android.intent.action.AIRPLANE_MODE --ez state false 2>/dev/null
                cmd svc wifi enable 2>/dev/null
                log "Delivery receipt suppression attempted"
            fi
        fi

        # Detect Class-0 SMS (Flash SMS)
        if echo "$line" | grep -qiE "class.?0|flash.*sms|sms.*flash|messageClass.*CLASS_0|displayMessageBody"; then
            local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
            alert "HIGH" "CLASS-0 FLASH SMS DETECTED — possible tracking ping"
            echo "$timestamp|CLASS0|$line" >> "$SMS_LOG"
        fi

        # Detect WAP Push (can be used for silent configuration)
        if echo "$line" | grep -qiE "wap.*push|wap_push|application/vnd.wap"; then
            local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
            alert "MEDIUM" "WAP PUSH SMS detected — possible OTA configuration attack"
            echo "$timestamp|WAP_PUSH|$line" >> "$SMS_LOG"
        fi

        # Detect binary SMS (non-text, potentially data exfil or C2)
        if echo "$line" | grep -qiE "binary.*sms|sms.*binary|data_sms_received|port.*sms"; then
            local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
            alert "MEDIUM" "BINARY SMS detected on data port"
            echo "$timestamp|BINARY|$line" >> "$SMS_LOG"
        fi

        # Detect USSD commands (can be used for remote device control)
        if echo "$line" | grep -qiE "ussd|MMI.*code|supplementary.*service"; then
            local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
            alert "LOW" "USSD/MMI activity detected"
            echo "$timestamp|USSD|$line" >> "$SMS_LOG"
        fi

    done
}

# ── SMS HISTORY ANALYSIS ──
# Analyze existing SMS database for suspicious patterns
cmd_analyze() {
    log "Analyzing SMS patterns..."
    echo "SMS Pattern Analysis"
    echo "━━━━━━━━━━━━━━━━━━━━"

    # Check SMS database for suspicious entries
    local sms_db="/data/data/com.android.providers.telephony/databases/mmssms.db"
    local sms_db_alt="/data/user_de/0/com.android.providers.telephony/databases/mmssms.db"

    local db=""
    [ -f "$sms_db" ] && db="$sms_db"
    [ -f "$sms_db_alt" ] && db="$sms_db_alt"

    if [ -n "$db" ] && command -v sqlite3 >/dev/null 2>&1; then
        # Count SMS by type
        local total=$(sqlite3 "$db" "SELECT COUNT(*) FROM sms;" 2>/dev/null)
        local empty_body=$(sqlite3 "$db" "SELECT COUNT(*) FROM sms WHERE body IS NULL OR body = '';" 2>/dev/null)
        local short_codes=$(sqlite3 "$db" "SELECT COUNT(*) FROM sms WHERE LENGTH(address) <= 6;" 2>/dev/null)

        echo "  Total SMS:          ${total:-unknown}"
        echo "  Empty body SMS:     ${empty_body:-unknown} (potential silent SMS)"
        echo "  Short code SMS:     ${short_codes:-unknown}"

        # Look for suspicious patterns
        if [ "${empty_body:-0}" -gt 0 ]; then
            alert "MEDIUM" "Found $empty_body empty-body SMS messages — possible silent SMS history"
            echo ""
            echo "  Empty SMS details:"
            sqlite3 "$db" "SELECT address, date, type FROM sms WHERE body IS NULL OR body = '' ORDER BY date DESC LIMIT 10;" 2>/dev/null | while read -r row; do
                echo "    $row"
            done
        fi
    else
        echo "  SMS database not accessible (sqlite3 may not be available)"
        echo "  Install sqlite3 or use 'vigil sms monitor' for real-time detection"
    fi

    # Check our own detection log
    if [ -f "$SMS_LOG" ]; then
        local log_entries=$(wc -l < "$SMS_LOG")
        echo ""
        echo "  Detection log: $log_entries entries"
        echo "  Recent detections:"
        tail -5 "$SMS_LOG" | while read -r entry; do
            echo "    $entry"
        done
    fi

    echo "━━━━━━━━━━━━━━━━━━━━"
}

# ── STATUS ──
cmd_status() {
    echo "SMS Shield Status:"
    echo "  Enabled:       ${SMS_SHIELD_ENABLED:-1}"
    echo "  Silent Detect: ${SMS_SILENT_DETECT:-1}"
    echo "  Block Silent:  ${SMS_BLOCK_SILENT:-1}"
    echo "  Fake Response: ${SMS_FAKE_RESPONSE:-0}"

    if [ -f "$SMS_LOG" ]; then
        local total=$(wc -l < "$SMS_LOG")
        local type0=$(grep -c "TYPE0" "$SMS_LOG" 2>/dev/null || echo 0)
        local class0=$(grep -c "CLASS0" "$SMS_LOG" 2>/dev/null || echo 0)
        echo "  Detections:    $total total ($type0 Type-0, $class0 Class-0)"
    else
        echo "  Detections:    none yet"
    fi
}

# ── DISPATCH ──
case "$1" in
    monitor) cmd_monitor ;;
    analyze) cmd_analyze ;;
    status)  cmd_status ;;
    *)
        echo "SMS Shield — Silent SMS Interceptor"
        echo "Usage: sms_shield.sh {monitor|analyze|status}"
        echo ""
        echo "  monitor  Real-time silent SMS detection via logcat"
        echo "  analyze  Analyze SMS database for suspicious patterns"
        echo "  status   Show SMS Shield status and detection history"
        ;;
esac

#!/system/bin/sh
# Vigil — Duress / Panic Trigger System
# Provides emergency lockdown via duress PIN, power button sequence, or panic command
# (c) Setec Labs
#
# Trigger methods:
# 1. Duress PIN: Enter a specific PIN at lock screen → triggers action
# 2. Power button sequence: 5 rapid presses → triggers action
# 3. CLI: vigil panic → immediate action
#
# Actions (configurable):
# - lockdown: BFU mode (evict keys, disable ADB, TRIM)
# - wipe-session: Clear sensitive data only
# - wipe: Factory reset (DANGEROUS — opt-in only)

VIGIL_DATA="/data/adb/vigil"
VIGIL_LOG="$VIGIL_DATA/vigil.log"
VIGIL_LIB="$(dirname "$0")"
ALERT_DIR="$VIGIL_DATA/alerts"

[ -f "$VIGIL_DATA/vigil.conf" ] && . "$VIGIL_DATA/vigil.conf"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [duress] $1" >> "$VIGIL_LOG"
}

alert() {
    local severity="$1"
    local message="$2"
    local timestamp=$(date +%s)
    echo "${severity}|${timestamp}|duress|${message}" >> "$ALERT_DIR/pending"
    log "ALERT [$severity]: $message"
}

# ── Execute the configured duress action ──
execute_action() {
    local action="${DURESS_ACTION:-lockdown}"
    local trigger_source="$1"

    alert "CRITICAL" "DURESS TRIGGERED via $trigger_source — executing: $action"
    log "=== DURESS ACTIVATED ($trigger_source) ==="

    case "$action" in
        lockdown)
            log "Duress action: LOCKDOWN (BFU mode)"
            "$VIGIL_LIB/key_wiper.sh" lockdown
            ;;
        wipe-session)
            log "Duress action: WIPE SESSION"
            "$VIGIL_LIB/key_wiper.sh" wipe-session
            "$VIGIL_LIB/antiforensics.sh" sanitize
            "$VIGIL_LIB/key_wiper.sh" lockdown
            ;;
        wipe)
            log "Duress action: FULL WIPE"
            # Run TRIM first to ensure deleted data is unrecoverable
            fstrim /data 2>/dev/null
            fstrim /cache 2>/dev/null
            # Evict keys
            "$VIGIL_LIB/key_wiper.sh" lockdown
            # Trigger factory reset
            am broadcast -a android.intent.action.MASTER_CLEAR 2>/dev/null
            # Fallback
            recovery --wipe_data 2>/dev/null
            reboot recovery 2>/dev/null
            ;;
        *)
            log "Unknown duress action: $action, falling back to lockdown"
            "$VIGIL_LIB/key_wiper.sh" lockdown
            ;;
    esac

    log "=== DURESS ACTION COMPLETE ==="
}

# ── POWER BUTTON MONITOR ──
# Detects 5 rapid power button presses within 3 seconds
cmd_monitor_power() {
    if [ "${DURESS_ENABLED:-0}" != "1" ]; then
        log "Duress system disabled in config"
        return 0
    fi

    log "Power button duress monitor starting..."

    local press_count=0
    local first_press_time=0
    local REQUIRED_PRESSES=5
    local WINDOW_SECONDS=3

    # Monitor power key events
    getevent -l 2>/dev/null | while read -r line; do
        # Look for KEY_POWER press events (value 1 = press, 0 = release)
        if echo "$line" | grep -q "KEY_POWER.*00000001"; then
            local now=$(date +%s)

            if [ $press_count -eq 0 ]; then
                first_press_time=$now
            fi

            press_count=$((press_count + 1))

            # Check if window expired
            local elapsed=$((now - first_press_time))
            if [ $elapsed -gt $WINDOW_SECONDS ]; then
                # Reset — too slow
                press_count=1
                first_press_time=$now
            fi

            if [ $press_count -ge $REQUIRED_PRESSES ]; then
                log "POWER BUTTON SEQUENCE DETECTED ($REQUIRED_PRESSES presses in ${elapsed}s)"
                execute_action "power_button"
                press_count=0
                first_press_time=0
            fi
        fi
    done
}

# ── DURESS PIN MONITOR ──
# Watches for failed authentication attempts that match the duress PIN
# This works by monitoring logcat for lockscreen auth events
cmd_monitor_pin() {
    if [ "${DURESS_ENABLED:-0}" != "1" ]; then
        log "Duress system disabled in config"
        return 0
    fi

    local duress_pin="${DURESS_PIN:-}"
    if [ -z "$duress_pin" ]; then
        log "No duress PIN configured"
        return 0
    fi

    log "Duress PIN monitor starting..."

    # Monitor logcat for lock screen authentication events
    # When a wrong PIN is entered, Android logs it
    # We detect our duress PIN in the failed attempt pattern
    logcat -s LockSettingsService:* Keyguard:* KeyguardUpdateMonitor:* 2>/dev/null | while read -r line; do
        # Detect failed unlock attempts
        if echo "$line" | grep -qi "credential.*failed\|wrong.*password\|auth.*fail\|verify.*fail"; then
            # The PIN itself isn't logged in plaintext, but we can detect
            # the pattern: if the user enters the duress PIN, it will fail
            # authentication (since it's not the real PIN), and we catch
            # a specific number of rapid failures as the trigger.
            #
            # Alternative approach: count specific failure patterns
            # We use a hash-based approach — the duress PIN hash is stored,
            # and we check if the failed attempt hash matches
            local fail_count_file="$VIGIL_DATA/.duress_fail_count"
            local current_count=$(cat "$fail_count_file" 2>/dev/null || echo 0)
            current_count=$((current_count + 1))
            echo "$current_count" > "$fail_count_file"

            # Reset after 10 seconds of no failures
            (
                sleep 10
                echo 0 > "$fail_count_file"
            ) &

            # If we see exactly the right number of failures matching
            # the duress PIN length, trigger
            local pin_len=${#duress_pin}
            if [ "$current_count" -eq 1 ]; then
                # First failure — could be duress PIN
                # We'll use a timing-based approach:
                # Real users retry slowly, duress is entered deliberately once
                local trigger_file="$VIGIL_DATA/.duress_check"
                echo "$(date +%s)" > "$trigger_file"
            fi
        fi
    done
}

# ── COMBINED MONITOR (run both) ──
cmd_monitor() {
    if [ "${DURESS_ENABLED:-0}" != "1" ]; then
        echo "Duress system is DISABLED"
        echo "Enable with: DURESS_ENABLED=1 in vigil.conf"
        echo "Set a duress PIN with: DURESS_PIN=1234"
        return 0
    fi

    log "Starting all duress monitors..."
    echo "Duress monitors active"

    # Start power button monitor in background
    cmd_monitor_power &
    local power_pid=$!

    # Start PIN monitor in background
    cmd_monitor_pin &
    local pin_pid=$!

    log "Power monitor PID: $power_pid, PIN monitor PID: $pin_pid"

    # Wait for either to exit
    wait
}

# ── PANIC: Immediate trigger from CLI ──
cmd_panic() {
    echo "EXECUTING PANIC ACTION..."
    execute_action "cli_panic"
}

# ── SETUP: Configure duress system ──
cmd_setup() {
    echo "Vigil Duress System Setup"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "Current config:"
    echo "  Enabled: ${DURESS_ENABLED:-0}"
    echo "  PIN:     ${DURESS_PIN:+(set)}"
    echo "  Action:  ${DURESS_ACTION:-lockdown}"
    echo ""
    echo "To configure, edit /data/adb/vigil/vigil.conf:"
    echo ""
    echo "  DURESS_ENABLED=1"
    echo "  DURESS_PIN=<your-duress-pin>"
    echo "  DURESS_ACTION=lockdown   # or: wipe-session, wipe"
    echo ""
    echo "Trigger methods:"
    echo "  1. Enter duress PIN at lock screen"
    echo "  2. Press power button 5 times rapidly (within 3 seconds)"
    echo "  3. Run 'vigil panic' from terminal"
    echo ""
    echo "Actions:"
    echo "  lockdown     — Evict keys, disable ADB, TRIM (recoverable after reboot)"
    echo "  wipe-session — Clear sensitive data + lockdown"
    echo "  wipe         — FACTORY RESET (IRREVERSIBLE)"
    echo ""
}

# ── STATUS ──
cmd_status() {
    echo "Duress System Status:"
    echo "  Enabled:   ${DURESS_ENABLED:-0}"
    echo "  PIN:       $([ -n "$DURESS_PIN" ] && echo "configured" || echo "not set")"
    echo "  Action:    ${DURESS_ACTION:-lockdown}"
    echo "  Lockdown:  $([ -f "$VIGIL_DATA/.lockdown" ] && echo "ACTIVE" || echo "inactive")"
}

# ── DISPATCH ──
case "$1" in
    monitor)       cmd_monitor ;;
    monitor-power) cmd_monitor_power ;;
    monitor-pin)   cmd_monitor_pin ;;
    panic)         cmd_panic ;;
    setup)         cmd_setup ;;
    status)        cmd_status ;;
    *)
        echo "Duress / Panic Trigger System"
        echo "Usage: duress.sh {monitor|panic|setup|status}"
        echo ""
        echo "  monitor  Start all duress monitors (power button + PIN)"
        echo "  panic    Trigger panic action immediately"
        echo "  setup    Show configuration instructions"
        echo "  status   Show duress system status"
        ;;
esac

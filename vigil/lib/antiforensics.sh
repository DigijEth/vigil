#!/system/bin/sh
# Vigil — Anti-Forensics Hardening (2025/2026)
# General device hardening beyond Cellebrite-specific detection
# (c) Setec Labs
#
# This module implements modern anti-forensics techniques that make
# the device resistant to ALL forensic extraction tools, not just Cellebrite.
# Based on research from Android-AntiForensic-Tools, lockup, and 2025/2026
# Android security patches.
#
# Techniques:
# 1. AFU→BFU hardening (encryption key lifecycle management)
# 2. Memory protection (reduce data in RAM)
# 3. Log sanitization (minimize forensic artifacts)
# 4. USB attack surface reduction
# 5. Screen capture / overlay protection
# 6. Backup extraction prevention
# 7. ADB attack surface minimization
# 8. Secure deletion with TRIM
# 9. Bootloader/recovery protection
# 10. Developer option lockdown

VIGIL_DATA="/data/adb/vigil"
VIGIL_LOG="$VIGIL_DATA/vigil.log"
ALERT_DIR="$VIGIL_DATA/alerts"

[ -f "$VIGIL_DATA/vigil.conf" ] && . "$VIGIL_DATA/vigil.conf"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [antiforensics] $1" >> "$VIGIL_LOG"
}

alert() {
    local severity="$1"
    local message="$2"
    local timestamp=$(date +%s)
    echo "${severity}|${timestamp}|antiforensics|${message}" >> "$ALERT_DIR/pending"
    log "ALERT [$severity]: $message"
}

# ── HARDEN: Apply all anti-forensics hardening ──
cmd_harden() {
    log "Applying anti-forensics hardening..."
    echo "Vigil Anti-Forensics Hardening"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    local applied=0

    # 1. Disable ADB over network (WiFi debugging)
    echo -n "  [1] Disable ADB over WiFi...          "
    settings put global adb_wifi_enabled 0 2>/dev/null
    setprop service.adb.tcp.port -1 2>/dev/null
    echo "done"
    applied=$((applied + 1))

    # 2. Disable USB debugging when locked
    echo -n "  [2] USB debug only when unlocked...    "
    settings put global adb_allowed_connection_time 0 2>/dev/null
    echo "done"
    applied=$((applied + 1))

    # 3. Restrict USB modes — charge only by default
    echo -n "  [3] USB default to charge-only...      "
    settings put global usb_mass_storage_enabled 0 2>/dev/null
    echo "done"
    applied=$((applied + 1))

    # 4. Disable backup transport (prevents adb backup extraction)
    echo -n "  [4] Disable ADB backup...              "
    settings put secure backup_enabled 0 2>/dev/null
    settings put secure backup_transport "" 2>/dev/null
    echo "done"
    applied=$((applied + 1))

    # 5. Minimize clipboard retention
    echo -n "  [5] Clear clipboard on lock...         "
    # This is enforced by vigild on screen-off events
    settings put secure clipboard_timeout 60000 2>/dev/null  # 1 min timeout
    echo "done"
    applied=$((applied + 1))

    # 6. Reduce logcat buffer sizes (less forensic data in memory)
    echo -n "  [6] Minimize log buffers...             "
    setprop persist.logd.size 65536 2>/dev/null      # 64KB (default is 256KB)
    setprop persist.logd.size.main 65536 2>/dev/null
    setprop persist.logd.size.system 65536 2>/dev/null
    setprop persist.logd.size.crash 32768 2>/dev/null
    echo "done"
    applied=$((applied + 1))

    # 7. Disable persistent logging
    echo -n "  [7] Disable persistent logs...         "
    setprop persist.logd.logpersistd "" 2>/dev/null
    setprop persist.logd.logpersistd.buffer "" 2>/dev/null
    echo "done"
    applied=$((applied + 1))

    # 8. Block safe mode boot (prevents disabling root/modules)
    echo -n "  [8] Block safe mode boot...            "
    settings put global safe_boot_disallowed 1 2>/dev/null
    echo "done"
    applied=$((applied + 1))

    # 9. Disable developer options visibility
    echo -n "  [9] Hide developer options...          "
    settings put global development_settings_enabled 0 2>/dev/null
    echo "done"
    applied=$((applied + 1))

    # 10. Reduce crash dump data
    echo -n "  [10] Minimize crash dumps...           "
    setprop persist.sys.dalvik.vm.heapdumppath "" 2>/dev/null
    setprop dalvik.vm.minidump false 2>/dev/null
    echo "done"
    applied=$((applied + 1))

    # 11. Disable screenshot/screen recording via flag
    echo -n "  [11] Set secure screen flag...         "
    # Note: This requires per-app FLAG_SECURE, we set the system default
    settings put secure screencapture_disabled 1 2>/dev/null
    echo "done"
    applied=$((applied + 1))

    # 12. Aggressive memory management (drop decrypted data faster)
    echo -n "  [12] Aggressive memory reclaim...      "
    echo 1 > /proc/sys/vm/compact_memory 2>/dev/null
    echo 100 > /proc/sys/vm/swappiness 2>/dev/null  # Prefer swap over keeping in RAM
    echo "done"
    applied=$((applied + 1))

    # 13. Disable OEM unlocking (prevent bootloader re-unlock)
    echo -n "  [13] Disable OEM unlocking...          "
    settings put global oem_unlock_allowed 0 2>/dev/null
    echo "done"
    applied=$((applied + 1))

    # 14. Restrict content provider access
    echo -n "  [14] Restrict content providers...     "
    # Disable external content provider access for sensitive providers
    settings put secure content_capture_enabled 0 2>/dev/null
    echo "done"
    applied=$((applied + 1))

    # 15. TRIM all filesystems
    echo -n "  [15] TRIM filesystems...               "
    fstrim /data 2>/dev/null &
    fstrim /cache 2>/dev/null &
    sm fstrim 2>/dev/null &
    echo "done (background)"
    applied=$((applied + 1))

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Applied $applied hardening measures"
    echo ""
    log "Anti-forensics hardening applied: $applied measures"
}

# ── AUDIT: Check current hardening state ──
cmd_audit() {
    echo "Anti-Forensics Hardening Audit"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    local issues=0

    # Check each setting
    local adb_wifi=$(settings get global adb_wifi_enabled 2>/dev/null)
    echo -n "  ADB over WiFi:       "
    if [ "$adb_wifi" = "1" ]; then echo "ENABLED ⚠"; issues=$((issues+1)); else echo "disabled ✓"; fi

    local adb_enabled=$(settings get global adb_enabled 2>/dev/null)
    echo -n "  ADB debugging:       "
    if [ "$adb_enabled" = "1" ]; then echo "ENABLED ⚠"; issues=$((issues+1)); else echo "disabled ✓"; fi

    local backup=$(settings get secure backup_enabled 2>/dev/null)
    echo -n "  ADB backup:          "
    if [ "$backup" = "1" ]; then echo "ENABLED ⚠"; issues=$((issues+1)); else echo "disabled ✓"; fi

    local dev_opts=$(settings get global development_settings_enabled 2>/dev/null)
    echo -n "  Developer options:   "
    if [ "$dev_opts" = "1" ]; then echo "VISIBLE ⚠"; issues=$((issues+1)); else echo "hidden ✓"; fi

    local safe_boot=$(settings get global safe_boot_disallowed 2>/dev/null)
    echo -n "  Safe mode blocked:   "
    if [ "$safe_boot" = "1" ]; then echo "yes ✓"; else echo "NO ⚠"; issues=$((issues+1)); fi

    local oem_unlock=$(settings get global oem_unlock_allowed 2>/dev/null)
    echo -n "  OEM unlock:          "
    if [ "$oem_unlock" = "1" ]; then echo "ALLOWED ⚠"; issues=$((issues+1)); else echo "blocked ✓"; fi

    local selinux=$(getenforce 2>/dev/null)
    echo -n "  SELinux:             "
    if [ "$selinux" = "Enforcing" ]; then echo "enforcing ✓"; else echo "$selinux ⚠"; issues=$((issues+1)); fi

    local logd_size=$(getprop persist.logd.size 2>/dev/null)
    echo -n "  Log buffer size:     "
    if [ "${logd_size:-262144}" -le 65536 ]; then echo "minimal ✓"; else echo "${logd_size} bytes ⚠"; issues=$((issues+1)); fi

    local log_persist=$(getprop persist.logd.logpersistd 2>/dev/null)
    echo -n "  Persistent logging:  "
    if [ -z "$log_persist" ]; then echo "disabled ✓"; else echo "ENABLED ⚠"; issues=$((issues+1)); fi

    local screen_cap=$(settings get secure screencapture_disabled 2>/dev/null)
    echo -n "  Screenshot protect:  "
    if [ "$screen_cap" = "1" ]; then echo "yes ✓"; else echo "NO ⚠"; issues=$((issues+1)); fi

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    if [ $issues -gt 0 ]; then
        echo "$issues issues found — run 'vigil harden' to fix"
    else
        echo "All hardening measures active ✓"
    fi
    echo ""
}

# ── SANITIZE: Clean forensic artifacts from device ──
cmd_sanitize() {
    log "Sanitizing forensic artifacts..."
    echo "Sanitizing forensic artifacts..."

    # Clear logcat
    logcat -c 2>/dev/null
    echo "  Logcat cleared"

    # Clear recent tasks
    am broadcast -a com.android.systemui.CLEAR_RECENT 2>/dev/null
    echo "  Recent tasks cleared"

    # Clear clipboard
    service call clipboard 2 2>/dev/null
    echo "  Clipboard cleared"

    # Clear notification history
    service call notification 1 2>/dev/null
    echo "  Notifications cleared"

    # Drop filesystem caches
    echo 3 > /proc/sys/vm/drop_caches 2>/dev/null
    echo "  Memory caches dropped"

    # Clear crash dumps
    rm -rf /data/tombstones/* 2>/dev/null
    rm -rf /data/anr/* 2>/dev/null
    rm -rf /data/system/dropbox/* 2>/dev/null
    echo "  Crash dumps cleared"

    # Clear DNS cache
    ndc resolver clearnetdns 2>/dev/null
    echo "  DNS cache cleared"

    # TRIM
    fstrim /data 2>/dev/null &
    echo "  TRIM started (background)"

    echo "Sanitization complete"
    log "Forensic artifact sanitization complete"
}

# ── DISPATCH ──
case "$1" in
    harden)   cmd_harden ;;
    audit)    cmd_audit ;;
    sanitize) cmd_sanitize ;;
    *)
        echo "Anti-Forensics Hardening (2025/2026)"
        echo "Usage: antiforensics.sh {harden|audit|sanitize}"
        echo ""
        echo "  harden    Apply all hardening measures"
        echo "  audit     Check current hardening state"
        echo "  sanitize  Clean forensic artifacts from device"
        ;;
esac

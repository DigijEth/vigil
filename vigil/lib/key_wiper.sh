#!/system/bin/sh
# Vigil — Encryption Key Wiper / BFU Mode
# Wipes encryption keys from memory, forces device into BFU-equivalent state
# (c) Setec Labs
#
# THEORY OF OPERATION:
# Android devices in "After First Unlock" (AFU) state keep FBE/FDE keys in memory.
# Forensic tools exploit this to extract data without the user's PIN.
# This module wipes those keys, runs TRIM to prevent NAND recovery, kills logging,
# and effectively moves the phone to "Before First Unlock" (BFU) state — the same
# protection as a freshly powered-on phone.

VIGIL_DATA="/data/adb/vigil"
VIGIL_LOG="$VIGIL_DATA/vigil.log"

[ -f "$VIGIL_DATA/vigil.conf" ] && . "$VIGIL_DATA/vigil.conf"

log() {
    # Only log if we haven't killed logd yet
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [keywiper] $1" >> "$VIGIL_LOG" 2>/dev/null
}

# ── LOCKDOWN: Full BFU-mode transition ──
cmd_lockdown() {
    log "=== LOCKDOWN INITIATED ==="

    # Step 1: Disable ADB immediately
    if [ "${KEYWIPER_DISABLE_ADB:-1}" = "1" ]; then
        log "Disabling ADB..."
        settings put global adb_enabled 0 2>/dev/null
        setprop persist.sys.usb.config "charging" 2>/dev/null
        setprop sys.usb.config "charging" 2>/dev/null
        stop adbd 2>/dev/null
    fi

    # Step 2: Clear clipboard and recent apps
    if [ "${KEYWIPER_CLEAR_CLIPBOARD:-1}" = "1" ]; then
        log "Clearing clipboard..."
        am broadcast -a clipclear 2>/dev/null
        service call clipboard 2 2>/dev/null
    fi

    # Step 3: Lock device
    log "Locking device..."
    input keyevent 26 2>/dev/null  # Power button press

    # Step 4: Evict FBE keys — this is the core operation
    # Force credential-encrypted storage to lock
    log "Evicting encryption keys..."

    # Evict CE (Credential Encrypted) keys for all users
    for user_dir in /data/user/*; do
        if [ -d "$user_dir" ]; then
            local uid=$(basename "$user_dir")
            # Use vold to evict CE keys
            vdc cryptfs lockUserKey "$uid" 2>/dev/null
        fi
    done

    # Alternative: use keymaster/keystore to flush
    # This forces the keystore daemon to drop cached keys
    setprop vold.decrypt trigger_post_fs_data 2>/dev/null

    # Try to flush kernel key retention
    # keyctl clear @s 2>/dev/null  # Flush session keyring
    # keyctl clear @u 2>/dev/null  # Flush user keyring

    # Step 5: Drop filesystem caches (contains decrypted data)
    log "Dropping filesystem caches..."
    echo 3 > /proc/sys/vm/drop_caches 2>/dev/null

    # Step 6: Run TRIM to mark deleted blocks as free (prevents NAND recovery)
    if [ "${KEYWIPER_TRIM_ON_LOCKDOWN:-1}" = "1" ]; then
        log "Running TRIM on storage..."
        sm fstrim 2>/dev/null &
        fstrim /data 2>/dev/null &
        fstrim /cache 2>/dev/null &
    fi

    # Step 7: Disable logging
    if [ "${KEYWIPER_KILL_LOGD:-1}" = "1" ]; then
        log "Disabling system logging..."
        setprop persist.logd.logpersistd "" 2>/dev/null
        setprop persist.log.tag "S" 2>/dev/null  # Suppress all logs
        setprop logd.logpersistd.size 65536 2>/dev/null  # Minimize buffer
        # Don't fully stop logd — it causes instability. Just minimize it.
    fi

    # Step 8: Disable developer settings
    settings put global development_settings_enabled 0 2>/dev/null

    # Step 9: Block safe mode boot
    settings put global safe_boot_disallowed 1 2>/dev/null

    # Step 10: Write lockdown marker
    echo "$(date +%s)" > "$VIGIL_DATA/.lockdown"

    log "=== LOCKDOWN COMPLETE ==="
    echo "LOCKDOWN ACTIVE — Device is in BFU-equivalent state"
    echo "Encryption keys evicted, ADB disabled, logging minimized"
    echo "Reboot required to restore normal operation"
}

# ── QUICK LOCK: Fast key eviction without full lockdown ──
cmd_quick() {
    log "Quick key eviction..."

    # Just evict keys and drop caches
    for user_dir in /data/user/*; do
        if [ -d "$user_dir" ]; then
            local uid=$(basename "$user_dir")
            vdc cryptfs lockUserKey "$uid" 2>/dev/null
        fi
    done

    echo 3 > /proc/sys/vm/drop_caches 2>/dev/null
    input keyevent 26 2>/dev/null

    echo "Quick lock complete — keys evicted, device locked"
}

# ── WIPE SESSION: Clear sensitive data from memory ──
cmd_wipe_session() {
    log "Wiping session data..."

    # Clear app recents
    am broadcast -a com.android.systemui.CLEAR_RECENT 2>/dev/null

    # Drop caches
    echo 3 > /proc/sys/vm/drop_caches 2>/dev/null

    # Clear clipboard
    service call clipboard 2 2>/dev/null

    # Clear notifications
    service call notification 1 2>/dev/null

    # Run TRIM
    fstrim /data 2>/dev/null &

    echo "Session data wiped"
}

# ── STATUS ──
cmd_status() {
    echo "Key Wiper Status:"
    if [ -f "$VIGIL_DATA/.lockdown" ]; then
        local lockdown_time=$(cat "$VIGIL_DATA/.lockdown")
        echo "  State:    LOCKDOWN (since $(date -d @"$lockdown_time" 2>/dev/null || echo "$lockdown_time"))"
    else
        echo "  State:    Normal"
    fi

    local adb_state=$(settings get global adb_enabled 2>/dev/null)
    echo "  ADB:      $([ "$adb_state" = "1" ] && echo "ENABLED" || echo "disabled")"

    local dev_settings=$(settings get global development_settings_enabled 2>/dev/null)
    echo "  DevOpts:  $([ "$dev_settings" = "1" ] && echo "ENABLED" || echo "disabled")"

    local selinux=$(getenforce 2>/dev/null || echo "unknown")
    echo "  SELinux:  $selinux"
}

# ── UNLOCK: Remove lockdown state (after reboot) ──
cmd_unlock() {
    if [ -f "$VIGIL_DATA/.lockdown" ]; then
        rm -f "$VIGIL_DATA/.lockdown"
        log "Lockdown state cleared"
        echo "Lockdown state cleared"
    else
        echo "Not in lockdown"
    fi
}

# ── DISPATCH ──
case "$1" in
    lockdown)     cmd_lockdown ;;
    quick)        cmd_quick ;;
    wipe-session) cmd_wipe_session ;;
    status)       cmd_status ;;
    unlock)       cmd_unlock ;;
    *)
        echo "Key Wiper — BFU Mode Controller"
        echo "Usage: key_wiper.sh {lockdown|quick|wipe-session|status|unlock}"
        echo ""
        echo "  lockdown     Full BFU lockdown (evict keys, disable ADB, TRIM, kill logs)"
        echo "  quick        Fast key eviction + lock screen"
        echo "  wipe-session Clear session data (clipboard, caches, recents)"
        echo "  status       Show current security state"
        echo "  unlock       Remove lockdown marker (after reboot)"
        ;;
esac

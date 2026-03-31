#!/system/bin/sh
# Vigil — post-fs-data stage (runs before Zygote/apps)
# This is the earliest stage — used for file integrity checks and forensic shield

MODDIR="${0%/*}"
VIGIL_DATA="/data/adb/vigil"
VIGIL_LIB="$MODDIR/vigil/lib"
VIGIL_LOG="$VIGIL_DATA/vigil.log"

log_vigil() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [post-fs] $1" >> "$VIGIL_LOG"
}

log_vigil "Vigil post-fs-data stage starting"

# Load config
[ -f "$VIGIL_DATA/vigil.conf" ] && . "$VIGIL_DATA/vigil.conf"

# --- FILE INTEGRITY CHECK (FrostGuard) ---
# Check critical system files before anything else loads
if [ "${FROSTGUARD_ENABLED:-1}" = "1" ]; then
    log_vigil "FrostGuard: Running early integrity check"
    "$VIGIL_LIB/integrity.sh" verify-critical 2>/dev/null
    INTEGRITY_RESULT=$?
    if [ $INTEGRITY_RESULT -ne 0 ]; then
        log_vigil "FrostGuard: INTEGRITY VIOLATION DETECTED (code: $INTEGRITY_RESULT)"
        # Write alert for daemon to pick up
        echo "integrity_violation:$(date +%s):post-fs-data" >> "$VIGIL_DATA/alerts/pending"
    fi
fi

# --- FORENSIC SHIELD: Early USB monitoring ---
# Disable ADB if forensic shield is in lockdown mode
if [ -f "$VIGIL_DATA/.lockdown" ]; then
    log_vigil "LOCKDOWN MODE: Disabling ADB and USB debugging"
    settings put global adb_enabled 0 2>/dev/null
    setprop persist.sys.usb.config "charging" 2>/dev/null
fi

# --- ANTI-FORENSIC: Disable safe boot if configured ---
if [ "${BLOCK_SAFE_MODE:-1}" = "1" ]; then
    settings put global safe_boot_disallowed 1 2>/dev/null
fi

log_vigil "Vigil post-fs-data stage complete"

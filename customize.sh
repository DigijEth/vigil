#!/system/bin/sh
# Vigil — Anti-Surveillance Shield
# KernelSU-Next Module Installation Script
# (c) Setec Labs

# Let KernelSU/Magisk handle extraction (MODPATH is set by the framework)

# ── Volume key selector ──
# Reads volume key press: returns 0 for Vol+, 1 for Vol-
# Timeout returns the default ($1: 0=yes, 1=no)
keycheck() {
    local default="${1:-0}"
    local timeout="${2:-5}"
    local start=$(date +%s)

    # Find input devices for volume keys
    local KEYCHECK=""
    for d in /dev/input/event*; do
        [ -e "$d" ] && KEYCHECK="$d"
    done

    while true; do
        local now=$(date +%s)
        local elapsed=$((now - start))
        local remaining=$((timeout - elapsed))

        if [ $remaining -le 0 ]; then
            return $default
        fi

        # Try to read a key event with timeout
        local key=$(timeout 1 getevent -lc 1 2>/dev/null | grep -oE 'KEY_VOLUME(UP|DOWN)' | head -1)

        if [ "$key" = "KEY_VOLUMEUP" ]; then
            return 0
        elif [ "$key" = "KEY_VOLUMEDOWN" ]; then
            return 1
        fi
    done
}

ui_print "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
ui_print "  Vigil — Anti-Surveillance Shield v0.1.0"
ui_print "  by Setec Labs"
ui_print "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
ui_print ""

# Detect environment
if [ "$KSU" = "true" ]; then
    ui_print "[*] KernelSU detected (version: $KSU_VER_CODE)"
elif [ "$APATCH" = "true" ]; then
    ui_print "[*] APatch detected"
else
    ui_print "[*] Magisk detected (version: $MAGISK_VER_CODE)"
fi

# Check Android version
API=$(getprop ro.build.version.sdk)
if [ "$API" -lt 28 ]; then
    ui_print "[!] Android 9+ (API 28) required. Aborting."
    abort
fi
ui_print "[*] Android API: $API"

# Check architecture
ARCH=$(getprop ro.product.cpu.abi)
ui_print "[*] Architecture: $ARCH"

# Set permissions on executables
ui_print "[*] Setting permissions..."
set_perm_recursive "$MODPATH/vigil/bin" 0 0 0755 0755
set_perm_recursive "$MODPATH/vigil/lib" 0 0 0755 0755

# Create runtime directories
mkdir -p "$MODPATH/vigil/logs"
mkdir -p /data/adb/vigil
mkdir -p /data/adb/vigil/baseline
mkdir -p /data/adb/vigil/alerts
mkdir -p /data/adb/vigil/quarantine

# Initialize config if first install
if [ ! -f /data/adb/vigil/vigil.conf ]; then
    ui_print "[*] First install — initializing configuration..."
    cp "$MODPATH/vigil/config/vigil.conf" /data/adb/vigil/vigil.conf
    cp "$MODPATH/vigil/config/exclusions.conf" /data/adb/vigil/exclusions.conf
fi

# Copy IOC database
ui_print "[*] Installing threat indicator database..."
cp -r "$MODPATH/vigil/ioc/"* /data/adb/vigil/ 2>/dev/null

# ── FrostGuard: File Integrity Selection ──
ui_print ""
ui_print "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
ui_print "  FrostGuard — File Integrity Monitor"
ui_print "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
ui_print ""
ui_print "  FrostGuard hashes all system files to"
ui_print "  detect unauthorized modifications."
ui_print ""
ui_print "  WARNING: This can take 5-10 minutes on"
ui_print "  first boot while it builds the baseline."
ui_print ""
ui_print "  Vol UP   = ENABLE  (recommended)"
ui_print "  Vol DOWN = DISABLE"
ui_print ""
ui_print -n "  Waiting 5 seconds... "

keycheck 0 5
if [ $? -eq 0 ]; then
    ui_print "ENABLED"
    touch /data/adb/vigil/.needs_baseline
    sed -i 's/^FROSTGUARD_ENABLED=.*/FROSTGUARD_ENABLED=1/' /data/adb/vigil/vigil.conf 2>/dev/null
    ui_print "[*] Baseline will generate on first boot (5-10 min)"
else
    ui_print "DISABLED"
    rm -f /data/adb/vigil/.needs_baseline
    sed -i 's/^FROSTGUARD_ENABLED=.*/FROSTGUARD_ENABLED=0/' /data/adb/vigil/vigil.conf 2>/dev/null
    ui_print "[*] FrostGuard disabled — enable later with vigil.conf"
fi

# ── Threat Scan Selection ──
ui_print ""
ui_print "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
ui_print "  Initial Threat Scan"
ui_print "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
ui_print ""
ui_print "  Scan installed apps against 11,000+"
ui_print "  threat indicators (stalkerware, spyware,"
ui_print "  Pegasus, government surveillance tools)."
ui_print ""
ui_print "  Vol UP   = SCAN NOW (during install)"
ui_print "  Vol DOWN = SCAN ON NEXT BOOT"
ui_print ""
ui_print -n "  Waiting 5 seconds... "

keycheck 1 5
if [ $? -eq 0 ]; then
    ui_print "SCANNING NOW"
    ui_print ""
    ui_print "[*] Running threat scan..."
    # Quick scan: packages + processes (fastest useful scan)
    VIGIL_DATA="/data/adb/vigil" "$MODPATH/vigil/lib/scanner.sh" quick 2>/dev/null | while read -r line; do
        ui_print "  $line"
    done
    ui_print "[*] Scan complete"
else
    ui_print "DEFERRED TO BOOT"
    touch /data/adb/vigil/.needs_scan
    ui_print "[*] Scan will run automatically on next boot"
fi

ui_print ""
ui_print "[✓] Vigil installed successfully."
ui_print ""
ui_print "  Commands:"
ui_print "    vigil scan       — Run full threat scan"
ui_print "    vigil status     — Show protection status"
ui_print "    vigil lockdown   — Enter lockdown / BFU mode"
ui_print "    vigil integrity  — Check file integrity"
ui_print "    vigil update-ioc — Update threat indicators"
ui_print ""
ui_print "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

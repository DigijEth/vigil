#!/system/bin/sh
# Vigil — Anti-Surveillance Shield
# KernelSU-Next Module Installation Script
# (c) Setec Labs

SKIPUNZIP=1

ui_print "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
ui_print "  Vigil — Anti-Surveillance Shield v0.1.0"
ui_print "  by Setec Labs"
ui_print "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
ui_print ""

# Detect environment
if [ "$KSU" = "true" ]; then
    ui_print "[*] KernelSU detected (version: $KSU_VER_CODE)"
    MODPATH="/data/adb/modules/vigil"
elif [ "$APATCH" = "true" ]; then
    ui_print "[*] APatch detected"
    MODPATH="/data/adb/modules/vigil"
else
    ui_print "[*] Magisk detected (version: $MAGISK_VER_CODE)"
    MODPATH="/data/adb/modules/vigil"
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

# Extract module files
ui_print "[*] Extracting module files..."
mkdir -p "$MODPATH"
unzip -o "$ZIPFILE" -d "$MODPATH" >&2

# Set permissions
ui_print "[*] Setting permissions..."
set_perm_recursive "$MODPATH" 0 0 0755 0644
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

# Generate initial file integrity baseline
ui_print "[*] Generating file integrity baseline..."
"$MODPATH/vigil/lib/integrity.sh" baseline 2>/dev/null

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

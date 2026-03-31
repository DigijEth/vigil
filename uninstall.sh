#!/system/bin/sh
# Vigil — Uninstall cleanup

VIGIL_DATA="/data/adb/vigil"

# Stop daemon
if [ -f "$VIGIL_DATA/vigild.pid" ]; then
    kill $(cat "$VIGIL_DATA/vigild.pid") 2>/dev/null
fi

# Remove bind mount
umount /system/bin/vigil 2>/dev/null

# Remove CLI wrapper
rm -f /data/local/tmp/vigil

# Ask user about data retention via prop
# If user set vigil.keep_data=1 before uninstall, preserve data
if [ "$(getprop vigil.keep_data)" != "1" ]; then
    rm -rf "$VIGIL_DATA"
fi

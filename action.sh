#!/system/bin/sh
# Vigil — Module Action Button
# This runs when the user taps the module card in KernelSU/Magisk manager
# Opens the WebUI in the default browser

VIGIL_DATA="/data/adb/vigil"
WEBUI_PORT=8088

[ -f "$VIGIL_DATA/vigil.conf" ] && . "$VIGIL_DATA/vigil.conf"

# Check if WebUI is running
WEBUI_RUNNING=0
if [ -f "$VIGIL_DATA/vigild.pid" ]; then
    VIGILD_PID=$(cat "$VIGIL_DATA/vigild.pid")
    kill -0 "$VIGILD_PID" 2>/dev/null && WEBUI_RUNNING=1
fi

if [ "$WEBUI_RUNNING" = "0" ]; then
    echo "Starting Vigil WebUI..."
    MODDIR="${0%/*}"
    nohup "$MODDIR/vigil/lib/webui.sh" serve >> "$VIGIL_DATA/vigil.log" 2>&1 &
    sleep 2
fi

# Open WebUI in browser
am start -a android.intent.action.VIEW -d "http://localhost:${WEBUI_PORT}" 2>/dev/null

echo "Vigil WebUI: http://localhost:${WEBUI_PORT}"

#!/system/bin/sh
# Vigil — late_start service stage (runs after boot completes)
# Starts the main Vigil daemon

MODDIR="${0%/*}"
VIGIL_DATA="/data/adb/vigil"
VIGIL_BIN="$MODDIR/vigil/bin"
VIGIL_LOG="$VIGIL_DATA/vigil.log"

log_vigil() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [service] $1" >> "$VIGIL_LOG"
}

# Wait for boot to complete
while [ "$(getprop sys.boot_completed)" != "1" ]; do
    sleep 1
done

# Small delay to let system settle
sleep 5

log_vigil "Vigil service stage starting"

# Symlink CLI to PATH
[ ! -f /data/adb/vigil/bin/vigil ] && {
    mkdir -p /data/adb/vigil/bin
    ln -sf "$VIGIL_BIN/vigil" /data/adb/vigil/bin/vigil
}
# Make accessible via su
mount --bind "$VIGIL_BIN/vigil" /system/bin/vigil 2>/dev/null || {
    # Fallback: create wrapper in a PATH-accessible location
    cat > /data/local/tmp/vigil <<WRAPPER
#!/system/bin/sh
exec "$VIGIL_BIN/vigil" "\$@"
WRAPPER
    chmod 755 /data/local/tmp/vigil
}

# Generate file integrity baseline if needed (deferred from install)
if [ -f "$VIGIL_DATA/.needs_baseline" ]; then
    log_vigil "Generating file integrity baseline in background..."
    (
        "$MODDIR/vigil/lib/integrity.sh" baseline >> "$VIGIL_LOG" 2>&1
        rm -f "$VIGIL_DATA/.needs_baseline"
        log_vigil "File integrity baseline complete"
    ) &
fi

# Run deferred threat scan if requested during install
if [ -f "$VIGIL_DATA/.needs_scan" ]; then
    log_vigil "Running deferred threat scan in background..."
    (
        "$MODDIR/vigil/lib/scanner.sh" quick >> "$VIGIL_LOG" 2>&1
        rm -f "$VIGIL_DATA/.needs_scan"
        log_vigil "Deferred threat scan complete"
    ) &
fi

# Start the main daemon
log_vigil "Starting vigild daemon"
nohup "$VIGIL_BIN/vigild" >> "$VIGIL_LOG" 2>&1 &
DAEMON_PID=$!
echo $DAEMON_PID > "$VIGIL_DATA/vigild.pid"
log_vigil "vigild started (PID: $DAEMON_PID)"

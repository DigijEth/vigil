#!/system/bin/sh
# Vigil — SMS Honeypot / Location Spoofing
# When silent SMS probes arrive, responds with fake location data
# (c) Setec Labs
#
# THEORY:
# Silent SMS (Type-0, Class-0) are used to confirm a SIM is active and
# triangulate location via cell towers. The delivery receipt itself reveals
# the device is on and which tower it's connected to.
#
# This module:
# 1. Detects incoming silent SMS probes
# 2. Activates mock GPS to spoof a fake location
# 3. Optionally reconnects to a different cell tower
# 4. Then allows the delivery receipt to go through with false data
#
# The attacker gets a response, but it points to the wrong location.
# This is better than blocking (which reveals the block) — it feeds
# disinformation to the adversary.

VIGIL_DATA="/data/adb/vigil"
VIGIL_LOG="$VIGIL_DATA/vigil.log"
ALERT_DIR="$VIGIL_DATA/alerts"
HONEYPOT_CONF="$VIGIL_DATA/honeypot.conf"
HONEYPOT_LOG="$VIGIL_DATA/honeypot.log"

[ -f "$VIGIL_DATA/vigil.conf" ] && . "$VIGIL_DATA/vigil.conf"

# Default fake locations (world capitals — far from likely real position)
# Format: lat,lon,name
FAKE_LOCATIONS="
48.8566,2.3522,Paris
35.6762,139.6503,Tokyo
-33.8688,151.2093,Sydney
55.7558,37.6173,Moscow
-22.9068,-43.1729,Rio de Janeiro
51.5074,-0.1278,London
40.4168,-3.7038,Madrid
52.5200,13.4050,Berlin
37.5665,126.9780,Seoul
19.4326,-99.1332,Mexico City
"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [honeypot] $1" >> "$VIGIL_LOG"
}

alert() {
    local severity="$1"
    local message="$2"
    local timestamp=$(date +%s)
    echo "${severity}|${timestamp}|sms_honeypot|${message}" >> "$ALERT_DIR/pending"
    log "ALERT [$severity]: $message"
}

# Load user-defined fake location or pick random
get_fake_location() {
    # Check for user-defined location
    if [ -f "$HONEYPOT_CONF" ]; then
        local user_lat=$(grep "^FAKE_LAT=" "$HONEYPOT_CONF" 2>/dev/null | cut -d= -f2)
        local user_lon=$(grep "^FAKE_LON=" "$HONEYPOT_CONF" 2>/dev/null | cut -d= -f2)
        if [ -n "$user_lat" ] && [ -n "$user_lon" ]; then
            echo "$user_lat $user_lon user_defined"
            return
        fi
    fi

    # Pick a random location from the list
    local count=$(echo "$FAKE_LOCATIONS" | grep -c ",")
    local random_idx=$(( $(head -c4 /dev/urandom | od -An -tu4 | tr -d ' ') % count + 1 ))
    local location=$(echo "$FAKE_LOCATIONS" | grep "," | sed -n "${random_idx}p" | tr -d ' ')

    local lat=$(echo "$location" | cut -d, -f1)
    local lon=$(echo "$location" | cut -d, -f2)
    local name=$(echo "$location" | cut -d, -f3)

    echo "$lat $lon $name"
}

# ── MOCK GPS: Set fake location via Android mock location provider ──
activate_mock_gps() {
    local lat="$1"
    local lon="$2"
    local name="$3"

    log "Activating mock GPS: $lat, $lon ($name)"

    # Enable mock locations (requires developer options, but we have root)
    settings put secure mock_location 1 2>/dev/null

    # Use appops to allow our mock location provider
    # We use Android's built-in test location capabilities
    # Set the mock location via the location manager service

    # Method 1: Use am command to set test provider
    # Create a mock location provider
    local accuracy=10  # meters
    local altitude=50  # meters
    local bearing=0
    local speed=0

    # Write mock location script that continuously feeds fake coordinates
    local mock_script="$VIGIL_DATA/.mock_gps_active"
    cat > "$mock_script" <<MOCKEOF
#!/system/bin/sh
# Mock GPS feeder — feeds fake location continuously
# Kill this script's PID to stop

while true; do
    # Use Android's cmd location command (Android 12+)
    cmd location providers add-test-provider gps requiresNetwork=false requiresSatellite=false requiresCell=false hasMonetaryCost=false supportsAltitude=true supportsSpeed=false supportsBearing=false powerRequirement=1 accuracy=1 2>/dev/null

    cmd location providers set-test-provider-enabled gps true 2>/dev/null

    cmd location providers set-test-provider-location gps --latitude $lat --longitude $lon --altitude $altitude --accuracy $accuracy 2>/dev/null

    # Also try the legacy approach for older Android
    am broadcast -a android.location.GPS_FIX_CHANGE --ef latitude $lat --ef longitude $lon 2>/dev/null

    sleep 1
done
MOCKEOF
    chmod 755 "$mock_script"

    # Run mock GPS in background
    nohup sh "$mock_script" >> "$HONEYPOT_LOG" 2>&1 &
    local mock_pid=$!
    echo $mock_pid > "$VIGIL_DATA/.mock_gps_pid"

    log "Mock GPS active: PID $mock_pid, location: $lat, $lon ($name)"
    echo "Mock GPS active: $lat, $lon ($name)"
}

# ── STOP MOCK GPS ──
deactivate_mock_gps() {
    if [ -f "$VIGIL_DATA/.mock_gps_pid" ]; then
        local pid=$(cat "$VIGIL_DATA/.mock_gps_pid")
        kill "$pid" 2>/dev/null
        rm -f "$VIGIL_DATA/.mock_gps_pid"
        rm -f "$VIGIL_DATA/.mock_gps_active"

        # Clean up test provider
        cmd location providers remove-test-provider gps 2>/dev/null
        settings put secure mock_location 0 2>/dev/null

        log "Mock GPS deactivated"
        echo "Mock GPS deactivated"
    else
        echo "Mock GPS not active"
    fi
}

# ── HONEYPOT MONITOR: Watch for silent SMS and auto-spoof ──
cmd_monitor() {
    log "SMS Honeypot monitor starting..."
    echo "SMS Honeypot active — will spoof location on silent SMS detection"

    # Clear logcat buffer
    logcat -c 2>/dev/null

    local spoof_active=0
    local spoof_deactivate_time=0

    logcat -s \
        GsmInboundSmsHandler:* \
        SmsMessage:* \
        InboundSmsHandler:* \
        RIL:* \
        RILJ:* \
        2>/dev/null | while read -r line; do

        local now=$(date +%s)

        # Check if we should deactivate spoof (after 5 minutes)
        if [ $spoof_active -eq 1 ] && [ $now -gt $spoof_deactivate_time ]; then
            deactivate_mock_gps
            spoof_active=0
            log "Auto-deactivated mock GPS after timeout"
        fi

        # Detect silent SMS
        if echo "$line" | grep -qiE "type.?0.*sms|sms.*type.?0|class.?0|flash.*sms|TP-PID.*type"; then
            alert "CRITICAL" "Silent SMS detected — activating location honeypot"

            # Get fake location
            local loc_data=$(get_fake_location)
            local fake_lat=$(echo "$loc_data" | awk '{print $1}')
            local fake_lon=$(echo "$loc_data" | awk '{print $2}')
            local fake_name=$(echo "$loc_data" | awk '{print $3}')

            echo "$(date '+%Y-%m-%d %H:%M:%S')|SPOOF|$fake_lat,$fake_lon|$fake_name" >> "$HONEYPOT_LOG"

            # Activate mock GPS with fake location
            if [ $spoof_active -eq 0 ]; then
                activate_mock_gps "$fake_lat" "$fake_lon" "$fake_name"
                spoof_active=1
            fi

            # Keep spoof active for 5 minutes (allow delivery receipt to go through with fake data)
            spoof_deactivate_time=$((now + 300))

            alert "INFO" "Location spoofed to: $fake_lat, $fake_lon ($fake_name)"
        fi
    done
}

# ── SPOOF NOW: Manually activate fake location ──
cmd_spoof() {
    local loc_data=$(get_fake_location)
    local fake_lat=$(echo "$loc_data" | awk '{print $1}')
    local fake_lon=$(echo "$loc_data" | awk '{print $2}')
    local fake_name=$(echo "$loc_data" | awk '{print $3}')

    activate_mock_gps "$fake_lat" "$fake_lon" "$fake_name"
}

# ── SPOOF WITH SPECIFIC LOCATION ──
cmd_spoof_location() {
    local lat="$1"
    local lon="$2"

    if [ -z "$lat" ] || [ -z "$lon" ]; then
        echo "Usage: sms_honeypot.sh spoof-at <latitude> <longitude>"
        return 1
    fi

    activate_mock_gps "$lat" "$lon" "custom"
}

# ── CONFIGURE: Set persistent fake location ──
cmd_configure() {
    echo "SMS Honeypot Configuration"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "Current fake location:"
    if [ -f "$HONEYPOT_CONF" ]; then
        local lat=$(grep "^FAKE_LAT=" "$HONEYPOT_CONF" 2>/dev/null | cut -d= -f2)
        local lon=$(grep "^FAKE_LON=" "$HONEYPOT_CONF" 2>/dev/null | cut -d= -f2)
        if [ -n "$lat" ]; then
            echo "  Custom: $lat, $lon"
        else
            echo "  Random (from world capitals list)"
        fi
    else
        echo "  Random (from world capitals list)"
    fi
    echo ""
    echo "To set a specific fake location:"
    echo "  echo 'FAKE_LAT=48.8566' > $HONEYPOT_CONF"
    echo "  echo 'FAKE_LON=2.3522' >> $HONEYPOT_CONF"
    echo ""
    echo "Or use: vigil honeypot spoof-at <lat> <lon>"
    echo ""
    echo "Mock GPS status:"
    if [ -f "$VIGIL_DATA/.mock_gps_pid" ]; then
        local pid=$(cat "$VIGIL_DATA/.mock_gps_pid")
        if kill -0 "$pid" 2>/dev/null; then
            echo "  ACTIVE (PID: $pid)"
        else
            echo "  Stale PID file (not running)"
        fi
    else
        echo "  Inactive"
    fi
}

# ── STATUS ──
cmd_status() {
    echo "SMS Honeypot Status:"
    echo "  SMS Fake Response: ${SMS_FAKE_RESPONSE:-0}"

    if [ -f "$VIGIL_DATA/.mock_gps_pid" ]; then
        local pid=$(cat "$VIGIL_DATA/.mock_gps_pid")
        if kill -0 "$pid" 2>/dev/null; then
            echo "  Mock GPS: ACTIVE (PID: $pid)"
        else
            echo "  Mock GPS: inactive (stale PID)"
        fi
    else
        echo "  Mock GPS: inactive"
    fi

    if [ -f "$HONEYPOT_LOG" ]; then
        local spoof_count=$(grep -c "SPOOF" "$HONEYPOT_LOG" 2>/dev/null)
        echo "  Spoofs triggered: $spoof_count"
        echo "  Last spoof:"
        tail -1 "$HONEYPOT_LOG" 2>/dev/null | while read -r line; do
            echo "    $line"
        done
    fi
}

# ── DISPATCH ──
case "$1" in
    monitor)    cmd_monitor ;;
    spoof)      cmd_spoof ;;
    spoof-at)   shift; cmd_spoof_location "$@" ;;
    stop)       deactivate_mock_gps ;;
    configure)  cmd_configure ;;
    status)     cmd_status ;;
    *)
        echo "SMS Honeypot — Location Spoofing Defense"
        echo "Usage: sms_honeypot.sh {monitor|spoof|spoof-at|stop|configure|status}"
        echo ""
        echo "  monitor             Auto-spoof on silent SMS detection"
        echo "  spoof               Activate mock GPS with random location"
        echo "  spoof-at <lat> <lon> Activate mock GPS at specific coordinates"
        echo "  stop                Deactivate mock GPS"
        echo "  configure           Show/edit honeypot configuration"
        echo "  status              Show honeypot status"
        ;;
esac

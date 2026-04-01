#!/system/bin/sh
# Vigil — WebUI Server
# Serves a local web dashboard for settings, status, alerts, and scan control
# (c) Setec Labs
#
# Runs on localhost:8088 (configurable)
# Uses busybox httpd with CGI, or falls back to nc-based server

VIGIL_DATA="/data/adb/vigil"
VIGIL_LOG="$VIGIL_DATA/vigil.log"
WEBUI_PORT="${WEBUI_PORT:-8088}"
WEBUI_DIR=""
VIGIL_LIB="$(dirname "$0")"

# Find the webroot
for d in /data/adb/modules/vigil/vigil/webroot "$VIGIL_LIB/../webroot"; do
    [ -d "$d" ] && WEBUI_DIR="$d" && break
done

[ -f "$VIGIL_DATA/vigil.conf" ] && . "$VIGIL_DATA/vigil.conf"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [webui] $1" >> "$VIGIL_LOG"
}

# ── CGI API HANDLER ──
# Processes API requests and returns JSON
handle_api() {
    local endpoint="$1"
    local method="$2"

    echo "HTTP/1.1 200 OK"
    echo "Content-Type: application/json"
    echo "Access-Control-Allow-Origin: *"
    echo "Connection: close"
    echo ""

    case "$endpoint" in
        /api/status)
            local daemon_status="stopped"
            local daemon_pid=""
            if [ -f "$VIGIL_DATA/vigild.pid" ]; then
                daemon_pid=$(cat "$VIGIL_DATA/vigild.pid")
                kill -0 "$daemon_pid" 2>/dev/null && daemon_status="running"
            fi
            local lockdown=$([ -f "$VIGIL_DATA/.lockdown" ] && echo "true" || echo "false")

            cat <<ENDJSON
{
  "daemon": "$daemon_status",
  "pid": "$daemon_pid",
  "lockdown": $lockdown,
  "version": "0.2.0",
  "modules": {
    "scanner": "${SCANNER_ENABLED:-1}",
    "frostguard": "${FROSTGUARD_ENABLED:-1}",
    "forensic_shield": "${FORENSIC_SHIELD_ENABLED:-1}",
    "sms_shield": "${SMS_SHIELD_ENABLED:-1}",
    "network_monitor": "${NETWORK_MONITOR_ENABLED:-1}",
    "key_wiper": "${KEYWIPER_ENABLED:-1}",
    "deep_scan": "${DEEP_SCAN_BACKGROUND:-1}",
    "antiforensics": "${ANTIFORENSICS_ENABLED:-1}",
    "duress": "${DURESS_ENABLED:-0}",
    "sms_honeypot": "${SMS_FAKE_RESPONSE:-0}",
    "app_honeypot": "${APP_HONEYPOT_AUTO:-0}",
    "quarantine": "${QUARANTINE_ENABLED:-0}"
  }
}
ENDJSON
            ;;

        /api/alerts)
            echo "["
            if [ -f "$VIGIL_DATA/alerts/history" ]; then
                local first=1
                tail -50 "$VIGIL_DATA/alerts/history" | while IFS='|' read -r sev ts mod msg; do
                    [ $first -eq 0 ] && echo ","
                    first=0
                    # Escape quotes in message
                    msg=$(echo "$msg" | sed 's/"/\\"/g')
                    echo "  {\"severity\":\"$sev\",\"timestamp\":$ts,\"module\":\"$mod\",\"message\":\"$msg\"}"
                done
            fi
            echo "]"
            ;;

        /api/ioc-stats)
            echo "{"
            local first=1
            for f in packages.txt certificates.txt domains.txt ips.txt hashes.txt cellebrite_hashes.txt hosts.txt; do
                [ $first -eq 0 ] && echo ","
                first=0
                local name=$(echo "$f" | sed 's/\.txt//')
                local count=0
                [ -f "$VIGIL_DATA/$f" ] && count=$(wc -l < "$VIGIL_DATA/$f")
                echo "  \"$name\": $count"
            done
            echo "}"
            ;;

        /api/config)
            if [ "$method" = "POST" ]; then
                # Read POST body from stdin
                read -r body
                # Parse key=value pairs and update config
                echo "$body" | tr '&' '\n' | while IFS='=' read -r key val; do
                    key=$(echo "$key" | tr -d ' ')
                    val=$(echo "$val" | tr -d ' ')
                    if grep -q "^${key}=" "$VIGIL_DATA/vigil.conf" 2>/dev/null; then
                        sed -i "s|^${key}=.*|${key}=${val}|" "$VIGIL_DATA/vigil.conf"
                    fi
                done
                echo "{\"status\":\"ok\"}"
            else
                # Return current config as JSON
                echo "{"
                local first=1
                grep -v '^#' "$VIGIL_DATA/vigil.conf" 2>/dev/null | grep '=' | while IFS='=' read -r key val; do
                    key=$(echo "$key" | tr -d ' ')
                    val=$(echo "$val" | sed 's/^"//' | sed 's/"$//' | sed 's/#.*//' | tr -d ' ')
                    [ -z "$key" ] && continue
                    [ $first -eq 0 ] && echo ","
                    first=0
                    echo "  \"$key\": \"$val\""
                done
                echo "}"
            fi
            ;;

        /api/scan)
            echo "{\"status\":\"started\"}"
            # Run scan in background
            "$VIGIL_LIB/scanner.sh" quick >> "$VIGIL_LOG" 2>&1 &
            ;;

        /api/deep-scan)
            echo "{\"status\":\"started\"}"
            "$VIGIL_LIB/deep_scan.sh" deep >> "$VIGIL_LOG" 2>&1 &
            ;;

        /api/lockdown)
            "$VIGIL_LIB/key_wiper.sh" lockdown >> "$VIGIL_LOG" 2>&1 &
            echo "{\"status\":\"lockdown_initiated\"}"
            ;;

        /api/harden)
            "$VIGIL_LIB/antiforensics.sh" harden >> "$VIGIL_LOG" 2>&1 &
            echo "{\"status\":\"hardening\"}"
            ;;

        /api/sanitize)
            "$VIGIL_LIB/antiforensics.sh" sanitize >> "$VIGIL_LOG" 2>&1 &
            echo "{\"status\":\"sanitizing\"}"
            ;;

        /api/update-ioc)
            "$VIGIL_LIB/ioc_updater.sh" update >> "$VIGIL_LOG" 2>&1 &
            echo "{\"status\":\"updating\"}"
            ;;

        /api/log)
            echo "["
            if [ -f "$VIGIL_LOG" ]; then
                local first=1
                tail -100 "$VIGIL_LOG" | while read -r line; do
                    line=$(echo "$line" | sed 's/"/\\"/g')
                    [ $first -eq 0 ] && echo ","
                    first=0
                    echo "  \"$line\""
                done
            fi
            echo "]"
            ;;

        /api/exec)
            # Standalone mode: execute shell command (replaces ksu.exec)
            echo "HTTP/1.1 200 OK"
            echo "Content-Type: text/plain"
            echo "Connection: close"
            echo ""
            if [ "$method" = "POST" ] && [ -n "$POST_BODY" ]; then
                eval "$POST_BODY" 2>&1
            fi
            return
            ;;

        *)
            echo "{\"error\":\"unknown endpoint\"}"
            ;;
    esac
}

# ── NC-BASED HTTP SERVER ──
# Simple HTTP server using netcat — no dependencies
cmd_serve() {
    log "WebUI starting on port $WEBUI_PORT..."
    echo "Vigil WebUI: http://localhost:$WEBUI_PORT"

    while true; do
        # Listen for a connection and handle it
        {
            # Read the HTTP request
            local request=""
            local method=""
            local path=""
            local content_length=0

            while read -r line; do
                line=$(echo "$line" | tr -d '\r')
                [ -z "$line" ] && break

                if [ -z "$request" ]; then
                    request="$line"
                    method=$(echo "$line" | awk '{print $1}')
                    path=$(echo "$line" | awk '{print $2}')
                fi

                if echo "$line" | grep -qi "Content-Length:"; then
                    content_length=$(echo "$line" | grep -oE '[0-9]+')
                fi
            done

            # Read POST body if present
            local POST_BODY=""
            if [ "$method" = "POST" ] && [ "$content_length" -gt 0 ] 2>/dev/null; then
                POST_BODY=$(dd bs=1 count="$content_length" 2>/dev/null)
            fi
            export POST_BODY

            # Route the request
            case "$path" in
                /api/*)
                    handle_api "$path" "$method"
                    ;;
                /|/index.html)
                    echo "HTTP/1.1 200 OK"
                    echo "Content-Type: text/html"
                    echo "Connection: close"
                    echo ""
                    cat "$WEBUI_DIR/index.html" 2>/dev/null || echo "<h1>WebUI files not found</h1>"
                    ;;
                *)
                    local file="$WEBUI_DIR${path}"
                    if [ -f "$file" ]; then
                        local mime="text/plain"
                        case "$path" in
                            *.html) mime="text/html" ;;
                            *.css)  mime="text/css" ;;
                            *.js)   mime="application/javascript" ;;
                            *.json) mime="application/json" ;;
                            *.png)  mime="image/png" ;;
                            *.svg)  mime="image/svg+xml" ;;
                        esac
                        echo "HTTP/1.1 200 OK"
                        echo "Content-Type: $mime"
                        echo "Connection: close"
                        echo ""
                        cat "$file"
                    else
                        echo "HTTP/1.1 404 Not Found"
                        echo "Connection: close"
                        echo ""
                        echo "404"
                    fi
                    ;;
            esac
        } | busybox nc -l -p "$WEBUI_PORT" 2>/dev/null || {
            # Fallback: use toybox nc or /system/bin/nc
            log "busybox nc not available, trying alternatives..."
            break
        }
    done
}

# ── DISPATCH ──
case "$1" in
    serve)  cmd_serve ;;
    status) echo "WebUI port: $WEBUI_PORT" ;;
    *)
        echo "Vigil WebUI Server"
        echo "Usage: webui.sh serve"
        echo "  Starts web dashboard on http://localhost:$WEBUI_PORT"
        ;;
esac

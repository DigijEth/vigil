#!/system/bin/sh
# Vigil — IOC Auto-Updater [WIP]
# Pulls fresh threat indicators from backend or git sources
# (c) Setec Labs
#
# Update sources (in priority order):
# 1. Autarch backend API (when configured)
# 2. Direct git raw downloads from indicator repos
# 3. Manual update via vigil update-ioc

VIGIL_DATA="/data/adb/vigil"
VIGIL_LOG="$VIGIL_DATA/vigil.log"
IOC_DIR="$VIGIL_DATA"
ALERT_DIR="$VIGIL_DATA/alerts"
UPDATE_LOCK="$VIGIL_DATA/.ioc_updating"
IOC_VERSION_FILE="$VIGIL_DATA/.ioc_version"

[ -f "$VIGIL_DATA/vigil.conf" ] && . "$VIGIL_DATA/vigil.conf"

# Update interval: default 24 hours
IOC_UPDATE_INTERVAL="${IOC_UPDATE_INTERVAL:-86400}"

# Git raw URLs for indicator sources (fallback when no backend)
STALKERWARE_URL="https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/ioc.yaml"
CITIZENLAB_URL="https://raw.githubusercontent.com/citizenlab/malware-indicators/master"
META_THREATS_URL="https://raw.githubusercontent.com/facebook/threat-research/main/indicators"
MOBILETRACKERS_URL="https://raw.githubusercontent.com/craiu/mobiletrackers/master/list.txt"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ioc_updater] $1" >> "$VIGIL_LOG"
}

alert() {
    local severity="$1"
    local message="$2"
    local timestamp=$(date +%s)
    echo "${severity}|${timestamp}|ioc_updater|${message}" >> "$ALERT_DIR/pending"
    log "ALERT [$severity]: $message"
}

get_current_version() {
    if [ -f "$IOC_VERSION_FILE" ]; then
        cat "$IOC_VERSION_FILE"
    else
        echo "0|0|unknown"
    fi
}

save_version() {
    local count="$1"
    local timestamp=$(date +%s)
    local source="$2"
    echo "${timestamp}|${count}|${source}" > "$IOC_VERSION_FILE"
}

needs_update() {
    if [ ! -f "$IOC_VERSION_FILE" ]; then
        return 0  # Never updated
    fi
    local last_update=$(cut -d'|' -f1 < "$IOC_VERSION_FILE")
    local now=$(date +%s)
    local elapsed=$((now - last_update))
    [ $elapsed -ge "$IOC_UPDATE_INTERVAL" ]
}

# ── Download with retry ──
download() {
    local url="$1"
    local output="$2"
    local attempts=3

    while [ $attempts -gt 0 ]; do
        if curl -sf --connect-timeout 10 --max-time 60 -o "$output" "$url" 2>/dev/null; then
            return 0
        fi
        attempts=$((attempts - 1))
        sleep 2
    done
    return 1
}

# ── UPDATE FROM AUTARCH BACKEND ──
update_from_backend() {
    if [ -z "$VIGIL_BACKEND_URL" ]; then
        return 1
    fi

    log "Updating IOCs from Autarch backend: $VIGIL_BACKEND_URL"

    local api_key="${VIGIL_API_KEY:-}"
    local auth_header=""
    [ -n "$api_key" ] && auth_header="-H \"Authorization: Bearer $api_key\""

    local tmp_dir="$VIGIL_DATA/.ioc_update_tmp"
    mkdir -p "$tmp_dir"
    local success=0
    local total=0

    for ioc_file in packages.txt certificates.txt domains.txt ips.txt hashes.txt hosts.txt cellebrite_hashes.txt; do
        log "Fetching $ioc_file from backend..."
        if curl -sf --connect-timeout 10 --max-time 120 \
            -H "X-Vigil-Device: ${VIGIL_DEVICE_ID:-unknown}" \
            ${auth_header} \
            -o "$tmp_dir/$ioc_file" \
            "$VIGIL_BACKEND_URL/api/ioc/$ioc_file" 2>/dev/null; then

            # Validate: file should have content and reasonable format
            local lines=$(wc -l < "$tmp_dir/$ioc_file" 2>/dev/null || echo 0)
            if [ "$lines" -gt 10 ]; then
                mv "$tmp_dir/$ioc_file" "$IOC_DIR/$ioc_file"
                total=$((total + lines))
                success=$((success + 1))
                log "Updated $ioc_file: $lines indicators"
            else
                log "WARNING: $ioc_file too small ($lines lines), skipping"
            fi
        else
            log "Failed to fetch $ioc_file from backend"
        fi
    done

    rm -rf "$tmp_dir"

    if [ $success -gt 0 ]; then
        save_version "$total" "backend"
        alert "INFO" "IOC database updated from backend: $total indicators across $success files"
        return 0
    fi
    return 1
}

# ── UPDATE FROM GIT RAW SOURCES ──
update_from_git() {
    log "Updating IOCs from git raw sources..."

    local tmp_dir="$VIGIL_DATA/.ioc_update_tmp"
    mkdir -p "$tmp_dir"
    local updates=0

    # 1. Stalkerware indicators YAML → extract packages and domains
    log "Fetching stalkerware-indicators..."
    if download "$STALKERWARE_URL" "$tmp_dir/ioc.yaml"; then
        # Extract package names
        grep "^    - " "$tmp_dir/ioc.yaml" 2>/dev/null | \
            sed 's/^    - //' | \
            grep -E '^[a-zA-Z][a-zA-Z0-9_.]+$' | \
            sort -u | \
            while read -r pkg; do
                echo "${pkg}|stalkerware-indicators|stalkerware"
            done > "$tmp_dir/stalkerware_pkgs.txt"

        if [ -s "$tmp_dir/stalkerware_pkgs.txt" ]; then
            # Merge with existing packages (don't replace, append new)
            cat "$IOC_DIR/packages.txt" "$tmp_dir/stalkerware_pkgs.txt" 2>/dev/null | \
                sort -t'|' -k1,1 -u > "$tmp_dir/packages_merged.txt"
            mv "$tmp_dir/packages_merged.txt" "$IOC_DIR/packages.txt"
            updates=$((updates + 1))
            log "Stalkerware packages updated"
        fi
    fi

    # 2. Mobile trackers domain list
    log "Fetching mobiletrackers..."
    if download "$MOBILETRACKERS_URL" "$tmp_dir/trackers.txt"; then
        # Extract domains from the tracker list
        grep -oE '[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' "$tmp_dir/trackers.txt" 2>/dev/null | \
            sort -u | \
            while read -r domain; do
                echo "${domain}|mobiletrackers|tracking"
            done > "$tmp_dir/tracker_domains.txt"

        if [ -s "$tmp_dir/tracker_domains.txt" ]; then
            cat "$IOC_DIR/domains.txt" "$tmp_dir/tracker_domains.txt" 2>/dev/null | \
                sort -t'|' -k1,1 -u > "$tmp_dir/domains_merged.txt"
            mv "$tmp_dir/domains_merged.txt" "$IOC_DIR/domains.txt"

            # Rebuild hosts blocklist
            cut -d'|' -f1 "$IOC_DIR/domains.txt" | \
                sed 's/^/0.0.0.0 /' | sort -u > "$IOC_DIR/hosts.txt"

            updates=$((updates + 1))
            log "Tracker domains updated"
        fi
    fi

    rm -rf "$tmp_dir"

    if [ $updates -gt 0 ]; then
        local total=$(cat "$IOC_DIR/packages.txt" "$IOC_DIR/domains.txt" "$IOC_DIR/ips.txt" "$IOC_DIR/hashes.txt" "$IOC_DIR/certificates.txt" 2>/dev/null | wc -l)
        save_version "$total" "git"
        alert "INFO" "IOC database updated from git sources: $total total indicators"
        return 0
    fi

    log "No updates available from git sources"
    return 1
}

# ── MANUAL UPDATE (from CLI) ──
cmd_update() {
    # Prevent concurrent updates
    if [ -f "$UPDATE_LOCK" ]; then
        local lock_age=$(( $(date +%s) - $(stat -c %Y "$UPDATE_LOCK" 2>/dev/null || echo 0) ))
        if [ $lock_age -lt 300 ]; then
            echo "Update already in progress"
            return 1
        fi
        rm -f "$UPDATE_LOCK"
    fi
    touch "$UPDATE_LOCK"

    echo "Updating threat indicator database..."

    # Try backend first, fall back to git
    if update_from_backend; then
        echo "Updated from Autarch backend"
    elif update_from_git; then
        echo "Updated from git sources"
    else
        echo "Update failed — check network connectivity"
        rm -f "$UPDATE_LOCK"
        return 1
    fi

    rm -f "$UPDATE_LOCK"

    # Show stats
    echo ""
    echo "IOC Database:"
    for f in packages.txt certificates.txt domains.txt ips.txt hashes.txt; do
        if [ -f "$IOC_DIR/$f" ]; then
            local count=$(wc -l < "$IOC_DIR/$f")
            local name=$(echo "$f" | sed 's/\.txt//')
            printf "  %-15s %s indicators\n" "$name:" "$count"
        fi
    done
}

# ── AUTO-UPDATE (called from daemon) ──
cmd_auto() {
    if ! needs_update; then
        return 0
    fi

    log "Auto-update: IOC database due for refresh"

    # Run at lowest priority
    renice 19 $$ 2>/dev/null
    ionice -c 3 -p $$ 2>/dev/null

    if [ -f "$UPDATE_LOCK" ]; then
        return 0
    fi
    touch "$UPDATE_LOCK"

    if update_from_backend; then
        log "Auto-update: refreshed from backend"
    elif update_from_git; then
        log "Auto-update: refreshed from git"
    else
        log "Auto-update: failed"
    fi

    rm -f "$UPDATE_LOCK"
}

# ── STATUS ──
cmd_status() {
    echo "IOC Updater Status:"
    local version=$(get_current_version)
    local last_ts=$(echo "$version" | cut -d'|' -f1)
    local count=$(echo "$version" | cut -d'|' -f2)
    local source=$(echo "$version" | cut -d'|' -f3)

    if [ "$last_ts" = "0" ]; then
        echo "  Last update: never"
    else
        local last_date=$(date -d @"$last_ts" '+%Y-%m-%d %H:%M' 2>/dev/null || echo "$last_ts")
        echo "  Last update: $last_date"
    fi
    echo "  Indicators:  $count"
    echo "  Source:      $source"
    echo "  Interval:    $((IOC_UPDATE_INTERVAL / 3600))h"
    echo "  Backend:     ${VIGIL_BACKEND_URL:-not configured}"

    if needs_update; then
        echo "  Status:      UPDATE DUE"
    else
        echo "  Status:      current"
    fi
}

# ── DISPATCH ──
case "$1" in
    update) cmd_update ;;
    auto)   cmd_auto ;;
    status) cmd_status ;;
    *)
        echo "IOC Auto-Updater [WIP]"
        echo "Usage: ioc_updater.sh {update|auto|status}"
        echo ""
        echo "  update   Manual IOC update (tries backend, then git)"
        echo "  auto     Check if update needed and refresh if due"
        echo "  status   Show update status and IOC stats"
        ;;
esac

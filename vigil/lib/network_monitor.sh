#!/system/bin/sh
# Vigil — Network Monitor / C2 Domain Blocker
# Blocks known C2, tracking, and surveillance domains via hosts + iptables
# (c) Setec Labs

VIGIL_DATA="/data/adb/vigil"
VIGIL_LOG="$VIGIL_DATA/vigil.log"
IOC_DIR="$VIGIL_DATA"
ALERT_DIR="$VIGIL_DATA/alerts"
NET_LOG="$VIGIL_DATA/network.log"

[ -f "$VIGIL_DATA/vigil.conf" ] && . "$VIGIL_DATA/vigil.conf"

HOSTS_MARKER="# vigil-managed"
IPTABLES_CHAIN="VIGIL_BLOCK"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [network] $1" >> "$VIGIL_LOG"
}

alert() {
    local severity="$1"
    local message="$2"
    local timestamp=$(date +%s)
    echo "${severity}|${timestamp}|network|${message}" >> "$ALERT_DIR/pending"
    log "ALERT [$severity]: $message"
}

# ── HOSTS FILE: Install domain blocklist ──
cmd_install_hosts() {
    log "Installing domain blocklist into hosts file..."

    local hosts_file="/system/etc/hosts"
    local vigil_hosts="$IOC_DIR/hosts.txt"

    if [ ! -f "$vigil_hosts" ]; then
        log "WARNING: hosts.txt not found"
        echo "ERROR: No hosts blocklist found at $vigil_hosts"
        return 1
    fi

    # Count domains to block
    local domain_count=$(grep -c "^0.0.0.0" "$vigil_hosts" 2>/dev/null || echo 0)

    # Backup original hosts if not already backed up
    if [ ! -f "$VIGIL_DATA/hosts.backup" ]; then
        cp "$hosts_file" "$VIGIL_DATA/hosts.backup" 2>/dev/null
    fi

    # Make /system writable (KernelSU overlay should handle this)
    mount -o rw,remount /system 2>/dev/null

    # Remove old vigil entries
    if grep -q "$HOSTS_MARKER" "$hosts_file" 2>/dev/null; then
        sed -i "/$HOSTS_MARKER/d" "$hosts_file"
    fi

    # Append new entries
    echo "" >> "$hosts_file"
    while read -r line; do
        echo "$line $HOSTS_MARKER" >> "$hosts_file"
    done < "$vigil_hosts"

    mount -o ro,remount /system 2>/dev/null

    log "Hosts blocklist installed: $domain_count domains"
    echo "Domain blocklist active: $domain_count domains blocked"
}

# ── HOSTS FILE: Remove blocklist ──
cmd_remove_hosts() {
    log "Removing domain blocklist from hosts file..."

    local hosts_file="/system/etc/hosts"

    mount -o rw,remount /system 2>/dev/null

    if grep -q "$HOSTS_MARKER" "$hosts_file" 2>/dev/null; then
        sed -i "/$HOSTS_MARKER/d" "$hosts_file"
        log "Hosts blocklist removed"
        echo "Domain blocklist removed"
    else
        echo "No vigil entries in hosts file"
    fi

    mount -o ro,remount /system 2>/dev/null
}

# ── IPTABLES: Block known malicious IPs ──
cmd_install_iptables() {
    if [ "${NETWORK_IPTABLES_ENABLED:-1}" != "1" ]; then
        echo "iptables blocking disabled in config"
        return 0
    fi

    log "Installing iptables IP blocklist..."

    local ip_file="$IOC_DIR/ips.txt"
    if [ ! -f "$ip_file" ]; then
        log "WARNING: ips.txt not found"
        echo "ERROR: No IP blocklist found"
        return 1
    fi

    # Create chain if it doesn't exist
    iptables -N "$IPTABLES_CHAIN" 2>/dev/null
    ip6tables -N "$IPTABLES_CHAIN" 2>/dev/null

    # Flush existing rules in our chain
    iptables -F "$IPTABLES_CHAIN" 2>/dev/null
    ip6tables -F "$IPTABLES_CHAIN" 2>/dev/null

    # Add our chain to OUTPUT if not already there
    iptables -C OUTPUT -j "$IPTABLES_CHAIN" 2>/dev/null || \
        iptables -I OUTPUT -j "$IPTABLES_CHAIN" 2>/dev/null

    ip6tables -C OUTPUT -j "$IPTABLES_CHAIN" 2>/dev/null || \
        ip6tables -I OUTPUT -j "$IPTABLES_CHAIN" 2>/dev/null

    # Block each IP with logging
    local count=0
    while IFS='|' read -r ip threat_name category; do
        [ -z "$ip" ] && continue
        [ "${ip:0:1}" = "#" ] && continue

        # Determine if IPv4 or IPv6
        if echo "$ip" | grep -q ":"; then
            ip6tables -A "$IPTABLES_CHAIN" -d "$ip" -j DROP 2>/dev/null && count=$((count + 1))
        else
            iptables -A "$IPTABLES_CHAIN" -d "$ip" -j DROP 2>/dev/null && count=$((count + 1))
        fi
    done < "$ip_file"

    log "iptables blocklist installed: $count IPs"
    echo "IP blocklist active: $count IPs blocked"
}

# ── IPTABLES: Remove blocklist ──
cmd_remove_iptables() {
    log "Removing iptables blocklist..."

    iptables -D OUTPUT -j "$IPTABLES_CHAIN" 2>/dev/null
    ip6tables -D OUTPUT -j "$IPTABLES_CHAIN" 2>/dev/null
    iptables -F "$IPTABLES_CHAIN" 2>/dev/null
    ip6tables -F "$IPTABLES_CHAIN" 2>/dev/null
    iptables -X "$IPTABLES_CHAIN" 2>/dev/null
    ip6tables -X "$IPTABLES_CHAIN" 2>/dev/null

    echo "IP blocklist removed"
}

# ── CONNECTION MONITOR: Watch for suspicious network activity ──
cmd_monitor() {
    log "Network monitor starting..."
    echo "Network monitor active — watching for C2 connections"

    local domain_file="$IOC_DIR/domains.txt"

    while true; do
        # Check active connections against known C2 IPs
        if [ -f "$IOC_DIR/ips.txt" ]; then
            # Get current connections
            cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | awk '{print $3}' | while read -r hex_addr; do
                # Convert hex IP to dotted notation
                local hex_ip=$(echo "$hex_addr" | cut -d: -f1)
                if [ ${#hex_ip} -eq 8 ]; then
                    # IPv4
                    local ip=$(printf "%d.%d.%d.%d" \
                        "0x${hex_ip:6:2}" "0x${hex_ip:4:2}" \
                        "0x${hex_ip:2:2}" "0x${hex_ip:0:2}" 2>/dev/null)

                    if grep -q "^${ip}|" "$IOC_DIR/ips.txt" 2>/dev/null; then
                        local match=$(grep "^${ip}|" "$IOC_DIR/ips.txt" | head -1)
                        local threat=$(echo "$match" | cut -d'|' -f2)
                        alert "CRITICAL" "ACTIVE C2 CONNECTION: $ip ($threat)"
                        echo "$(date +%s)|C2_CONNECTION|$ip|$threat" >> "$NET_LOG"
                    fi
                fi
            done
        fi

        # Check DNS cache / resolved domains if possible
        # dumpsys connectivity can reveal recent DNS lookups on some ROMs
        if [ -f "$domain_file" ]; then
            dumpsys connectivity 2>/dev/null | grep -oE '[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | sort -u | while read -r domain; do
                if grep -q "^${domain}|" "$domain_file" 2>/dev/null; then
                    local match=$(grep "^${domain}|" "$domain_file" | head -1)
                    local threat=$(echo "$match" | cut -d'|' -f2)
                    local category=$(echo "$match" | cut -d'|' -f3)
                    alert "HIGH" "SUSPICIOUS DOMAIN RESOLVED: $domain ($threat) [$category]"
                    echo "$(date +%s)|DNS_RESOLVE|$domain|$threat" >> "$NET_LOG"
                fi
            done
        fi

        sleep 30
    done
}

# ── STATUS ──
cmd_status() {
    echo "Network Monitor Status:"
    echo "  Enabled:     ${NETWORK_MONITOR_ENABLED:-1}"
    echo "  C2 Block:    ${NETWORK_BLOCK_C2:-1}"
    echo "  Tracker Block: ${NETWORK_BLOCK_TRACKERS:-1}"
    echo "  iptables:    ${NETWORK_IPTABLES_ENABLED:-1}"

    # Check if our hosts entries are active
    local hosts_count=$(grep -c "$HOSTS_MARKER" /system/etc/hosts 2>/dev/null || echo 0)
    echo "  Hosts rules: $hosts_count domains"

    # Check iptables chain
    local ipt_count=$(iptables -L "$IPTABLES_CHAIN" 2>/dev/null | grep -c "DROP" || echo 0)
    echo "  IP rules:    $ipt_count IPs"

    if [ -f "$NET_LOG" ]; then
        local detections=$(wc -l < "$NET_LOG")
        echo "  Detections:  $detections logged"
    fi
}

# ── FULL INSTALL ──
cmd_install() {
    cmd_install_hosts
    cmd_install_iptables
}

# ── FULL REMOVE ──
cmd_remove() {
    cmd_remove_hosts
    cmd_remove_iptables
}

# ── DISPATCH ──
case "$1" in
    install)          cmd_install ;;
    remove)           cmd_remove ;;
    install-hosts)    cmd_install_hosts ;;
    remove-hosts)     cmd_remove_hosts ;;
    install-iptables) cmd_install_iptables ;;
    remove-iptables)  cmd_remove_iptables ;;
    monitor)          cmd_monitor ;;
    status)           cmd_status ;;
    *)
        echo "Network Monitor — C2 & Tracker Blocker"
        echo "Usage: network_monitor.sh {install|remove|monitor|status}"
        echo ""
        echo "  install           Install hosts + iptables blocklists"
        echo "  remove            Remove all blocklists"
        echo "  install-hosts     Install hosts-based domain blocking only"
        echo "  install-iptables  Install iptables IP blocking only"
        echo "  monitor           Live network connection monitoring"
        echo "  status            Show network monitor status"
        ;;
esac

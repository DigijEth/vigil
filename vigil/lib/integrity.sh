#!/system/bin/sh
# Vigil — FrostGuard File Integrity Monitor
# Provides pseudo-locked-bootloader protection via file integrity + heuristics
# (c) Setec Labs

VIGIL_DATA="/data/adb/vigil"
BASELINE_DIR="$VIGIL_DATA/baseline"
ALERT_DIR="$VIGIL_DATA/alerts"
VIGIL_LOG="$VIGIL_DATA/vigil.log"

# Load config
[ -f "$VIGIL_DATA/vigil.conf" ] && . "$VIGIL_DATA/vigil.conf"

CRITICAL_PATHS="${FROSTGUARD_CRITICAL_PATHS:-/system/bin /system/xbin /system/lib64 /system/framework /system/app /system/priv-app /vendor/bin}"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [frostguard] $1" >> "$VIGIL_LOG"
}

alert() {
    local severity="$1"
    local message="$2"
    local timestamp=$(date +%s)
    echo "${severity}|${timestamp}|frostguard|${message}" >> "$ALERT_DIR/pending"
    log "ALERT [$severity]: $message"
}

# Generate SHA256 hash of a file
hash_file() {
    sha256sum "$1" 2>/dev/null | cut -d' ' -f1
}

# ── BASELINE: Create integrity baseline of critical system files ──
cmd_baseline() {
    log "Creating file integrity baseline..."
    mkdir -p "$BASELINE_DIR"

    local count=0
    for path in $CRITICAL_PATHS; do
        if [ -d "$path" ]; then
            find "$path" -type f 2>/dev/null | while read -r file; do
                local hash=$(hash_file "$file")
                local perms=$(stat -c '%a:%u:%g' "$file" 2>/dev/null || ls -ln "$file" | awk '{print $1":"$3":"$4}')
                local size=$(stat -c '%s' "$file" 2>/dev/null || ls -ln "$file" | awk '{print $5}')
                echo "${hash}|${perms}|${size}|${file}"
            done
        elif [ -f "$path" ]; then
            local hash=$(hash_file "$path")
            local perms=$(stat -c '%a:%u:%g' "$path" 2>/dev/null || ls -ln "$path" | awk '{print $1":"$3":"$4}')
            local size=$(stat -c '%s' "$path" 2>/dev/null || ls -ln "$path" | awk '{print $5}')
            echo "${hash}|${perms}|${size}|${path}"
        fi
    done > "$BASELINE_DIR/system.baseline"

    # Also baseline boot image hashes if accessible
    for part in boot init_boot vendor_boot dtbo vbmeta; do
        local block=$(find /dev/block -name "$part" 2>/dev/null | head -1)
        if [ -n "$block" ] && [ -r "$block" ]; then
            local bhash=$(sha256sum "$block" 2>/dev/null | cut -d' ' -f1)
            echo "${bhash}|${part}" >> "$BASELINE_DIR/partitions.baseline"
        fi
    done

    count=$(wc -l < "$BASELINE_DIR/system.baseline" 2>/dev/null || echo 0)
    log "Baseline created: $count files indexed"
    echo "Baseline created: $count files indexed"
}

# ── VERIFY: Check current state against baseline ──
cmd_verify() {
    if [ ! -f "$BASELINE_DIR/system.baseline" ]; then
        log "No baseline found — run 'vigil integrity baseline' first"
        echo "ERROR: No baseline found"
        return 1
    fi

    log "Verifying file integrity..."
    local violations=0
    local checked=0
    local missing=0
    local modified=0
    local perm_changed=0
    local new_files=0

    # Check each baselined file
    while IFS='|' read -r expected_hash expected_perms expected_size filepath; do
        checked=$((checked + 1))

        if [ ! -f "$filepath" ]; then
            alert "HIGH" "File MISSING: $filepath"
            missing=$((missing + 1))
            violations=$((violations + 1))
            continue
        fi

        local current_hash=$(hash_file "$filepath")
        local current_perms=$(stat -c '%a:%u:%g' "$filepath" 2>/dev/null || ls -ln "$filepath" | awk '{print $1":"$3":"$4}')
        local current_size=$(stat -c '%s' "$filepath" 2>/dev/null || ls -ln "$filepath" | awk '{print $5}')

        if [ "$current_hash" != "$expected_hash" ]; then
            alert "CRITICAL" "File MODIFIED: $filepath (expected: ${expected_hash:0:16}... got: ${current_hash:0:16}...)"
            modified=$((modified + 1))
            violations=$((violations + 1))
        fi

        if [ "$current_perms" != "$expected_perms" ]; then
            alert "MEDIUM" "Permissions CHANGED: $filepath ($expected_perms -> $current_perms)"
            perm_changed=$((perm_changed + 1))
            violations=$((violations + 1))
        fi
    done < "$BASELINE_DIR/system.baseline"

    # Heuristic: check for NEW files in critical paths (could indicate implants)
    for path in $CRITICAL_PATHS; do
        if [ -d "$path" ]; then
            find "$path" -type f -newer "$BASELINE_DIR/system.baseline" 2>/dev/null | while read -r newfile; do
                if ! grep -q "|${newfile}$" "$BASELINE_DIR/system.baseline" 2>/dev/null; then
                    alert "HIGH" "NEW file detected: $newfile"
                    new_files=$((new_files + 1))
                    violations=$((violations + 1))
                fi
            done
        fi
    done

    # Check boot partitions
    if [ -f "$BASELINE_DIR/partitions.baseline" ]; then
        while IFS='|' read -r expected_hash part_name; do
            local block=$(find /dev/block -name "$part_name" 2>/dev/null | head -1)
            if [ -n "$block" ] && [ -r "$block" ]; then
                local current_hash=$(sha256sum "$block" 2>/dev/null | cut -d' ' -f1)
                if [ "$current_hash" != "$expected_hash" ]; then
                    alert "CRITICAL" "PARTITION MODIFIED: $part_name"
                    violations=$((violations + 1))
                fi
            fi
        done < "$BASELINE_DIR/partitions.baseline"
    fi

    log "Integrity check complete: $checked files checked, $violations violations"
    echo "FrostGuard Report:"
    echo "  Files checked:      $checked"
    echo "  Modified:           $modified"
    echo "  Missing:            $missing"
    echo "  Permission changes: $perm_changed"
    echo "  New files:          $new_files"
    echo "  Total violations:   $violations"

    return $violations
}

# ── VERIFY-CRITICAL: Fast check of most important files only ──
cmd_verify_critical() {
    if [ ! -f "$BASELINE_DIR/system.baseline" ]; then
        return 0  # No baseline yet, skip
    fi

    # Only check key binaries and framework files
    local violations=0
    for pattern in "/system/bin/app_process" "/system/bin/linker" "/system/framework/framework.jar" "/system/framework/services.jar" "/init"; do
        local line=$(grep "|${pattern}$" "$BASELINE_DIR/system.baseline" 2>/dev/null)
        if [ -n "$line" ]; then
            local expected_hash=$(echo "$line" | cut -d'|' -f1)
            local current_hash=$(hash_file "$pattern")
            if [ -n "$current_hash" ] && [ "$current_hash" != "$expected_hash" ]; then
                alert "CRITICAL" "Critical file MODIFIED: $pattern"
                violations=$((violations + 1))
            fi
        fi
    done

    return $violations
}

# ── HEURISTIC: Detect suspicious system modifications ──
cmd_heuristic() {
    log "Running heuristic analysis..."
    local suspicious=0

    # Check for common implant locations
    for dir in /data/local/tmp /data/local/tmp/cb /cblr /dev/shm; do
        if [ -d "$dir" ] && [ "$(ls -A "$dir" 2>/dev/null)" ]; then
            local fcount=$(find "$dir" -type f 2>/dev/null | wc -l)
            if [ "$fcount" -gt 0 ]; then
                alert "HIGH" "Suspicious files in staging directory: $dir ($fcount files)"
                suspicious=$((suspicious + 1))
            fi
        fi
    done

    # Check for unexpected SUID binaries
    find /system /vendor -perm -4000 -type f 2>/dev/null | while read -r suid; do
        if ! grep -q "|${suid}$" "$BASELINE_DIR/system.baseline" 2>/dev/null; then
            alert "HIGH" "Unexpected SUID binary: $suid"
            suspicious=$((suspicious + 1))
        fi
    done

    # Check for Frida, Xposed, or other injection frameworks
    for proc_name in frida-server frida-agent xposed zygisk; do
        if ps -A 2>/dev/null | grep -qi "$proc_name"; then
            alert "MEDIUM" "Injection framework detected: $proc_name"
            suspicious=$((suspicious + 1))
        fi
    done

    # Check SELinux status
    local selinux=$(getenforce 2>/dev/null)
    if [ "$selinux" = "Permissive" ] || [ "$selinux" = "Disabled" ]; then
        alert "HIGH" "SELinux is $selinux — system may be compromised"
        suspicious=$((suspicious + 1))
    fi

    echo "Heuristic analysis: $suspicious suspicious findings"
    return $suspicious
}

# ── DISPATCH ──
case "$1" in
    baseline)       cmd_baseline ;;
    verify)         cmd_verify ;;
    verify-critical) cmd_verify_critical ;;
    heuristic)      cmd_heuristic ;;
    *)
        echo "FrostGuard — File Integrity Monitor"
        echo "Usage: integrity.sh {baseline|verify|verify-critical|heuristic}"
        ;;
esac

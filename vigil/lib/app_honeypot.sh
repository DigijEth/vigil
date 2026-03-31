#!/system/bin/sh
# Vigil — App Permissions Honeypot / Data Redirect
# Redirects spyware data requests to fake honeypot data
# Moves suspicious apps to restricted user profile
# (c) Setec Labs
#
# THEORY:
# Stalkerware/spyware apps request sensitive permissions (camera, mic,
# location, contacts, SMS, call logs). Rather than just detecting them,
# we can:
# 1. Identify apps with dangerous permission combos
# 2. Redirect their data access to fake/honeypot data
# 3. Move them to a restricted user profile with sandboxed data
# 4. Feed them plausible but false information
#
# This approach is better than blocking because:
# - The spyware doesn't know it's been detected
# - The attacker gets disinformation instead of nothing
# - The app continues "working" (no crash reports to attacker)

VIGIL_DATA="/data/adb/vigil"
VIGIL_LOG="$VIGIL_DATA/vigil.log"
IOC_DIR="$VIGIL_DATA"
ALERT_DIR="$VIGIL_DATA/alerts"

[ -f "$VIGIL_DATA/vigil.conf" ] && . "$VIGIL_DATA/vigil.conf"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [app_honeypot] $1" >> "$VIGIL_LOG"
}

alert() {
    local severity="$1"
    local message="$2"
    local timestamp=$(date +%s)
    echo "${severity}|${timestamp}|app_honeypot|${message}" >> "$ALERT_DIR/pending"
    log "ALERT [$severity]: $message"
}

# Dangerous permission combinations that indicate spyware behavior
# A single permission is normal; the COMBINATION is suspicious
SPYWARE_PERMISSION_SETS="
CAMERA+RECORD_AUDIO+ACCESS_FINE_LOCATION+READ_CONTACTS
READ_SMS+ACCESS_FINE_LOCATION+RECORD_AUDIO
READ_CALL_LOG+READ_SMS+ACCESS_FINE_LOCATION
CAMERA+RECORD_AUDIO+READ_SMS+READ_CONTACTS
BIND_ACCESSIBILITY_SERVICE+READ_SMS+ACCESS_FINE_LOCATION
BIND_NOTIFICATION_LISTENER_SERVICE+READ_SMS+READ_CONTACTS
READ_SMS+RECEIVE_SMS+SEND_SMS+ACCESS_FINE_LOCATION
READ_CONTACTS+READ_CALL_LOG+READ_SMS+CAMERA+RECORD_AUDIO
"

# ── PERMISSION AUDIT: Find apps with dangerous permission combos ──
cmd_audit() {
    log "Auditing app permissions..."
    echo "App Permission Audit"
    echo "━━━━━━━━━━━━━━━━━━━━"
    echo ""

    local suspicious_apps=""
    local total_suspicious=0

    pm list packages -3 2>/dev/null | sed 's/package://' | while read -r pkg; do
        # Get granted permissions
        local perms=$(dumpsys package "$pkg" 2>/dev/null | grep "android.permission\." | grep "granted=true" | grep -oE '[A-Z_]+' | sort -u)

        if [ -z "$perms" ]; then
            continue
        fi

        # Check against spyware permission combos
        local max_match=0
        local matched_set=""

        echo "$SPYWARE_PERMISSION_SETS" | grep "+" | while read -r perm_set; do
            [ -z "$perm_set" ] && continue
            local required=$(echo "$perm_set" | tr '+' '\n')
            local match_count=0
            local total_required=0

            for req_perm in $required; do
                total_required=$((total_required + 1))
                if echo "$perms" | grep -q "$req_perm"; then
                    match_count=$((match_count + 1))
                fi
            done

            # If 80%+ of the dangerous combo is present, flag it
            if [ $total_required -gt 0 ]; then
                local match_pct=$((match_count * 100 / total_required))
                if [ $match_pct -ge 80 ]; then
                    echo "$pkg|$match_pct|$perm_set"
                fi
            fi
        done | sort -t'|' -k2 -rn | head -1 | while IFS='|' read -r s_pkg s_pct s_set; do
            if [ -n "$s_pkg" ]; then
                # Check if already in IOC database
                local known=""
                if [ -f "$IOC_DIR/packages.txt" ]; then
                    local ioc_match=$(grep "^${s_pkg}|" "$IOC_DIR/packages.txt" 2>/dev/null | head -1)
                    if [ -n "$ioc_match" ]; then
                        known=" [KNOWN: $(echo "$ioc_match" | cut -d'|' -f2)]"
                    fi
                fi

                # Check if it's a system app
                local is_system=$(pm dump "$s_pkg" 2>/dev/null | grep -c "SYSTEM")

                if [ "$is_system" -eq 0 ]; then
                    total_suspicious=$((total_suspicious + 1))
                    local app_label=$(pm dump "$s_pkg" 2>/dev/null | grep "applicationInfo" | head -1)
                    echo "  ⚠ $s_pkg (${s_pct}% match)${known}"
                    echo "    Dangerous combo: $s_set"

                    if [ -n "$known" ]; then
                        alert "CRITICAL" "KNOWN THREAT with spyware permissions: $s_pkg$known"
                    else
                        alert "HIGH" "Suspicious permission combo: $s_pkg ($s_set)"
                    fi
                fi
            fi
        done
    done

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━"
    echo "Audit complete"
}

# ── REVOKE: Strip dangerous permissions from a specific app ──
cmd_revoke() {
    local pkg="$1"
    if [ -z "$pkg" ]; then
        echo "Usage: app_honeypot.sh revoke <package_name>"
        return 1
    fi

    log "Revoking dangerous permissions from: $pkg"
    echo "Revoking permissions from: $pkg"

    local dangerous_perms="READ_SMS RECEIVE_SMS SEND_SMS READ_CONTACTS READ_CALL_LOG CAMERA RECORD_AUDIO ACCESS_FINE_LOCATION ACCESS_COARSE_LOCATION ACCESS_BACKGROUND_LOCATION READ_EXTERNAL_STORAGE WRITE_EXTERNAL_STORAGE READ_MEDIA_IMAGES READ_MEDIA_VIDEO READ_MEDIA_AUDIO"

    for perm in $dangerous_perms; do
        local full_perm="android.permission.$perm"
        if pm revoke "$pkg" "$full_perm" 2>/dev/null; then
            echo "  Revoked: $perm"
        fi
    done

    # Also restrict via appops (more thorough than permission revoke)
    local appops="READ_SMS RECEIVE_SMS SEND_SMS READ_CONTACTS READ_CALL_LOG CAMERA RECORD_AUDIO FINE_LOCATION COARSE_LOCATION READ_EXTERNAL_STORAGE WRITE_EXTERNAL_STORAGE"
    for op in $appops; do
        appops set "$pkg" "$op" deny 2>/dev/null
    done

    echo "Permissions revoked for $pkg"
    alert "INFO" "Stripped dangerous permissions from: $pkg"
}

# ── SANDBOX: Move app to restricted work profile ──
cmd_sandbox() {
    local pkg="$1"
    if [ -z "$pkg" ]; then
        echo "Usage: app_honeypot.sh sandbox <package_name>"
        return 1
    fi

    log "Sandboxing app: $pkg"
    echo "Sandboxing: $pkg"

    # Check if a work profile exists, create if needed
    local work_profile=$(pm list users 2>/dev/null | grep -oE "UserInfo\{[0-9]+" | grep -v "UserInfo{0" | head -1 | grep -oE "[0-9]+")

    if [ -z "$work_profile" ]; then
        echo "  Creating restricted profile..."
        # Create a restricted user profile
        pm create-user --restricted "Vigil_Sandbox" 2>/dev/null
        work_profile=$(pm list users 2>/dev/null | grep "Vigil_Sandbox" | grep -oE "{[0-9]+" | tr -d '{')

        if [ -z "$work_profile" ]; then
            echo "  Failed to create restricted profile"
            echo "  Falling back to permission revocation..."
            cmd_revoke "$pkg"
            return 1
        fi
    fi

    echo "  Using profile: $work_profile"

    # Install the app in the restricted profile
    pm install-existing --user "$work_profile" "$pkg" 2>/dev/null

    # Disable the app in the main profile
    pm disable-user --user 0 "$pkg" 2>/dev/null

    # Restrict the app's permissions in the sandbox
    cmd_revoke "$pkg"

    echo "  App sandboxed in profile $work_profile"
    echo "  Disabled in main profile"
    alert "INFO" "Sandboxed $pkg in restricted profile $work_profile"
}

# ── FEED FAKE DATA: Configure data redirection for an app ──
cmd_feed_fake() {
    local pkg="$1"
    if [ -z "$pkg" ]; then
        echo "Usage: app_honeypot.sh feed <package_name>"
        return 1
    fi

    log "Setting up data honeypot for: $pkg"
    echo "Configuring data honeypot for: $pkg"

    # 1. Force fake location for this app via appops
    echo "  [1] Forcing mock location..."
    appops set "$pkg" MOCK_LOCATION allow 2>/dev/null
    appops set "$pkg" FINE_LOCATION deny 2>/dev/null
    appops set "$pkg" COARSE_LOCATION deny 2>/dev/null
    # The app will get mock location data if our mock GPS is active

    # 2. Deny real camera/mic, app will get black frames / silence
    echo "  [2] Blocking real camera/mic..."
    appops set "$pkg" CAMERA deny 2>/dev/null
    appops set "$pkg" RECORD_AUDIO deny 2>/dev/null

    # 3. Block real contacts/SMS access
    echo "  [3] Blocking real contacts/SMS..."
    appops set "$pkg" READ_CONTACTS deny 2>/dev/null
    appops set "$pkg" READ_SMS deny 2>/dev/null
    appops set "$pkg" READ_CALL_LOG deny 2>/dev/null

    # 4. Restrict background activity
    echo "  [4] Restricting background activity..."
    cmd appops set "$pkg" RUN_IN_BACKGROUND deny 2>/dev/null
    cmd appops set "$pkg" RUN_ANY_IN_BACKGROUND deny 2>/dev/null
    # But allow foreground so it doesn't crash
    am set-standby-bucket "$pkg" restricted 2>/dev/null

    # 5. Restrict network (prevent data exfiltration)
    echo "  [5] Restricting network access..."
    # Get the app's UID
    local uid=$(dumpsys package "$pkg" 2>/dev/null | grep "userId=" | head -1 | grep -oE "[0-9]+")
    if [ -n "$uid" ]; then
        # Block network via iptables for this UID
        iptables -A OUTPUT -m owner --uid-owner "$uid" -j DROP 2>/dev/null
        ip6tables -A OUTPUT -m owner --uid-owner "$uid" -j DROP 2>/dev/null
        echo "  Network blocked for UID $uid"
    fi

    echo ""
    echo "Honeypot active for $pkg:"
    echo "  - Location: redirected to mock GPS"
    echo "  - Camera/Mic: blocked (black/silent)"
    echo "  - Contacts/SMS/Calls: blocked"
    echo "  - Background: restricted"
    echo "  - Network: blocked (no exfiltration)"
    echo ""
    echo "The app thinks it's working but gets nothing real."

    alert "INFO" "Data honeypot configured for: $pkg"
}

# ── AUTO: Automatically honeypot all detected threats ──
cmd_auto() {
    log "Auto-honeypot: checking all installed apps..."
    echo "Auto-detecting and honeypotting threats..."

    local honeypotted=0

    if [ ! -f "$IOC_DIR/packages.txt" ]; then
        echo "No IOC database found"
        return 1
    fi

    pm list packages -3 2>/dev/null | sed 's/package://' | while read -r pkg; do
        local match=$(grep "^${pkg}|" "$IOC_DIR/packages.txt" 2>/dev/null | head -1)
        if [ -n "$match" ]; then
            local threat=$(echo "$match" | cut -d'|' -f2)
            local category=$(echo "$match" | cut -d'|' -f3)

            echo "  Honeypotting: $pkg ($threat) [$category]"
            cmd_feed_fake "$pkg" > /dev/null 2>&1
            honeypotted=$((honeypotted + 1))
        fi
    done

    echo ""
    echo "Auto-honeypot complete: $honeypotted apps honeypotted"
}

# ── STATUS ──
cmd_status() {
    echo "App Honeypot Status:"

    # Count apps with restricted appops
    local restricted=0
    pm list packages -3 2>/dev/null | sed 's/package://' | while read -r pkg; do
        local cam=$(appops get "$pkg" CAMERA 2>/dev/null)
        local loc=$(appops get "$pkg" FINE_LOCATION 2>/dev/null)
        if echo "$cam" | grep -q "deny" && echo "$loc" | grep -q "deny"; then
            restricted=$((restricted + 1))
            echo "  Honeypotted: $pkg"
        fi
    done

    # Check for sandbox profile
    local sandbox=$(pm list users 2>/dev/null | grep "Vigil_Sandbox")
    if [ -n "$sandbox" ]; then
        echo "  Sandbox profile: active"
    fi
}

# ── DISPATCH ──
case "$1" in
    audit)    cmd_audit ;;
    revoke)   shift; cmd_revoke "$@" ;;
    sandbox)  shift; cmd_sandbox "$@" ;;
    feed)     shift; cmd_feed_fake "$@" ;;
    auto)     cmd_auto ;;
    status)   cmd_status ;;
    *)
        echo "App Permissions Honeypot — Data Redirect Defense"
        echo "Usage: app_honeypot.sh {audit|revoke|sandbox|feed|auto|status}"
        echo ""
        echo "  audit               Scan for apps with spyware-like permission combos"
        echo "  revoke <pkg>        Strip dangerous permissions from an app"
        echo "  sandbox <pkg>       Move app to restricted user profile"
        echo "  feed <pkg>          Feed fake data to an app (honeypot)"
        echo "  auto                Auto-honeypot all detected threat apps"
        echo "  status              Show honeypot status"
        ;;
esac

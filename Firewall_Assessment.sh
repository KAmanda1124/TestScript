
#!/usr/bin/env bash
# ============================================================
# MWCCDC - FW01 Host Firewall Assessment and Hardening
#
# Supported: iptables, firewalld
# Runtime-only changes
#
# Functions:
# 1. Assess current firewall
# 2. Apply service-specific hardening
# 3. Verify firewall configuration
# 4. Capture before/after evidence
#
# WARNING:
# Applying rules can interrupt network services.
# Test in a disposable VM with console access.
# ============================================================

set -Eeuo pipefail

CHAIN="MWCCDC_HOST"
EVIDENCE_DIR="./firewall-evidence"

BACKEND=""
SESSION_DIR=""
SELECTED_PROFILES=""
TCP_PORTS=()
UDP_PORTS=()

has() {
    command -v "$1" >/dev/null 2>&1
}

pause_menu() {
    echo
    read -r -p "Press Enter to continue..." _
}

heading() {
    echo
    echo "========================================"
    echo " $1"
    echo "========================================"
}

error() {
    echo "[ERROR] $*" >&2
}

info() {
    echo "[INFO] $*"
}

warn() {
    echo "[WARN] $*"
}

need_root() {
    [[ $EUID -eq 0 ]] || {
        error "Run using sudo."
        exit 1
    }
}

# ============================================================
# FIREWALL DETECTION
# ============================================================

detect_backend() {
    BACKEND="unknown"

    if has firewall-cmd &&
       firewall-cmd --state 2>/dev/null |
       grep -qx running; then
        BACKEND="firewalld"
        return
    fi

    if has ufw &&
       ufw status 2>/dev/null |
       grep -qi '^Status: active'; then
        BACKEND="ufw"
        return
    fi

    if has iptables; then
        BACKEND="iptables"
        return
    fi

    BACKEND="unsupported"
}

# ============================================================
# SCROLLABLE OUTPUT
# ============================================================

show_scrollable() {
    local title="$1"
    shift

    local output
    output="$(mktemp)"

    {
        heading "$title"
        "$@"
    } > "$output" 2>&1

    if has less; then
        less -S -R "$output"
    else
        cat "$output"
        pause_menu
    fi

    rm -f "$output"
}

# ============================================================
# HOST INFORMATION
# ============================================================

host_info() {
    detect_backend

    echo "Hostname : $(hostname)"
    echo "OS       : $(. /etc/os-release; echo "$PRETTY_NAME")"
    echo "Firewall : $BACKEND"
}

# ============================================================
# FIREWALL ASSESSMENT
# ============================================================

assess_firewall() {
    detect_backend

    heading "CURRENT FIREWALL RULES"
    host_info

    echo
    echo "--- Active Firewall Configuration ---"

    case "$BACKEND" in

        firewalld)
            echo
            echo "Active zones:"
            firewall-cmd --get-active-zones

            echo
            echo "Zone rules:"

            while read -r zone; do
                [[ -n "$zone" ]] || continue

                echo
                echo "Zone: $zone"
                firewall-cmd --zone="$zone" --list-all

            done < <(
                firewall-cmd --get-active-zones |
                awk '/^[^[:space:]]/ {print $1}'
            )
            ;;

        ufw)
            ufw status verbose
            ;;

        iptables)
            echo
            echo "IPv4:"
            iptables -L -n -v

            if has ip6tables; then
                echo
                echo "IPv6:"
                ip6tables -L -n -v
            fi
            ;;

        *)
            echo "Unsupported firewall manager."
            ;;
    esac

    echo
    echo "--- Listening Services ---"
    ss -tuln
}

# ============================================================
# SERVICE PROFILES
# ============================================================

choose_profiles() {
    echo
    echo "Available profiles:"
    echo
    echo " webserver : TCP 80,443"
    echo " mail      : TCP 25,465,587,110,995,143,993"
    echo " splunk    : TCP 8000,8089,9997"
    echo " dnsntp    : TCP/UDP 53, UDP 123"
    echo " wrkstn    : No additional inbound ports"
    echo
    echo "Combine profiles using commas."
    echo "Example: mail,webserver"
    echo

    read -r -p "Profiles: " SELECTED_PROFILES

    SELECTED_PROFILES="${SELECTED_PROFILES// /}"

    [[ -n "$SELECTED_PROFILES" ]] || {
        error "No profile selected."
        return 1
    }

    TCP_PORTS=()
    UDP_PORTS=()

    local profile
    local -a profiles

    IFS=',' read -r -a profiles <<< "$SELECTED_PROFILES"

    for profile in "${profiles[@]}"; do
        case "$profile" in

            webserver)
                TCP_PORTS+=(80 443)
                ;;

            mail)
                TCP_PORTS+=(25 465 587 110 995 143 993)
                ;;

            splunk)
                TCP_PORTS+=(8000 8089 9997)
                ;;

            dnsntp)
                TCP_PORTS+=(53)
                UDP_PORTS+=(53 123)
                ;;

            wrkstn)
                ;;

            *)
                error "Unknown profile: $profile"
                return 1
                ;;
        esac
    done

    if ((${#TCP_PORTS[@]})); then
        mapfile -t TCP_PORTS < <(
            printf '%s\n' "${TCP_PORTS[@]}" | sort -nu
        )
    fi

    if ((${#UDP_PORTS[@]})); then
        mapfile -t UDP_PORTS < <(
            printf '%s\n' "${UDP_PORTS[@]}" | sort -nu
        )
    fi
}

# ============================================================
# HARDENING PLAN
# ============================================================

show_plan() {
    heading "FIREWALL HARDENING PLAN"

    echo "Hostname : $(hostname)"
    echo "Firewall : $BACKEND"
    echo "Profiles : $SELECTED_PROFILES"
    echo
    echo "Required inbound TCP: ${TCP_PORTS[*]:-None}"
    echo "Required inbound UDP: ${UDP_PORTS[*]:-None}"
    echo
    echo "Security controls:"
    echo " - Allow loopback traffic"
    echo " - Allow established/related connections"
    echo " - Block inbound SSH (TCP 22)"
    echo " - Allow selected service ports"
    echo " - Drop other inbound traffic"
    echo " - Preserve existing outbound policy"
    echo
    echo "Changes are runtime-only."
}

# ============================================================
# EVIDENCE COLLECTION
# ============================================================

capture_phase() {
    local phase="$1"
    local directory="$SESSION_DIR/$phase"

    mkdir -p "$directory"

    date -Is > "$directory/timestamp.txt"
    host_info > "$directory/host.txt"
    ip -br addr > "$directory/network.txt"
    ss -tuln > "$directory/listening.txt"

    assess_firewall > "$directory/firewall-rules.txt" 2>&1

    if has iptables; then
        iptables-save > "$directory/iptables.txt" 2>&1 || true
    fi

    if has ip6tables; then
        ip6tables-save > "$directory/ip6tables.txt" 2>&1 || true
    fi

    if has nft; then
        nft -a list ruleset > "$directory/nftables.txt" 2>&1 || true
    fi

    if has firewall-cmd; then
        firewall-cmd --list-all-zones \
            > "$directory/firewalld-zones.txt" 2>&1 || true
    fi

    info "Captured $phase evidence."
}

# ============================================================
# IPTABLES ENFORCEMENT
# ============================================================

apply_iptables_family() {
    local cmd="$1"
    local port

    "$cmd" -N "$CHAIN" 2>/dev/null || true
    "$cmd" -F "$CHAIN"

    "$cmd" -A "$CHAIN" -i lo -j ACCEPT

    "$cmd" -A "$CHAIN" -m conntrack \
        --ctstate ESTABLISHED,RELATED -j ACCEPT

    "$cmd" -A "$CHAIN" -p tcp --dport 22 -j DROP

    for port in "${TCP_PORTS[@]}"; do
        "$cmd" -A "$CHAIN" -p tcp \
            --dport "$port" -j ACCEPT
    done

    for port in "${UDP_PORTS[@]}"; do
        "$cmd" -A "$CHAIN" -p udp \
            --dport "$port" -j ACCEPT
    done

    if [[ "$cmd" == ip6tables ]]; then
        "$cmd" -A "$CHAIN" -p ipv6-icmp -j ACCEPT
    else
        "$cmd" -A "$CHAIN" -p icmp -j ACCEPT
    fi

    "$cmd" -A "$CHAIN" -j DROP

    "$cmd" -C INPUT -j "$CHAIN" 2>/dev/null ||
        "$cmd" -I INPUT 1 -j "$CHAIN"
}

apply_iptables() {
    has iptables || {
        error "iptables not installed."
        return 1
    }

    if [[ -s /proc/net/if_inet6 ]] && ! has ip6tables; then
        error "IPv6 enabled but ip6tables missing."
        return 1
    fi

    apply_iptables_family iptables

    if [[ -s /proc/net/if_inet6 ]]; then
        apply_iptables_family ip6tables
    fi

    info "iptables firewall profile applied."
}

# ============================================================
# FIREWALLD ENFORCEMENT
# ============================================================

apply_firewalld() {
    has firewall-cmd || {
        error "firewall-cmd not installed."
        return 1
    }

    # firewalld runtime direct rules use an independent
    # chain to filter inbound traffic.
    #
    # NOTE: Direct-rule behavior depends on firewalld
    # backend and should be tested carefully.

    local port
    local priority=0

    firewall-cmd --direct --add-chain ipv4 filter "$CHAIN" \
        2>/dev/null || true

    firewall-cmd --direct --add-rule ipv4 filter INPUT \
        "$priority" -j "$CHAIN" 2>/dev/null || true

    firewall-cmd --direct --add-rule ipv4 filter "$CHAIN" \
        0 -i lo -j ACCEPT

    firewall-cmd --direct --add-rule ipv4 filter "$CHAIN" \
        1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    firewall-cmd --direct --add-rule ipv4 filter "$CHAIN" \
        2 -p tcp --dport 22 -j DROP

    priority=10

    for port in "${TCP_PORTS[@]}"; do
        firewall-cmd --direct --add-rule ipv4 filter "$CHAIN" \
            "$priority" -p tcp --dport "$port" -j ACCEPT
        ((priority+=1))
    done

    for port in "${UDP_PORTS[@]}"; do
        firewall-cmd --direct --add-rule ipv4 filter "$CHAIN" \
            "$priority" -p udp --dport "$port" -j ACCEPT
        ((priority+=1))
    done

    firewall-cmd --direct --add-rule ipv4 filter "$CHAIN" \
        100 -j DROP

    info "firewalld runtime direct rules applied."
    warn "Verify active zone allowances and IPv6 separately."
}

# ============================================================
# APPLY HARDENING
# ============================================================

apply_hardening() {
    detect_backend

    case "$BACKEND" in
        iptables|firewalld)
            ;;
        *)
            error "Automatic enforcement not supported for $BACKEND."
            return
            ;;
    esac

    choose_profiles || return
    show_plan

    echo
    warn "This will change active firewall rules."
    warn "Ensure you have console access."
    echo
    read -r -p "Type APPLY to continue: " confirm

    [[ "$confirm" == "APPLY" ]] || {
        info "Cancelled."
        return
    }

    SESSION_DIR="$EVIDENCE_DIR/$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$SESSION_DIR"

    show_plan > "$SESSION_DIR/hardening-plan.txt"

    capture_phase before

    case "$BACKEND" in
        iptables)
            apply_iptables
            ;;
        firewalld)
            apply_firewalld
            ;;
    esac

    capture_phase after

    info "Hardening process completed."
    echo "Evidence: $SESSION_DIR"
}

# ============================================================
# VERIFICATION
# ============================================================

verify_firewall() {
    heading "FIREWALL VERIFICATION"

    detect_backend

    echo "Hostname : $(hostname)"
    echo "Firewall : $BACKEND"

    echo
    echo "--- Active Firewall Rules ---"

    case "$BACKEND" in
        iptables)
            iptables -L INPUT -n -v
            iptables -L "$CHAIN" -n -v 2>/dev/null || true

            if has ip6tables; then
                echo
                echo "IPv6:"
                ip6tables -L INPUT -n -v
                ip6tables -L "$CHAIN" -n -v 2>/dev/null || true
            fi
            ;;
        firewalld)
            firewall-cmd --get-active-zones
            firewall-cmd --direct --get-all-rules
            ;;
    esac

    echo
    echo "--- Listening Services ---"
    ss -tuln

    echo
    echo "External connectivity testing is required"
    echo "to confirm allowed and blocked traffic."
}

# ============================================================
# MANUAL EVIDENCE CAPTURE
# ============================================================

manual_capture() {
    SESSION_DIR="$EVIDENCE_DIR/$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$SESSION_DIR"

    capture_phase verification

    echo
    info "Verification evidence saved:"
    echo "$SESSION_DIR"
}

# ============================================================
# MAIN MENU
# ============================================================

main() {
    need_root

    while true; do
        clear
        detect_backend

        echo "========================================"
        echo "      MWCCDC FIREWALL ASSESSMENT"
        echo "========================================"
        echo
        echo "Hostname : $(hostname)"
        echo "Firewall : $BACKEND"
        echo
        echo "1) Assess current firewall rules"
        echo "2) Generate and apply hardening plan"
        echo "3) Verify firewall configuration"
        echo "4) Capture verification evidence"
        echo "5) Exit"
        echo

        read -r -p "Select option: " choice

        case "$choice" in
            1)
                show_scrollable \
                    "CURRENT FIREWALL ASSESSMENT" \
                    assess_firewall
                ;;
            2)
                apply_hardening
                pause_menu
                ;;
            3)
                show_scrollable \
                    "FIREWALL VERIFICATION" \
                    verify_firewall
                ;;
            4)
                manual_capture
                pause_menu
                ;;
            5)
                exit 0
                ;;
            *)
                error "Invalid option."
                pause_menu
                ;;
        esac
    done
}

main "$@"

#!/usr/bin/env bash
# ============================================================
# MWCCDC - FW01 Firewall Assessment and Hardening
#
# Supports:
#   - iptables / iptables-nft (Ubuntu)
#   - firewalld (Fedora)
#
# Functions:
#   1. Assess current firewall rules
#   2. Generate and apply a service profile
#   3. Verify rules and display screenshot-ready evidence
#   4. Exit
#
# Changes are runtime-only.
# No evidence files are created.
#
# WARNING:
# Applying firewall rules can interrupt connectivity.
# Use console access and test on disposable VMs first.
# ============================================================

set -Eeuo pipefail

CHAIN="MWCCDC_HOST"

BACKEND=""
SELECTED_PROFILES=""
TCP_PORTS=()
UDP_PORTS=()

# ============================================================
# GENERAL FUNCTIONS
# ============================================================

has() {
    command -v "$1" >/dev/null 2>&1
}

heading() {
    echo
    echo "========================================"
    echo " $1"
    echo "========================================"
}

info() {
    echo "[INFO] $*"
}

warn() {
    echo "[WARN] $*"
}

error() {
    echo "[ERROR] $*" >&2
}

exit_script() {
    echo
    echo "[INFO] Exiting MWCCDC Firewall Assessment."
    exit 0
}

is_exit() {
    local answer="${1,,}"
    [[ "$answer" == "exit" || "$answer" == "4" ]]
}

read_input() {
    local variable="$1"
    local prompt="$2"
    local answer

    if ! IFS= read -r -p "$prompt" answer; then
        exit_script
    fi

    if is_exit "$answer"; then
        exit_script
    fi

    printf -v "$variable" '%s' "$answer"
}

pause_menu() {
    local answer
    echo
    read_input answer "Press Enter to return to menu (or exit): "
}

need_root() {
    if [[ $EUID -ne 0 ]]; then
        error "Run this script using sudo."
        exit 1
    fi
}

# ============================================================
# FIREWALL BACKEND DETECTION
# ============================================================

detect_backend() {
    BACKEND="unknown"

    # firewalld takes precedence when actively running.
    if has firewall-cmd &&
       firewall-cmd --state 2>/dev/null | grep -qx running; then
        BACKEND="firewalld"
        return
    fi

    # Detect active UFW.
    if has ufw &&
       ufw status 2>/dev/null | grep -qi '^Status: active'; then
        BACKEND="ufw"
        return
    fi

    # Existing MWCCDC chain means iptables is in use.
    if has iptables &&
       iptables -nL "$CHAIN" >/dev/null 2>&1; then

        if iptables -V 2>/dev/null | grep -q 'nf_tables'; then
            BACKEND="iptables (nf_tables)"
        else
            BACKEND="iptables"
        fi
        return
    fi

    # Check for iptables-nft-managed tables.
    if has iptables && has nft &&
       iptables -V 2>/dev/null | grep -q 'nf_tables' &&
       nft list tables 2>/dev/null |
       grep -Eq '^table (ip|ip6) filter$'; then

        BACKEND="iptables (nf_tables)"
        return
    fi

    # Detect standalone nftables only after iptables.
    if has nft &&
       nft list ruleset 2>/dev/null |
       grep -Eq 'hook (input|forward|output)'; then

        BACKEND="nftables"
        return
    fi

    # Fall back to iptables if installed.
    if has iptables; then
        if iptables -V 2>/dev/null | grep -q 'nf_tables'; then
            BACKEND="iptables (nf_tables)"
        else
            BACKEND="iptables"
        fi
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
# OPTION 1 - ASSESS CURRENT FIREWALL
# ============================================================

assess_firewall() {
    detect_backend

    host_info

    echo
    echo "--- Current Firewall Rules ---"

    case "$BACKEND" in

        firewalld)
            echo
            echo "Active zones:"
            firewall-cmd --get-active-zones

            echo
            echo "Zone configurations:"

            while IFS= read -r zone; do
                [[ -n "$zone" ]] || continue

                echo
                echo "Zone: $zone"
                firewall-cmd --zone="$zone" --list-all
            done < <(
                firewall-cmd --get-active-zones |
                awk '/^[^[:space:]]/ {print $1}'
            )

            echo
            echo "Runtime direct rules:"
            firewall-cmd --direct --get-all-rules
            ;;

        ufw)
            ufw status verbose
            ;;

        "iptables"|"iptables (nf_tables)")
            echo
            echo "IPv4:"
            iptables -L -n -v

            if has ip6tables; then
                echo
                echo "IPv6:"
                ip6tables -L -n -v
            fi
            ;;

        nftables)
            echo
            echo "Standalone nftables rules:"
            nft list ruleset
            ;;

        *)
            echo "No supported firewall manager detected."
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
    echo " dnsntp    : TCP 53 / UDP 53,123"
    echo " wrkstn    : No additional inbound ports"
    echo
    echo "Combine profiles using commas."
    echo "Example: mail,webserver"
    echo

    read_input SELECTED_PROFILES "Profiles: "

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
    echo "Planned controls:"
    echo " - Allow loopback traffic"
    echo " - Allow established/related connections"
    echo " - Block inbound SSH (TCP 22)"
    echo " - Allow required service ports"
    echo " - Drop other inbound traffic"
    echo " - Preserve outbound policy"
    echo
    echo "Changes are runtime-only."
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
        error "iptables is unavailable."
        return 1
    }

    if [[ -s /proc/net/if_inet6 ]] &&
       ! has ip6tables; then
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
        error "firewall-cmd unavailable."
        return 1
    }

    local zone port

    zone="$(firewall-cmd --get-default-zone)"

    [[ -n "$zone" ]] || {
        error "No default firewalld zone found."
        return 1
    }

    warn "Using existing zone: $zone"
    warn "Existing allowances may remain active."

    for port in "${TCP_PORTS[@]}"; do
        firewall-cmd --zone="$zone" \
            --add-port="$port/tcp"
    done

    for port in "${UDP_PORTS[@]}"; do
        firewall-cmd --zone="$zone" \
            --add-port="$port/udp"
    done

    firewall-cmd --zone="$zone" \
        --add-rich-rule='rule family="ipv4" port port="22" protocol="tcp" drop'

    firewall-cmd --zone="$zone" \
        --add-rich-rule='rule family="ipv6" port port="22" protocol="tcp" drop'

    info "firewalld runtime rules updated."
    warn "Existing allowed services were not removed."
}

# ============================================================
# OPTION 2 - APPLY HARDENING
# ============================================================

apply_hardening() {
    detect_backend

    case "$BACKEND" in
        "iptables"|"iptables (nf_tables)"|firewalld)
            ;;
        *)
            error "Automatic enforcement unsupported for $BACKEND."
            return
            ;;
    esac

    choose_profiles || return
    show_plan

    echo
    warn "This will modify active firewall rules."
    warn "Ensure you have console access."
    echo

    local confirm
    read_input confirm "Type APPLY to continue: "

    [[ "$confirm" == "APPLY" ]] || {
        info "Cancelled."
        return
    }

    case "$BACKEND" in
        "iptables"|"iptables (nf_tables)")
            apply_iptables
            ;;
        firewalld)
            apply_firewalld
            ;;
    esac

    echo
    info "Firewall commands completed."
    info "Use Option 3 to verify the applied rules."
}

# ============================================================
# OPTION 3 - VERIFICATION AND EVIDENCE
# ============================================================

verify_firewall() {
    detect_backend

    host_info

    echo
    echo "--- Applied Firewall Rules ---"

    case "$BACKEND" in

        "iptables"|"iptables (nf_tables)")
            echo
            echo "[IPv4 INPUT]"
            iptables -S INPUT

            echo
            echo "[IPv4 MWCCDC_HOST]"

            if iptables -nL "$CHAIN" >/dev/null 2>&1; then
                iptables -S "$CHAIN"
            else
                echo "[WARN] MWCCDC_HOST chain not found."
            fi

            if has ip6tables; then
                echo
                echo "[IPv6 INPUT]"
                ip6tables -S INPUT

                echo
                echo "[IPv6 MWCCDC_HOST]"
                ip6tables -S "$CHAIN" 2>/dev/null ||
                    echo "[WARN] IPv6 custom chain not found."
            fi
            ;;

        firewalld)
            echo
            echo "[Active Zones]"
            firewall-cmd --get-active-zones

            echo
            echo "[Zone Rules]"

            while IFS= read -r zone; do
                [[ -n "$zone" ]] || continue

                echo
                echo "Zone: $zone"
                firewall-cmd --zone="$zone" --list-all
            done < <(
                firewall-cmd --get-active-zones |
                awk '/^[^[:space:]]/ {print $1}'
            )
            ;;

        *)
            echo "Unsupported verification backend."
            ;;
    esac

    echo
    echo "----------------------------------------"
    echo "Rule configuration displayed."
    echo "External connectivity testing is required"
    echo "to confirm allowed and blocked traffic."
    echo "----------------------------------------"
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
        echo "3) Verify firewall and display evidence"
        echo "4) Exit"
        echo
        echo "Type 'exit' at any prompt to quit."
        echo

        local choice
        read_input choice "Select option: "

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
                    "FW01 FIREWALL VERIFICATION" \
                    verify_firewall
                ;;
            *)
                error "Invalid selection."
                pause_menu
                ;;
        esac
    done
}

main "$@"

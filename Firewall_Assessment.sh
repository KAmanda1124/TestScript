
#!/usr/bin/env bash
# ============================================================
# MWCCDC FW01 - Firewall Assessment and Hardening
#
# Supports:
#   Ubuntu: iptables / iptables-nft
#   Fedora: firewalld
#
# 1. Assess current firewall rules
# 2. Apply service-specific hardening
# 3. Verify firewall rules for screenshots
# 4. Exit
#
# Runtime-only changes. No evidence files saved.
#
# WARNING:
# Applying a profile replaces INPUT filtering rules on
# iptables hosts and modifies active firewalld zones.
# Use VM console access and test before competition.
# ============================================================

set -Eeuo pipefail

BACKEND=""
PROFILES=""
TCP_PORTS=()
UDP_PORTS=()

has() {
    command -v "$1" >/dev/null 2>&1
}

heading() {
    echo
    echo "========================================"
    echo " $1"
    echo "========================================"
}

exit_script() {
    echo
    echo "[INFO] Exiting firewall assessment."
    exit 0
}

read_input() {
    local variable="$1"
    local prompt="$2"
    local answer

    if ! IFS= read -r -p "$prompt" answer; then
        exit_script
    fi

    case "${answer,,}" in
        exit|4)
            exit_script
            ;;
    esac

    printf -v "$variable" '%s' "$answer"
}

pause_menu() {
    local answer
    read_input answer "Press Enter to return to menu (or exit): "
}

detect_backend() {
    BACKEND="unsupported"

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
        if iptables -V | grep -q nf_tables; then
            BACKEND="iptables (nf_tables)"
        else
            BACKEND="iptables"
        fi
        return
    fi

    if has nft; then
        BACKEND="nftables"
    fi
}

host_info() {
    detect_backend

    echo "Hostname : $(hostname)"
    echo "OS       : $(. /etc/os-release; echo "$PRETTY_NAME")"
    echo "Firewall : $BACKEND"
}

show_scrollable() {
    local output
    output="$(mktemp)"

    "$@" > "$output" 2>&1

    if has less; then
        less -S "$output"
    else
        cat "$output"
        pause_menu
    fi

    rm -f "$output"
}

# ============================================================
# OPTION 1 - ASSESS FIREWALL
# ============================================================

assess_firewall() {
    heading "CURRENT FIREWALL ASSESSMENT"
    host_info

    echo
    echo "--- Current Firewall Rules ---"

    case "$BACKEND" in

        "iptables"|"iptables (nf_tables)")
            echo
            echo "[IPv4 INPUT]"
            iptables -S INPUT

            if has ip6tables; then
                echo
                echo "[IPv6 INPUT]"
                ip6tables -S INPUT
            fi
            ;;

        firewalld)
            echo
            echo "[Active Zones]"
            firewall-cmd --get-active-zones

            echo
            echo "[Zone Rules]"

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

        nftables)
            nft list ruleset
            ;;

        *)
            echo "Unsupported firewall backend."
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

    read_input PROFILES "Profiles: "

    PROFILES="${PROFILES// /}"

    [[ -n "$PROFILES" ]] || {
        echo "[ERROR] No profile selected."
        return 1
    }

    TCP_PORTS=()
    UDP_PORTS=()

    local profile
    local -a selected

    IFS=',' read -r -a selected <<< "$PROFILES"

    for profile in "${selected[@]}"; do
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
                echo "[ERROR] Unknown profile: $profile"
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
# IPTABLES - DIRECT INPUT RULES
# ============================================================

apply_iptables_family() {
    local cmd="$1"
    local port

    # Reset INPUT rules.
    "$cmd" -P INPUT ACCEPT
    "$cmd" -F INPUT

    # Allow loopback.
    "$cmd" -A INPUT -i lo -j ACCEPT

    # Allow established/related connections.
    "$cmd" -A INPUT -m conntrack \
        --ctstate ESTABLISHED,RELATED -j ACCEPT

    # Explicitly block SSH.
    "$cmd" -A INPUT -p tcp --dport 22 -j DROP

    # Allow selected service ports.
    for port in "${TCP_PORTS[@]}"; do
        "$cmd" -A INPUT -p tcp \
            --dport "$port" -j ACCEPT
    done

    for port in "${UDP_PORTS[@]}"; do
        "$cmd" -A INPUT -p udp \
            --dport "$port" -j ACCEPT
    done

    # Preserve ICMP functionality.
    if [[ "$cmd" == ip6tables ]]; then
        "$cmd" -A INPUT -p ipv6-icmp -j ACCEPT
    else
        "$cmd" -A INPUT -p icmp -j ACCEPT
    fi

    # Block remaining inbound traffic.
    "$cmd" -P INPUT DROP
}

apply_iptables() {
    if [[ -s /proc/net/if_inet6 ]] &&
       ! has ip6tables; then
        echo "[ERROR] IPv6 enabled but ip6tables unavailable."
        return 1
    fi

    apply_iptables_family iptables

    if [[ -s /proc/net/if_inet6 ]]; then
        apply_iptables_family ip6tables
    fi

    echo "[OK] INPUT firewall rules applied."
}

# ============================================================
# FIREWALLD - ACTIVE ZONES
# ============================================================

apply_firewalld() {
    local zone port
    local -a zones=()

    mapfile -t zones < <(
        firewall-cmd --get-active-zones |
        awk '/^[^[:space:]]/ {print $1}'
    )

    if ((${#zones[@]} == 0)); then
        echo "[ERROR] No active firewalld zones."
        return 1
    fi

    for zone in "${zones[@]}"; do
        echo "[INFO] Configuring zone: $zone"

        # Block SSH.
        firewall-cmd --zone="$zone" \
            --remove-service=ssh 2>/dev/null || true

        firewall-cmd --zone="$zone" \
            --remove-port=22/tcp 2>/dev/null || true

        # Add required ports.
        for port in "${TCP_PORTS[@]}"; do
            firewall-cmd --zone="$zone" \
                --add-port="$port/tcp"
        done

        for port in "${UDP_PORTS[@]}"; do
            firewall-cmd --zone="$zone" \
                --add-port="$port/udp"
        done

        # Explicitly block SSH.
        firewall-cmd --zone="$zone" \
            --add-rich-rule='rule port port="22" protocol="tcp" drop'
    done

    echo
    echo "[OK] firewalld runtime rules updated."
    echo "[WARN] Existing non-SSH allowances remain."
}

# ============================================================
# OPTION 2 - HARDENING
# ============================================================

apply_hardening() {
    detect_backend

    case "$BACKEND" in
        "iptables"|"iptables (nf_tables)"|firewalld)
            ;;
        *)
            echo "[ERROR] Unsupported enforcement backend."
            return
            ;;
    esac

    choose_profiles || return

    heading "FIREWALL HARDENING PLAN"

    echo "Hostname : $(hostname)"
    echo "Firewall : $BACKEND"
    echo "Profiles : $PROFILES"
    echo
    echo "Inbound TCP: ${TCP_PORTS[*]:-None}"
    echo "Inbound UDP: ${UDP_PORTS[*]:-None}"
    echo
    echo "Controls:"
    echo " - Allow loopback"
    echo " - Allow established/related traffic"
    echo " - Block SSH (TCP 22)"
    echo " - Allow required service ports"
    echo " - Restrict unnecessary inbound traffic"
    echo " - Preserve outbound policy"
    echo

    echo "[WARN] Active firewall rules will change."
    echo "[WARN] Use VM console access."
    echo

    local confirm
    read_input confirm "Type APPLY to continue: "

    if [[ "$confirm" != "APPLY" ]]; then
        echo "[INFO] Cancelled."
        return
    fi

    case "$BACKEND" in
        "iptables"|"iptables (nf_tables)")
            apply_iptables
            ;;
        firewalld)
            apply_firewalld
            ;;
    esac

    echo
    echo "Use Option 3 to verify the configuration."
}

# ============================================================
# OPTION 3 - VERIFICATION EVIDENCE
# ============================================================

verify_firewall() {
    heading "FW01 FIREWALL VERIFICATION"
    host_info

    echo
    echo "Selected Profile: ${PROFILES:-Not selected in this session}"

    echo
    echo "--- Applied Firewall Rules ---"

    case "$BACKEND" in

        "iptables"|"iptables (nf_tables)")
            echo
            echo "[IPv4 INPUT]"
            iptables -S INPUT

            if has ip6tables; then
                echo
                echo "[IPv6 INPUT]"
                ip6tables -S INPUT
            fi
            ;;

        firewalld)
            while read -r zone; do
                [[ -n "$zone" ]] || continue

                echo
                echo "[Zone: $zone]"
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
    echo "Firewall rules displayed for review."
    echo "External connectivity testing is required"
    echo "to confirm permitted and blocked traffic."
    echo "----------------------------------------"
}

# ============================================================
# MAIN MENU
# ============================================================

main() {
    if [[ $EUID -ne 0 ]]; then
        echo "[ERROR] Run using sudo."
        exit 1
    fi

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
                show_scrollable assess_firewall
                ;;
            2)
                apply_hardening
                pause_menu
                ;;
            3)
                show_scrollable verify_firewall
                ;;
            *)
                echo "[ERROR] Invalid selection."
                pause_menu
                ;;
        esac
    done
}

main "$@"

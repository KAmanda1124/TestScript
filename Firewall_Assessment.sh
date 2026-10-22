
#!/usr/bin/env bash
# ============================================================
# MWCCDC - FW01 Host-Based Firewall Assessment
#
# Purpose:
#   1. Assess current firewall rules
#   2. Generate a role-based firewall hardening plan
#   3. Capture evidence for the FW01 inject
#
# This script is READ-ONLY.
# It does not apply or remove firewall rules.
# ============================================================

set -Eeuo pipefail

EVIDENCE_DIR="./firewall-evidence"
BACKEND="unknown"
PLAN_FILE=""

has() {
    command -v "$1" >/dev/null 2>&1
}

pause_menu() {
    echo
    read -r -p "Press Enter to return to menu..." _
}

heading() {
    echo
    echo "========================================"
    echo " $1"
    echo "========================================"
}

# ------------------------------------------------------------
# Scrollable output
# ------------------------------------------------------------

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

# ------------------------------------------------------------
# Detect firewall manager
# ------------------------------------------------------------

detect_backend() {
    BACKEND="unknown"

    if has firewall-cmd &&
       firewall-cmd --state 2>/dev/null | grep -qx running; then
        BACKEND="firewalld"
        return
    fi

    if has ufw &&
       ufw status 2>/dev/null | grep -qi "^Status: active"; then
        BACKEND="ufw"
        return
    fi

    if has nft &&
       systemctl is-active --quiet nftables 2>/dev/null; then
        BACKEND="nftables"
        return
    fi

    if has nft &&
       nft list ruleset 2>/dev/null |
       grep -Eq 'hook (input|forward|output)'; then
        BACKEND="nftables (existing rules)"
        return
    fi

    if has iptables; then
        BACKEND="iptables (verify active rules)"
        return
    fi

    BACKEND="not detected"
}

# ------------------------------------------------------------
# Host information
# ------------------------------------------------------------

show_host() {
    detect_backend

    echo "Hostname : $(hostname)"
    echo "OS       : $(. /etc/os-release; echo "$PRETTY_NAME")"
    echo "Firewall : $BACKEND"
}

# ------------------------------------------------------------
# Current firewall rules
# ------------------------------------------------------------

show_firewall_rules() {
    detect_backend

    heading "CURRENT FIREWALL RULES"
    show_host

    echo
    echo "--- Firewall Configuration ---"

    case "$BACKEND" in

        firewalld)
            echo
            echo "Active zones:"
            firewall-cmd --get-active-zones

            echo
            echo "Zone configuration:"

            local zone
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
            echo "Default zone:"
            firewall-cmd --get-default-zone
            ;;

        ufw)
            ufw status verbose
            ;;

        nftables*)
            nft list ruleset
            ;;

        iptables*)
            echo
            echo "IPv4 rules:"
            iptables -L -n -v

            if has ip6tables; then
                echo
                echo "IPv6 rules:"
                ip6tables -L -n -v
            fi
            ;;

        *)
            echo "No supported firewall manager detected."
            ;;
    esac

    echo
    echo "--- Listening Services ---"
    ss -tuln

    echo
    echo "NOTE:"
    echo "Allowed firewall ports are not necessarily"
    echo "reachable from another host."
    echo "External connectivity testing is required."
}

# ------------------------------------------------------------
# Role-based hardening plan
# ------------------------------------------------------------

show_profiles() {
    echo
    echo "Available host profiles:"
    echo
    echo "  webserver : TCP 80,443"
    echo "  mail      : TCP 25,465,587,110,995,143,993"
    echo "  splunk    : TCP 8000,8089,9997"
    echo "  dnsntp    : TCP/UDP 53, UDP 123"
    echo "  wrkstn    : No additional inbound services"
    echo
    echo "Multiple profiles can be combined."
    echo "Example: mail,webserver"
}

generate_plan() {
    local selection profile
    local -a profiles tcp_ports udp_ports
    local -A seen_tcp=()
    local -A seen_udp=()

    heading "FIREWALL HARDENING PLAN"
    show_host
    show_profiles

    echo
    read -r -p "Enter profile(s): " selection

    selection="${selection// /}"

    [[ -n "$selection" ]] || {
        echo "[ERROR] No profile selected."
        return
    }

    IFS=',' read -r -a profiles <<< "$selection"

    tcp_ports=()
    udp_ports=()

    for profile in "${profiles[@]}"; do
        case "$profile" in
            webserver)
                tcp_ports+=(80 443)
                ;;
            mail)
                tcp_ports+=(25 465 587 110 995 143 993)
                ;;
            splunk)
                tcp_ports+=(8000 8089 9997)
                ;;
            dnsntp)
                tcp_ports+=(53)
                udp_ports+=(53 123)
                ;;
            wrkstn)
                ;;
            *)
                echo "[ERROR] Unknown profile: $profile"
                return
                ;;
        esac
    done

    local port
    for port in "${tcp_ports[@]}"; do
        seen_tcp["$port"]=1
    done

    for port in "${udp_ports[@]}"; do
        seen_udp["$port"]=1
    done

    local tcp_text="None"
    local udp_text="None"

    if ((${#seen_tcp[@]})); then
        tcp_text="$(
            printf '%s\n' "${!seen_tcp[@]}" |
            sort -n |
            paste -sd, -
        )"
    fi

    if ((${#seen_udp[@]})); then
        udp_text="$(
            printf '%s\n' "${!seen_udp[@]}" |
            sort -n |
            paste -sd, -
        )"
    fi

    local plan
    plan="$(
        cat <<EOF
========================================
        FW01 FIREWALL HARDENING PLAN
========================================

Hostname : $(hostname)
Firewall : $BACKEND
Profiles : ${profiles[*]}

REQUIRED INBOUND PORTS
----------------------------------------
TCP: $tcp_text
UDP: $udp_text

RECOMMENDED ACTIONS
----------------------------------------
1. Review all currently allowed inbound
   ports and services.

2. Restrict inbound traffic to only the
   ports required for the host's role.

3. Block unnecessary inbound SSH access
   on Linux hosts.

4. Allow established and related traffic.

5. Preserve required loopback traffic.

6. Review IPv4 and IPv6 firewall rules.

7. Confirm required outbound connectivity
   remains functional.

8. Test permitted and blocked ports from
   another host after remediation.

9. Capture firewall rules before and
   after any configuration changes.

========================================
This is a proposed hardening plan.
No firewall rules have been modified.
========================================
EOF
    )"

    echo
    echo "$plan"

    mkdir -p "$EVIDENCE_DIR"
    PLAN_FILE="$EVIDENCE_DIR/hardening-plan.txt"

    printf '%s\n' "$plan" > "$PLAN_FILE"

    echo
    echo "[OK] Plan saved to: $PLAN_FILE"
}

# ------------------------------------------------------------
# Capture evidence
# ------------------------------------------------------------

capture_evidence() {
    local timestamp directory

    timestamp="$(date +%Y%m%d-%H%M%S)"
    directory="$EVIDENCE_DIR/$timestamp"

    mkdir -p "$directory"

    heading "CAPTURE FIREWALL EVIDENCE"

    date -Is > "$directory/timestamp.txt"
    hostname > "$directory/hostname.txt"

    show_host > "$directory/host-information.txt"

    ip -br addr > "$directory/network-interfaces.txt"
    ss -tuln > "$directory/listening-services.txt"

    show_firewall_rules > "$directory/current-firewall-rules.txt" 2>&1

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

    if has ufw; then
        ufw status verbose \
            > "$directory/ufw.txt" 2>&1 || true
    fi

    if [[ -f "$EVIDENCE_DIR/hardening-plan.txt" ]]; then
        cp "$EVIDENCE_DIR/hardening-plan.txt" \
            "$directory/hardening-plan.txt"
    fi

    echo "[OK] Firewall evidence captured."
    echo
    echo "Directory: $directory"
    echo
    echo "Evidence includes:"
    echo " - Host information"
    echo " - Network interfaces"
    echo " - Listening services"
    echo " - Current firewall rules"
    echo " - Available firewall configurations"

    if [[ -f "$directory/hardening-plan.txt" ]]; then
        echo " - Firewall hardening plan"
    else
        echo
        echo "[NOTE] Generate a hardening plan using"
        echo "Option 2 before capturing evidence."
    fi
}

# ------------------------------------------------------------
# Main menu
# ------------------------------------------------------------

main() {
    [[ $EUID -eq 0 ]] || {
        echo "[ERROR] Run this script with sudo."
        exit 1
    }

    while true; do
        clear
        detect_backend

        echo "========================================"
        echo "     MWCCDC FIREWALL ASSESSMENT"
        echo "========================================"
        echo
        echo "Hostname : $(hostname)"
        echo "Firewall : $BACKEND"
        echo
        echo "1) Assess current firewall rules"
        echo "2) Generate firewall hardening plan"
        echo "3) Capture verification evidence"
        echo "4) Exit"
        echo

        read -r -p "Select option: " choice

        case "$choice" in
            1)
                show_scrollable \
                    "FW01 CURRENT FIREWALL ASSESSMENT" \
                    show_firewall_rules
                ;;
            2)
                generate_plan
                pause_menu
                ;;
            3)
                capture_evidence
                pause_menu
                ;;
            4)
                echo "Exiting."
                exit 0
                ;;
            *)
                echo "[ERROR] Invalid selection."
                pause_menu
                ;;
        esac
    done
}

main "$@"

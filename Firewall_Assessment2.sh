
#!/usr/bin/env bash
# MWCCDC Linux Firewall Assessment
# E-commerce, Roundcube Webmail, Splunk, Workstation
# Built-in iptables chains only
# No custom chains, flushing, or permanent saves

set -uo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: Run this script with sudo."
    exit 1
fi

for cmd in iptables ss; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: $cmd is not installed."
        exit 1
    fi
done

pause() {
    echo
    while true; do
        read -r -p "Press q to return to the main menu: " answer
        case "$answer" in
            q|Q) return ;;
        esac
    done
}

show_firewall() {
    echo
    echo "========== CURRENT FIREWALL RULES =========="
    iptables -L INPUT -n -v --line-numbers

    echo
    echo "========== OUTPUT RULES =========="
    iptables -L OUTPUT -n -v

    echo
    echo "========== FORWARD RULES =========="
    iptables -L FORWARD -n -v

    echo
    echo "========== LISTENING SERVICES =========="
    ss -tuln

    pause
}

# Add a rule directly to INPUT.
# Existing matching rules are not duplicated.
allow_rule() {
    local chain="$1"
    shift

    if iptables -C "$chain" "$@" 2>/dev/null; then
        echo "[OK] Rule already exists: $chain $*"
    else
        if iptables -I "$chain" 1 "$@"; then
            echo "[ADDED] $chain $*"
        else
            echo "[ERROR] Failed to add: $chain $*"
            return 1
        fi
    fi
}

# Service definitions
get_ports() {
    local service="$1"

    TCP_PORTS=(22)

    case "$service" in
        ecommerce)
            TCP_PORTS+=(80 443)
            ;;
        webmail)
            # Roundcube, Postfix, Dovecot
            TCP_PORTS+=(80 443 25 110 143 465 587 993 995)
            ;;
        splunk)
            TCP_PORTS+=(8000 8089 9997)
            ;;
        workstation)
            ;;
        *)
            echo "ERROR: Unknown service."
            return 1
            ;;
    esac
}

configure_service() {
    local service="$1"
    local port confirm
    local errors=0

    get_ports "$service" || return

    echo
    echo "========== CONFIGURATION SUMMARY =========="
    echo "Service: $service"
    echo "Allowed TCP Ports: ${TCP_PORTS[*]}"
    echo "ICMP Ping: Allowed"
    echo "Loopback: Allowed"
    echo "Established Connections: Allowed"
    echo "Outbound Traffic: Unchanged"
    echo "Default Policies: Unchanged"
    echo
    echo "No custom chains will be created."
    echo "No existing rules will be flushed."
    echo "No permanent configurations will be saved."
    echo
    echo "WARNING: Rules are inserted at the top of INPUT."
    echo "They may override existing access restrictions."
    echo

    read -r -p "Apply these rules? (yes/no): " confirm

    [[ "$confirm" == "yes" ]] || {
        echo "Configuration cancelled."
        return
    }

    echo
    echo "========== APPLYING FIREWALL RULES =========="

    allow_rule INPUT -i lo -j ACCEPT || ((errors+=1))

    allow_rule INPUT -m conntrack \
        --ctstate ESTABLISHED,RELATED -j ACCEPT || ((errors+=1))

    allow_rule INPUT -p icmp \
        --icmp-type echo-request -j ACCEPT || ((errors+=1))

    for port in "${TCP_PORTS[@]}"; do
        allow_rule INPUT -p tcp \
            --dport "$port" -j ACCEPT || ((errors+=1))
    done

    echo
    echo "========== CONFIGURATION RESULT =========="

    if ((errors == 0)); then
        echo "[OK] All requested rules were processed."
    else
        echo "[WARNING] $errors rule(s) could not be added."
    fi

    echo "No custom chains created."
    echo "No rules flushed."
    echo "No configurations saved."
    echo
    echo "Verify scored services from another machine."
}

# Check whether the configured service ports
# are listening locally.
check_service() {
    local service="$1"
    local port

    get_ports "$service" || return

    echo
    echo "========== SCORED SERVICE CHECK =========="
    echo "Selected service: $service"
    echo

    printf '%-12s %-18s\n' "TCP PORT" "LISTENING STATUS"
    echo "----------------------------------"

    for port in "${TCP_PORTS[@]}"; do
        if ss -H -ltn | awk '{print $4}' |
            grep -Eq "[:.]${port}$"; then
            printf '%-12s %-18s\n' "$port" "[LISTENING]"
        else
            printf '%-12s %-18s\n' "$port" "[NOT LISTENING]"
        fi
    done

    echo
    echo "========== INPUT FIREWALL RULES =========="
    iptables -L INPUT -n -v --line-numbers

    echo
    echo "NOTE: A listening service may still be blocked"
    echo "by a firewall or another network control."
    echo "Some mail services may intentionally listen"
    echo "only on localhost."

    pause
}

scoring_menu() {
    local choice

    while true; do
        clear
        echo "=========================================="
        echo "           SCORED SERVICE CHECK"
        echo "=========================================="
        echo "1) E-commerce"
        echo "2) Roundcube Webmail"
        echo "3) Splunk"
        echo "4) Workstation"
        echo "q) Return to Main Menu"
        echo "=========================================="

        read -r -p "Select an option: " choice

        case "$choice" in
            1) check_service ecommerce ;;
            2) check_service webmail ;;
            3) check_service splunk ;;
            4) check_service workstation ;;
            q|Q) return ;;
            *) echo "Invalid selection."; sleep 1 ;;
        esac
    done
}

check_conflicts() {
    echo
    echo "========== FIREWALL CONFLICT CHECK =========="

    if command -v firewall-cmd >/dev/null 2>&1; then
        if firewall-cmd --state 2>/dev/null |
            grep -qx running; then
            echo "[WARNING] firewalld is running."
        else
            echo "[OK] firewalld is not running."
        fi
    fi

    if command -v ufw >/dev/null 2>&1; then
        if ufw status 2>/dev/null |
            grep -q "Status: active"; then
            echo "[WARNING] UFW is active."
        else
            echo "[OK] UFW is not active."
        fi
    fi

    echo
    echo "========== INPUT POLICY =========="
    iptables -S INPUT | head -n 1

    echo
    echo "========== OUTPUT POLICY =========="
    iptables -S OUTPUT | head -n 1

    echo
    echo "========== DROP/REJECT RULES =========="
    iptables -S INPUT |
        grep -E -- '-j (DROP|REJECT)' ||
        echo "No direct INPUT DROP/REJECT rules found."

    echo
    echo "========== IPV6 STATUS =========="
    if command -v ip6tables >/dev/null 2>&1; then
        ip6tables -S INPUT | head -n 1
        echo "NOTE: IPv6 rules are not modified."
    else
        echo "ip6tables is unavailable."
    fi

    echo
    echo "NOTE: Other firewall backends and existing"
    echo "rules may still affect network traffic."

    pause
}

while true; do
    clear

    echo "=========================================="
    echo "        MWCCDC FIREWALL ASSESSMENT"
    echo "=========================================="
    echo "1) View Current Firewall Rules"
    echo "2) Configure E-commerce"
    echo "3) Configure Roundcube Webmail"
    echo "4) Configure Splunk"
    echo "5) Configure Workstation"
    echo "6) Check Scored Services"
    echo "7) Check Firewall Conflicts"
    echo "q) Exit"
    echo "=========================================="

    read -r -p "Select an option: " choice

    case "$choice" in
        1)
            show_firewall
            ;;
        2)
            configure_service ecommerce
            pause
            ;;
        3)
            configure_service webmail
            pause
            ;;
        4)
            configure_service splunk
            pause
            ;;
        5)
            configure_service workstation
            pause
            ;;
        6)
            scoring_menu
            ;;
        7)
            check_conflicts
            ;;
        q|Q)
            echo "Exiting Firewall Assessment."
            exit 0
            ;;
        *)
            echo "Invalid selection."
            sleep 1
            ;;
    esac
done

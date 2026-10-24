
#!/usr/bin/env bash
# MWCCDC Linux Firewall Assessment

set -uo pipefail

# Require root
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: Please run this script with sudo."
    exit 1
fi

# Check dependencies
for cmd in iptables ss; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: $cmd is not installed."
        exit 1
    fi
done

# Return to main menu
pause() {
    echo
    while true; do
        read -r -p "Press q to return to the main menu: " answer
        case "$answer" in
            q|Q) return ;;
        esac
    done
}

# Display firewall information
show_firewall() {
    echo
    echo "========== FIREWALL STATUS =========="
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

# Add a rule only if it does not already exist
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

# Configure firewall for selected Linux service
configure_service() {
    local service="$1"
    local port
    local tcp_ports=(22)

    case "$service" in
        ecommerce)
            tcp_ports+=(80 443)
            ;;
        webmail)
            tcp_ports+=(25 110 143 587)
            ;;
        splunk)
            tcp_ports+=(8000 8089 9997)
            ;;
        workstation)
            ;;
        *)
            echo "ERROR: Invalid service."
            return
            ;;
    esac

    echo
    echo "========== CONFIGURATION SUMMARY =========="
    echo "Selected Service: $service"
    echo "Allowed TCP Ports: ${tcp_ports[*]}"
    echo "ICMP Ping: Allowed"
    echo "Established Connections: Allowed"
    echo "Outbound Traffic: Unchanged"
    echo "Default Policies: Unchanged"
    echo
    echo "No custom chains will be created."
    echo "Existing rules will not be flushed."
    echo "No firewall configurations will be saved."
    echo

    read -r -p "Apply these firewall rules? (yes/no): " confirm

    if [[ "$confirm" != "yes" ]]; then
        echo "Configuration cancelled."
        return
    fi

    echo
    echo "========== APPLYING FIREWALL RULES =========="

    # Allow loopback
    allow_rule INPUT -i lo -j ACCEPT

    # Allow established and related connections
    allow_rule INPUT -m conntrack \
        --ctstate ESTABLISHED,RELATED -j ACCEPT

    # Allow ICMP ping
    allow_rule INPUT -p icmp \
        --icmp-type echo-request -j ACCEPT

    # Allow scored TCP services
    for port in "${tcp_ports[@]}"; do
        allow_rule INPUT -p tcp \
            --dport "$port" -j ACCEPT
    done

    echo
    echo "========== CONFIGURATION COMPLETE =========="
    echo "Firewall rules have been processed."
    echo
    echo "No custom chains created."
    echo "No existing rules flushed."
    echo "No permanent configurations saved."
    echo
    echo "Verify scored services from another machine."
}

# Check scored Linux services
check_scoring() {
    echo
    echo "========== SCORED LINUX SERVICES =========="
    echo
    printf '%-22s %-12s %s\n' \
        "SERVICE" "PORT" "PROTOCOL"
    echo "----------------------------------------------"

    printf '%-22s %-12s %s\n' "SSH" "22" "TCP"
    printf '%-22s %-12s %s\n' "HTTP" "80" "TCP"
    printf '%-22s %-12s %s\n' "HTTPS" "443" "TCP"
    printf '%-22s %-12s %s\n' "SMTP" "25" "TCP"
    printf '%-22s %-12s %s\n' "Submission" "587" "TCP"
    printf '%-22s %-12s %s\n' "POP3" "110" "TCP"
    printf '%-22s %-12s %s\n' "IMAP" "143" "TCP"
    printf '%-22s %-12s %s\n' "Splunk Web" "8000" "TCP"
    printf '%-22s %-12s %s\n' "Splunk Management" "8089" "TCP"
    printf '%-22s %-12s %s\n' "Splunk Indexer" "9997" "TCP"

    echo
    echo "========== LISTENING PORTS =========="
    ss -tuln

    echo
    echo "========== INPUT FIREWALL RULES =========="
    iptables -L INPUT -n -v --line-numbers

    echo
    echo "NOTE: This does not guarantee scoring availability."
    echo "External connectivity testing is required."

    pause
}

# Check for firewall conflicts
check_conflicts() {
    echo
    echo "========== FIREWALL CONFLICT CHECK =========="

    if command -v firewall-cmd >/dev/null 2>&1; then
        if firewall-cmd --state 2>/dev/null | grep -qx running; then
            echo "[WARNING] firewalld is running."
        else
            echo "[OK] firewalld is not running."
        fi
    fi

    if command -v ufw >/dev/null 2>&1; then
        if ufw status 2>/dev/null | grep -q "Status: active"; then
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
    iptables -S INPUT | grep -E -- '-j (DROP|REJECT)' ||
        echo "No direct INPUT DROP/REJECT rules found."

    echo
    echo "NOTE: Existing chains and other firewall backends"
    echo "may still affect traffic."

    pause
}

# Main menu
while true; do
    clear

    echo "=========================================="
    echo "        MWCCDC FIREWALL ASSESSMENT"
    echo "=========================================="
    echo "1) View Current Firewall Rules"
    echo "2) Configure E-commerce"
    echo "3) Configure Webmail"
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
            check_scoring
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

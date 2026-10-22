
#!/usr/bin/env bash
# MWCCDC Linux Host Firewall
# Ubuntu / Fedora / Oracle Linux
# Runtime-only rules; no persistent configuration.
# Run from the VM console, not over SSH.

set -Eeuo pipefail

CHAIN="MWCCDC_HOST"
NFT_TABLE="mwccdc_host"
FW_ZONE="mwccdc-host"
EVIDENCE_DIR="./firewall-evidence"

BACKEND=""
IPT=""
IP6T=""
PROFILES=()
TCP_PORTS=()
UDP_PORTS=()

die() {
    echo "[ERROR] $*" >&2
    exit 1
}

info() { echo "[INFO] $*"; }
warn() { echo "[WARN] $*"; }

need_root() {
    [[ $EUID -eq 0 ]] || die "Run with sudo."
}

has() {
    command -v "$1" >/dev/null 2>&1
}

active() {
    systemctl is-active --quiet "$1" 2>/dev/null
}

ipv6_enabled() {
    [[ -f /proc/net/if_inet6 ]] &&
    [[ -n "$(cat /proc/net/if_inet6)" ]]
}

# -----------------------------
# Firewall detection
# -----------------------------

detect_backend() {
    local -a managers=()

    if active firewalld && has firewall-cmd; then
        managers+=(firewalld)
    fi

    if has ufw && ufw status 2>/dev/null |
        grep -qi '^Status: active'; then
        managers+=(ufw)
    fi

    if active nftables && has nft; then
        managers+=(nftables)
    fi

    if ((${#managers[@]} > 1)); then
        BACKEND="conflict"
        return
    fi

    if ((${#managers[@]} == 1)); then
        BACKEND="${managers[0]}"
        return
    fi

    # A running service is not the only way to
    # manage firewall rules. Detect existing rules.
    if has nft && nft list ruleset 2>/dev/null |
        grep -Eq '^[[:space:]]*hook (input|forward|output)'; then
        BACKEND="unmanaged-nft"
        return
    fi

    if has iptables && iptables-save 2>/dev/null |
        grep -Eq '^-[AI] (INPUT|FORWARD|OUTPUT) '; then
        BACKEND="unmanaged-iptables"
        return
    fi

    BACKEND="none"
}

show_system() {
    echo
    echo "========================================"
    echo "         MWCCDC HOST FIREWALL"
    echo "========================================"

    echo "Hostname : $(hostname)"
    echo "OS       : $(. /etc/os-release; echo "$PRETTY_NAME")"
    echo "Kernel   : $(uname -r)"

    detect_backend
    echo "Manager  : $BACKEND"

    if has iptables; then
        echo "iptables : $(iptables -V)"
    fi

    echo
    echo "IPv4 Interfaces:"
    ip -br -4 addr || true

    echo
    echo "IPv6 Interfaces:"
    ip -br -6 addr || true

    echo "========================================"
}

# -----------------------------
# Evidence collection
# -----------------------------

capture_evidence() {
    local phase="$1"
    local dir="$EVIDENCE_DIR/$phase"

    mkdir -p "$dir"

    date -Is > "$dir/timestamp.txt"
    hostnamectl > "$dir/host.txt" 2>&1 || true
    ip -br addr > "$dir/addresses.txt"
    ip route > "$dir/routes.txt"
    ip -6 route > "$dir/ipv6-routes.txt"
    ss -tulpen > "$dir/listening.txt" 2>&1

    if has iptables; then
        iptables-save > "$dir/iptables.txt" 2>&1 || true
        iptables -L -n -v > "$dir/iptables-counters.txt" 2>&1 || true
    fi

    if has ip6tables; then
        ip6tables-save > "$dir/ip6tables.txt" 2>&1 || true
    fi

    if has nft; then
        nft -a list ruleset > "$dir/nftables.txt" 2>&1 || true
    fi

    if has firewall-cmd; then
        firewall-cmd --state > "$dir/firewalld-state.txt" 2>&1 || true
        firewall-cmd --list-all-zones > "$dir/firewalld.txt" 2>&1 || true
    fi

    if has ufw; then
        ufw status verbose > "$dir/ufw.txt" 2>&1 || true
    fi

    info "Evidence captured: $dir"
}

# -----------------------------
# Service profiles
# -----------------------------

add_tcp() { TCP_PORTS+=("$@"); }
add_udp() { UDP_PORTS+=("$@"); }

build_profiles() {
    TCP_PORTS=()
    UDP_PORTS=()

    local profile

    for profile in "${PROFILES[@]}"; do
        case "$profile" in
            webserver)
                add_tcp 80 443
                ;;
            mail)
                add_tcp 25 465 587 110 995 143 993
                ;;
            splunk)
                add_tcp 8000 8089 9997
                ;;
            dnsntp)
                add_tcp 53
                add_udp 53 123
                ;;
            wrkstn)
                ;;
            *)
                die "Unknown profile: $profile"
                ;;
        esac
    done

    # Remove duplicates.
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

choose_profiles() {
    echo
    echo "Available profiles:"
    echo "  webserver : TCP 80,443"
    echo "  mail      : TCP 25,465,587,110,995,143,993"
    echo "  splunk    : TCP 8000,8089,9997"
    echo "  dnsntp    : TCP 53; UDP 53,123"
    echo "  wrkstn    : No additional inbound ports"
    echo
    echo "Combine profiles with commas."
    echo "Example: mail,webserver"
    echo

    local answer
    read -r -p "Profiles: " answer

    answer="${answer// /}"
    IFS=',' read -r -a PROFILES <<< "$answer"

    ((${#PROFILES[@]})) || die "No profile selected."

    build_profiles
}

show_plan() {
    echo
    echo "========================================"
    echo "           FIREWALL PLAN"
    echo "========================================"
    echo "Backend : $BACKEND"
    echo "Profiles: ${PROFILES[*]}"
    echo
    echo "Inbound TCP: ${TCP_PORTS[*]:-None}"
    echo "Inbound UDP: ${UDP_PORTS[*]:-None}"
    echo
    echo "Inbound SSH: BLOCK"
    echo "Loopback: ALLOW"
    echo "Established traffic: ALLOW"
    echo "Other inbound traffic: DROP"
    echo "Outbound traffic: Existing policy"
    echo "IPv6: Filtered when enabled"
    echo
    echo "Rules are runtime-only."
    echo "========================================"
}

# -----------------------------
# iptables backend
# -----------------------------

apply_iptables_family() {
    local cmd="$1"
    local port

    "$cmd" -N "$CHAIN" 2>/dev/null || true
    "$cmd" -F "$CHAIN"

    "$cmd" -A "$CHAIN" -i lo -j ACCEPT

    "$cmd" -A "$CHAIN" -m conntrack \
        --ctstate ESTABLISHED,RELATED -j ACCEPT

    # Explicit SSH block before service allowances.
    "$cmd" -A "$CHAIN" -p tcp --dport 22 -j DROP

    for port in "${TCP_PORTS[@]}"; do
        "$cmd" -A "$CHAIN" -p tcp \
            --dport "$port" -j ACCEPT
    done

    for port in "${UDP_PORTS[@]}"; do
        "$cmd" -A "$CHAIN" -p udp \
            --dport "$port" -j ACCEPT
    done

    # Allow basic ICMP for troubleshooting and
    # IPv6 neighbor discovery.
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
    has iptables || die "iptables is not installed."

    if ipv6_enabled && ! has ip6tables; then
        die "IPv6 is enabled but ip6tables is missing."
    fi

    apply_iptables_family iptables

    if ipv6_enabled; then
        apply_iptables_family ip6tables
    fi

    info "iptables rules applied."
}

# -----------------------------
# nftables backend
# -----------------------------

apply_nftables() {
    has nft || die "nft is not installed."

    local tmp port
    tmp="$(mktemp)"
    trap 'rm -f "$tmp"' RETURN

    {
        echo "destroy table inet $NFT_TABLE"
    } > /dev/null

    # Delete only our dedicated table if it exists.
    if nft list table inet "$NFT_TABLE" >/dev/null 2>&1; then
        nft delete table inet "$NFT_TABLE"
    fi

    {
        echo "table inet $NFT_TABLE {"
        echo " chain input {"
        echo "  type filter hook input priority -10; policy accept;"
        echo "  iifname \"lo\" accept"
        echo "  ct state established,related accept"
        echo "  tcp dport 22 drop"

        for port in "${TCP_PORTS[@]}"; do
            echo "  tcp dport $port accept"
        done

        for port in "${UDP_PORTS[@]}"; do
            echo "  udp dport $port accept"
        done

        echo "  ip protocol icmp accept"
        echo "  meta l4proto ipv6-icmp accept"
        echo "  counter drop"
        echo " }"
        echo "}"
    } > "$tmp"

    nft -c -f "$tmp" || die "nftables validation failed."
    nft -f "$tmp"

    info "nftables rules applied."
}

# -----------------------------
# firewalld backend
# -----------------------------

apply_firewalld() {
    has firewall-cmd || die "firewall-cmd missing."

    local -a interfaces=()
    local iface port

    # Dedicated runtime zone avoids modifying
    # permanent firewalld configuration.
    if ! firewall-cmd --get-zones |
        tr ' ' '\n' | grep -qx "$FW_ZONE"; then
        firewall-cmd --new-zone="$FW_ZONE"
    fi

    firewall-cmd --zone="$FW_ZONE" --set-target=DROP

    firewall-cmd --zone="$FW_ZONE" \
        --add-service=ssh >/dev/null 2>&1 || true
    firewall-cmd --zone="$FW_ZONE" \
        --remove-service=ssh >/dev/null 2>&1 || true

    for port in "${TCP_PORTS[@]}"; do
        firewall-cmd --zone="$FW_ZONE" \
            --add-port="$port/tcp"
    done

    for port in "${UDP_PORTS[@]}"; do
        firewall-cmd --zone="$FW_ZONE" \
            --add-port="$port/udp"
    done

    # Bind active non-loopback interfaces.
    mapfile -t interfaces < <(
        ip -o link show |
        awk -F': ' '$2 !~ /^lo(@|$)/ {
            split($2,a,"@"); print a[1]
        }'
    )

    for iface in "${interfaces[@]}"; do
        firewall-cmd --zone="$FW_ZONE" \
            --change-interface="$iface"
    done

    info "Runtime firewalld zone applied."
}

# -----------------------------
# UFW backend
# -----------------------------

apply_ufw() {
    has ufw || die "ufw is not installed."

    local port

    # Do not reset UFW or remove unrelated rules.
    # Existing allow rules may need manual review.
    ufw deny in 22/tcp

    for port in "${TCP_PORTS[@]}"; do
        ufw allow in "$port/tcp"
    done

    for port in "${UDP_PORTS[@]}"; do
        ufw allow in "$port/udp"
    done

    ufw default deny incoming
    ufw --force enable

    info "UFW rules applied."
}

# -----------------------------
# Apply configuration
# -----------------------------

apply_firewall() {
    detect_backend

    case "$BACKEND" in
        conflict|unmanaged-nft|unmanaged-iptables)
            die "Existing or conflicting rules detected.
Review them before selecting an enforcement backend."
            ;;
        none)
            echo
            echo "No active firewall manager detected."
            echo "Select a backend:"
            echo "1) iptables"
            echo "2) nftables"
            read -r -p "Choice: " choice

            case "$choice" in
                1) BACKEND="iptables" ;;
                2) BACKEND="nftables" ;;
                *) die "Invalid backend selection." ;;
            esac
            ;;
    esac

    choose_profiles
    show_plan

    echo
    warn "This changes live firewall rules."
    warn "Existing services may become unreachable."
    read -r -p "Type APPLY to continue: " confirm

    [[ "$confirm" == "APPLY" ]] || {
        info "Cancelled."
        return
    }

    capture_evidence before

    case "$BACKEND" in
        iptables)  apply_iptables ;;
        nftables)  apply_nftables ;;
        firewalld) apply_firewalld ;;
        ufw)       apply_ufw ;;
        *) die "Unsupported backend." ;;
    esac

    capture_evidence after

    info "Firewall configuration completed."
    info "Verify allowed and denied traffic from another VM."
}

# -----------------------------
# Verification
# -----------------------------

verify_firewall() {
    echo
    echo "========== FIREWALL VERIFICATION =========="

    detect_backend
    echo "Detected manager: $BACKEND"

    if has iptables; then
        echo
        echo "--- IPv4 iptables ---"
        iptables -L -n -v
    fi

    if has ip6tables; then
        echo
        echo "--- IPv6 iptables ---"
        ip6tables -L -n -v
    fi

    if has nft; then
        echo
        echo "--- nftables ---"
        nft list ruleset
    fi

    if active firewalld; then
        echo
        echo "--- firewalld ---"
        firewall-cmd --get-active-zones
        firewall-cmd --list-all-zones
    fi

    if has ufw; then
        echo
        echo "--- UFW ---"
        ufw status verbose
    fi

    echo
    echo "--- Listening services ---"
    ss -tulpen

    echo
    echo "Verification requires external connectivity tests."
}

# -----------------------------
# Menu
# -----------------------------

main() {
    need_root

    while true; do
        show_system

        echo
        echo "1) Assess current firewall"
        echo "2) Apply service profile"
        echo "3) Verify firewall configuration"
        echo "4) Capture firewall evidence"
        echo "5) View firewall logs"
        echo "6) Exit"
        echo

        read -r -p "Select option: " choice

        case "$choice" in
            1)
                verify_firewall
                ;;
            2)
                apply_firewall
                ;;
            3)
                verify_firewall
                ;;
            4)
                capture_evidence manual
                ;;
            5)
                echo "--- Recent firewall logs ---"
                journalctl -k -n 100 --no-pager
                ;;
            6)
                exit 0
                ;;
            *)
                warn "Invalid selection."
                ;;
        esac

        echo
        read -r -p "Press Enter to continue..." _
    done
}

main "$@"

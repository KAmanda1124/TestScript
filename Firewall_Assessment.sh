#!/usr/bin/env bash
# MWCCDC FW01 - Linux Host Firewall Assessment
# Interactive menu, iptables enforcement, evidence and summary
#
# Run: sudo bash fw01-host-firewall-menu.sh
# Preview: sudo bash fw01-host-firewall-menu.sh mail webserver --dry-run
# Persist: sudo bash fw01-host-firewall-menu.sh --persist
#
# WARNING: New inbound IPv4 SSH connections are blocked.
# Run from the VM console. IPv6 and Docker FORWARD/NAT are unchanged.

set -euo pipefail

# ================= CONFIGURATION =================

DEFAULT_MGMT_NETS=("172.20.240.0/24" "172.20.242.0/24")
MGMT_NETS=("${DEFAULT_MGMT_NETS[@]}")

ALLOW_PING=1
SPLUNK_OPEN=0
DRY_RUN=0
MODE="apply"

PROFILES=()
EXTRA_TCP=()
PUBLIC_TCP=()
PUBLIC_UDP=()
MGMT_TCP=()
HAS_WRKSTN=0

die() {
    echo "ERROR: $*" >&2
    exit 1
}

valid_port() {
    [[ "$1" =~ ^[1-9][0-9]*$ ]] || return 1
    (( 10#$1 <= 65535 ))
}

valid_cidr() {
    local value="$1" ip mask a b c d octet

    [[ "$value" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]] || return 1

    ip="${value%/*}"
    mask="${value#*/}"

    [[ "$mask" =~ ^(0|[1-9][0-9]?)$ ]] || return 1
    (( 10#$mask <= 32 )) || return 1

    IFS='.' read -r a b c d <<< "$ip"

    for octet in "$a" "$b" "$c" "$d"; do
        [[ "$octet" =~ ^(0|[1-9][0-9]{0,2})$ ]] || return 1
        (( 10#$octet <= 255 )) || return 1
    done
}

dedupe() {
    if (( $# > 0 )); then
        printf '%s\n' "$@" | sort -nu
    fi
}

usage() {
    cat <<'HELP'
MWCCDC FW01 - Linux Host Firewall

Usage:
  sudo bash fw01-host-firewall-menu.sh
  sudo bash fw01-host-firewall-menu.sh mail webserver
  sudo bash fw01-host-firewall-menu.sh splunk --dry-run
  sudo bash fw01-host-firewall-menu.sh --persist

Profiles:
  webserver   TCP 80,443
  mail        TCP 25,110
  mail-full   TCP 25,465,587,110,995,143,993
  splunk      TCP 8000,8089,9997
  dnsntp      TCP 53, UDP 53,123
  wrkstn      DHCP client replies

Options:
  --mgmt-nets CIDR[,CIDR]
  --extra-tcp PORT[,PORT]
  --splunk-open
  --allow-ping
  --no-ping
  --dry-run
  --preview
  --persist
  -h, --help
HELP
}

# ================= INTERACTIVE MENU =================

if [[ $# -eq 0 ]]; then

    echo
    echo "=============================================="
    echo "       MWCCDC FW01 - HOST FIREWALL"
    echo "=============================================="
    echo
    echo " Select your assigned Linux system:"
    echo
    echo "   1) Ubuntu Ecom Server"
    echo "   2) Fedora Webmail Server"
    echo "   3) Oracle Linux Splunk Server"
    echo "   4) Ubuntu Desktop Workstation"
    echo
    echo "   0) Exit"
    echo

    read -r -p " Enter selection: " selection

    case "$selection" in
        1) set -- webserver ;;
        2) set -- mail webserver ;;
        3) set -- splunk ;;
        4) set -- wrkstn ;;
        0) echo "No changes made."; exit 0 ;;
        *) die "Invalid selection. No changes made." ;;
    esac
fi

# ================= ARGUMENT PARSING =================

while [[ $# -gt 0 ]]; do
    case "$1" in

        --mgmt-nets)
            [[ $# -ge 2 ]] || die "Missing management networks"
            IFS=',' read -ra MGMT_NETS <<< "$2"
            (( ${#MGMT_NETS[@]} > 0 )) || die "No management networks"
            shift 2
            ;;

        --extra-tcp)
            [[ $# -ge 2 ]] || die "Missing TCP ports"
            IFS=',' read -ra EXTRA_TCP <<< "$2"
            (( ${#EXTRA_TCP[@]} > 0 )) || die "No extra TCP ports"
            shift 2
            ;;

        --splunk-open)
            SPLUNK_OPEN=1
            shift
            ;;

        --allow-ping)
            ALLOW_PING=1
            shift
            ;;

        --no-ping)
            ALLOW_PING=0
            shift
            ;;

        --dry-run|--preview)
            DRY_RUN=1
            shift
            ;;

        --persist)
            MODE="persist"
            shift
            ;;

        -h|--help)
            usage
            exit 0
            ;;

        -*)
            die "Unknown option: $1"
            ;;

        *)
            PROFILES+=("$1")
            shift
            ;;
    esac
done

[[ $EUID -eq 0 ]] || die "Run with sudo or as root."

for cmd in iptables iptables-save ss; do
    command -v "$cmd" >/dev/null 2>&1 || die "Missing command: $cmd"
done

# ================= PERSIST MODE =================

firewall_manager_active() {
    if command -v systemctl >/dev/null 2>&1 &&
       systemctl is-active --quiet firewalld 2>/dev/null; then
        return 0
    fi

    if command -v ufw >/dev/null 2>&1 &&
       ufw status 2>/dev/null | grep -q '^Status: active'; then
        return 0
    fi

    return 1
}

if [[ "$MODE" == "persist" ]]; then

    if firewall_manager_active; then
        die "firewalld or UFW is active. Resolve firewall manager conflicts."
    fi

    iptables -C INPUT -j MWCCDC_HOST 2>/dev/null ||
        die "MWCCDC_HOST is not attached to INPUT."

    if command -v netfilter-persistent >/dev/null 2>&1; then
        netfilter-persistent save
        echo "Rules saved using netfilter-persistent."

    elif [[ -d /etc/sysconfig ]]; then
        iptables-save > /etc/sysconfig/iptables
        echo "Rules saved to /etc/sysconfig/iptables."
        echo "Verify that the iptables service loads them at boot."

    else
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4
        echo "Rules saved to /etc/iptables/rules.v4."
        echo "WARNING: Configure a persistence service to load them at boot."
    fi

    exit 0
fi

# ================= VALIDATION =================

(( ${#PROFILES[@]} > 0 )) || {
    usage
    exit 1
}

for port in "${EXTRA_TCP[@]}"; do
    valid_port "$port" || die "Invalid TCP port: $port"
done

for net in "${MGMT_NETS[@]}"; do
    valid_cidr "$net" || die "Invalid management network: $net"
done

# ================= BUILD FIREWALL PROFILES =================

for profile in "${PROFILES[@]}"; do

    case "$profile" in

        webserver)
            PUBLIC_TCP+=(80 443)
            ;;

        mail)
            PUBLIC_TCP+=(25 110)
            ;;

        mail-full)
            PUBLIC_TCP+=(25 465 587 110 995 143 993)
            ;;

        splunk)
            if (( SPLUNK_OPEN )); then
                PUBLIC_TCP+=(8000 8089 9997)
            else
                MGMT_TCP+=(8000 8089 9997)
            fi
            ;;

        dnsntp)
            PUBLIC_TCP+=(53)
            PUBLIC_UDP+=(53 123)
            ;;

        wrkstn)
            HAS_WRKSTN=1
            ;;

        *)
            die "Unknown profile: $profile"
            ;;
    esac
done

PUBLIC_TCP+=("${EXTRA_TCP[@]}")

mapfile -t PUBLIC_TCP < <(dedupe "${PUBLIC_TCP[@]}")
mapfile -t PUBLIC_UDP < <(dedupe "${PUBLIC_UDP[@]}")
mapfile -t MGMT_TCP < <(dedupe "${MGMT_TCP[@]}")

# ================= REPORT DIRECTORY =================

PROFILE_TAG="$(IFS=_; echo "${PROFILES[*]}")"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"

REPORT_DIR="/root/FW01_${PROFILE_TAG}_${TIMESTAMP}"

mkdir -p "$REPORT_DIR"
chmod 700 "$REPORT_DIR"

SUMMARY="$REPORT_DIR/summary.txt"

# ================= EVIDENCE COLLECTION =================

capture() {
    local stage="$1"

    iptables -L INPUT -n -v --line-numbers \
        > "$REPORT_DIR/${stage}-input.txt"

    iptables -L OUTPUT -n -v --line-numbers \
        > "$REPORT_DIR/${stage}-output.txt"

    iptables-save \
        > "$REPORT_DIR/${stage}-iptables.rules"

    ss -tulnp \
        > "$REPORT_DIR/${stage}-listening.txt"

    if command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --list-all \
            > "$REPORT_DIR/${stage}-firewalld.txt" 2>&1 || true
    fi

    if command -v ufw >/dev/null 2>&1; then
        ufw status verbose \
            > "$REPORT_DIR/${stage}-ufw.txt" 2>&1 || true
    fi

    if command -v nft >/dev/null 2>&1; then
        nft list ruleset \
            > "$REPORT_DIR/${stage}-nftables.txt" 2>&1 || true
    fi

    if command -v ip6tables-save >/dev/null 2>&1; then
        ip6tables-save \
            > "$REPORT_DIR/${stage}-ip6tables.rules" 2>&1 || true
    fi
}

# ================= CLEAN SUMMARY =================

print_summary() {
    local status="$1"
    local port net

    echo
    echo "=================================================="
    echo "          MWCCDC FW01 - FIREWALL RESULTS"
    echo "=================================================="
    echo
    printf " Status:    %s\n" "$status"
    printf " Host:      %s\n" "$(hostname)"
    printf " Profiles:  %s\n" "${PROFILES[*]}"
    echo

    echo "--------------------------------------------------"
    echo " ALLOWED INBOUND TRAFFIC"
    echo "--------------------------------------------------"
    printf " %-8s %-16s %-20s\n" "PROTO" "PORT" "SOURCE"
    echo "--------------------------------------------------"

    for port in "${PUBLIC_TCP[@]}"; do
        printf " %-8s %-16s %-20s\n" "TCP" "$port" "Any"
    done

    for port in "${PUBLIC_UDP[@]}"; do
        printf " %-8s %-16s %-20s\n" "UDP" "$port" "Any"
    done

    for port in "${MGMT_TCP[@]}"; do
        for net in "${MGMT_NETS[@]}"; do
            printf " %-8s %-16s %-20s\n" "TCP" "$port" "$net"
        done
    done

    if (( HAS_WRKSTN )); then
        printf " %-8s %-16s %-20s\n" "UDP" "68" "DHCP replies"
    fi

    if (( ALLOW_PING )); then
        printf " %-8s %-16s %-20s\n" "ICMP" "Echo request" "Any"
    fi

    echo
    echo "--------------------------------------------------"
    echo " SECURITY RULES"
    echo "--------------------------------------------------"
    echo " [BLOCK] New inbound SSH (TCP 22)"
    echo " [BLOCK] Unmatched IPv4 inbound traffic"
    echo " [ALLOW] Established/related connections"
    echo " [ALLOW] Loopback traffic"
    echo " [NOTE]  Outbound traffic unchanged"
    echo " [NOTE]  IPv6 and Docker FORWARD/NAT unchanged"

    echo
    echo "--------------------------------------------------"
    echo " EVIDENCE"
    echo "--------------------------------------------------"
    echo " Directory: $REPORT_DIR"

    if [[ "$status" == "APPLIED" ]]; then
        echo " Before:    before-iptables.rules"
        echo " After:     after-iptables.rules"
        echo " Changes:   firewall-changes.txt"
        echo " Recovery:  recovery-commands.txt"
    else
        echo " Preview only - no changes applied"
    fi

    echo
    echo "--------------------------------------------------"
    echo " NEXT STEPS"
    echo "--------------------------------------------------"

    if [[ "$status" == "APPLIED" ]]; then
        echo " 1. Verify scored services in NISE."
        echo " 2. Test required network connections."
        echo " 3. Review saved firewall evidence."
        echo " 4. Persist rules only after verification."
    else
        echo " Review the plan before applying changes."
    fi

    echo
    echo "=================================================="
}

# ================= DRY RUN =================

if (( DRY_RUN )); then

    ss -tulnp > "$REPORT_DIR/dry-run-listening.txt"

    print_summary "DRY RUN" | tee "$SUMMARY"

    exit 0
fi

# ================= PRE-CHANGE CHECKS =================

echo
echo "[1/5] Capturing current firewall configuration..."

capture before

if firewall_manager_active; then
    die "firewalld or UFW is active. No changes applied."
fi

echo
echo "Selected profiles: ${PROFILES[*]}"
echo "New inbound SSH will be blocked."
echo "Unmatched IPv4 inbound traffic will be dropped."
echo
echo "WARNING: Use the VM console for recovery."
echo

read -r -p "Apply these firewall rules? [y/N]: " confirm

[[ "$confirm" =~ ^[Yy]([Ee][Ss])?$ ]] || {
    echo "No changes made."
    exit 0
}

# ================= CHAIN VALIDATION =================

TEMP_CHAIN="MWCCDC_HOST_NEW"

if iptables -L "$TEMP_CHAIN" -n >/dev/null 2>&1; then
    die "Temporary chain already exists. Inspect before retrying."
fi

chain_has_external_references() {
    local target="$1"

    iptables -t filter -S | awk -v target="$target" '
        $1 == "-A" && $2 != "INPUT" {
            for (i = 3; i < NF; i++) {
                if (($i == "-j" || $i == "-g") &&
                    $(i+1) == target) {
                    found = 1
                }
            }
        }
        END { exit(found ? 0 : 1) }
    '
}

if iptables -L MWCCDC_HOST -n >/dev/null 2>&1; then

    iptables -C INPUT -j MWCCDC_HOST 2>/dev/null ||
        die "Existing chain is not attached to INPUT."

    if chain_has_external_references MWCCDC_HOST; then
        die "Existing chain has references outside INPUT."
    fi
fi

# ================= BUILD FIREWALL =================

echo "[2/5] Building firewall rules..."

iptables -N "$TEMP_CHAIN"

# Loopback
iptables -A "$TEMP_CHAIN" -i lo -j ACCEPT

# Invalid connections
iptables -A "$TEMP_CHAIN" \
    -m conntrack --ctstate INVALID -j DROP

# Block new inbound SSH
iptables -A "$TEMP_CHAIN" \
    -p tcp --dport 22 \
    -m conntrack --ctstate NEW -j DROP

# Allow existing connections
iptables -A "$TEMP_CHAIN" \
    -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# ICMP
if (( ALLOW_PING )); then
    iptables -A "$TEMP_CHAIN" \
        -p icmp --icmp-type echo-request -j ACCEPT
fi

# Public TCP
for port in "${PUBLIC_TCP[@]}"; do
    iptables -A "$TEMP_CHAIN" \
        -p tcp --dport "$port" \
        -m conntrack --ctstate NEW -j ACCEPT
done

# Public UDP
for port in "${PUBLIC_UDP[@]}"; do
    iptables -A "$TEMP_CHAIN" \
        -p udp --dport "$port" \
        -m conntrack --ctstate NEW -j ACCEPT
done

# Restricted management TCP
for port in "${MGMT_TCP[@]}"; do
    for net in "${MGMT_NETS[@]}"; do
        iptables -A "$TEMP_CHAIN" \
            -p tcp -s "$net" --dport "$port" \
            -m conntrack --ctstate NEW -j ACCEPT
    done
done

# Workstation DHCP
if (( HAS_WRKSTN )); then
    iptables -A "$TEMP_CHAIN" \
        -p udp --sport 67 --dport 68 -j ACCEPT
fi

# Default drop
iptables -A "$TEMP_CHAIN" -j DROP

# ================= ACTIVATE FIREWALL =================

echo "[3/5] Activating firewall..."

if ! iptables -I INPUT 1 -j "$TEMP_CHAIN"; then
    iptables -F "$TEMP_CHAIN" 2>/dev/null || true
    iptables -X "$TEMP_CHAIN" 2>/dev/null || true
    die "Failed to attach replacement chain."
fi

# Remove previous INPUT references
while iptables -C INPUT -j MWCCDC_HOST 2>/dev/null; do
    iptables -D INPUT -j MWCCDC_HOST ||
        die "Failed to remove old INPUT reference."
done

# Remove old chain
if iptables -L MWCCDC_HOST -n >/dev/null 2>&1; then

    if chain_has_external_references MWCCDC_HOST; then
        die "Old chain has unexpected external references."
    fi

    iptables -F MWCCDC_HOST
    iptables -X MWCCDC_HOST
fi

# Rename replacement
iptables -E "$TEMP_CHAIN" MWCCDC_HOST ||
    die "Failed to rename replacement chain."

# Verify attachment
iptables -C INPUT -j MWCCDC_HOST ||
    die "Firewall chain is not attached to INPUT."

# ================= AFTER EVIDENCE =================

echo "[4/5] Capturing updated firewall configuration..."

capture after

iptables -L MWCCDC_HOST -n -v --line-numbers \
    > "$REPORT_DIR/after-host-rules.txt"

# ================= CHANGE REPORT =================

echo "[5/5] Generating firewall change report..."

normalize_rules() {
    sed -E \
        -e '/^# Generated by /d' \
        -e '/^# Completed on /d' \
        -e 's/\[[0-9]+:[0-9]+\]//g' "$1"
}

diff -u \
    <(normalize_rules "$REPORT_DIR/before-iptables.rules") \
    <(normalize_rules "$REPORT_DIR/after-iptables.rules") \
    > "$REPORT_DIR/firewall-changes.txt" || true

# ================= RECOVERY COMMANDS =================

cat > "$REPORT_DIR/recovery-commands.txt" <<'RECOVERY'
MWCCDC FW01 - Manual Firewall Recovery

Run from the VM console.

1. Verify the firewall chain:

sudo iptables -L INPUT -n | grep MWCCDC_HOST

2. Save current rules:

sudo iptables-save > /root/fw01-before-recovery.rules

3. Remove the INPUT jump:

sudo iptables -D INPUT -j MWCCDC_HOST

Repeat if multiple jumps exist.

4. Remove the firewall chain:

sudo iptables -F MWCCDC_HOST
sudo iptables -X MWCCDC_HOST

5. Verify:

sudo iptables -L INPUT -n -v

WARNING:
Removing the MWCCDC_HOST chain restores the remaining
INPUT rules, which may permit additional traffic.
RECOVERY

# ================= FINAL SUMMARY =================

print_summary "APPLIED" | tee "$SUMMARY"

echo
echo "Firewall configuration complete."
echo "Detailed evidence saved successfully."
echo
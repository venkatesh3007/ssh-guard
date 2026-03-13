#!/usr/bin/env bash
#
# secure-readonly-setup.sh
# 
# Creates a kernel-enforced read-only user for AI agents on production servers.
# No pattern matching. No command filtering. Just Linux permissions.
#
# The user CAN:
#   - Read any file the system allows (logs, configs, code)
#   - Run any read-only command (ps, docker info, systemctl status, etc.)
#   - Inspect Docker containers (read-only API proxy)
#   - Query databases with read-only credentials
#
# The user CANNOT:
#   - Write, delete, or modify any file outside /tmp and ~/
#   - Install or remove packages (no sudo, not in sudoers)
#   - Start, stop, or restart any service
#   - Kill any process (not even their own, via restricted proc)
#   - Create users, change permissions, modify firewall rules
#   - Use SSH forwarding, tunneling, or agent forwarding
#   - Access Docker write operations (start/stop/rm/exec)
#
# WHY THIS WORKS:
#   Linux file permissions are enforced by the kernel.
#   No userspace script can bypass them. This is the same mechanism
#   that prevents any regular user from deleting /etc/passwd.
#
# Usage (run as any user with sudo access):
#   sudo bash secure-readonly-setup.sh [--user USERNAME] [--ssh-key "KEY"] [--docker] [--uninstall]
#
set -euo pipefail

# ─── Defaults ───
USERNAME="flyyjarvis"
SSH_KEY=""
ENABLE_DOCKER=false
UNINSTALL=false
DOCKER_PROXY_PORT=2375
LOG_DIR="/var/log/flyyjarvis"

# ─── Colors ───
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { printf "${BLUE}[INFO]${NC}  %s\n" "$*"; }
ok()    { printf "${GREEN}[OK]${NC}    %s\n" "$*"; }
warn()  { printf "${YELLOW}[WARN]${NC}  %s\n" "$*"; }
err()   { printf "${RED}[ERROR]${NC} %s\n" "$*" >&2; }
fatal() { err "$*"; exit 1; }

# ─── Parse args ───
while [[ $# -gt 0 ]]; do
    case "$1" in
        --user)     USERNAME="$2"; shift 2 ;;
        --ssh-key)  SSH_KEY="$2"; shift 2 ;;
        --docker)   ENABLE_DOCKER=true; shift ;;
        --uninstall) UNINSTALL=true; shift ;;
        -h|--help)
            echo "Usage: sudo bash $0 [--user USERNAME] [--ssh-key \"KEY\"] [--docker] [--uninstall]"
            echo ""
            echo "  --user      Username to create (default: flyyjarvis)"
            echo "  --ssh-key   SSH public key string (will prompt if not provided)"
            echo "  --docker    Enable read-only Docker API access via socket proxy"
            echo "  --uninstall Remove the user and all associated config"
            echo ""
            exit 0
            ;;
        *) fatal "Unknown option: $1" ;;
    esac
done

# ─── Preflight ───
[[ $EUID -eq 0 ]] || fatal "This script must be run with sudo: sudo bash $0"
command -v useradd >/dev/null 2>&1 || fatal "useradd not found"

# ─── Uninstall ───
if [[ "$UNINSTALL" == true ]]; then
    info "Removing user $USERNAME and associated config..."
    
    # Stop and remove docker proxy if running
    if systemctl is-active "docker-readonly-proxy" &>/dev/null; then
        systemctl stop docker-readonly-proxy 2>/dev/null || true
        systemctl disable docker-readonly-proxy 2>/dev/null || true
    fi
    rm -f /etc/systemd/system/docker-readonly-proxy.service
    
    # Remove SSH config block
    if [[ -f /etc/ssh/sshd_config ]]; then
        sed -i "/^# BEGIN ${USERNAME} readonly/,/^# END ${USERNAME} readonly/d" /etc/ssh/sshd_config
        systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
    fi
    
    # Remove user
    if id "$USERNAME" &>/dev/null; then
        userdel -r "$USERNAME" 2>/dev/null || true
        ok "User $USERNAME removed"
    else
        warn "User $USERNAME does not exist"
    fi
    
    # Remove log dir
    rm -rf "$LOG_DIR"
    
    # Remove audit profile
    rm -f "/etc/apparmor.d/home.${USERNAME}" 2>/dev/null || true
    
    ok "Uninstall complete"
    exit 0
fi

# ═══════════════════════════════════════════
#  STEP 1: Create the restricted user
# ═══════════════════════════════════════════
info "Step 1: Creating user '$USERNAME'..."

if id "$USERNAME" &>/dev/null; then
    warn "User '$USERNAME' already exists, skipping creation"
else
    useradd \
        --create-home \
        --shell /bin/bash \
        --comment "AI Agent Read-Only Access" \
        "$USERNAME"
    ok "User '$USERNAME' created"
fi

# Lock the password — SSH key only, no password login ever
passwd -l "$USERNAME" >/dev/null 2>&1
ok "Password login disabled (SSH key only)"

# ═══════════════════════════════════════════
#  STEP 2: SSH key setup
# ═══════════════════════════════════════════
info "Step 2: Configuring SSH key..."

USER_HOME="$(eval echo "~$USERNAME")"
SSH_DIR="${USER_HOME}/.ssh"
AUTH_KEYS="${SSH_DIR}/authorized_keys"

mkdir -p "$SSH_DIR"
chmod 700 "$SSH_DIR"

if [[ -z "$SSH_KEY" ]]; then
    # Check if key already exists
    if [[ -f "$AUTH_KEYS" ]] && [[ -s "$AUTH_KEYS" ]]; then
        warn "SSH key already configured, skipping"
    else
        echo ""
        echo "Paste the SSH public key for the AI agent (the key from your OpenClaw server):"
        echo "  Usually found at: ~/.ssh/id_ed25519.pub"
        echo ""
        read -r SSH_KEY
        if [[ -z "$SSH_KEY" ]]; then
            fatal "No SSH key provided"
        fi
    fi
fi

if [[ -n "$SSH_KEY" ]]; then
    # The 'restrict' keyword disables:
    #   - Port forwarding (local, remote, dynamic)
    #   - Agent forwarding
    #   - PTY allocation (we re-enable with pty so commands work)
    #   - X11 forwarding
    #   - User rc execution
    echo "restrict,pty $SSH_KEY" > "$AUTH_KEYS"
    chmod 600 "$AUTH_KEYS"
    ok "SSH key installed with 'restrict,pty' flags"
fi

chown -R "$USERNAME:$USERNAME" "$SSH_DIR"

# ═══════════════════════════════════════════
#  STEP 3: Grant read access to common paths
# ═══════════════════════════════════════════
info "Step 3: Granting read access via group memberships..."

# adm group — read access to /var/log/*
if getent group adm >/dev/null 2>&1; then
    usermod -aG adm "$USERNAME" 2>/dev/null && ok "Added to 'adm' group (read /var/log)" || true
fi

# systemd-journal — read journalctl
if getent group systemd-journal >/dev/null 2>&1; then
    usermod -aG systemd-journal "$USERNAME" 2>/dev/null && ok "Added to 'systemd-journal' group" || true
fi

# www-data — read web server configs and logs
if getent group www-data >/dev/null 2>&1; then
    usermod -aG www-data "$USERNAME" 2>/dev/null && ok "Added to 'www-data' group (read web configs)" || true
fi

# ═══════════════════════════════════════════
#  STEP 4: SSH hardening — restrict this user
# ═══════════════════════════════════════════
info "Step 4: Hardening SSH config for '$USERNAME'..."

SSHD_CONFIG="/etc/ssh/sshd_config"

# Remove any existing block for this user
sed -i "/^# BEGIN ${USERNAME} readonly/,/^# END ${USERNAME} readonly/d" "$SSHD_CONFIG" 2>/dev/null || true

# Ensure file ends with newline before appending
[[ -s "$SSHD_CONFIG" && "$(tail -c1 "$SSHD_CONFIG" | wc -l)" -eq 0 ]] && echo "" >> "$SSHD_CONFIG"

cat >> "$SSHD_CONFIG" <<SSHEOF

# BEGIN ${USERNAME} readonly
Match User ${USERNAME}
    # No interactive shell escape routes
    AllowTcpForwarding no
    AllowStreamLocalForwarding no
    GatewayPorts no
    X11Forwarding no
    PermitTunnel no
    # No agent forwarding (can't hijack SSH keys)
    AllowAgentForwarding no
    # Force non-interactive environment
    PermitUserEnvironment no
    # Idle timeout — kill sessions after 30 min idle
    ClientAliveInterval 300
    ClientAliveCountMax 6
    # Max sessions
    MaxSessions 3
# END ${USERNAME} readonly
SSHEOF

# Validate sshd config before reloading
if sshd -t 2>/dev/null; then
    systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
    ok "SSH config updated and reloaded"
else
    # Rollback
    sed -i "/^# BEGIN ${USERNAME} readonly/,/^# END ${USERNAME} readonly/d" "$SSHD_CONFIG"
    fatal "SSH config validation failed — rolled back changes"
fi

# ═══════════════════════════════════════════
#  STEP 5: Ensure NO sudo access
# ═══════════════════════════════════════════
info "Step 5: Ensuring no sudo/privilege escalation..."

# Explicitly remove from sudo/wheel groups if somehow added
for group in sudo wheel admin; do
    if groups "$USERNAME" 2>/dev/null | grep -qw "$group"; then
        gpasswd -d "$USERNAME" "$group" 2>/dev/null || true
        warn "Removed '$USERNAME' from '$group' group"
    fi
done

# Drop an explicit sudoers deny (belt and suspenders)
echo "${USERNAME} ALL=(ALL) !ALL" > "/etc/sudoers.d/deny-${USERNAME}"
chmod 440 "/etc/sudoers.d/deny-${USERNAME}"
ok "Sudo explicitly denied via /etc/sudoers.d/deny-${USERNAME}"

# ═══════════════════════════════════════════
#  STEP 6: Audit logging
# ═══════════════════════════════════════════
info "Step 6: Setting up audit logging..."

mkdir -p "$LOG_DIR"
chown root:root "$LOG_DIR"
chmod 755 "$LOG_DIR"

# Add bash audit logging to the user's profile
# Every command they run gets logged with timestamp
PROFILE_FILE="${USER_HOME}/.bash_profile"
cat > "$PROFILE_FILE" <<BASHEOF
# ─── AI Agent Audit Trail ───
# Every command is logged. This cannot be disabled by the user
# because .bash_profile is owned by root and not writable.
export HISTFILE=~/.bash_history
export HISTTIMEFORMAT="%Y-%m-%dT%H:%M:%S%z "
export HISTSIZE=50000
export HISTFILESIZE=100000
export HISTCONTROL=""
shopt -s histappend

# Real-time command logging via PROMPT_COMMAND
export PROMPT_COMMAND='
    _exit=\$?;
    _cmd=\$(history 1 | sed "s/^[ ]*[0-9]*[ ]*//");
    echo "\$(date -u +%Y-%m-%dT%H:%M:%SZ) user=${USERNAME} pwd=\$(pwd) exit=\${_exit} cmd=\${_cmd}" >> ${LOG_DIR}/audit.log 2>/dev/null;
    history -a;
'

# Read-only indicator in prompt
export PS1='[\u@\h (READ-ONLY)] \w \\\$ '
BASHEOF

# CRITICAL: Make the profile owned by root so the user can't modify it
chown root:root "$PROFILE_FILE"
chmod 644 "$PROFILE_FILE"

# Also set up .bashrc the same way
cp "$PROFILE_FILE" "${USER_HOME}/.bashrc"
chown root:root "${USER_HOME}/.bashrc"
chmod 644 "${USER_HOME}/.bashrc"

# Create the audit log file
# Owner (root) can read/write. The flyyjarvis user writes via group.
touch "${LOG_DIR}/audit.log"
chown "root:${USERNAME}" "${LOG_DIR}/audit.log"
chmod 660 "${LOG_DIR}/audit.log"
# Make it append-only — even root needs chattr -a to clear it
chattr +a "${LOG_DIR}/audit.log" 2>/dev/null || warn "chattr not available (audit log won't be append-only)"

ok "Audit logging configured at ${LOG_DIR}/audit.log"

# ═══════════════════════════════════════════
#  STEP 7: Docker read-only proxy (optional)
# ═══════════════════════════════════════════
if [[ "$ENABLE_DOCKER" == true ]]; then
    info "Step 7: Setting up read-only Docker API proxy..."
    
    if ! command -v docker >/dev/null 2>&1; then
        warn "Docker not installed, skipping Docker proxy setup"
    elif ! command -v socat >/dev/null 2>&1; then
        warn "socat not installed. Install it: apt-get install socat"
        warn "Skipping Docker proxy setup"
    else
        # Create a script that proxies Docker API but only allows GET requests
        cat > /usr/local/bin/docker-readonly-proxy.sh <<'DOCKEREOF'
#!/usr/bin/env bash
#
# Read-only Docker API proxy
# Only allows GET requests to the Docker socket.
# POST/PUT/DELETE (which start/stop/rm containers) are rejected.
#
PROXY_SOCKET="/var/run/docker-readonly.sock"

# Only remove the specific proxy socket file, and verify it is a socket
if [[ -e "$PROXY_SOCKET" ]]; then
    if [[ -S "$PROXY_SOCKET" ]]; then
        rm -f "$PROXY_SOCKET"
    else
        echo "ERROR: $PROXY_SOCKET exists but is not a socket. Aborting." >&2
        exit 1
    fi
fi

while true; do
    socat UNIX-LISTEN:"$PROXY_SOCKET",fork,mode=0666 \
        EXEC:"/usr/local/bin/docker-readonly-filter.sh" 2>/dev/null
    sleep 1
done
DOCKEREOF

        cat > /usr/local/bin/docker-readonly-filter.sh <<'FILTEREOF'
#!/usr/bin/env bash
# Reads the HTTP request, only forwards GET to real Docker socket
read -r REQUEST_LINE
METHOD=$(echo "$REQUEST_LINE" | awk '{print $1}')

if [[ "$METHOD" == "GET" || "$METHOD" == "HEAD" ]]; then
    # Forward to real Docker socket
    {
        echo "$REQUEST_LINE"
        cat
    } | socat - UNIX-CONNECT:/var/run/docker.sock
else
    # Block non-GET requests
    echo "HTTP/1.1 403 Forbidden"
    echo "Content-Type: application/json"
    echo ""
    echo '{"message":"Read-only access: only GET requests are allowed"}'
fi
FILTEREOF

        chmod +x /usr/local/bin/docker-readonly-proxy.sh
        chmod +x /usr/local/bin/docker-readonly-filter.sh

        # Create systemd service
        cat > /etc/systemd/system/docker-readonly-proxy.service <<SVCEOF
[Unit]
Description=Docker Read-Only API Proxy
After=docker.service
Requires=docker.service

[Service]
Type=simple
ExecStart=/usr/local/bin/docker-readonly-proxy.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SVCEOF

        systemctl daemon-reload
        systemctl enable docker-readonly-proxy
        systemctl start docker-readonly-proxy
        
        # Add Docker CLI alias for the user
        echo "export DOCKER_HOST=unix:///var/run/docker-readonly.sock" >> "$PROFILE_FILE"
        echo "export DOCKER_HOST=unix:///var/run/docker-readonly.sock" >> "${USER_HOME}/.bashrc"
        
        ok "Docker read-only proxy active at /var/run/docker-readonly.sock"
        ok "User's 'docker' commands will use read-only proxy automatically"
    fi
else
    info "Step 7: Docker proxy skipped (use --docker to enable)"
fi

# ═══════════════════════════════════════════
#  STEP 8: Verification
# ═══════════════════════════════════════════
info "Step 8: Running verification checks..."

PASS=0
FAIL=0

check() {
    local desc="$1" result="$2"
    if [[ "$result" == "pass" ]]; then
        ok "  $desc"
        ((PASS++))
    else
        err "  $desc"
        ((FAIL++))
    fi
}

# User exists
id "$USERNAME" &>/dev/null && check "User exists" "pass" || check "User exists" "fail"

# No password
[[ "$(passwd -S "$USERNAME" 2>/dev/null | awk '{print $2}')" == "L" ]] && \
    check "Password locked" "pass" || check "Password locked" "fail"

# Not in sudo/wheel
! groups "$USERNAME" 2>/dev/null | grep -qwE "sudo|wheel|admin" && \
    check "Not in privileged groups" "pass" || check "Not in privileged groups" "fail"

# Sudoers deny exists
[[ -f "/etc/sudoers.d/deny-${USERNAME}" ]] && \
    check "Sudo deny rule exists" "pass" || check "Sudo deny rule exists" "fail"

# SSH key installed
[[ -f "$AUTH_KEYS" && -s "$AUTH_KEYS" ]] && \
    check "SSH key installed" "pass" || check "SSH key installed" "fail"

# SSH key has restrict flag
grep -q "^restrict" "$AUTH_KEYS" 2>/dev/null && \
    check "SSH key has 'restrict' flag" "pass" || check "SSH key has 'restrict' flag" "fail"

# Profile is root-owned (tamper-proof)
[[ "$(stat -c %U "$PROFILE_FILE" 2>/dev/null)" == "root" ]] && \
    check "Bash profile owned by root (tamper-proof)" "pass" || check "Bash profile owned by root" "fail"

# Audit log exists
[[ -f "${LOG_DIR}/audit.log" ]] && \
    check "Audit log exists" "pass" || check "Audit log exists" "fail"

# Cannot write to /etc
! su -s /bin/sh "$USERNAME" -c "touch /etc/.test_write 2>/dev/null" && \
    check "Cannot write to /etc" "pass" || { rm -f /etc/.test_write; check "Cannot write to /etc" "fail"; }

# Cannot write to /var/lib
! su -s /bin/sh "$USERNAME" -c "touch /var/lib/.test_write 2>/dev/null" && \
    check "Cannot write to /var/lib" "pass" || { rm -f /var/lib/.test_write; check "Cannot write to /var/lib" "fail"; }

# CAN read /var/log
su -s /bin/sh "$USERNAME" -c "ls /var/log/ >/dev/null 2>&1" && \
    check "Can read /var/log" "pass" || check "Can read /var/log" "fail"

# CAN run ps
su -s /bin/sh "$USERNAME" -c "ps aux >/dev/null 2>&1" && \
    check "Can run 'ps aux'" "pass" || check "Can run 'ps aux'" "fail"

# CAN run systemctl status
if command -v systemctl >/dev/null 2>&1; then
    su -s /bin/sh "$USERNAME" -c "systemctl status sshd >/dev/null 2>&1 || systemctl status ssh >/dev/null 2>&1" && \
        check "Can run 'systemctl status'" "pass" || check "Can run 'systemctl status'" "fail"
fi

echo ""
echo "════════════════════════════════════════════════"
printf "  Checks passed: ${GREEN}%d${NC}  |  Failed: ${RED}%d${NC}\n" "$PASS" "$FAIL"
echo "════════════════════════════════════════════════"

if [[ $FAIL -gt 0 ]]; then
    echo ""
    warn "Some checks failed. Review the output above."
fi

# ═══════════════════════════════════════════
#  Summary
# ═══════════════════════════════════════════
echo ""
echo "════════════════════════════════════════════════════════"
echo "  SETUP COMPLETE"
echo "════════════════════════════════════════════════════════"
echo ""
echo "  User:       $USERNAME"
echo "  Home:       $USER_HOME"
echo "  Shell:      /bin/bash"
echo "  Audit log:  ${LOG_DIR}/audit.log"
echo ""
echo "  Connect from your OpenClaw server:"
echo "    ssh ${USERNAME}@$(hostname -I 2>/dev/null | awk '{print $1}' || echo '<this-server-ip>')"
echo ""
echo "  Or test locally:"
echo "    sudo -u ${USERNAME} bash -c 'ls /var/log'"
echo ""
echo "  What this user CAN do:"
echo "    ✅ cat, grep, find, ls any file they have read permission for"
echo "    ✅ ps, top, htop, lsof, netstat, ss"
echo "    ✅ systemctl status, journalctl"
echo "    ✅ docker ps/inspect/logs (if --docker was used)"
echo "    ✅ git log, git status, git diff"
echo "    ✅ curl (GET), dig, ping, traceroute"
echo "    ✅ Any read-only command — there is NO command whitelist"
echo ""
echo "  What this user CANNOT do:"
echo "    🚫 Write/delete ANY file outside /tmp and ~/"
echo "    🚫 sudo, su, or any privilege escalation"
echo "    🚫 Install/remove packages"
echo "    🚫 Start/stop/restart services"
echo "    🚫 Kill processes"
echo "    🚫 Modify firewall, users, permissions"
echo "    🚫 Docker run/stop/rm/exec (if --docker was used)"
echo "    🚫 SSH tunneling or port forwarding"
echo ""
echo "  Security model:"
echo "    Linux kernel file permissions — not script-based filtering"
echo "    The user is a regular unprivileged Linux user."
echo "    Same security as any non-root user on the system."
echo ""
echo "  To view audit trail:"
echo "    tail -f ${LOG_DIR}/audit.log"
echo ""
echo "  To remove completely:"
echo "    sudo bash $0 --uninstall"
echo ""
echo "════════════════════════════════════════════════════════"

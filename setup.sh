#!/usr/bin/env bash
#
# SSH Guard — Secure Read-Only Setup for AI Agents
#
# One-liner install:
#   curl -sL https://raw.githubusercontent.com/venkatesh3007/ssh-guard/main/setup.sh | sudo bash
#
# Or with options:
#   curl -sL https://raw.githubusercontent.com/venkatesh3007/ssh-guard/main/setup.sh | sudo bash -s -- --user myagent --github myusername
#   curl -sL https://raw.githubusercontent.com/venkatesh3007/ssh-guard/main/setup.sh | sudo bash -s -- --uninstall
#
# What this does:
#   1. Creates an unprivileged Linux user (default: flyyjarvis)
#   2. Fetches SSH public keys from GitHub (like ssh-import-id-gh)
#   3. Locks down SSH (no forwarding, no tunneling)
#   4. Explicitly denies sudo access
#   5. Sets up tamper-proof audit logging
#   6. Installs SSH command logger (logs non-interactive commands via ForceCommand)
#
# What the user CAN do:   Read anything — files, logs, configs, process info
# What the user CANNOT do: Write, delete, install, restart, kill, sudo — anything destructive
#
# Security model: Linux kernel file permissions. Not script-based filtering.
#
set -euo pipefail

# ─── Defaults ───
USERNAME="flyyjarvis"
GITHUB_USER="venkatesh3007"
SSH_KEY=""
UNINSTALL=false
LOG_DIR="/var/log/flyyjarvis"
# Preferred key type (ed25519 is most secure and compact)
PREFERRED_KEY_TYPE="ssh-ed25519"

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
        --github)   GITHUB_USER="$2"; shift 2 ;;
        --ssh-key)  SSH_KEY="$2"; shift 2 ;;
        --uninstall) UNINSTALL=true; shift ;;
        -h|--help)
            cat <<'HELP'
Usage: sudo bash setup.sh [OPTIONS]

Options:
  --user NAME       Username to create (default: flyyjarvis)
  --github USER     GitHub username to fetch SSH keys from (default: venkatesh3007)
  --ssh-key "KEY"   Provide SSH public key directly (skips GitHub fetch)
  --uninstall       Remove the user and all config cleanly

Examples:
  # Default — creates flyyjarvis user, fetches key from GitHub
  curl -sL <url> | sudo bash

  # Custom username
  curl -sL <url> | sudo bash -s -- --user aiagent

  # Uninstall
  curl -sL <url> | sudo bash -s -- --uninstall
HELP
            exit 0
            ;;
        *) fatal "Unknown option: $1" ;;
    esac
done

# ─── Preflight ───
[[ $EUID -eq 0 ]] || fatal "Run with sudo: curl ... | sudo bash"

echo ""
echo "════════════════════════════════════════════════════════"
echo "  SSH Guard — Secure Read-Only Setup for AI Agents"
echo "════════════════════════════════════════════════════════"
echo ""

# ─── Uninstall ───
if [[ "$UNINSTALL" == true ]]; then
    info "Removing user $USERNAME and associated config..."

    # Remove command logger
    rm -f "/usr/local/bin/${USERNAME}-logger.sh"

    # Remove SSH config block
    if [[ -f /etc/ssh/sshd_config ]]; then
        sed -i "/^# BEGIN ${USERNAME} readonly/,/^# END ${USERNAME} readonly/d" /etc/ssh/sshd_config
        systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
    fi

    # Remove sudoers deny
    rm -f "/etc/sudoers.d/deny-${USERNAME}"

    # Remove user
    if id "$USERNAME" &>/dev/null; then
        userdel -r "$USERNAME" 2>/dev/null || true
        ok "User $USERNAME removed"
    else
        warn "User $USERNAME does not exist"
    fi

    # Remove log dir (need to remove append-only flag first)
    chattr -a "${LOG_DIR}/audit.log" 2>/dev/null || true
    rm -rf "$LOG_DIR"

    ok "Uninstall complete"
    exit 0
fi

# ═══════════════════════════════════════════
#  STEP 1: Fetch SSH key from GitHub
# ═══════════════════════════════════════════
if [[ -z "$SSH_KEY" ]]; then
    info "Step 1: Fetching SSH key from github.com/${GITHUB_USER}..."

    GITHUB_KEYS_URL="https://github.com/${GITHUB_USER}.keys"
    ALL_KEYS=$(curl -sf "$GITHUB_KEYS_URL" 2>/dev/null) || fatal "Could not fetch keys from $GITHUB_KEYS_URL"

    if [[ -z "$ALL_KEYS" ]]; then
        fatal "No SSH keys found on GitHub for user '${GITHUB_USER}'"
    fi

    # Prefer ed25519 key, fall back to first available
    SSH_KEY=$(echo "$ALL_KEYS" | grep "$PREFERRED_KEY_TYPE" | head -1)

    if [[ -n "$SSH_KEY" ]]; then
        ok "Found ${PREFERRED_KEY_TYPE} key from GitHub"
    else
        SSH_KEY=$(echo "$ALL_KEYS" | head -1)
        warn "No ${PREFERRED_KEY_TYPE} key found, using first available key"
    fi
else
    info "Step 1: Using provided SSH key"
fi

[[ -n "$SSH_KEY" ]] || fatal "No SSH key available. Provide one with --ssh-key or check GitHub keys."
info "Key: ${SSH_KEY:0:30}...${SSH_KEY: -20}"

# ═══════════════════════════════════════════
#  STEP 2: Create the restricted user
# ═══════════════════════════════════════════
info "Step 2: Creating user '$USERNAME'..."

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

# Lock password — SSH key only
passwd -l "$USERNAME" >/dev/null 2>&1
ok "Password login disabled (SSH key only)"

# ═══════════════════════════════════════════
#  STEP 3: Install SSH key
# ═══════════════════════════════════════════
info "Step 3: Installing SSH key..."

USER_HOME="$(eval echo "~$USERNAME")"
SSH_DIR="${USER_HOME}/.ssh"
AUTH_KEYS="${SSH_DIR}/authorized_keys"

mkdir -p "$SSH_DIR"
chmod 700 "$SSH_DIR"

# 'restrict' disables: port forwarding, agent forwarding, X11, user rc
# 'pty' re-enables PTY so commands actually work
echo "restrict,pty $SSH_KEY" > "$AUTH_KEYS"
chmod 600 "$AUTH_KEYS"
chown -R "$USERNAME:$USERNAME" "$SSH_DIR"

ok "SSH key installed with 'restrict,pty' flags"

# ═══════════════════════════════════════════
#  STEP 4: Grant read access via groups
# ═══════════════════════════════════════════
info "Step 4: Granting read access..."

for group in adm systemd-journal www-data; do
    if getent group "$group" >/dev/null 2>&1; then
        usermod -aG "$group" "$USERNAME" 2>/dev/null && ok "Added to '$group'" || true
    fi
done

# ═══════════════════════════════════════════
#  STEP 5: Harden SSH for this user
# ═══════════════════════════════════════════
info "Step 5: SSH hardening (applied in Step 8 with command logger)..."
ok "SSH hardening deferred to Step 8"

# ═══════════════════════════════════════════
#  STEP 6: Deny sudo
# ═══════════════════════════════════════════
info "Step 6: Blocking privilege escalation..."

for group in sudo wheel admin; do
    if groups "$USERNAME" 2>/dev/null | grep -qw "$group"; then
        gpasswd -d "$USERNAME" "$group" 2>/dev/null || true
    fi
done

echo "${USERNAME} ALL=(ALL) !ALL" > "/etc/sudoers.d/deny-${USERNAME}"
chmod 440 "/etc/sudoers.d/deny-${USERNAME}"
ok "Sudo explicitly denied"

# ═══════════════════════════════════════════
#  STEP 7: Audit logging
# ═══════════════════════════════════════════
info "Step 7: Setting up audit logging..."

mkdir -p "$LOG_DIR"
chown root:root "$LOG_DIR"
chmod 755 "$LOG_DIR"

PROFILE_FILE="${USER_HOME}/.bash_profile"
cat > "$PROFILE_FILE" <<BASHEOF
# ─── AI Agent Audit Trail (owned by root, tamper-proof) ───
export HISTFILE=~/.bash_history
export HISTTIMEFORMAT="%Y-%m-%dT%H:%M:%S%z "
export HISTSIZE=50000
export HISTFILESIZE=100000
export HISTCONTROL=""
shopt -s histappend

export PROMPT_COMMAND='
    _exit=\$?;
    _cmd=\$(history 1 | sed "s/^[ ]*[0-9]*[ ]*//");
    echo "\$(date -u +%Y-%m-%dT%H:%M:%SZ) user=${USERNAME} pwd=\$(pwd) exit=\${_exit} cmd=\${_cmd}" >> ${LOG_DIR}/audit.log 2>/dev/null;
    history -a;
'

export PS1='[\u@\h (READ-ONLY)] \w \\\$ '
BASHEOF

# Tamper-proof: owned by root, user can't modify
chown root:root "$PROFILE_FILE"
chmod 644 "$PROFILE_FILE"
cp "$PROFILE_FILE" "${USER_HOME}/.bashrc"
chown root:root "${USER_HOME}/.bashrc"
chmod 644 "${USER_HOME}/.bashrc"

# Audit log: root + user's group, append-only
# Remove append-only flag first if re-running
chattr -a "${LOG_DIR}/audit.log" 2>/dev/null || true
touch "${LOG_DIR}/audit.log"
chown "root:${USERNAME}" "${LOG_DIR}/audit.log"
chmod 660 "${LOG_DIR}/audit.log"
chattr +a "${LOG_DIR}/audit.log" 2>/dev/null || warn "chattr not available (audit log won't be append-only)"

ok "Audit logging at ${LOG_DIR}/audit.log"

# ═══════════════════════════════════════════
#  STEP 8: SSH command logger (non-interactive)
# ═══════════════════════════════════════════
info "Step 8: Setting up SSH command logger..."

LOGGER_SCRIPT="/usr/local/bin/${USERNAME}-logger.sh"

cat > "$LOGGER_SCRIPT" <<LOGGEREOF
#!/bin/bash
CMD="\${SSH_ORIGINAL_COMMAND:-/bin/bash -li}"
echo "\$(date -u +%Y-%m-%dT%H:%M:%SZ) user=${USERNAME} pwd=\$HOME cmd=\${CMD}" >> ${LOG_DIR}/audit.log 2>/dev/null
exec /bin/bash -c "\$CMD"
LOGGEREOF

chmod 755 "$LOGGER_SCRIPT"
chown root:root "$LOGGER_SCRIPT"

# Add ForceCommand to the existing SSH Match block
SSHD_CONFIG="/etc/ssh/sshd_config"
if grep -q "^# BEGIN ${USERNAME} readonly" "$SSHD_CONFIG"; then
    # Remove old block and rewrite with ForceCommand included
    sed -i "/^# BEGIN ${USERNAME} readonly/,/^# END ${USERNAME} readonly/d" "$SSHD_CONFIG"
fi

# Ensure trailing newline
[[ -s "$SSHD_CONFIG" && "$(tail -c1 "$SSHD_CONFIG" | wc -l)" -eq 0 ]] && echo "" >> "$SSHD_CONFIG"

cat >> "$SSHD_CONFIG" <<SSHEOF

# BEGIN ${USERNAME} readonly
Match User ${USERNAME}
    AllowTcpForwarding no
    AllowStreamLocalForwarding no
    GatewayPorts no
    X11Forwarding no
    PermitTunnel no
    AllowAgentForwarding no
    PermitUserEnvironment no
    ClientAliveInterval 300
    ClientAliveCountMax 6
    MaxSessions 3
    ForceCommand ${LOGGER_SCRIPT}
# END ${USERNAME} readonly
SSHEOF

# Validate before reload — rollback on failure
if sshd -t 2>/dev/null; then
    systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
    ok "SSH command logger installed at ${LOGGER_SCRIPT}"
else
    sed -i "/^# BEGIN ${USERNAME} readonly/,/^# END ${USERNAME} readonly/d" "$SSHD_CONFIG"
    systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
    fatal "SSH config validation failed — changes rolled back"
fi

# ═══════════════════════════════════════════
#  STEP 9: Verify everything
# ═══════════════════════════════════════════
info "Step 9: Verifying..."

PASS=0; FAIL=0
check() {
    if [[ "$2" == "pass" ]]; then ok "  $1"; ((PASS++))
    else err "  $1"; ((FAIL++)); fi
}

id "$USERNAME" &>/dev/null && check "User exists" "pass" || check "User exists" "fail"
[[ "$(passwd -S "$USERNAME" 2>/dev/null | awk '{print $2}')" == "L" ]] && check "Password locked" "pass" || check "Password locked" "fail"
! groups "$USERNAME" 2>/dev/null | grep -qwE "sudo|wheel|admin" && check "Not in privileged groups" "pass" || check "Not in privileged groups" "fail"
[[ -f "/etc/sudoers.d/deny-${USERNAME}" ]] && check "Sudo deny rule" "pass" || check "Sudo deny rule" "fail"
[[ -f "$AUTH_KEYS" && -s "$AUTH_KEYS" ]] && check "SSH key installed" "pass" || check "SSH key installed" "fail"
grep -q "^restrict" "$AUTH_KEYS" 2>/dev/null && check "SSH restrict flag" "pass" || check "SSH restrict flag" "fail"
[[ "$(stat -c %U "$PROFILE_FILE" 2>/dev/null)" == "root" ]] && check "Profile tamper-proof" "pass" || check "Profile tamper-proof" "fail"
[[ -f "${LOG_DIR}/audit.log" ]] && check "Audit log exists" "pass" || check "Audit log exists" "fail"
[[ -x "/usr/local/bin/${USERNAME}-logger.sh" ]] && check "Command logger installed" "pass" || check "Command logger installed" "fail"
grep -q "ForceCommand" "$SSHD_CONFIG" 2>/dev/null && check "ForceCommand configured" "pass" || check "ForceCommand configured" "fail"
! su -s /bin/sh "$USERNAME" -c "touch /etc/.sshguard_test 2>/dev/null" && check "Cannot write /etc" "pass" || { rm -f /etc/.sshguard_test; check "Cannot write /etc" "fail"; }
! su -s /bin/sh "$USERNAME" -c "touch /var/lib/.sshguard_test 2>/dev/null" && check "Cannot write /var/lib" "pass" || { rm -f /var/lib/.sshguard_test; check "Cannot write /var/lib" "fail"; }
su -s /bin/sh "$USERNAME" -c "ls /var/log/ >/dev/null 2>&1" && check "Can read /var/log" "pass" || check "Can read /var/log" "fail"
su -s /bin/sh "$USERNAME" -c "ps aux >/dev/null 2>&1" && check "Can run ps" "pass" || check "Can run ps" "fail"

echo ""
printf "  ${GREEN}%d passed${NC}  |  ${RED}%d failed${NC}\n" "$PASS" "$FAIL"

# ═══════════════════════════════════════════
#  Done
# ═══════════════════════════════════════════
SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo '<server-ip>')

echo ""
echo "════════════════════════════════════════════════════════"
echo "  ✅ SETUP COMPLETE"
echo "════════════════════════════════════════════════════════"
echo ""
echo "  User:      $USERNAME"
echo "  SSH key:   From github.com/${GITHUB_USER}"
echo "  Audit log: ${LOG_DIR}/audit.log"
echo ""
echo "  Connect:   ssh ${USERNAME}@${SERVER_IP}"
echo "  Test:      sudo -u ${USERNAME} bash -c 'ls /var/log'"
echo "  Audit:     tail -f ${LOG_DIR}/audit.log"
echo "  Remove:    curl -sL <this-url> | sudo bash -s -- --uninstall"
echo ""
echo "════════════════════════════════════════════════════════"

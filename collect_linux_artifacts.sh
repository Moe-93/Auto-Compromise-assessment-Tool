#!/bin/bash
###############################################################################
# Linux Forensic Artifact Collection Script for CAT Tool
# 
# DESCRIPTION: Collects forensic artifacts from Linux systems for CAT analysis
# 
# USAGE:
#   sudo ./collect_linux_artifacts.sh
#   sudo ./collect_linux_artifacts.sh -o /cases/artifact
#   sudo ./collect_linux_artifacts.sh -a "ShellHistory SSHLogin"
#   sudo ./collect_linux_artifacts.sh -p
#
# AUTHOR: CAT Tool
# VERSION: 2.0
###############################################################################

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOSTNAME=$(hostname)
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_DIR="collected_artifacts"
PACKAGE=0
SPECIFIC_ARTIFACTS=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -a|--artifacts)
            SPECIFIC_ARTIFACTS="$2"
            shift 2
            ;;
        -p|--package)
            PACKAGE=1
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  -o, --output DIR     Output directory (default: collected_artifacts)"
            echo "  -a, --artifacts LIST Space-separated list of specific artifacts"
            echo "  -p, --package        Package collection into tar.gz"
            echo "  -h, --help          Show this help message"
            echo ""
            echo "Examples:"
            echo "  sudo $0"
            echo "  sudo $0 -o /cases/artifacts"
            echo "  sudo $0 -a "ShellHistory SSHLogin""
            echo "  sudo $0 -p"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

COLLECTION_DIR="${OUTPUT_DIR}/${HOSTNAME}_${TIMESTAMP}"
LINUX_DIR="${COLLECTION_DIR}/Linux"
COLLECTED_FILES=()
ERRORS=()

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logging function
log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")

    case "$level" in
        "INFO")
            echo -e "${CYAN}[$timestamp] [$level] $message${NC}"
            ;;
        "WARNING")
            echo -e "${YELLOW}[$timestamp] [$level] $message${NC}"
            ;;
        "ERROR")
            echo -e "${RED}[$timestamp] [$level] $message${NC}"
            ;;
        "SUCCESS")
            echo -e "${GREEN}[$timestamp] [$level] $message${NC}"
            ;;
    esac

    # Write to log file
    mkdir -p "$LINUX_DIR"
    echo "[$timestamp] [$level] $message" >> "${COLLECTION_DIR}/collection.log"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log "WARNING" "Not running as root. Some artifacts may not be accessible."
        log "WARNING" "For full collection, run: sudo $0"
    else
        log "INFO" "Running with root privileges"
    fi
}

# Copy file or directory
copy_artifact() {
    local src="$1"
    local dst="$2"
    local name="$3"

    if [[ -e "$src" ]]; then
        local dest_path="${LINUX_DIR}/${dst}"
        mkdir -p "$(dirname "$dest_path")"

        if [[ -d "$src" ]]; then
            cp -r "$src" "$dest_path"
        else
            cp "$src" "$dest_path"
        fi

        COLLECTED_FILES+=("$dest_path")
        log "INFO" "Collected $name: $src"
        return 0
    else
        log "WARNING" "Source not found for $name: $src"
        return 1
    fi
}

# Execute command and save output
run_command() {
    local cmd="$1"
    local dst="$2"
    local name="$3"

    local dest_path="${LINUX_DIR}/${dst}"
    mkdir -p "$(dirname "$dest_path")"

    if eval "$cmd" > "$dest_path" 2>&1; then
        COLLECTED_FILES+=("$dest_path")
        log "INFO" "Executed command for $name"
        return 0
    else
        log "WARNING" "Command failed for $name (may be normal)"
        return 1
    fi
}

# Find and copy files
find_and_copy() {
    local pattern="$1"
    local dst="$2"
    local name="$3"

    local dest_dir="${LINUX_DIR}/${dst}"
    mkdir -p "$dest_dir"

    local count=0
    while IFS= read -r file; do
        if [[ -f "$file" ]]; then
            cp "$file" "${dest_dir}/${name}_${count}_$(basename "$file")"
            COLLECTED_FILES+=("${dest_dir}/${name}_${count}_$(basename "$file")")
            ((count++))
        fi
    done < <(eval "$pattern" 2>/dev/null)

    if [[ $count -gt 0 ]]; then
        log "INFO" "Collected $count files for $name"
    else
        log "WARNING" "No files found for $name"
    fi
}

# Collect specific artifact
collect_artifact() {
    local name="$1"

    log "INFO" "Processing: $name"

    case "$name" in
        "Yumlog")
            for file in /var/log/yum.log /var/log/dnf.log /var/log/dnf.rpm.log; do
                if [[ -f "$file" ]]; then
                    copy_artifact "$file" "Yumlog/$(basename "$file")" "Yumlog"
                fi
            done
            ;;

        "ShellHistory")
            find_and_copy "find /home -name '.bash_history' -o -name '.zsh_history' -o -name '.sh_history' 2>/dev/null" "ShellHistory" "ShellHistory"
            ;;

        "Crontab")
            for path in /etc/crontab /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
                if [[ -e "$path" ]]; then
                    copy_artifact "$path" "Crontab/$(basename "$path")" "Crontab"
                fi
            done
            ;;

        "LastUserLogin")
            run_command "last -a" "LastUserLogin/last.txt" "LastUserLogin"
            ;;

        "AddUser")
            for file in /etc/passwd /etc/shadow /etc/group /etc/sudoers; do
                if [[ -f "$file" ]]; then
                    copy_artifact "$file" "AddUser/$(basename "$file")" "AddUser"
                fi
            done
            ;;

        "SSHLogin")
            for file in /var/log/auth.log /var/log/secure /var/log/sshd.log; do
                if [[ -f "$file" ]]; then
                    copy_artifact "$file" "SSHLogin/$(basename "$file")" "SSHLogin"
                fi
            done
            ;;

        "SudoCommands")
            run_command "(grep -i sudo /var/log/auth.log 2>/dev/null || grep -i sudo /var/log/secure 2>/dev/null || echo 'No sudo logs found')" "SudoCommands/sudo_usage.txt" "SudoCommands"
            ;;

        "Netstat")
            run_command "netstat -tulpn 2>/dev/null || netstat -tuln" "Netstat/netstat.txt" "Netstat"
            ;;

        "AuthorizedKeys")
            find_and_copy "find /home -name 'authorized_keys' 2>/dev/null" "AuthorizedKeys" "AuthorizedKeys"
            ;;

        "KnownHosts")
            find_and_copy "find /home -name 'known_hosts' 2>/dev/null" "KnownHosts" "KnownHosts"
            ;;

        "Users")
            run_command "cat /etc/passwd" "Users/passwd.txt" "Users"
            ;;

        "DockerContainers")
            run_command "(docker ps -a && docker images && docker system info) 2>/dev/null || echo 'Docker not available or permission denied'" "DockerContainers/docker_info.txt" "DockerContainers"
            ;;

        "WebShells")
            for path in /var/log/apache2 /var/log/httpd /var/log/nginx /var/www; do
                if [[ -d "$path" ]]; then
                    copy_artifact "$path" "WebShells/$(basename "$path")" "WebShells"
                fi
            done
            ;;

        "MalShells")
            find_and_copy "find /tmp /var/tmp /dev/shm -name '*.sh' -o -name '*.py' -o -name '*.pl' 2>/dev/null" "MalShells" "MalShells"
            ;;

        "TmpListing")
            run_command "ls -la /tmp /var/tmp /dev/shm 2>/dev/null" "TmpListing/tmp_listing.txt" "TmpListing"
            ;;

        "Systemd")
            for path in /etc/systemd/system /usr/lib/systemd/system /run/systemd/system; do
                if [[ -d "$path" ]]; then
                    copy_artifact "$path" "Systemd/$(basename "$path")" "Systemd"
                fi
            done
            ;;

        "PreloadCheck")
            for path in /etc/ld.so.preload /etc/ld.so.conf /etc/ld.so.conf.d; do
                if [[ -e "$path" ]]; then
                    copy_artifact "$path" "PreloadCheck/$(basename "$path")" "PreloadCheck"
                fi
            done
            ;;

        "SyslogEvents")
            for file in /var/log/syslog /var/log/messages /var/log/kern.log; do
                if [[ -f "$file" ]]; then
                    copy_artifact "$file" "SyslogEvents/$(basename "$file")" "SyslogEvents"
                fi
            done
            ;;

        "SecureEvents")
            for file in /var/log/secure /var/log/auth.log /var/log/audit/audit.log; do
                if [[ -f "$file" ]]; then
                    copy_artifact "$file" "SecureEvents/$(basename "$file")" "SecureEvents"
                fi
            done
            ;;

        "OSInfo")
            run_command "uname -a" "OSInfo/uname.txt" "OSInfo-uname"
            run_command "cat /etc/os-release" "OSInfo/os_release.txt" "OSInfo-os-release"
            run_command "hostnamectl" "OSInfo/hostnamectl.txt" "OSInfo-hostnamectl"
            run_command "lscpu" "OSInfo/lscpu.txt" "OSInfo-lscpu"
            run_command "free -h" "OSInfo/memory.txt" "OSInfo-memory"
            run_command "df -h" "OSInfo/disk.txt" "OSInfo-disk"
            run_command "uptime" "OSInfo/uptime.txt" "OSInfo-uptime"
            run_command "who" "OSInfo/who.txt" "OSInfo-who"
            run_command "w" "OSInfo/w.txt" "OSInfo-w"
            run_command "lastlog" "OSInfo/lastlog.txt" "OSInfo-lastlog"
            ;;

        *)
            log "WARNING" "Unknown artifact: $name"
            ;;
    esac
}

# Main function
main() {
    echo -e "${CYAN}==============================================${NC}"
    echo -e "${CYAN}Linux Forensic Artifact Collection${NC}"
    echo -e "${CYAN}==============================================${NC}"

    # Check root
    check_root

    # Create directories
    mkdir -p "$LINUX_DIR"
    log "INFO" "Starting Linux artifact collection..."
    log "INFO" "Collection directory: $COLLECTION_DIR"

    # Define all artifacts
    ALL_ARTIFACTS=(
        "Yumlog" "ShellHistory" "Crontab" "LastUserLogin" "AddUser"
        "SSHLogin" "SudoCommands" "Netstat" "AuthorizedKeys" "KnownHosts"
        "Users" "DockerContainers" "WebShells" "MalShells" "TmpListing"
        "Systemd" "PreloadCheck" "SyslogEvents" "SecureEvents" "OSInfo"
    )

    # Filter artifacts if specific list provided
    if [[ -n "$SPECIFIC_ARTIFACTS" ]]; then
        IFS=' ' read -r -a ARTIFACTS_TO_COLLECT <<< "$SPECIFIC_ARTIFACTS"
    else
        ARTIFACTS_TO_COLLECT=("${ALL_ARTIFACTS[@]}")
    fi

    # Collect each artifact
    for artifact in "${ARTIFACTS_TO_COLLECT[@]}"; do
        echo ""
        collect_artifact "$artifact"
    done

    # Create summary
    echo ""
    log "INFO" "Creating collection summary..."

    cat > "${COLLECTION_DIR}/Linux_collection_summary.json" << EOF
{
  "collection_timestamp": "$TIMESTAMP",
  "hostname": "$HOSTNAME",
  "os_type": "Linux",
  "total_files_collected": ${#COLLECTED_FILES[@]},
  "errors": $(printf '%s\n' "${ERRORS[@]}" | jq -R . | jq -s .),
  "collected_files": $(printf '%s\n' "${COLLECTED_FILES[@]}" | jq -R . | jq -s .),
  "collection_directory": "$COLLECTION_DIR"
}
EOF

    log "SUCCESS" "Collection complete. Summary saved."

    # Package if requested
    if [[ $PACKAGE -eq 1 ]]; then
        echo ""
        log "INFO" "Packaging collection..."

        local tar_file="${OUTPUT_DIR}/${HOSTNAME}_${TIMESTAMP}_forensics.tar.gz"

        if tar -czf "$tar_file" -C "$OUTPUT_DIR" "${HOSTNAME}_${TIMESTAMP}"; then
            log "SUCCESS" "Collection packaged: $tar_file"
        else
            log "ERROR" "Failed to create package"
        fi
    fi

    # Final summary
    echo ""
    echo -e "${GREEN}==============================================${NC}"
    echo -e "${GREEN}COLLECTION COMPLETE${NC}"
    echo -e "${GREEN}==============================================${NC}"
    echo -e "Total files collected: ${#COLLECTED_FILES[@]}"
    echo -e "Errors: ${#ERRORS[@]}"
    echo -e "Collection directory: $COLLECTION_DIR"
    if [[ $PACKAGE -eq 1 ]]; then
        echo -e "Package: ${tar_file}"
    fi
    echo -e "${GREEN}==============================================${NC}"

    # Return collection directory
    echo "$COLLECTION_DIR"
}

# Run main function
main "$@"

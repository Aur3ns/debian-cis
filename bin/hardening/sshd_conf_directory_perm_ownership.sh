#!/bin/bash
# run-shellcheck
# Ensure access to the SSH server configuration drop-in directory is configured.

set -e
set -u

# shellcheck disable=2034
HARDENING_LEVEL=1
# shellcheck disable=2034
DESCRIPTION="Check root ownership and restrictive SSH configuration directory permissions."

SSHD_CONF_DIR_PATH="/etc/ssh/sshd_config.d"
SSHD_CONF_DIR_FIX_OWNER=1
SSHD_CONF_DIR_FIX_MODE=1

check_config() {
    if [[ "$SSHD_CONF_DIR_PATH" != /* ]]; then
        crit "SSHD_CONF_DIR_PATH must be an absolute path"
        exit 128
    fi
    # A trailing slash must not cause stat to follow a final symbolic link.
    while [[ "$SSHD_CONF_DIR_PATH" != / && "$SSHD_CONF_DIR_PATH" == */ ]]; do
        SSHD_CONF_DIR_PATH=${SSHD_CONF_DIR_PATH%/}
    done
}

create_config() {
    echo 'status=audit'
    echo '# Directory to audit; other Include directories must be checked separately.'
    echo 'SSHD_CONF_DIR_PATH="/etc/ssh/sshd_config.d"'
}

audit() {
    local metadata file_type mode uid gid
    # Reset actions: a repeated audit must not retain an earlier remediation decision.
    SSHD_CONF_DIR_FIX_OWNER=1
    SSHD_CONF_DIR_FIX_MODE=1
    is_pkg_installed "openssh-server"
    if [ "$FNRET" != 0 ]; then
        ok "openssh-server is not installed - not applicable"
        return
    fi
    # stat is deliberately not dereferenced: report links instead of changing targets.
    # Use the privileged read wrapper for custom directories with protected parents.
    if ! metadata=$($SUDO_CMD stat -c '%f %a %u %g' -- "$SSHD_CONF_DIR_PATH" 2>/dev/null); then
        crit "Cannot read metadata for $SSHD_CONF_DIR_PATH; review the SSH Include configuration"
        return
    fi
    read -r file_type mode uid gid <<<"$metadata"
    if (((16#$file_type & 0170000) != 0040000)); then
        crit "$SSHD_CONF_DIR_PATH is not a directory or is a symbolic link; review manually"
        return
    fi
    if [ "$uid" = 0 ] && [ "$gid" = 0 ]; then
        ok "$SSHD_CONF_DIR_PATH is owned by root:root"
    else
        crit "$SSHD_CONF_DIR_PATH must be owned by root:root"
        SSHD_CONF_DIR_FIX_OWNER=0
    fi
    if (((8#$mode & 0077) == 0)); then
        ok "$SSHD_CONF_DIR_PATH has no group or other permissions"
    else
        crit "$SSHD_CONF_DIR_PATH grants group or other permissions"
        SSHD_CONF_DIR_FIX_MODE=0
    fi
}

apply() {
    if [ "$SSHD_CONF_DIR_FIX_OWNER" = 0 ]; then
        info "Setting root:root ownership on $SSHD_CONF_DIR_PATH"
        chown --no-dereference root:root -- "$SSHD_CONF_DIR_PATH"
    fi
    if [ "$SSHD_CONF_DIR_FIX_MODE" = 0 ]; then
        info "Removing group and other permissions from $SSHD_CONF_DIR_PATH"
        chmod go-rwx -- "$SSHD_CONF_DIR_PATH"
    fi
}

# Source Root Dir Parameter
if [ -r /etc/default/cis-hardening ]; then
    # shellcheck source=../../debian/default
    . /etc/default/cis-hardening
fi
if [ -z "${CIS_LIB_DIR:-}" ]; then
    echo "Cannot source CIS_LIB_DIR, aborting."
    exit 128
fi
# shellcheck source=../../lib/main.sh
. "${CIS_LIB_DIR}/main.sh"

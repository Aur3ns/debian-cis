#!/bin/bash

# run-shellcheck
#
# CIS Debian Hardening
#

#
# Ensure auditing for processes that start prior to auditd is enabled (Scored)
#

set -e # One error, it's over
set -u # One variable unset, it's over

# shellcheck disable=2034
HARDENING_LEVEL=4
# shellcheck disable=2034
DESCRIPTION="Enable auditing for processes that start prior to auditd."

FILE='/etc/default/grub'
GRUB_PARAMS='GRUB_CMDLINE_LINUX GRUB_CMDLINE_LINUX_DEFAULT'
GRUB_VALUE='audit=1'

# 0 = true / success, 1 = false / failure
AUDIT_BOOTLOADER_FILE_EXISTS=1

# 0 = compliant, 1 = non-compliant
AUDIT_BOOTLOADER_AUDIT_ENABLED=1
AUDIT_BOOTLOADER_TARGET_PARAM='GRUB_CMDLINE_LINUX'

# Append audit=1 without discarding existing kernel command-line arguments.
audit_bootloader_append_audit() {
    local param=$1 line raw value quote replacement tmp
    line=$(grep -m1 "^${param}=" "$FILE") || return 1
    raw=${line#*=}
    value=$raw
    quote=''
    if [[ "$raw" == \"*\" && "$raw" == *\" ]]; then
        quote='"'
        value=${raw#\"}
        value=${value%\"}
    elif [[ "$raw" == \'*\' && "$raw" == *\' ]]; then
        quote="'"
        value=${raw#\'}
        value=${value%\'}
    fi

    if [ -n "$value" ]; then
        value="$value $GRUB_VALUE"
    else
        value="$GRUB_VALUE"
    fi
    if [ -n "$quote" ]; then
        replacement="${param}=${quote}${value}${quote}"
    else
        replacement="${param}=\"${value}\""
    fi

    backup_file "$FILE"
    tmp=$(mktemp)
    while IFS= read -r line || [ -n "$line" ]; do
        if [[ "$line" == "${param}="* ]]; then
            printf '%s\n' "$replacement"
        else
            printf '%s\n' "$line"
        fi
    done <"$FILE" >"$tmp"
    cat "$tmp" >"$FILE"
    rm -f -- "$tmp"
    FNRET=0
}

# This function will be called if the script status is on enabled / audit mode
audit() {
    AUDIT_BOOTLOADER_FILE_EXISTS=1
    AUDIT_BOOTLOADER_AUDIT_ENABLED=1
    AUDIT_BOOTLOADER_TARGET_PARAM='GRUB_CMDLINE_LINUX'
    does_file_exist "$FILE"
    if [ "$FNRET" != 0 ]; then
        crit "$FILE does not exist"
    else
        AUDIT_BOOTLOADER_FILE_EXISTS=0
        ok "$FILE exists, checking configuration"
        for GRUB_PARAM in $GRUB_PARAMS; do
            does_pattern_exist_in_file "$FILE" "^$GRUB_PARAM="
            if [ "$FNRET" = 0 ]; then
                AUDIT_BOOTLOADER_TARGET_PARAM="$GRUB_PARAM"
            fi

            PATTERN="^$GRUB_PARAM=.*$GRUB_VALUE"
            debug "$GRUB_PARAM should be set to $GRUB_VALUE"
            does_pattern_exist_in_file "$FILE" "$PATTERN"
            if [ "$FNRET" != 0 ]; then
                info "$PATTERN is not present in $FILE"
            else
                ok "$PATTERN is present in $FILE"
                AUDIT_BOOTLOADER_AUDIT_ENABLED=0
            fi
        done

        if [ "$AUDIT_BOOTLOADER_AUDIT_ENABLED" != 0 ]; then
            crit "audit=1 is not present in GRUB_CMDLINE_LINUX or GRUB_CMDLINE_LINUX_DEFAULT in $FILE"
        fi
    fi
}

# This function will be called if the script status is on enabled mode
apply() {
    if [ "$AUDIT_BOOTLOADER_AUDIT_ENABLED" = 0 ]; then
        ok "audit=1 already configured in GRUB_CMDLINE_LINUX or GRUB_CMDLINE_LINUX_DEFAULT"
        return
    fi

    if [ "$AUDIT_BOOTLOADER_FILE_EXISTS" != 0 ]; then
        warn "$FILE does not exist, cannot update bootloader parameters"
        return
    fi

    debug "$AUDIT_BOOTLOADER_TARGET_PARAM should contain $GRUB_VALUE"
    does_pattern_exist_in_file "$FILE" "^$AUDIT_BOOTLOADER_TARGET_PARAM="
    if [ "$FNRET" != 0 ]; then
        info "Parameter $AUDIT_BOOTLOADER_TARGET_PARAM seems absent from $FILE, adding at the end"
        add_end_of_file "$FILE" "$AUDIT_BOOTLOADER_TARGET_PARAM=\"$GRUB_VALUE\""
    else
        info "Parameter $AUDIT_BOOTLOADER_TARGET_PARAM is present but missing $GRUB_VALUE -- Appending it"
        audit_bootloader_append_audit "$AUDIT_BOOTLOADER_TARGET_PARAM"
    fi
}

# This function will check config parameters required
check_config() {
    :
}

# Source Root Dir Parameter
if [ -r /etc/default/cis-hardening ]; then
    # shellcheck source=../../debian/default
    . /etc/default/cis-hardening
fi
if [ -z "$CIS_LIB_DIR" ]; then
    echo "There is no /etc/default/cis-hardening file nor cis-hardening directory in current environment."
    echo "Cannot source CIS_LIB_DIR variable, aborting."
    exit 128
fi

# Main function, will call the proper functions given the configuration (audit, enabled, disabled)
if [ -r "${CIS_LIB_DIR}"/main.sh ]; then
    # shellcheck source=../../lib/main.sh
    . "${CIS_LIB_DIR}"/main.sh
else
    echo "Cannot find main.sh, have you correctly defined your root directory? Current value is $CIS_LIB_DIR in /etc/default/cis-hardening"
    exit 128
fi

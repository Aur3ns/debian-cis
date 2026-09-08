# shellcheck shell=bash
# run-shellcheck
test_audit() {
    if ! dpkg-query -W -f='${Status}' openssh-server 2>/dev/null | grep -q 'install ok installed'; then
        describe "Absent openssh-server is not applicable"
        register_test retvalshouldbe 0
        # shellcheck disable=2154
        run absent "${CIS_CHECKS_DIR}/${script}.sh" --audit-all
        return
    fi
    local fixture config backup apply_result=0
    fixture=$(mktemp -d)
    chmod 755 "$fixture"
    # shellcheck disable=2154
    config="${CIS_CONF_DIR}/conf.d/${script}.cfg"
    backup="${fixture}/original.cfg"
    if [ ! -f "$config" ]; then
        "${CIS_CHECKS_DIR}/${script}.sh" --create-config-files-only
    fi
    cp -p "$config" "$backup"
    printf 'status=audit\nSSHD_CONF_DIR_PATH="%s/drop-ins"\n' "$fixture" >"$config"
    mkdir "${fixture}/drop-ins"
    chmod 755 "${fixture}/drop-ins"
    describe "Reject group and other access without changing the directory"
    register_test retvalshouldbe 1
    run noncompliant "${CIS_CHECKS_DIR}/${script}.sh" --audit-all

    describe "Apply restrictive permissions"
    sed -i 's/status=audit/status=enabled/' "$config"
    "${CIS_CHECKS_DIR}/${script}.sh" --apply || apply_result=$?
    # The framework returns the initial failed audit even after successful apply.
    if [ "$apply_result" -gt 1 ]; then
        cp -p "$backup" "$config"
        rm -rf -- "$fixture"
        return "$apply_result"
    fi
    register_test retvalshouldbe 0
    run resolved "${CIS_CHECKS_DIR}/${script}.sh" --audit-all

    describe "Accept permissions more restrictive than 0700"
    chmod 500 "${fixture}/drop-ins"
    register_test retvalshouldbe 0
    run restrictive "${CIS_CHECKS_DIR}/${script}.sh" --audit-all

    describe "Reject a missing directory without creating configuration"
    rmdir "${fixture}/drop-ins"
    register_test retvalshouldbe 1
    run missing "${CIS_CHECKS_DIR}/${script}.sh" --audit-all

    describe "Reject a symbolic link for manual review"
    mkdir "${fixture}/target"
    ln -s "${fixture}/target" "${fixture}/drop-ins"
    register_test retvalshouldbe 1
    run symlink "${CIS_CHECKS_DIR}/${script}.sh" --audit-all

    cp -p "$backup" "$config"
    rm -rf -- "$fixture"
}

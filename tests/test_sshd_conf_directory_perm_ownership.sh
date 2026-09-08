#!/bin/bash
# run-shellcheck
# Standalone regression test. Run as root; all changes stay inside a temporary directory.
set -eu
if [ "$EUID" -ne 0 ]; then
    echo "Run as root to test ownership changes in the temporary fixture."
    exit 77
fi
repo=$(cd "$(dirname "$0")/.." && pwd)
fixture=$(mktemp -d)
trap 'rm -rf -- "$fixture"' EXIT
export CIS_LIB_DIR="${repo}/lib"
export CIS_CONF_DIR="${fixture}/config"
export CIS_TMP_DIR="${fixture}/tmp"
export CIS_CHECKS_DIR="${repo}/bin/hardening"
export CIS_VERSIONS_DIR="${repo}/versions"
mkdir -p "$CIS_CONF_DIR/conf.d" "$CIS_TMP_DIR"
chmod 755 "$fixture"
printf 'LOGLEVEL=info\nBACKUPDIR="%s/backups"\n' "$CIS_TMP_DIR" >"$CIS_CONF_DIR/hardening.cfg"
script="${CIS_CHECKS_DIR}/sshd_conf_directory_perm_ownership.sh"
config="${CIS_CONF_DIR}/conf.d/sshd_conf_directory_perm_ownership.cfg"
target="${fixture}/drop-ins"
printf 'status=audit\nSSHD_CONF_DIR_PATH="%s"\n' "$target" >"$config"
check() {
    local expected="$1" label="$2" result=0
    "$script" --audit-all >"${fixture}/output" 2>&1 || result=$?
    if [ "$result" != "$expected" ]; then
        cat "${fixture}/output"
        echo "FAIL: $label (expected $expected, got $result)"
        exit 1
    fi
    echo "PASS: $label"
}
fix() {
    local result=0
    sed -i 's/status=audit/status=enabled/' "$config"
    "$script" --apply >"${fixture}/output" 2>&1 || result=$?
    # Framework reports the initial audit's failures even after remediation.
    if [ "$result" -gt 1 ]; then
        cat "${fixture}/output"
        exit 1
    fi
}
mkdir "$target"
chmod 755 "$target"
check 1 '0755 rejected'
[ "$(stat -c %a "$target")" = 755 ]
fix
check 0 'remediation produces a compliant directory'
[ "$(stat -c %a "$target")" = 700 ]
printf 'keep this content\n' >"$target/example.conf"
chmod 644 "$target/example.conf"
chmod 750 "$target"
fix
[ "$(stat -c %a "$target/example.conf")" = 644 ]
[ "$(cat "$target/example.conf")" = 'keep this content' ]
echo 'PASS: remediation is not recursive and preserves file contents'
chmod 500 "$target"
check 0 '0500 accepted'
fix
[ "$(stat -c %a "$target")" = 500 ]
echo 'PASS: compliant stricter permissions preserved'
chmod 700 "$target"
chown 65534:65534 "$target"
check 1 'non-root ownership rejected'
fix
check 0 'ownership repaired'
[ "$(stat -c '%u:%g' "$target")" = '0:0' ]
# Read-only audit must also work for an unprivileged account.
runuser -u nobody -- "$script" --audit-all >"${fixture}/unprivileged" 2>&1
[ "$(stat -c %a "$target")" = 700 ]
echo 'PASS: unprivileged audit can inspect root-owned 0700 directory metadata'
chmod 755 "$target"
sed -i 's/status=enabled/status=disabled/' "$config"
result=0
"$script" --audit >"${fixture}/output" 2>&1 || result=$?
[ "$result" = 2 ]
[ "$(stat -c %a "$target")" = 755 ]
echo 'PASS: disabled configuration is respected by --audit'
sed -i 's/status=disabled/status=audit/' "$config"
result=0
"$script" --apply >"${fixture}/output" 2>&1 || result=$?
[ "$result" = 1 ]
[ "$(stat -c %a "$target")" = 755 ]
echo 'PASS: --apply does not enable an audit-only configuration'
mkdir "${fixture}/version"
ln -s "$script" "${fixture}/version/test_directory.sh"
result=0
"${fixture}/version/test_directory.sh" --audit-all >"${fixture}/output" 2>&1 || result=$?
[ "$result" = 1 ]
[ -L "${CIS_CONF_DIR}/conf.d/test_directory.cfg" ]
echo 'PASS: versioned invocation uses the canonical configuration'
# Exercise selection through the real launcher, not only the direct script.
"${repo}/bin/hardening.sh" --audit-all --only 99.5.2.9 --summary-json >"${fixture}/summary"
grep -q '"run_checks": 1' "${fixture}/summary"
grep -q '"passed_checks": 0' "${fixture}/summary"
echo 'PASS: default launcher selects the new check exactly once'
rm "$target/example.conf"
rmdir "$target"
check 1 'missing directory rejected'
fix
[ ! -e "$target" ]
echo 'PASS: no directory created from an invalid Include path'
printf 'do not replace\n' >"$target"
check 1 'regular file rejected'
fix
[ "$(cat "$target")" = 'do not replace' ]
rm "$target"
mkdir "${fixture}/linked-target"
chmod 755 "${fixture}/linked-target"
ln -s "${fixture}/linked-target" "$target"
check 1 'symbolic link rejected for manual review'
fix
[ -L "$target" ]
[ "$(stat -c %a "${fixture}/linked-target")" = 755 ]
echo 'PASS: symbolic link target unchanged'

printf 'status=enabled\nSSHD_CONF_DIR_PATH="%s/"\n' "$target" >"$config"
check 1 'trailing slash does not bypass symbolic link rejection'
fix
[ "$(stat -c %a "${fixture}/linked-target")" = 755 ]
echo 'PASS: symbolic link with trailing slash is not remediated'

# Exercise unavailable prerequisites without changing installed system packages.
(
    # Source only function definitions; the production framework is tested above.
    # shellcheck source=/dev/null
    . <(sed '/^# Source Root Dir Parameter/,$d' "$script")
    failures=0
    ok() { :; }
    crit() { failures=$((failures + 1)); }
    info() { :; }
    is_pkg_installed() { FNRET=1; }
    SSHD_CONF_DIR_PATH="${fixture}/linked-target"
    audit
    [ "$failures" = 0 ]
    apply
    [ "$(stat -c %a "$SSHD_CONF_DIR_PATH")" = 755 ]
    echo 'PASS: absent package produces no remediation'
    # shellcheck disable=SC2034
    is_pkg_installed() { FNRET=0; }
    # shellcheck disable=SC2034
    SUDO_CMD=false
    audit
    [ "$failures" = 1 ]
    apply
    [ "$(stat -c %a "$SSHD_CONF_DIR_PATH")" = 755 ]
    echo 'PASS: unreadable metadata fails without remediation'
)

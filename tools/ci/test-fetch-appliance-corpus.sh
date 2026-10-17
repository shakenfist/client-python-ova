#!/bin/bash

# Tests for tools/ci/fetch-appliance-corpus.sh, offline.
#
# The first cases run the script with one required input missing or
# wrong, and assert that it exits non-zero, says why, and never prints
# the token it was given. Those guards all run before the script touches
# git, and that is asserted too.
#
# The later cases put a tree at the agreed path and test what the
# script does with it: that it refuses a tree whose repository
# configuration carries a key a clone does not, before any git command
# but the configuration reads; that it fails, without printing the
# token, when the token turns up under .git after the authenticated
# commands; that it removes a git-lfs log that recorded the token, and
# any log an earlier run left, before the first authenticated command;
# and that it refuses a git too old to honour the configuration
# variables it relies on.
# There, `git` is a stub that passes configuration reads through to the
# real git and stands in for the rest, so that nothing needs the
# network, the real token or the private repository. What the stub
# cannot show -- that the real fetch and LFS pull authenticate -- is the
# CI job's test.
#
# Every case runs under `env -i`, so a TESTDATA_* variable in the
# caller's environment cannot change what a case means, and with a PATH
# of stubs. Cases needing a tree use TESTDATA_CONTRACT_CACHE to move the
# agreed path into a throwaway directory, never the real one.

set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
script="${root}/tools/ci/fetch-appliance-corpus.sh"
# A value no output should contain. Not credential-shaped, so that
# secret scanners have nothing to say about this file.
sentinel='sentinel-value-for-the-fetch-guard-tests'

scratch=$(mktemp -d)
trap 'rm -rf "${scratch}"' EXIT

# PATH directories: none, git alone, and both. All of them stubs.
mkdir -p "${scratch}/path-empty" "${scratch}/path-git" "${scratch}/path-both"
for stub in "${scratch}/path-git/git" "${scratch}/path-both/git" \
            "${scratch}/path-both/git-lfs"; do
    printf '#!/bin/sh\necho called >> "%s/stub-calls"\nexit 99\n' \
        "${scratch}" > "${stub}"
    chmod +x "${stub}"
done

# A directory to stand in for the agreed path: it exists, and has no
# .git, which is the case the script must refuse.
mkdir -p "${scratch}/cache"

failures=0

# expect_failure NAME EXPECTED-TEXT ENV-ASSIGNMENT...
#
# Runs the script with exactly the given environment (plus HOME), and
# checks the exit status, the message, and that the sentinel and the
# stubs stayed out of it.
expect_failure() {
    local name=$1 expected=$2
    shift 2
    local output status=0
    output=$(env -i HOME="${scratch}" "$@" "${BASH}" "${script}" 2>&1) || status=$?

    local problems=()
    if [ "${status}" = 0 ]; then
        problems+=("exited 0")
    fi
    if [[ "${output}" != *"${expected}"* ]]; then
        problems+=("did not say '${expected}'")
    fi
    if [[ "${output}" == *"${sentinel}"* ]]; then
        problems+=("printed the token")
    fi
    if [ -e "${scratch}/stub-calls" ]; then
        problems+=("ran git or git-lfs before refusing")
        rm -f "${scratch}/stub-calls"
    fi
    if [ -e "${scratch}/cache/.git" ]; then
        problems+=("created ${scratch}/cache/.git")
    fi

    if [ "${#problems[@]}" = 0 ]; then
        echo "ok: ${name}"
    else
        echo "FAIL: ${name}: $(IFS=';'; echo "${problems[*]}")"
        echo "  output was: ${output//${sentinel}/<token>}"
        failures=$((failures + 1))
    fi
}

expect_failure 'no git on PATH' \
    'git is not installed' \
    PATH="${scratch}/path-empty" TESTDATA_TOKEN="${sentinel}"

expect_failure 'no git-lfs on PATH' \
    'git-lfs is not installed' \
    PATH="${scratch}/path-git" TESTDATA_TOKEN="${sentinel}"

expect_failure 'TESTDATA_TOKEN unset' \
    'TESTDATA_TOKEN is not set' \
    PATH="${scratch}/path-both"

expect_failure 'TESTDATA_TOKEN empty' \
    'TESTDATA_TOKEN is not set' \
    PATH="${scratch}/path-both" TESTDATA_TOKEN=''

expect_failure 'TESTDATA_USER with a colon' \
    'TESTDATA_USER contains a colon' \
    PATH="${scratch}/path-both" TESTDATA_TOKEN="${sentinel}" \
    TESTDATA_USER='deploy:token'

expect_failure 'TESTDATA_CACHE is not the agreed path' \
    'not the agreed /srv/ci/cached/instar-testdata' \
    PATH="${scratch}/path-both" TESTDATA_TOKEN="${sentinel}" \
    TESTDATA_CACHE="${scratch}/cache"

# The seam alone must not satisfy the check: TESTDATA_CACHE still
# defaults to the real path, which now disagrees with the moved one.
expect_failure 'the agreed path moved but TESTDATA_CACHE left alone' \
    "not the agreed ${scratch}/cache" \
    PATH="${scratch}/path-both" TESTDATA_TOKEN="${sentinel}" \
    TESTDATA_CONTRACT_CACHE="${scratch}/cache"

expect_failure 'no tree at the agreed path' \
    "runner with the 'instar' label" \
    PATH="${scratch}/path-both" TESTDATA_TOKEN="${sentinel}" \
    TESTDATA_CONTRACT_CACHE="${scratch}/cache" \
    TESTDATA_CACHE="${scratch}/cache"

# The seam is for this file only. A workflow that set it could point the
# agreed path anywhere.
if grep -rqF 'TESTDATA_CONTRACT_CACHE' "${root}/.github"; then
    echo "FAIL: something under .github/ sets TESTDATA_CONTRACT_CACHE"
    failures=$((failures + 1))
else
    echo "ok: nothing under .github/ sets TESTDATA_CONTRACT_CACHE"
fi

# Shapes that would put the credential somewhere it outlives the
# command, or print it: a remote URL holding it, and shell tracing.
if grep -nE 'set-url|oauth2:\$\{|@gitlab' "${script}" >/dev/null; then
    echo "FAIL: the script builds a credentialed URL"
    failures=$((failures + 1))
else
    echo "ok: the script builds no credentialed URL"
fi
if grep -nE '^[[:space:]]*set[[:space:]]+-[a-zA-Z]*x' "${script}" >/dev/null; then
    echo "FAIL: the script turns on shell tracing"
    failures=$((failures + 1))
else
    echo "ok: the script does not turn on shell tracing"
fi

# The cases below need a tree at the agreed path, and a git that can
# read configuration. They run the stub in path-run: it passes `git
# config` through to the real git, and otherwise appends the
# subcommand's name to run-calls and does what the file stub-mode says,
# which is nothing, or planting the token somewhere the script must find
# it. The real git is used to set the trees up too, with no system or
# global configuration, so that the caller's cannot add to them.
real_git=$(command -v git)
mkdir -p "${scratch}/path-run"
cat > "${scratch}/path-run/git" <<EOF
#!/bin/sh
dir=
if [ "\$1" = -C ]; then
    dir=\$2
    shift 2
fi
if [ "\$1" = config ]; then
    if [ -n "\${dir}" ]; then
        exec "${real_git}" -C "\${dir}" "\$@"
    fi
    exec "${real_git}" "\$@"
fi
echo "\$1" >> "${scratch}/run-calls"
if [ -n "\$(find "\${dir}/.git/lfs/logs" -type f 2>/dev/null)" ]; then
    echo "\$1" >> "${scratch}/logs-seen"
fi
case "\$1:\$(cat "${scratch}/stub-mode")" in
    fetch:config)
        printf '[remote "copy"]\\n\\turl = https://oauth2:%s@example.invalid/x.git\\n' \\
            "${sentinel}" >> "\${dir}/.git/config" ;;
    fetch:description)
        printf '%s\\n' "${sentinel}" > "\${dir}/.git/description" ;;
    lfs:lfs-log)
        mkdir -p "\${dir}/.git/lfs/logs"
        printf 'GIT_CONFIG_VALUE_1=%s\\n' "${sentinel}" > "\${dir}/.git/lfs/logs/x.log" ;;
esac
exit 0
EOF
printf '#!/bin/sh\nexit 0\n' > "${scratch}/path-run/git-lfs"
chmod +x "${scratch}/path-run/git" "${scratch}/path-run/git-lfs"

setup_git() {
    env -i HOME="${scratch}" GIT_CONFIG_NOSYSTEM=1 "${real_git}" "$@"
}

# make_tree NAME: a repository at ${scratch}/NAME configured as the
# fleet's disk build leaves it, with one appliance under the corpus
# directory that is not an LFS pointer.
make_tree() {
    local tree="${scratch}/$1"
    setup_git init --quiet "${tree}"
    setup_git -C "${tree}" config remote.origin.url \
        'https://gitlab.home.stillhq.com/private/instar-testdata.git'
    setup_git -C "${tree}" config remote.origin.fetch '+refs/heads/main:refs/remotes/origin/main'
    setup_git -C "${tree}" config branch.main.remote origin
    setup_git -C "${tree}" config branch.main.merge refs/heads/main
    setup_git -C "${tree}" config lfs.repositoryformatversion 0
    setup_git -C "${tree}" config \
        'lfs.https://gitlab.home.stillhq.com/private/instar-testdata.git/info/lfs.access' basic
    setup_git -C "${tree}" config filter.lfs.process 'git-lfs filter-process'
    setup_git -C "${tree}" config filter.lfs.smudge 'git-lfs smudge -- %f'
    setup_git -C "${tree}" config filter.lfs.clean 'git-lfs clean -- %f'
    setup_git -C "${tree}" config filter.lfs.required true
    mkdir -p "${tree}/downloaded/ova"
    printf 'an appliance\n' > "${tree}/downloaded/ova/a.ova"
    printf '{"kind": "whole"}\n' > "${tree}/downloaded/ova/a.provenance.json"
}

# run_tree NAME MODE [STUBS]: runs the script on the tree NAME with the
# run stub in MODE, setting output and status. STUBS is a PATH directory
# to use in place of path-run.
run_tree() {
    local tree="${scratch}/$1"
    printf '%s\n' "$2" > "${scratch}/stub-mode"
    rm -f "${scratch}/run-calls" "${scratch}/logs-seen"
    status=0
    output=$(env -i HOME="${scratch}" PATH="${3:-${scratch}/path-run}:/usr/bin:/bin" \
        TESTDATA_TOKEN="${sentinel}" TESTDATA_CONTRACT_CACHE="${tree}" TESTDATA_CACHE="${tree}" \
        "${BASH}" "${script}" 2>&1) || status=$?
}

# The header carries the token base64-encoded, so that form must not be
# printed either.
encoded=$(printf 'oauth2:%s' "${sentinel}" | base64 -w0)

# report NAME PROBLEM...: ok when no problem was given.
report() {
    local name=$1
    shift
    if [ "$#" = 0 ]; then
        echo "ok: ${name}"
    else
        echo "FAIL: ${name}: $(IFS=';'; echo "$*")"
        output=${output//${sentinel}/<token>}
        echo "  output was: ${output//${encoded}/<encoded token>}"
        failures=$((failures + 1))
    fi
}

# expect_refused_config NAME KEY-PRINTED KEY VALUE [KEY VALUE...]
#
# A fleet-like tree with the given keys added must be refused before
# anything but a configuration read, naming KEY-PRINTED, and without
# printing the sentinel, which each case puts in a value or a name.
expect_refused_config() {
    local name=$1 printed=$2 tree
    shift 2
    tree="config-$(printf '%s' "${name}" | tr -c 'a-z0-9' '-')"
    make_tree "${tree}"
    while [ "$#" -gt 0 ]; do
        setup_git -C "${scratch}/${tree}" config --add "$1" "$2"
        shift 2
    done
    run_tree "${tree}" none

    local problems=()
    if [ "${status}" = 0 ]; then
        problems+=("exited 0")
    fi
    if [[ "${output}" != *"keys a clone of instar-testdata does not carry"* ]]; then
        problems+=("did not refuse the configuration")
    fi
    if [[ "${output}" != *"${printed}"* ]]; then
        problems+=("did not name ${printed}")
    fi
    if [[ "${output}" == *"${sentinel}"* || "${output}" == *"${encoded}"* ]]; then
        problems+=("printed a value or the token")
    fi
    if [ -e "${scratch}/run-calls" ]; then
        problems+=("ran git $(paste -sd ' ' "${scratch}/run-calls") before refusing")
    fi
    report "${name}" "${problems[@]}"
}

expect_refused_config 'a hooks path in the configuration' \
    'core.hookspath' core.hooksPath "/tmp/${sentinel}"
expect_refused_config 'an include in the configuration' \
    'include.path' include.path "/tmp/${sentinel}"
expect_refused_config 'a conditional include in the configuration' \
    'includeif.gitdir:/.path' 'includeIf.gitdir:/.path' "/tmp/${sentinel}"
expect_refused_config 'two keys refused at once' \
    'core.hookspath, include.path' include.path "/tmp/${sentinel}" core.hooksPath "/tmp/${sentinel}"
expect_refused_config 'an LFS filter that is not git-lfs' \
    'filter.lfs.smudge' filter.lfs.smudge "${sentinel} -- %f"
expect_refused_config 'an LFS filter given a second value' \
    'filter.lfs.process' filter.lfs.process "${sentinel}"
expect_refused_config 'an HTTP setting in the configuration' \
    'http.proxy' http.proxy "http://${sentinel}.invalid/"
expect_refused_config 'an LFS endpoint with a password in its URL' \
    'lfs.https://<userinfo>@gitlab.home.stillhq.com/x.git/info/lfs.access' \
    "lfs.https://oauth2:${sentinel}@gitlab.home.stillhq.com/x.git/info/lfs.access" basic

# A configuration in config.worktree is checked as well.
make_tree config-worktree
printf '[core]\n\tfsmonitor = /tmp/%s\n' "${sentinel}" > "${scratch}/config-worktree/.git/config.worktree"
run_tree config-worktree none
problems=()
if [ "${status}" = 0 ] || [[ "${output}" != *'core.fsmonitor'* ]]; then
    problems+=("did not refuse core.fsmonitor in config.worktree")
fi
if [[ "${output}" == *"${sentinel}"* ]]; then
    problems+=("printed a value")
fi
if [ -e "${scratch}/run-calls" ]; then
    problems+=("ran git before refusing")
fi
report 'a key in config.worktree' "${problems[@]}"

# expect_credential_found NAME MODE: the stub plants the token in .git
# during the authenticated commands; the script must fail, say so, and
# not print it.
expect_credential_found() {
    local name=$1 mode=$2 tree="found-$2"
    make_tree "${tree}"
    run_tree "${tree}" "${mode}"
    local problems=()
    if [ "${status}" = 0 ]; then
        problems+=("exited 0")
    fi
    if [[ "${output}" != *'The credential was found'* ]]; then
        problems+=("did not report the credential")
    fi
    if [[ "${output}" == *"${sentinel}"* || "${output}" == *"${encoded}"* ]]; then
        problems+=("printed the token")
    fi
    if ! grep -qx fetch "${scratch}/run-calls" 2>/dev/null; then
        problems+=("never reached the fetch")
    fi
    report "${name}" "${problems[@]}"
}

expect_credential_found 'the token written to .git/config' config
expect_credential_found 'the token written to .git/description' description

# A git-lfs log holding the token is removed with a warning, and the run
# otherwise succeeds: nothing else recorded it.
make_tree lfs-log
run_tree lfs-log lfs-log
problems=()
if [ "${status}" != 0 ]; then
    problems+=("exited ${status}")
fi
if [ -e "${scratch}/lfs-log/.git/lfs/logs/x.log" ]; then
    problems+=("left the log in place")
fi
if [[ "${output}" != *'Removed 1 git-lfs error log(s)'* ]]; then
    problems+=("did not warn about the log")
fi
if [[ "${output}" == *"${sentinel}"* || "${output}" == *"${encoded}"* ]]; then
    problems+=("printed the token")
fi
if [[ "${output}" != *'Appliance corpus ready: 1 appliances.'* ]]; then
    problems+=("did not finish")
fi
if [ "$(paste -sd ' ' "${scratch}/run-calls" 2>/dev/null)" != 'fetch reset clean lfs' ]; then
    problems+=("ran '$(paste -sd ' ' "${scratch}/run-calls" 2>/dev/null)', not 'fetch reset clean lfs'")
fi
report 'a git-lfs log holding the token' "${problems[@]}"

# A git-lfs log left by an earlier run is removed before any
# authenticated command, whatever it holds: here, nothing this run's
# token would match, as with a log from before the token was rotated.
make_tree stale-log
mkdir -p "${scratch}/stale-log/.git/lfs/logs"
printf 'GIT_CONFIG_VALUE_1=an-earlier-token\n' > "${scratch}/stale-log/.git/lfs/logs/old.log"
run_tree stale-log none
problems=()
if [ "${status}" != 0 ]; then
    problems+=("exited ${status}")
fi
if [ -e "${scratch}/stale-log/.git/lfs/logs/old.log" ]; then
    problems+=("left the log in place")
fi
if [ -e "${scratch}/logs-seen" ]; then
    problems+=("ran git $(paste -sd ' ' "${scratch}/logs-seen") with the log still there")
fi
if [[ "${output}" == *"${sentinel}"* || "${output}" == *"${encoded}"* ]]; then
    problems+=("printed the token")
fi
report 'a git-lfs log from an earlier run' "${problems[@]}"

# expect_old_git NAME UNSET...: a git that ignores the given environment
# variables, as one older than 2.32 does, must be refused before it is
# run on the tree.
expect_old_git() {
    local name=$1 stubs tree
    shift
    stubs="${scratch}/path-old-$(printf '%s' "${name}" | tr -c 'a-z0-9' '-')"
    tree="old-$(printf '%s' "${name}" | tr -c 'a-z0-9' '-')"
    mkdir -p "${stubs}"
    # The stub's own variables are written for it to expand, not this shell.
    # shellcheck disable=SC2016
    {
        printf '#!/bin/sh\n'
        printf 'sub=$1; [ "$1" = -C ] && sub=$3\n'
        printf '[ "${sub}" = config ] || echo "${sub}" >> "%s/run-calls"\n' "${scratch}"
        printf 'exec env'
        printf ' -u %s' "$@"
        printf ' "%s" "$@"\n' "${real_git}"
    } > "${stubs}/git"
    printf '#!/bin/sh\nexit 0\n' > "${stubs}/git-lfs"
    chmod +x "${stubs}/git" "${stubs}/git-lfs"
    make_tree "${tree}"
    run_tree "${tree}" none "${stubs}"
    local problems=()
    if [ "${status}" = 0 ]; then
        problems+=("exited 0")
    fi
    if [[ "${output}" != *'git 2.32 or later is required'* ]]; then
        problems+=("did not refuse the git")
    fi
    if [[ "${output}" == *"${sentinel}"* || "${output}" == *"${encoded}"* ]]; then
        problems+=("printed the token")
    fi
    if [ -e "${scratch}/run-calls" ]; then
        problems+=("ran git $(paste -sd ' ' "${scratch}/run-calls") before refusing")
    fi
    report "${name}" "${problems[@]}"
}

expect_old_git 'a git that ignores GIT_CONFIG_COUNT and GIT_CONFIG_GLOBAL' \
    GIT_CONFIG_COUNT GIT_CONFIG_GLOBAL
expect_old_git 'a git that ignores GIT_CONFIG_GLOBAL alone' GIT_CONFIG_GLOBAL

if [ "${failures}" != 0 ]; then
    echo "${failures} case(s) failed" >&2
    exit 1
fi
echo "All cases passed."

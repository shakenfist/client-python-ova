#!/bin/bash

# Tests for tools/ci/fetch-appliance-corpus.sh's input guards.
#
# Each case runs the script with one required input missing or wrong,
# and asserts that it exits non-zero, says why, and never prints the
# token it was given. Nothing here needs the network, the real token or
# the runner fleet's testdata disk: the guards all run before the script
# touches git, and that is asserted too. The case that needs a tree at
# the agreed path uses TESTDATA_CONTRACT_CACHE to move the agreed path
# into a throwaway directory, never the real one.
#
# What this does not test is everything after the guards -- the fetch,
# the LFS pull and the credential search -- because each of those needs
# the private repository. The CI job that runs the script is their test.
#
# Every case runs under `env -i`, so a TESTDATA_* variable in the
# caller's environment cannot change what a case means, and with a PATH
# of stubs: `git` and `git-lfs` here are scripts that record being run
# and fail. A guard that let the script reach git would show up as a
# record, not as a network call.

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

if [ "${failures}" != 0 ]; then
    echo "${failures} case(s) failed" >&2
    exit 1
fi
echo "All cases passed."

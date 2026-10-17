#!/bin/bash

# Bring the appliance corpus -- downloaded/ova/ in the private
# instar-testdata repository -- up to date on a CI runner, and tell later
# steps where it is.
#
# THE CACHE. This runs only on runners carrying the `instar` label, which
# promises the runner fleet's pre-built instar-testdata disk mounted at
# /srv/ci/cached/instar-testdata. The tree there is updated in place: a
# depth-1 fetch of main, a hard reset to it, then a Git LFS pull of
# downloaded/ova/ alone, about 2GB, rather than the whole tree's objects.
# Updating rather than trusting the disk means an appliance added since
# the disk was built is tested. A missing tree is an error, never a
# fresh clone: a fallback would be a second, untested path that holds
# the credential, and it would turn a mislabelled runner into a job that
# merely looks slow. Developers do not use this script; they point
# APPLIANCE_CORPUS at their own checkout.
#
# THE CREDENTIAL. A read-only GitLab token, scoped to instar-testdata. It
# reaches git and git-lfs as an HTTP Authorization header, set through
# git's GIT_CONFIG_COUNT/KEY/VALUE environment variables on exactly the
# two commands that talk to GitLab. It is never put in a remote URL, so
# nothing is written to .git/config and there is nothing to strip
# afterwards, whether or not the runner is thrown away after the job.
# The environment rather than `git -c` because a command line is
# readable by every user on the host through /proc, and a process
# environment only by its owner. git-lfs reads the same variables, as
# it reads all of git's configuration.
#
# The fetch is from the repository URL written out below, not from the
# cache's `origin`, and git-lfs is told its endpoint with lfs.url rather
# than deriving it from `origin`. What `origin` holds is the disk
# build's business: it may be an SSH URL, or carry a credential of its
# own, and either would otherwise decide how this script authenticates.
#
# The script ends by searching the tree's .git, the git configuration
# and the usual credential stores for the token, and fails if it finds
# it. It does that on every exit, failed or not, because a failed fetch
# is the likeliest moment for something to have been written down.
#
# Inputs (environment):
#   TESTDATA_TOKEN   (required) the token.
#   TESTDATA_USER    (optional) the username the token authenticates as.
#                    oauth2, the default, is right for a GitLab project
#                    access token; a deploy token has its own username.
#   TESTDATA_CACHE   (optional) the tree to update. If set, it must be
#                    the agreed path below; it exists so that a change
#                    to either side of the agreement fails here.
#   TESTDATA_CONTRACT_CACHE
#                    (test seam) relocates the agreed path; see
#                    CONTRACT_CACHE below.
#   GITHUB_ENV       (optional) when set, APPLIANCE_CORPUS is written to
#                    it for later steps.
#
# No `set -x`, here or in any caller: tracing would print the header.

set -euo pipefail
shopt -s nullglob

REPO_URL='https://gitlab.home.stillhq.com/private/instar-testdata.git'
REPO_BRANCH='main'
LFS_URL="${REPO_URL}/info/lfs"
# The header is scoped to the GitLab host, so it never goes anywhere
# else: if a batch response sends git-lfs to object storage on another
# host, that request carries the batch response's own authorisation, not
# this token.
AUTH_SCOPE='https://gitlab.home.stillhq.com/'
CORPUS_SUBDIR='downloaded/ova'
LFS_POINTER_PREFIX='version https://git-lfs.github.com/spec/'

# Where the runner fleet mounts the testdata disk on `instar` runners.
# Written out literally, and not derived from TESTDATA_CACHE, because
# this is the half of the agreement with the fleet that this repository
# asserts.
#
# TESTDATA_CONTRACT_CACHE moves it, for one caller:
# tools/ci/test-fetch-appliance-corpus.sh, which cannot otherwise reach
# the missing-tree check without the real disk's path. It is a different
# variable from TESTDATA_CACHE on purpose: letting one variable supply
# both sides of the comparison would make the comparison always pass.
# Nothing under .github/ sets it, and the test asserts that.
CONTRACT_CACHE="${TESTDATA_CONTRACT_CACHE:-/srv/ci/cached/instar-testdata}"
cache="${TESTDATA_CACHE:-/srv/ci/cached/instar-testdata}"
user="${TESTDATA_USER:-oauth2}"

fail() {
    echo "::error::$*" >&2
    exit 1
}

if ! command -v git >/dev/null 2>&1; then
    fail "git is not installed on this runner."
fi

if ! command -v git-lfs >/dev/null 2>&1; then
    fail "git-lfs is not installed on this runner. The appliances are" \
         "Git LFS objects and cannot be fetched without it."
fi

if [ -z "${TESTDATA_TOKEN:-}" ]; then
    fail "TESTDATA_TOKEN is not set, so there is no credential for the" \
         "instar-testdata repository."
fi

case "${user}" in
    *:*)
        fail "TESTDATA_USER contains a colon. HTTP Basic authentication" \
             "splits the username from the token at the first colon, so" \
             "no such username can authenticate."
        ;;
esac

if [ "${cache}" != "${CONTRACT_CACHE}" ]; then
    fail "TESTDATA_CACHE is ${cache}, not the agreed ${CONTRACT_CACHE}." \
         "That path is half of the agreement with the runner fleet's" \
         "testdata disk; fix the override or the agreement, not this check."
fi

if [ ! -d "${CONTRACT_CACHE}/.git" ]; then
    fail "There is no instar-testdata tree at ${CONTRACT_CACHE}. The job" \
         "must run on a runner with the 'instar' label, which promises the" \
         "fleet's pre-built testdata disk mounted there. Either this runner" \
         "carries the label without the disk, or the mount path changed on" \
         "one side of the agreement. This is an infrastructure problem, not" \
         "a test failure, and there is deliberately no fresh-clone fallback."
fi

# Out of the exported environment from here on, so that nothing this
# script starts inherits the raw token. The header carries it encoded.
token="${TESTDATA_TOKEN}"
unset TESTDATA_TOKEN

# printf is a shell builtin, so the token is in no process's arguments;
# base64 reads it from a pipe. -w0 because a wrapped value would split
# the header.
auth_b64="$(printf '%s:%s' "${user}" "${token}" | base64 -w0)"

# GitHub masks the secret itself in the log, but not this encoding of
# it. Registering it means a header echoed by some future tool is masked
# too. The workflow command is consumed by the runner, not displayed.
if [ "${GITHUB_ACTIONS:-}" = 'true' ]; then
    echo "::add-mask::${auth_b64}"
fi

# git and git-lfs, with the credential and nothing else changed. The
# settings, in order:
#   credential.helper= empties the helper list, so that no helper the
#     runner configures is asked for a credential, or told to store one;
#   http.<host>.extraHeader is the credential;
#   lfs.url fixes the LFS endpoint (see the header comment);
#   lfs.<url>.access=basic is what git-lfs records in .git/config after
#     its first 401 from an endpoint. Saying it up front means git-lfs has
#     nothing to record, so even a failed pull writes nothing there.
authed_git() {
    GIT_TERMINAL_PROMPT=0 \
    GIT_CONFIG_COUNT=4 \
    GIT_CONFIG_KEY_0='credential.helper' \
    GIT_CONFIG_VALUE_0='' \
    GIT_CONFIG_KEY_1="http.${AUTH_SCOPE}.extraHeader" \
    GIT_CONFIG_VALUE_1="Authorization: Basic ${auth_b64}" \
    GIT_CONFIG_KEY_2='lfs.url' \
    GIT_CONFIG_VALUE_2="${LFS_URL}" \
    GIT_CONFIG_KEY_3="lfs.${LFS_URL}.access" \
    GIT_CONFIG_VALUE_3='basic' \
        git -C "${cache}" "$@"
}

# The token and its encoded form, one per line, as a grep pattern list.
# Given to grep through a pipe, never as an argument or a file.
credential_patterns() {
    printf '%s\n' "${token}" "${auth_b64}"
}

# Fails if the token, raw or encoded, is anywhere it could outlive this
# step. Prints where it looked, never what it found.
credential_checked=0
check_no_credential() {
    credential_checked=1
    local git_dir="${cache}/.git" found=0 rc log scrubbed=0 config_lines

    # git-lfs writes an error log under .git/lfs/logs when a command fails
    # badly, and the log includes its environment -- which here includes
    # the header, whichever way it was passed (GIT_CONFIG_PARAMETERS
    # carries a `git -c` value the same way). The error itself has
    # already gone to stderr, so a log that recorded the credential is
    # removed rather than kept. This is the one leak of this kind known;
    # the search below is for the ones that are not.
    for log in "${git_dir}"/lfs/logs/*; do
        if [ -f "${log}" ] && grep -qF -f <(credential_patterns) -- "${log}"; then
            rm -f -- "${log}"
            scrubbed=$((scrubbed + 1))
        fi
    done
    if [ "${scrubbed}" -gt 0 ]; then
        echo "::warning::Removed ${scrubbed} git-lfs error log(s) from" \
             "${git_dir}/lfs/logs because they recorded the credential." >&2
    fi

    # The object stores are left out: they hold content the server sent,
    # gigabytes of it, which cannot contain a credential this script
    # never committed. Everything else under .git is searched. grep
    # exits 1 for "not found"; anything else besides a match is an
    # error, and an error fails closed.
    rc=0
    grep -rqF --exclude-dir=objects -f <(credential_patterns) -- "${git_dir}" || rc=$?
    case "${rc}" in
        0) echo "::error::The credential was found under ${git_dir}." >&2; found=1 ;;
        1) ;;
        *) echo "::error::Could not search ${git_dir} for the credential." >&2; found=1 ;;
    esac

    # credential.helper=store's default files. Nothing here asks a helper
    # to store anything, so this proves that rather than assuming it.
    for store in "${HOME:-/nonexistent}/.git-credentials" \
                 "${XDG_CONFIG_HOME:-${HOME:-/nonexistent}/.config}/git/credentials"; do
        if [ -e "${store}" ]; then
            rc=0
            grep -qF -f <(credential_patterns) -- "${store}" || rc=$?
            if [ "${rc}" != 1 ]; then
                echo "::error::The credential was found in, or could not" \
                     "be searched for in, ${store}." >&2
                found=1
            fi
        fi
    done

    # Every configuration key that could carry it, at every scope git
    # reads. Run as plain git, without authed_git's settings, so that
    # it sees only what is written down. Exit 1 means no such keys.
    rc=0
    config_lines="$(git -C "${cache}" config --get-regexp \
        '^(http\..*extraheader|credential\.|url\..*insteadof|remote\..*\.url)')" || rc=$?
    case "${rc}" in
        0)
            if grep -qF -f <(credential_patterns) <<< "${config_lines}"; then
                echo "::error::The credential was found in git's configuration" \
                     "for ${cache}." >&2
                found=1
            fi
            ;;
        1) ;;
        *) echo "::error::Could not read git's configuration for ${cache}." >&2; found=1 ;;
    esac

    if [ "${found}" != 0 ]; then
        return 1
    fi
    echo "The credential is not under ${git_dir}, in git's configuration or" \
         "in a credential store."
}

# The check runs on every exit. A failure before the end still runs it,
# and keeps its own exit status unless the check fails as well.
on_exit() {
    local status=$?
    if [ "${credential_checked}" = 0 ]; then
        check_no_credential || status=1
    fi
    exit "${status}"
}
trap on_exit EXIT

echo "Updating ${cache} to ${REPO_BRANCH} of ${REPO_URL}"
authed_git fetch --quiet --depth 1 "${REPO_URL}" "${REPO_BRANCH}"

# GIT_LFS_SKIP_SMUDGE so that the reset writes LFS files as pointers
# rather than having the smudge filter download each changed one --
# across the whole tree, not only downloaded/ova/. The pull below
# materialises exactly the part this repository needs.
GIT_LFS_SKIP_SMUDGE=1 git -C "${cache}" reset --quiet --hard FETCH_HEAD

echo "Pulling the Git LFS objects under ${CORPUS_SUBDIR}/"
authed_git lfs pull --include "${CORPUS_SUBDIR}/**"

# The pull exits 0 when it had nothing to fetch, so check that it left
# what the test needs: every appliance materialised, and described.
corpus="${cache}/${CORPUS_SUBDIR}"
ovas=("${corpus}"/*.ova)
if [ "${#ovas[@]}" = 0 ]; then
    fail "There are no .ova files under ${corpus}."
fi
problems=0
for ova in "${ovas[@]}"; do
    name="${ova##*/}"
    name="${name%.ova}"
    # cmp rather than reading the bytes into a variable: an OVA is
    # binary, and the shell would complain about every NUL in it.
    if cmp -s -n "${#LFS_POINTER_PREFIX}" -- "${ova}" \
            <(printf '%s' "${LFS_POINTER_PREFIX}"); then
        echo "::error::${name}.ova is still a Git LFS pointer after the pull." >&2
        problems=$((problems + 1))
    fi
    if [ ! -f "${corpus}/${name}.provenance.json" ]; then
        echo "::error::${name}.ova has no ${name}.provenance.json." >&2
        problems=$((problems + 1))
    fi
done
if [ "${problems}" != 0 ]; then
    fail "The appliance corpus under ${corpus} is incomplete."
fi

check_no_credential

echo "Appliance corpus ready: ${#ovas[@]} appliances."
echo "APPLIANCE_CORPUS=${corpus}"
if [ -n "${GITHUB_ENV:-}" ]; then
    echo "APPLIANCE_CORPUS=${corpus}" >> "${GITHUB_ENV}"
fi

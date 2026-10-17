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
# THE TREE'S OWN CONFIGURATION. The disk sits on the runner, and the
# script cannot vouch for what wrote to it. A repository's .git/config
# can make git run a command (a hook path, a filter, a filesystem
# monitor) or send a request somewhere else (a proxy, a URL rewrite),
# and any command git runs while the credential is in its environment
# can read it. So before git touches the tree, the script lists the
# keys in that file and refuses the tree if any is outside the set a
# clone of instar-testdata carries; see config_key_allowed below. Every
# git command on the tree then runs with the runner's system and global
# configuration left out, and with hooks, the filesystem monitor and
# the LFS filter pinned to safe values, in case the check missed a way.
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

# git-lfs's own filter commands, as `git lfs install` writes them. A
# filter is a command git runs on every file it checks out, so these are
# the only values the tree's configuration may give it, and the values
# every git command here is given over whatever the file says.
LFS_FILTER_PROCESS='git-lfs filter-process'
LFS_FILTER_SMUDGE='git-lfs smudge -- %f'
LFS_FILTER_CLEAN='git-lfs clean -- %f'
LFS_FILTER_REQUIRED='true'

# config_key_allowed KEY FILE
#
# Whether KEY may appear in FILE, the tree's repository configuration.
# KEY is as `git config --name-only` prints it: the section and variable
# names in lower case, a subsection as written. The allowed set is what
# the fleet's disk build leaves (a depth-1 clone, `git lfs install
# --local`, `git lfs pull`, and its own removal of the credential from
# the remote URL and the LFS sections), and nothing else. Everything not
# named here is refused, among it include.path and includeIf.*.path,
# which would pull in a file this check never read, and every core,
# http, url, credential, protocol and remote key not listed.
config_key_allowed() {
    local key=$1 file=$2 stock values value
    case "${key}" in
        # What git init and git clone write about the repository itself.
        # Not core.hookspath, core.fsmonitor, core.sshcommand,
        # core.gitproxy, core.askpass, core.pager, core.editor or
        # core.worktree: each of those runs a command or moves the tree.
        core.repositoryformatversion|core.filemode|core.bare|core.logallrefupdates)
            return 0 ;;
        core.symlinks|core.ignorecase|core.precomposeunicode)
            return 0 ;;
        core.sparsecheckout|core.sparsecheckoutcone)
            return 0 ;;
        # Where the clone came from, and how its branch follows it. Inert
        # here: the fetch names its own URL and refspec, and git-lfs is
        # given its endpoint.
        remote.origin.url|remote.origin.fetch)
            return 0 ;;
        branch.*.remote|branch.*.merge)
            return 0 ;;
        # git-lfs's records: the repository format, and for an endpoint,
        # how it authenticates and whether it checks locks before a push.
        # Not an endpoint with a password in its URL, which is a
        # credential the disk build should have removed.
        lfs.repositoryformatversion)
            return 0 ;;
        lfs.*://*:*@*)
            return 1 ;;
        lfs.*.access|lfs.*.locksverify)
            return 0 ;;
        # git lfs install --local: allowed only as git-lfs's own commands.
        filter.lfs.process) stock="${LFS_FILTER_PROCESS}" ;;
        filter.lfs.smudge) stock="${LFS_FILTER_SMUDGE}" ;;
        filter.lfs.clean) stock="${LFS_FILTER_CLEAN}" ;;
        filter.lfs.required) stock="${LFS_FILTER_REQUIRED}" ;;
        *)
            return 1 ;;
    esac

    # A filter key: every value it is given must be the stock one. The
    # values are compared, never printed.
    values="$(git config --file "${file}" --get-all "${key}")" || return 1
    while IFS= read -r value; do
        if [ "${value}" != "${stock}" ]; then
            return 1
        fi
    done <<< "${values}"
}

# Refuses the tree unless its repository configuration holds only keys
# config_key_allowed accepts. Names the keys it refuses, with any
# credential in a URL hidden, and never prints a value: the values are
# where a credential would be.
check_cache_config() {
    local git_dir="${cache}/.git" file keys key rc names
    local -a refused=()

    # A linked worktree's git directory reads its configuration from the
    # directory commondir names, which this check would not have read.
    if [ -e "${git_dir}/commondir" ]; then
        fail "${git_dir} has a commondir file, so its configuration is" \
             "somewhere this script does not check. The testdata tree" \
             "should be a plain clone."
    fi

    # config.worktree is read too, when extensions.worktreeConfig is set;
    # that key is refused, but a file present is checked anyway.
    for file in "${git_dir}/config" "${git_dir}/config.worktree"; do
        if [ "${file}" != "${git_dir}/config" ] && [ ! -e "${file}" ]; then
            continue
        fi
        rc=0
        keys="$(git config --file "${file}" --list --name-only)" || rc=$?
        if [ "${rc}" != 0 ]; then
            fail "Could not read the repository configuration ${file}."
        fi
        while IFS= read -r key; do
            if [ -n "${key}" ] && ! config_key_allowed "${key}" "${file}"; then
                refused+=("${key}")
            fi
        done <<< "${keys}"
    done

    if [ "${#refused[@]}" != 0 ]; then
        names="$(printf '%s\n' "${refused[@]}" | sort -u \
            | sed -E 's#://[^/@]*@#://<userinfo>@#' | paste -sd ',' - | sed 's/,/, /g')"
        fail "The repository configuration under ${git_dir} has keys a" \
             "clone of instar-testdata does not carry: ${names}. Such a key" \
             "can make git run a command or send a request elsewhere while" \
             "it holds the credential, so the tree is refused. Values are" \
             "not shown, because they can hold credentials."
    fi
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

# Everything below rests on git honouring GIT_CONFIG_COUNT/KEY/VALUE (git
# 2.31) and GIT_CONFIG_GLOBAL (git 2.32). An older git ignores both
# silently: it would run without the hardening and with the runner's
# global configuration, and the fetch would go out without the header.
# So prove both are honoured, rather than parse a version string. This
# is the first git command, and it runs outside any repository, with no
# credential anywhere.
git_selftest() {
    local global rc=0 seen
    local -a vars
    global="$(mktemp)"
    printf '[corpus]\n\tglobal = ok\n' > "${global}"
    vars=(GIT_CONFIG_NOSYSTEM=1 "GIT_CONFIG_GLOBAL=${global}" GIT_CONFIG_COUNT=1
          GIT_CONFIG_KEY_0=corpus.selftest GIT_CONFIG_VALUE_0=ok)
    seen="$(cd / && env "${vars[@]}" git config --get corpus.selftest \
        && env "${vars[@]}" git config --get corpus.global)" || rc=$?
    rm -f -- "${global}"
    if [ "${rc}" != 0 ] || [ "${seen}" != $'ok\nok' ]; then
        fail "git on this runner does not honour GIT_CONFIG_COUNT and" \
             "GIT_CONFIG_GLOBAL, which this script relies on to give git" \
             "the credential and its hardening without writing them down," \
             "and to leave the runner's own configuration out." \
             "git 2.32 or later is required."
    fi
}
git_selftest

# Before any git command runs in the tree, and before the credential is
# prepared.
check_cache_config

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

# Settings every git command in the tree runs with, as key and value
# pairs, on top of the tree's own configuration (checked above):
#   core.hooksPath=/dev/null runs no hook, from .git/hooks or anywhere:
#     `git lfs install` puts four there, and the reset, which moves the
#     branch, would run the reference-transaction hook;
#   core.fsmonitor=false runs no filesystem monitor;
#   filter.lfs.* are git-lfs's own commands, whatever the file says;
#   safe.directory names this tree alone. The runner's global
#     configuration is left out (see cache_git), and with it any
#     safe.directory the runner sets; without one, git refuses a tree
#     another user owns, and a configuration read silently skips the
#     tree's file. The fleet's disk belongs to the runner user, so this
#     only keeps a change of owner from turning into a confusing error.
HARDENING=(
    core.hooksPath /dev/null
    core.fsmonitor false
    filter.lfs.process "${LFS_FILTER_PROCESS}"
    filter.lfs.smudge "${LFS_FILTER_SMUDGE}"
    filter.lfs.clean "${LFS_FILTER_CLEAN}"
    filter.lfs.required "${LFS_FILTER_REQUIRED}"
    safe.directory "${cache}"
)

# cache_git [--authenticated] ARGS...
#
# git in the tree, with HARDENING, and with the system and global
# configuration left out (GIT_CONFIG_NOSYSTEM, GIT_CONFIG_GLOBAL): the
# runner's /etc/gitconfig and ~/.gitconfig are nothing this script needs
# or has checked. With --authenticated, the credential and nothing else
# besides, in this order:
#   credential.helper= empties the helper list, so that no helper the
#     runner configures is asked for a credential, or told to store one;
#   http.<host>.extraHeader is the credential;
#   lfs.url fixes the LFS endpoint (see the header comment);
#   lfs.<url>.access=basic is what git-lfs records in .git/config after
#     its first 401 from an endpoint. Saying it up front means git-lfs has
#     nothing to record, so even a failed pull writes nothing there.
# The settings go in git's GIT_CONFIG_COUNT/KEY/VALUE variables, exported
# in a subshell, so they reach git's environment and no command line.
cache_git() {
    local -a settings=("${HARDENING[@]}")
    if [ "${1:-}" = '--authenticated' ]; then
        shift
        settings+=(
            credential.helper ''
            "http.${AUTH_SCOPE}.extraHeader" "Authorization: Basic ${auth_b64}"
            lfs.url "${LFS_URL}"
            "lfs.${LFS_URL}.access" basic
        )
    fi
    (
        local i count=$(( ${#settings[@]} / 2 ))
        export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0
        export GIT_CONFIG_COUNT="${count}"
        for (( i = 0; i < count; i++ )); do
            export "GIT_CONFIG_KEY_${i}=${settings[2 * i]}" \
                   "GIT_CONFIG_VALUE_${i}=${settings[2 * i + 1]}"
        done
        exec git -C "${cache}" "$@"
    )
}

# git and git-lfs with the credential: on exactly the two commands that
# talk to GitLab.
authed_git() {
    cache_git --authenticated "$@"
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
    # reads. Run as plain git, without cache_git's settings, so that it
    # sees only what is written down -- but for safe.directory, without
    # which git would skip the tree's own file, silently, were the tree
    # another user's. Exit 1 means no such keys.
    rc=0
    config_lines="$(GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory \
        GIT_CONFIG_VALUE_0="${cache}" git -C "${cache}" config --get-regexp \
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
# An interrupted or terminated run exits through on_exit too, with the
# status a shell gives a death by that signal; credential_checked keeps
# the check from running a second time.
trap 'exit 130' INT
trap 'exit 143' TERM

# A git-lfs error log left from an earlier run -- one killed before its
# EXIT trap, or one that recorded a token since rotated, which the
# token-matching scrub in check_no_credential cannot recognise -- would
# otherwise survive this run. So every file there goes before the first
# authenticated command, whatever it holds. The scrub stays, for the
# logs this run writes.
if [ -d "${cache}/.git/lfs/logs" ]; then
    find "${cache}/.git/lfs/logs" -mindepth 1 -type f -delete
fi

echo "Updating ${cache} to ${REPO_BRANCH} of ${REPO_URL}"
authed_git fetch --quiet --depth 1 "${REPO_URL}" "${REPO_BRANCH}"

# GIT_LFS_SKIP_SMUDGE so that the reset writes LFS files as pointers
# rather than having the smudge filter download each changed one --
# across the whole tree, not only downloaded/ova/. The pull below
# materialises exactly the part this repository needs.
GIT_LFS_SKIP_SMUDGE=1 cache_git reset --quiet --hard FETCH_HEAD

# The reset leaves untracked files alone, and the test reads every .ova
# under the corpus directory: remove anything there the commit does not
# hold, ignored files and nested repositories included.
cache_git clean -ffdxq -- "${CORPUS_SUBDIR}"

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

#!/bin/bash

# Fetch the two upstream OVF descriptor collections the parser's tests draw
# on, each at an exact pinned commit, into .cache/ovf-corpora/<repo>-<sha>/.
#
# Each fetch is `git init`, a sparse checkout of the one directory, and
# `git fetch --depth 1 --filter=blob:none origin <sha>`. GitHub serves any
# reachable commit, so a pin stays exact after the upstream branch moves.
# The fetch lands in <repo>-<sha>.tmp/, `git rev-parse HEAD` must equal the
# pin, and only then is the directory renamed into place, so an interrupted
# fetch never leaves a directory that looks complete. A directory is reused
# only under its final name. Nothing else in this script touches the network.
#
# Bumping a pin: change the sha here, which is the only place it is written, then regenerate
# shakenfist_client_ova/corpus_tests/curated.txt with tools/classify-ovf-corpus.py
# (its docstring has the command).

set -euo pipefail

GOVMOMI_URL=https://github.com/vmware/govmomi.git
GOVMOMI_SHA=79bc9d75e5c930649bc1b3e86bb0cfe76d60fdbe
GOVMOMI_PATH=ovf/fixtures

COT_URL=https://github.com/glennmatthews/cot.git
COT_SHA=0811b96311881a8293f28f2e300f6bed1b77ee31
COT_PATH=COT/tests

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cache="$root/.cache/ovf-corpora"

# fetch_corpus REPO URL SHA SUBDIRECTORY
fetch_corpus() {
    local repo=$1 url=$2 sha=$3 subdir=$4
    local final="$cache/$repo-$sha"
    local tmp="$final.tmp"

    if [ -d "$final" ]; then
        local have
        # --git-dir, not -C: the cache is inside this repository, so -C on a
        # broken cache directory would find and report this repository's HEAD.
        have=$(git --git-dir="$final/.git" rev-parse HEAD 2>/dev/null || echo "an unreadable checkout")
        if [ "$have" != "$sha" ]; then
            echo "$final is at $have, not the pin $sha; delete it and re-run" >&2
            exit 1
        fi
        echo "$repo: reusing $final (HEAD verified as $sha)"
        return
    fi

    echo "$repo: fetching $sha ($subdir) from $url"
    rm -rf "$tmp"
    mkdir -p "$tmp"
    git -C "$tmp" init --quiet
    git -C "$tmp" remote add origin "$url"
    git -C "$tmp" sparse-checkout set "$subdir"
    git -C "$tmp" fetch --quiet --depth 1 --filter=blob:none origin "$sha"
    git -C "$tmp" checkout --quiet FETCH_HEAD

    local got
    got=$(git --git-dir="$tmp/.git" rev-parse HEAD)
    if [ "$got" != "$sha" ]; then
        echo "$repo: fetched $got, expected the pin $sha" >&2
        exit 1
    fi
    mv "$tmp" "$final"
    echo "$repo: fetched $final (HEAD verified as $sha)"
}

mkdir -p "$cache"
fetch_corpus govmomi "$GOVMOMI_URL" "$GOVMOMI_SHA" "$GOVMOMI_PATH"
fetch_corpus cot "$COT_URL" "$COT_SHA" "$COT_PATH"

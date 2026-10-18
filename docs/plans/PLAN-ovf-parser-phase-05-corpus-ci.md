# OVF parser phase 5: the appliance corpus in CI

## Prompt

Before responding to questions or discussion points in this document,
read the master plan, [PLAN-ovf-parser.md](PLAN-ovf-parser.md),
particularly decisions 5 and 8, open question 3, and phase 5's section.
Then read phase 4's plan,
[PLAN-ovf-parser-phase-04-archive.md](PLAN-ovf-parser-phase-04-archive.md),
for the archive checks this phase runs over real appliances, and its
execution notes, which record the corpus outcomes this phase turns
into a test. The master plan's decisions are not restated here, except
where this phase's survey changed or sharpened them.

Phase 4 checked every appliance in `instar-testdata` by hand, from the
management session. This phase makes that check a test, and runs it in
CI on every same-repository pull request. Fetching the private corpus
needs a secret, which is the hard part of the phase: the secret must
reach the fetch and nothing else.

The phase also carries one change that is not about the corpus. The
operator decided, after phase 4's live import, to fold it in here:
artifacts stop using the `ova://` source URL.

## Planning effort

High: this phase puts a secret into CI, and the master plan sets
conditions on how it may be handled. Review effort: high for decisions
1 to 4 and step 5b, which handle the token. Medium for the rest.

## Scope

In scope:

* An appliance corpus test that runs `open_package()`, the digest
  checks and the command (with the client mocked) over every appliance
  in `instar-testdata`'s `downloaded/ova/`. It fails closed when the
  corpus is missing or incomplete, and runs as `tox -eappliance-corpus`.
* A fetch script in `tools/ci/` and a CI job that runs the test, gated
  so that fork pull requests never reach it.
* The artifact source URL: drop `ova://`, let the server apply its
  `sf://upload/<namespace>/<name>` default, and keep where the disk came
  from as artifact metadata.
* Documentation of all three.

Out of scope:

* **Adding appliances to the corpus.** `instar-testdata` holds 16
  appliances, and this phase tests the ones it has.
* **Keeping whole OVAs in the cluster.** That idea became a server-side
  placeholder plan, shakenfist/shakenfist `docs/plans/PLAN-blob-containers.md`
  (shakenfist/shakenfist#4562), and phase 5 does not depend on it.
* **Refusing an unfetchable disk base on the server.** That is
  shakenfist/shakenfist#4557.
* **Issue #12** (a traceback from the trim tool). It is unrelated to this
  phase.

## What the survey found

### 1. Phase 4 is complete

#16 merged as `a8f44bf`, which is an ancestor of `develop`. The master
plan's Execution table and `docs/plans/index.md` agreed (`In progress`)
before this phase's close-out commit.

I spot-checked the Definition of done against the tree:

* The `endswith`/`element_hashes`/`docs/plans` grep finds nothing.
* The security grep finds only text that says what the manifest does
  not protect against.
* `git diff b1f8894` over the descriptor parser and the model is one
  comment line in `ovf/model.py`, which phase 4's execution notes
  record.

The phase 4 worktree and local branch have been removed. The remote
branch `origin/ovf-phase-04-archive` still exists.

Step 4e ran after the merge. Its result is recorded in phase 4's
execution notes by this phase's close-out commit, and open question 1
is resolved: the Ubuntu image boots.

### 2. instar's `prepare-testdata.sh` is no longer something to adapt

The master plan says to "adapt instar's `prepare-testdata.sh`" and to
pull only `downloaded/ova/` from LFS. The script (instar `develop`,
`tools/ci/prepare-testdata.sh`) has since grown into something else.

It is built around the runner fleet's pre-built testdata disk, mounted
at `/srv/ci/cached/instar-testdata` on runners that carry the `instar`
label. It does four things:

* updates that tree in place (`git fetch --depth 1`, `git reset --hard`,
  `git lfs pull` of everything);
* with `TESTDATA_REQUIRE_CACHE=1`, refuses the 7.46 GiB fresh-clone
  fallback;
* lists changed paths, so that a later step can resparsify them;
* runs instar's own fixture check.

Most of that is instar's business: resparsifying, its fixture list,
the changed-file contract. One part conflicts with the master plan.
The script writes the token into the clone's remote URL
(`git remote set-url origin "${AUTHED_URL}"`) and never removes it. The
master plan requires the credential to be gone once the fetch is done.

The script also authenticates as `oauth2:<token>`. That works for a
GitLab project access token, but not for a deploy token, which has a
username of its own.

### 3. Open question 3 is answered

Every instar job that reads the testdata runs on
`[self-hosted, debian-13, xl, instar]`, with
`TESTDATA_TOKEN: ${{ secrets.GITLAB_TESTDATA_TOKEN }}` and
`TESTDATA_REQUIRE_CACHE: '1'` (instar `.github/workflows/functional-tests.yml`,
e.g. lines 777 and 857-861, and `coverage-fuzz.yml:58-74`). The
`instar` label is what promises the testdata disk.

Nothing in instar's repository says whether those runners are throwaway
VMs. The master plan's worry about a credential outliving the job in a
runner cache depends on that. Decision 2 makes the answer not matter.

### 4. The secret is not set on this repository

`gh secret list -R shakenfist/client-python-ova` is empty. Adding
`GITLAB_TESTDATA_TOKEN` is the operator's step (5e).

### 5. The corpus

`downloaded/ova/` is 2.0 GB: 17 LFS files (16 OVAs and `sources.json`),
plus a provenance file per OVA.

* **Whole archives (6):** `archiveteam-warrior-4.1`,
  `oracle-linux-9.8-olvm`, `photon-3.0-hw11`,
  `photon-5.0-aarch64-uefi-hw14`, `talos-1.14.3` and `vyos-1.2.1`. These
  are the six master plan decision 8 names.
* **Descriptor-only (10).** Each provenance file lists the members
  deliberately absent in `absent_members`.

Both CyberOps appliances are descriptor-only. Their descriptors are the
envelope, which the operator has said may be published. Their disks are
not in the corpus at all.

Phase 4's management-session run gives the expected outcome of every
entry:

* the five whole archives that parse verify every digest and import;
* `oracle-linux-9.8-olvm` gives `UnsupportedProducerError`;
* `tails-202607` gives `UnsupportedEnvelopeError`;
* the other nine give `MissingMemberError`, naming exactly their
  `absent_members`.

The scripts that produced that run are the model for this phase's test.

### 6. The descriptor corpus tier is the pattern to follow

`tox -edescriptor-corpus` runs a fetch script, then
`stestr --test-path ./shakenfist_client_ova/corpus_tests run`.
`corpus_tests/` sits outside `.stestr.conf`'s `test_path`, so `py3` never
collects it, and `pyproject.toml:75` excludes it from the wheel. The
appliance tier needs its own directory, for the same reason the
descriptor tier has one: its fail-closed guard must not fire in
`descriptor-corpus`, which has no appliance corpus.

### 7. What can reach the job

* `pull_request` from a branch of this repository, including Renovate's.
* `push` to `develop`.
* `workflow_dispatch`, which `pr-retest.yml` uses: an authorised
  "please retest" comment dispatches `ci.yml` on the pull request's
  head ref (same-repository pull requests only).

All three run code from a branch that someone with write access
controls.

### 8. The server applies its own source URL when none is sent

`POST /artifacts/upload/<name>` sets
`source_url = sf://upload/<caller's namespace>/<name>` when the request
carries none (shakenfist/shakenfist `external_api/artifact.py:621-623`).
That path serves both `upload_artifact()` and `blob_artifact()`. So the
plugin stops sending one, and does not need to build it. Phase 4's live
import found that the plugin's `ova://` URL only boots through the
server's fallback for unreachable sources (phase 4 plan, execution
notes).

Today an artifact is found by its source URL. With the default, it is
found by its name in the caller's namespace. Re-importing an appliance
then adds a version to the same artifact, or nothing at all if the
sha512 is unchanged (`add_index`). The plugin has never been released,
so no existing artifact needs migrating.

## Decisions

1. **Write a small fetch script; do not adapt instar's.**
   `tools/ci/fetch-appliance-corpus.sh` does only what this repository
   needs:
   * require `git-lfs`, the token and the cache;
   * update the cache tree to `origin/main` (`git fetch --depth 1`, then
     `git reset --hard`), as instar does, so that an appliance added
     since the disk was built is tested;
   * run `git lfs pull --include 'downloaded/ova/**'`;
   * check that the corpus materialised: no `.ova` is an LFS pointer, and
     every OVA has a provenance file;
   * print the corpus path to `GITHUB_ENV`.

   It does no resparsifying and no changed-file list, and uses no instar
   fixture list. Copying instar's script would bring roughly 400 lines
   of contract with the runner fleet that this repository would then
   have to keep in step.

2. **The token never touches disk.** The script passes the credential
   per command, as
   `git -c http.extraHeader="Authorization: Basic <base64 of user:token>"`,
   and does not put it in a remote URL. Nothing is written to
   `.git/config`, so there is nothing to strip. That holds whether or not
   the runner is a throwaway VM. git-lfs reads `http.extraHeader` from
   git's configuration, including one given by `-c`.

   As a check, the script ends by searching the tree's `.git` directory
   for the token, and fails if it finds it. The token is in the step's
   environment at that point, so this is the one place the check can be
   made. If git-lfs turns out not to honour the header (5b tests this),
   the fallback is a remote URL that the script removes with an `EXIT`
   trap, and the same check guards it.

3. **The cache is required; there is no clone fallback.** The job runs
   on `[self-hosted, debian-13, xl, instar]`. The script fails closed
   when `/srv/ci/cached/instar-testdata/.git` is missing, with a message
   that names the label contract, as instar's does. A fallback would be
   a second, untested path that holds the token. Developers do not use
   the script at all: they point the tox environment at a local
   checkout (decision 5).

4. **The token is dedicated to this repository and has one scope.** It
   is a GitLab project access token or deploy token on
   `private/instar-testdata` alone, with `read_repository` and nothing
   else. It is this repository's own, not instar's, so that either can
   be revoked without breaking the other. The username for the header
   comes from a repository variable, `GITLAB_TESTDATA_USER`, which
   defaults to `oauth2` for a project access token. A username is not a
   secret.

   The operator creates the token, adds the secret and variable, and
   owns rotation. The token's expiry date is recorded in this plan's
   execution notes, not in the repository.

5. **The test lives in `shakenfist_client_ova/appliance_tests/`** and
   runs as `tox -eappliance-corpus`, which calls `stestr --test-path` on
   that directory alone. `py3` never collects it, `pyproject.toml`
   excludes it from the wheel as it does `corpus_tests`, and
   `descriptor-corpus` does not run it.
   * **Where the corpus is.** The corpus path comes from the
     `APPLIANCE_CORPUS` environment variable, which tox passes through.
     It is the `downloaded/ova` directory of any `instar-testdata`
     checkout, CI's or a developer's.
   * **The guard fails, never skips.** It fails when the variable is
     unset, when the directory has no OVAs, when any OVA is an LFS
     pointer, and when an OVA has no provenance file or a provenance
     file has no OVA.

6. **The expected outcomes come from the corpus, with two named
   exceptions.**
   * **Whole archives:** an entry whose provenance `kind` is `whole` must
     open, and every disk must match its manifest digest.
   * **Descriptor-only archives:** an entry whose `kind` is
     `descriptor-only` must raise `MissingMemberError` with `members`
     equal to its `absent_members`.
   * **Exceptions:** the test is given two entries by name, in a
     committed `appliance_tests/expected.json`.
     `oracle-linux-9.8-olvm` must raise `UnsupportedProducerError`, and
     `tails-202607` `UnsupportedEnvelopeError`.
   * **Stale entries fail.** An entry in `expected.json` that names no
     appliance in the corpus fails the test.
   * **The command too.** Every whole archive that opens is also run
     through the command with `CliRunner` and a mocked client. The test
     asserts exit 0, and one upload per disk under the
     `<system id>-<disk id>` name.

   One test per appliance, so a failure names it. Assertion messages
   carry appliance names and outcome names only, never descriptor text.

7. **The job's secret reaches one step.** In `ci.yml`, a job named
   `appliance-corpus`:
   * **Gate.** It carries the master plan's fork gate
     (`if: github.event_name != 'pull_request' ||
     github.event.pull_request.head.repo.full_name == github.repository`),
     `permissions: contents: read`, a concurrency group and a timeout.
   * **The fetch step.** It runs the fetch script, and it is the only
     step whose `env` names `GITLAB_TESTDATA_TOKEN`. It runs after the
     checkout and before anything is installed.
   * **What follows.** Then the venv and `tox -eappliance-corpus`, with
     `APPLIANCE_CORPUS` taken from `GITHUB_ENV`.

   The job is not made a required check by this phase; the operator
   decides that once it has run green (5e).

8. **Artifacts take the server's default source URL.**
   * **No source URL.** The command passes no `source_url` to
     `blob_artifact()` or `upload_artifact_with_progress_file_like_object()`.
   * **Provenance as metadata.** After each artifact is created, it sets
     two metadata keys with `set_artifact_metadata_item()`: `ova_file`,
     the OVA's real path (what the source URL carried until now), and
     `ova_member`, the member name.
   * **Re-imports are visible.** The command looks the artifact name up
     first and says whether the import creates a new artifact or adds a
     version to an existing one. A name now identifies an artifact, so
     two different appliances with the same system id and disk id would
     share one, and the user should see that happen. The stricter option, refusing
     when the existing artifact's `ova_file` names a different OVA, was
     put to the operator at planning and declined: an appliance's next
     release usually sits at a different path, and refusing would block
     exactly the re-import that should add a version.
   * **Documented.** `docs/usage.md` describes the new naming and
     metadata, and stops describing `ova://`.

## Step plan

| Step | Effort | Model | Isolation | Brief for sub-agent |
|------|--------|-------|-----------|---------------------|
| 5a | high | opus | none | The appliance corpus test, to decisions 5 and 6 of `docs/plans/PLAN-ovf-parser-phase-05-corpus-ci.md` (read it whole first, then master plan decision 8, then `shakenfist_client_ova/corpus_tests/test_descriptor_corpus.py` for the tier pattern, `ovf/package.py`, and `tests/test_command.py` for how the command is driven with a mocked client). Create `shakenfist_client_ova/appliance_tests/` with `__init__.py`, `expected.json` and `test_appliance_corpus.py`. Generate one test per OVA so a failure names the appliance, following whatever the descriptor tier does for per-file tests. Implement the guard of decision 5 as a failure, never a skip. Add `[testenv:appliance-corpus]` to `tox.ini` beside `descriptor-corpus`, with `passenv = APPLIANCE_CORPUS`, and exclude `shakenfist_client_ova.appliance_tests*` in `pyproject.toml`. A real corpus is at `/srv/kasm_profiles/mikal/vscode/src/shakenfist/instar-testdata/downloaded/ova`; run against it with `APPLIANCE_CORPUS=<that> tox -eappliance-corpus`. It holds private data: never print, log or copy descriptor or manifest text, and keep assertion messages to names and outcome classes. Show the guard fails (not skips) with the variable unset, with an empty directory, with one OVA replaced by a 131-byte LFS pointer file, and with one provenance file missing. Build those cases in a temporary directory of copies or symlinks, never by editing the checkout. Show that `tox -epy3` does not collect the new tests, and that `python3 -m build` leaves them out of the wheel. Do not cite plan phases or decisions in code. Run `tox -epy3`, `pre-commit run --all-files` (stage new files first) and `~/src/shakenfist/development/scripts/audit-check.py --repo-path . --repo-name client-python-ova`. Commit subject: `Test every appliance in the corpus.` |
| 5b | high | opus | none | The fetch script and the CI job, to decisions 1 to 4 and 7. Read the plan whole, then master plan phase 5's section, then `.github/workflows/ci.yml` and instar's `tools/ci/prepare-testdata.sh` (in `/srv/kasm_profiles/mikal/vscode/src/shakenfist/instar`) for the cache contract only. Write `tools/ci/fetch-appliance-corpus.sh` (bash, `set -euo pipefail`, no `set -x`), taking `TESTDATA_TOKEN`, `TESTDATA_USER` (default `oauth2`) and an optional `TESTDATA_CACHE` that must equal the contract path. Pass the credential only through `git -c http.extraHeader=...` on each git and git-lfs command, never in a URL, an argument that is echoed, or a file. End by searching the tree's `.git` for the token and failing if it is found. Write `tools/ci/test-fetch-appliance-corpus.sh`, which runs the script with each required input missing and asserts a non-zero exit with the right message, and which uses a throwaway local cache directory, never the real one. Run it from the existing lint job. Prove decision 2 locally: make a scratch clone of `/srv/kasm_profiles/mikal/vscode/src/shakenfist/instar-testdata` (its origin is the GitLab remote) with `GIT_LFS_SKIP_SMUDGE=1`, then run the script's `lfs pull` invocation against it with a dummy header, and confirm that git-lfs sends the header (`GIT_TRACE=1 GIT_CURL_VERBOSE=1` shows it; redact before quoting any output) and that nothing lands in `.git/config`. If git-lfs ignores the header, implement the fallback in decision 2 and say so in your report. Add the `appliance-corpus` job to `ci.yml` exactly as decision 7 says, in the file's commenting style. Explain in comments why the secret is confined to one step and why the fork gate exists. Do not cite plan phases or decisions in code. Run `pre-commit run --all-files` and the audit script. This step cannot run the job; the management session pushes and watches it after 5e. Commit subject: `Run the appliance corpus in CI.` |
| 5c | high | opus | none | The source URL, to decision 8. Read the plan whole, then `shakenfist_client_ova/__init__.py`, `tests/test_command.py` and `docs/usage.md`. In `_upload()` and its callers, stop building and passing a source URL. After each artifact is created, set `ova_file` (the OVA's `os.path.realpath`) and `ova_member` with `client.set_artifact_metadata_item()`. Before uploading, look each artifact name up with the client's existing artifact lookup and print whether the import creates a new artifact or adds a version to an existing one; check client-python's `apiclient.py` (in `/home/mikal/src/shakenfist/client-python`) for the right call, and handle a 404 as "new". Update the `CliRunner` tests: no `source_url` reaches either upload path (assert the call arguments), the two metadata calls per disk, both "new" and "adds a version" messages, and that a metadata failure is reported in one line, not a traceback. Remove every `ova://` from code and tests. Mutation-check that a source URL sneaking back into either path fails a test, restoring from a copy. Do not cite plan phases or decisions in code. Run `tox -epy3`, `pre-commit run --all-files`, `.tox/py3/bin/python -c 'import shakenfist_client_ova'` and the audit script. Unit tests suffice. Commit subject: `Use the server's source URL for artifacts.` |
| 5d | medium | sonnet | none | Documentation. `docs/development.md`: describe the appliance corpus tier beside the descriptor tier: what it runs, `APPLIANCE_CORPUS`, how to run it against a local `instar-testdata` checkout, that it fails rather than skips without one, and that CI runs it only for same-repository branches. `docs/usage.md`: replace the source URL text with decision 8's naming, re-import and metadata behaviour, and the two metadata keys. `ARCHITECTURE.md` only if its test-tier summary lists the tiers; then add the third in one line. `AGENTS.md`: one Code Conventions line, saying that the appliance corpus is private and that tests and logs carry outcome names, never descriptor text. Read the code, not the plan, for anything the docs state. Never write a plan phase number in these files. Run `pre-commit run --all-files` and the audit script; `plan-phase-references`, `llm-doc-structure` and `readme-structure` must pass. Commit subject: `Document the appliance tier and artifact names.` |
| 5e | - | operator | - | **Before the pull request is pushed**, the operator:<br>• creates the token of decision 4;<br>• adds the `GITLAB_TESTDATA_TOKEN` secret, and the `GITLAB_TESTDATA_USER` variable if the token is not a project access token;<br>• confirms that `[self-hosted, debian-13, xl, instar]` is the right label set for a job that only reads `downloaded/ova/`;<br>• records the token's expiry in this plan's execution notes.<br><br>**After the job has run green**, the operator decides whether `appliance-corpus` becomes a required check. |

5a and 5c are independent and can run in parallel. 5b needs 5a's tox
environment. 5d needs 5a to 5c.

The management session reviews each step. After 5a, it runs
`tox -eappliance-corpus` against the local checkout itself and compares
the per-appliance outcomes with phase 4's table. After 5c, it imports
one whole corpus appliance against the cluster `~/.shakenfist` points
at, but only if the operator says so at the time. It then checks the
artifact's source URL and metadata, and that a second import adds no
version.

## Risks and mitigations

1. **git-lfs ignores `http.extraHeader` given with `-c`.** Then the LFS
   pull fails to authenticate, or the fallback is needed. Mitigation:
   5b proves the behaviour locally before the job exists, and the
   fallback is decided in advance (decision 2). Either way, the script's
   final search for the token fails the job if a credential reached
   disk.
2. **Someone with push access reads the token.** The fetch step runs
   `tools/ci/` from the branch under test. Accepted, as the master plan
   accepts it: the token is read-only and reaches one repository of test
   data. Decision 4 keeps it this repository's own, so it can be revoked
   alone.
3. **The cache update fetches the whole tree's new history.** Updating
   to `origin/main` touches every directory, not just `downloaded/ova`.
   The depth-1 fetch is small, and LFS objects outside `downloaded/ova`
   are not pulled. Accepted: the alternative tests a stale corpus.
4. **An `instar` runner is the wrong size or is scarce.** `xl` is what
   instar uses, not what this job needs. Mitigation: 5e asks the
   operator. The job reads 2 GB and runs no VM, so a smaller label with
   the testdata disk would do, if the fleet has one.
5. **Private data reaches a log.** The CyberOps descriptors are
   publishable, but the habit matters more than these two. Mitigation:
   decision 6 limits assertion messages to names and outcomes, and the
   management session reads the first CI log before calling the phase
   done.
6. **Two appliances share an artifact name.** Decision 8 makes the name
   the identity. Mitigation: the command says when an import adds a
   version to an existing artifact, so a collision is visible and not
   silent.

## Definition of done

* With `APPLIANCE_CORPUS` pointing at a full `downloaded/ova`,
  `tox -eappliance-corpus` passes with 16 per-appliance tests. Each of
  the four guard cases in decision 5 makes it fail, not skip.
* `tox -epy3` lists none of the appliance tests, and the built wheel
  contains no `appliance_tests`.
* `grep -c GITLAB_TESTDATA_TOKEN .github/workflows/ci.yml` prints 1, and
  that step comes before every `pip install` in its job.
* `grep -rn 'set-url\|oauth2:\${\|@gitlab' tools/ci/fetch-appliance-corpus.sh`
  prints nothing.
* `tools/ci/test-fetch-appliance-corpus.sh` runs in the lint job and
  passes.
* The `appliance-corpus` job has passed on this phase's pull request.
  Its run is linked in the execution notes, and its log shows no
  descriptor text and no token.
* `grep -rn 'ova://' shakenfist_client_ova docs/usage.md` prints
  nothing.
* A `CliRunner` test fails if either upload path is given a source URL.
* `tox -epy3`, `tox -edescriptor-corpus`, `pre-commit run --all-files`
  and `.tox/py3/bin/python -c 'import shakenfist_client_ova'` pass, and
  the consistency audit reports no failure.
* The master plan's Execution table and `docs/plans/index.md` agree, and
  this phase's Merged cell is left for phase 6's first commit.

## Corrections made to the master plan

Made in this phase's planning commit:

* Phase 5's section no longer says to adapt instar's script, or that
  the job pulls only `downloaded/ova/` instead of the whole 9 GB. On an
  `instar` runner the tree is the fleet's pre-built disk. The job
  updates it and pulls only `downloaded/ova/`'s LFS objects, with the
  token passed in a header rather than written to disk. The section
  also gains the source URL change.
* Open question 3 is resolved: `[self-hosted, debian-13, xl, instar]`,
  as instar uses.
* Phase 4's section said the source URL was built from the OVA's
  "absolute path", but the code used its real path. It now says so, and
  that phase 5 replaces the URL.

## Back brief

Before executing any step of this plan, back brief the operator on
your understanding of the plan and how the work you intend to do
aligns with it. Two points need the operator's answer before 5b's
output is pushed:

* step 5e, the token and the runner labels;
* whether the management session may run the live import after 5c.

## Execution notes

Dates here are the operator's local time, AEDT (UTC+11); CI timestamps
are UTC.

* **The steps ran in sequence, not in parallel.** 5a and 5c both run
  `pre-commit` and `tox` in the same worktree, so running them together
  would have had each tripping over the other's half-finished work. The
  order was 5a, 5c, 5b, 5d.
* **5a passed 17 of 17 against the local corpus.** That is 16
  appliances and the corpus check, run by the management session, and
  every outcome matches phase 4's table. The sub-agent also added an
  offline unit test of the guard, `tests/test_appliance_guard.py`, which
  runs in `py3`. It was kept, so that CI checks the guard even without a
  corpus.
* **The review sent 5c back for two defects.**
  * Suppose the caller's namespace already held an artifact with the
    name but a source URL no upload gives, such as one made by
    `artifact cache`. The server would then have made a second artifact
    with the same name, and the name would stop looking up. This is now
    refused before any disk is read.
  * "Adding a version" was false for an unchanged disk, because the
    server skips a version whose sha512 matches the latest. The line
    now says "into the existing artifact".

  The lookup also treats an artifact found only in another namespace
  (shared, or trusting the caller) as new, because an upload never adds
  to it.
* **5b found two git-lfs behaviours the plan did not anticipate.**
  * When git-lfs fails, it writes its environment, header included,
    into `.git/lfs/logs/`. That happens whichever way the header is
    passed: `-c` travels as `GIT_CONFIG_PARAMETERS`.
  * After a 401, git-lfs records `lfs.<url>.access` in `.git/config`.

  The script presets that access mode, so nothing is written. Its final
  check, which also runs from an `EXIT` trap, removes any log that
  captured the header and fails closed if the token or its base64 form
  remains anywhere under `.git`. The credential is passed through
  `GIT_CONFIG_*` environment variables rather than `-c`, because a
  process's environment is readable only by its owner, while its
  command line is readable by anyone on the host. The review added
  `persist-credentials: false` to the job's checkout.
* **Live check after 5c, 2026-10-18.** The operator approved it, and it
  ran against the cluster `~/.shakenfist` points at. `vyos-1.2.1`,
  imported from `dc625df`, got:
  * the source URL `sf://upload/system/VyOS-vmdisk1`;
  * both metadata keys.

  A second import said "into the existing artifact" and reused the
  blob. That left one artifact with one version. The artifact was
  deleted afterwards.
* **Definition of done, before CI.**
  * `py3` passes 495 tests and collects none of the appliance tier.
  * The wheel carries no test package.
  * `GITLAB_TESTDATA_TOKEN` appears once in `ci.yml`, before the job's
    `pip` lines.
  * The credential grep is empty, and the fetch script's guard test
    passes.
  * No `ova://` remains.
  * `descriptor-corpus` passes 4 of 4.
* **Step 5e departed from decision 4.** The operator shared the
  organisation-wide `GITLAB_TESTDATA_TOKEN` secret with this
  repository, rather than creating a token dedicated to it. It is the
  token instar's jobs use, with the `oauth2` username, which is the
  fetch script's default, so no `GITLAB_TESTDATA_USER` variable is
  needed. The consequence decision 4 was written to avoid now applies:
  revoking the token breaks instar and this repository together, and
  its scope and expiry are whatever the organisation secret's are. That
  was the operator's call. The script's handling of the credential does
  not depend on which token it is given.
* **The first `appliance-corpus` run passed on #18 at `2d1ec70`:**
  [run 39076633861](https://github.com/shakenfist/client-python-ova/actions/runs/39076633861/job/117525028241).
  * It took 3m41s, about three minutes of which were the update of the
    fleet's cached tree.
  * 16 appliances, and 17 tests passed with none skipped.
  * The log carries no descriptor text, and no credential except
    `actions/checkout`'s own GitHub token header, which GitHub masked.
* **The first review round took two fix items and six consider items.**
  * The corpus test's client mock is now configured explicitly, instead
    of relying on two MagicMocks comparing unequal.
  * `_api_error` no longer prints "None" for an empty body.
  * Absent members are compared without regard to order.
  * The fetch script refuses a cache whose repository config carries a
    key outside an allow-list drawn from the fleet disk's build. Every
    git command in the tree now runs with the system and global config
    emptied, hooks and fsmonitor off, the git-lfs filter pinned, and
    `safe.directory` set for exactly the cache.
  * The corpus directory is cleaned after the reset.
  * The job's checkout action is pinned to a commit.
  * The credential checks have offline tests.
  * `docs/usage.md` says that a metadata failure stops the import.

  The allow-list refuses a developer checkout's `pull.rebase` and
  `remote.origin.glab-resolved`. That is deliberate, because the script
  runs only on the fleet disk.
* **The config guard accepts the real fleet disk.** The
  `appliance-corpus` job passed again at `8adbe7a`, with the guard and
  the git hardening in place.
* **The second review round raised one fix item, which was wrong.** It
  said `ApiErrorTestCase` re-ran every command test. Its base class,
  `CommandTestCase`, defines no tests, and `stestr list` shows no
  duplicate ids. The round's document and consider items were taken:
  * missing server fields are handled without a traceback;
  * the fetch script self-tests that git honours `GIT_CONFIG_*` and
    `GIT_CONFIG_GLOBAL` (git 2.32);
  * it deletes every LFS log before authenticating, and exits through
    its credential check on INT and TERM;
  * a whole appliance must check at least one disk's digest.
* **#18 merged as `248ecd3` on 2026-10-18, without a third review
  round.** The second round's only fix item was wrong, and its other
  items were taken, so nothing was left for a third round to check.

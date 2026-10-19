# Development

## Setting up

```bash
python3 -m venv ~/venv-ova
. ~/venv-ova/bin/activate
pip install -e .
sf-client ova --help
```

The plugin registers through the `shakenfist_client.plugin` entry
point group, so once installed alongside `sf-client` its commands
appear without further configuration.

## Linting

Every linter this repository uses runs from pre-commit:

```bash
pip install pre-commit
pre-commit install
pre-commit run --all-files
```

The hooks are skillsaw over the agent context, actionlint over the
workflows, shellcheck over the shell scripts, and flake8 over the
Python, wrapped at 120 characters.

## Unit tests

The tests live in `shakenfist_client_ova/tests/` and follow the
client-python pattern of testtools run by stestr:

```bash
pip install tox
tox -epy3
```

`test_ovf_golden.py` runs the parser over every `.ovf` under
`shakenfist_client_ova/tests/fixtures/ovf/`, one test per descriptor.
Beside each descriptor is an `.expected.json` file. For a descriptor
that parses it is exactly `ovf.to_json()` of the result. For one that
is refused it holds the error's name (`ovf.outcome_name()`, a bare
class name such as `UnparsedContentError`) and a
`message_contains` fragment, which a person chooses as a phrase that
will survive rewording. A test fails if a descriptor has no expected
file or an expected file has no descriptor.

Never hand-edit an expected file. Regenerate them with
`OVF_UPDATE_EXPECTED=1 tox -epy3`, which rewrites every file whose
outcome changed and then fails, so that the variable cannot be left on
in CI. Review the rewritten files with `git diff`, replace any
`CHOOSE A STABLE FRAGMENT` placeholder, and run the tests again
without the variable.

`test_ovf_boundary.py` enforces that `shakenfist_client_ova/ovf/`
imports neither `click` nor `shakenfist_client`, imports only the
modules on its allowed list, and never prints or exits.

## Test fixtures

The parser's tests draw on three kinds of input, and the path of a
fixture says where it came from.

| Directory | Holds |
|-----------|-------|
| `shakenfist_client_ova/tests/fixtures/ovf/vendor/` | One trimmed descriptor per appliance in the corpus, named for the appliance and version. |
| `shakenfist_client_ova/tests/fixtures/ovf/handwritten/` | One descriptor per edge case in the master plan. Each opens, after the XML declaration, with a comment naming its case and the behaviour it tests. |
| `shakenfist_client_ova/tests/fixtures/ova/imported/glance/` | Five small archives imported unmodified from OpenStack Glance. `NOTICE` records the source commit, the licence and each file's SHA-256. |

`shakenfist_client_ova/tests/synthetic.py` builds the archives that no
surveyed producer writes, so the archive checks are tested without
committing binaries. `build()` writes a USTAR tar from a list of
members, each a `(name, data)` pair or one of `regular()`,
`symlink()`, `hardlink()`, `directory()`, `fifo()` and `device()`.
Names are written exactly as given, so a `./` prefix is kept and two
members may share a name, and every member has the same owner, mode
and time, so one list always builds the same bytes. Pass
`compressed=True` for a gzipped archive or `truncated=True` for one
cut short. Build into a temporary directory the test owns.

The `ova/` directory is the one place `.ova` files are committed: the
global `*.ova` rule in `.gitignore` is negated for it, so keep
fixtures there small and deliberate.

### Vendor descriptors

This repository is public, and a vendor descriptor can carry licence
text, product marketing and, from VirtualBox, the exporting host's
configuration. So a file in `vendor/` is only ever a copy made by
`tools/trim-ovf-descriptor.py`, and is never hand-edited. The tool
replaces the content of every prose element with `TRIMMED` and empties
the ignored vendor elements on its `EMPTIED_ELEMENTS` list, and it
inserts one comment naming the source URL and the SHA-256 of the
original. It splices bytes rather than re-serialising, so prefixes,
comments and whitespace are the original's. `--check` proves that
nothing else changed.

`--check` needs the original, which only `instar-testdata` holds, so
the unit tier instead runs a test over the committed files alone: each
must carry the provenance comment, every prose span must be exactly
`TRIMMED`, and every emptied element must be empty and keep only its
allowed attributes. The appliance corpus tier, below, has the
originals, and checks that each fixture still parses as its original
does. The fixtures are marked `-text` in
`.gitattributes` so that git never rewrites their line endings, and
any whitespace hook added later must exclude them.

A leak in an ignored vendor element is fixed by adding an entry to
`EMPTIED_ELEMENTS` and re-running the tool, never by editing a
fixture. The prose list (`PROSE_ELEMENTS`) is a defect to fix in the
same way if it misses something. It lives in
`shakenfist_client_ova/ovf/prose.py`, shared by the trim tool and the
parser's `scrub()`, which keeps upstream prose out of the curated
expected file described below.

### The appliance corpus

The originals live in the separate `instar-testdata` repository, under
`downloaded/ova/`, as Git LFS objects. An entry is either whole (the
full `.ova`, for the small appliances) or descriptor-only (a re-tar of
just the descriptor and manifest, with the disks removed). Each entry
has a `<name>.provenance.json` recording the source URL, the
checksums, every member of the original archive, the manifest check
and, for a descriptor-only entry, the absent members. The README's
table there is generated, not edited: `scripts/fetch-ova-corpus.py --readme`
prints it.

To add an appliance:

1. Add an entry to `downloaded/ova/sources.json` in `instar-testdata`
   (`name`, `url` or `local_path`, `kind`, `producer`,
   `vendor_checksum` or `null`, `redistributable`, and a `note`). The
   vendor checksum is a literal; the script never fetches one.
   `redistributable` is `true` only where an open-source licence or the
   vendor's stated terms plainly allow republishing the appliance,
   `false` where they do not, and `null` until someone checks. Only a
   `true` entry's `.ova` may be copied anywhere public, this
   repository's `tests/fixtures/ova/` included. A trimmed descriptor is
   not the appliance, so it is published for every entry.
2. Run `scripts/fetch-ova-corpus.py --only <name>`. It streams the
   archive once, verifies the vendor checksum and the archive's own
   manifest, and writes the `.ova` and provenance file. A second run
   changes nothing unless you pass `--force`. For the two local
   CyberOps exports, `--local-dir` names the directory holding the
   files. If an `.ova` is still an LFS pointer the script stops and
   tells you to run `git lfs pull --include downloaded/ova`.
3. Extract the `.ovf` member into a scratch directory. It is downloaded
   data, so run any Python that reads it with `python3 -I`.
4. Trim it, using the URL from its `provenance.json` as the source (for
   a local entry, `--source 'a local export, <name>.ova in
   instar-testdata'`):

   ```bash
   .tox/py3/bin/python -I tools/trim-ovf-descriptor.py --source URL ORIGINAL \
       shakenfist_client_ova/tests/fixtures/ovf/vendor/<name>.ovf
   .tox/py3/bin/python -I tools/trim-ovf-descriptor.py --check ORIGINAL \
       shakenfist_client_ova/tests/fixtures/ovf/vendor/<name>.ovf
   ```

   The tool needs `defusedxml`, which the `test` extra installs, so
   run it with the tox environment's Python after `tox -epy3`.

5. Read the result, then check that nothing identifying remains:

   ```bash
   grep -rliE '/home/|/Users/|[A-Za-z]:\\|copyright|\(c\)|@' \
       shakenfist_client_ova/tests/fixtures/ovf/vendor/
   ```

   It should find nothing, or only files whose every match you have
   read and can justify.

### Upstream descriptor collections

The tests also draw on the descriptors in two upstream projects,
govmomi (`ovf/fixtures`) and COT (`COT/tests`). They are not committed:
`tools/fetch-descriptor-corpus.sh` fetches each at an exact commit
into `.cache/ovf-corpora/<repo>-<sha>/`, which is gitignored. The
script holds the pins and is their source of truth. It fetches into a
`.tmp` directory, checks `git rev-parse HEAD` against the pin, and only
then renames it into place, so an interrupted fetch never looks
complete.

Which descriptors the tests use is decided by a rule, not by hand.
`tools/classify-ovf-corpus.py` classifies the descriptors by shape and
chooses the smallest examples of each. `shakenfist_client_ova/corpus_tests/curated.txt`
is exactly its output and is never edited. To add or drop a descriptor,
add a line to `curated-overrides.txt` beside it (`+<repo>:<path>` or
`-<repo>:<path>`, a tab, and the reason), then regenerate. The command
is in the tool's docstring. After bumping a pin, regenerate and
review what changed.

### Descriptor corpus tier

A second test tier runs the parser over every descriptor in the two
upstream collections, in `shakenfist_client_ova/corpus_tests/`:

```bash
tox -edescriptor-corpus
```

It needs the network: it first runs `tools/fetch-descriptor-corpus.sh`.
It is outside the default `tox -epy3` run, which stays offline. Its
tests read the pinned commits from that script, so the pins have one
home, and they fail, never skip, if a corpus has not been fetched, so
a missing corpus cannot look like a clean run.

* `ledger.txt` records the outcome of every descriptor, one
  `<repo>:<path>`, a tab and `model` or the outcome name per line.
  A change in what the parser accepts or refuses shows up as a diff
  of the ledger.
* `curated.expected.json` holds the full expected parse of each
  descriptor in `curated.txt`, with prose scrubbed so that no upstream
  text is committed.
* A test checks that the classifier still reproduces `curated.txt`.

Like the unit-tier expected files, the ledger and the curated expected
file are regenerated with `OVF_UPDATE_EXPECTED=1 tox -edescriptor-corpus`
(which then fails) and never hand-edited.

### Appliance corpus tier

A third tier runs the parser, the digest checks and the import command
over the real appliances in the private `instar-testdata` repository,
in `shakenfist_client_ova/appliance_tests/`. It takes each appliance in
`downloaded/ova` and the outcome from its provenance file: a whole
appliance must open, match its manifest and import (with the client
mocked) uploading each disk once; a descriptor-only one must fail with
`MissingMemberError` naming exactly the members it omits. The
appliances named in `expected.json` are the exceptions, each with the
outcome it must produce.

A second test per appliance checks its trimmed fixture against the
original. It parses the descriptor that `open_package()` reads from
the `.ova` and the fixture in `tests/fixtures/ovf/vendor/`, replaces
the prose in each model with `prose.scrub()`, and requires the two
`to_json()` serialisations to be equal. A descriptor the parser
refuses, as it does Oracle Linux's and Tails', must instead be refused
with the same outcome name as its fixture. So every appliance needs a
fixture, and every fixture an appliance: either missing fails the
tier.

`APPLIANCE_CORPUS` names the `downloaded/ova` directory. To run it
against a local checkout:

```bash
git lfs pull --include 'downloaded/ova/**'   # in the checkout
APPLIANCE_CORPUS=<checkout>/downloaded/ova tox -eappliance-corpus
```

It fails, never skips, if the variable is unset or the corpus is
missing, still Git LFS pointers, or lacks a provenance file. The corpus
is private, so assertion messages carry appliance, artifact and outcome
names and counts only, never descriptor or manifest text or a member's
name. Where two models differ, a message says that they differ, not
how. The offline unit tier
has a guard test (`tests/test_appliance_guard.py`, in `tox -epy3`) for
the tier itself.

In CI the `appliance-corpus` job runs only for branches of this
repository, not forks, on runners with the `instar` label that carry
the testdata disk. `tools/ci/fetch-appliance-corpus.sh` updates the
tree there using a read-only token held as a repository secret. It
refuses a tree whose repository configuration carries keys a clone of
instar-testdata does not, such as a hook path or an include, and runs
git there without the runner's system or global configuration and with
hooks off. The script's offline test,
`tools/ci/test-fetch-appliance-corpus.sh`, runs in the lint job.

### Adding a producer quirk

When an appliance is refused because its producer deviates from the
schema, add an entry to `shakenfist_client_ova/ovf/quirks.py` naming
the producer and giving the evidence: a fixture, or the corpus
descriptors that show it. Never special-case the deviation in the
parser. Then regenerate the expected files with
`OVF_UPDATE_EXPECTED=1 tox -epy3` (and `-edescriptor-corpus`), and
review the diff.

## CI

| Workflow | Runs | What it does |
|----------|------|--------------|
| `ci.yml` | Pull requests, merge queue entries, dispatch | Three jobs: the pre-commit hooks, the unit tests, the fetch script's guard test, and an sdist and wheel build with a check of the wheel's contents; the descriptor corpus tier (`tox -edescriptor-corpus`); and the appliance corpus tier (`tox -eappliance-corpus`), which skips fork pull requests. Then the automated reviewer on pull requests, and the "Can enqueue" and "Can merge" checks the merge queue requires. |
| `secret-scan.yml` | Pull requests, pushes to `develop`, dispatch | gitleaks over the history, after a positive control. `tools/gitleaks-scan.sh` runs the same scan locally. |
| `codeql-analysis.yml` | Pull requests, pushes, weekly | CodeQL. |
| `pr-re-review.yml` | A "please re-review" comment | Another automated review. |
| `pr-retest.yml` | A "please retest" comment | Dispatches the workflow named by the `RETEST_WORKFLOW` repository variable, which is `ci.yml` here. |
| `renovate.yml` | Hourly | Dependency and pre-commit hook bumps. |
| `export-repo-config.yml` | Daily | Exports the repository settings to `.github/exported-config/`. |
| `release.yml` | A `v*` tag | The release, as below. |

### Merging

Pull requests merge through a merge queue on `develop`, not with the
merge button directly. A pull request can be queued once its "Can
enqueue" check passes. The queue then runs `ci.yml` again on the
commit it is about to merge, and merges only when "Can merge" passes.
That second run is the one a release counts (see below), so a change
merged around the queue, by an administrator bypassing it, cannot be
released until a later commit has gone through the queue.

The wheel check in the lint job is
[`check-dist`](https://github.com/shakenfist/actions/blob/main/docs/actions.md#check-dist).
It fails if the wheel holds a test directory, so a packaging change
that would ship the tests fails on its pull request rather than at
release time.

## Releasing

Pushing a `v*` tag triggers `release.yml`. Its jobs, in order:

1. `ci-gate` checks that `ci.yml` succeeded on the tagged commit, in
   its merge queue run. A commit that only added
   review marks after a merge is checked through its parent. How the
   gate decides is documented with the action, as
   [`require-ci-success`](https://github.com/shakenfist/actions/blob/main/docs/actions.md#require-ci-success).
   It has no override.
2. `build` builds the sdist and wheel, then runs `twine check` and the
   same wheel check as CI. It runs only if the gate passed.
3. The publishing jobs wait for approval in the `release`
   environment, re-sign the tag with gitsign, and publish to PyPI with
   attestations.

So tag a commit that is on `develop` and went through the merge
queue, and wait for its `ci.yml` run to finish first. A gate failure
means nothing was signed or published, so every failure is
recoverable: the template's
[recovery table](https://github.com/shakenfist/development/blob/main/templates/release-automation/README.md#recovering-from-a-gate-failure)
says what to do for each cause, which is usually moving the tag or
re-running CI and then the `ci-gate` job.

Running `release.yml` by hand with `workflow_dispatch` skips the gate
and the publishing jobs, and only builds and checks the packages.

The version comes from the tag through setuptools_scm. The one-time
setup, and how to verify a release, are in `RELEASE-SETUP.md`.

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

## Test fixtures

The parser's tests draw on three kinds of input, and the path of a
fixture says where it came from.

| Directory | Holds |
|-----------|-------|
| `shakenfist_client_ova/tests/fixtures/ovf/vendor/` | One trimmed descriptor per appliance in the corpus, named for the appliance and version. |
| `shakenfist_client_ova/tests/fixtures/ovf/handwritten/` | One descriptor per edge case in the master plan. Each opens, after the XML declaration, with a comment naming its case and the master plan clause it tests. |
| `shakenfist_client_ova/tests/fixtures/ova/imported/glance/` | Five small archives imported unmodified from OpenStack Glance. `NOTICE` records the source commit, the licence and each file's SHA-256. |

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
CI instead runs a unit test over the committed files alone: each must
carry the provenance comment, every prose span must be exactly
`TRIMMED`, and every emptied element must be empty and keep only its
allowed attributes. The fixtures are marked `-text` in
`.gitattributes` so that git never rewrites their line endings, and
any whitespace hook added later must exclude them.

A leak in an ignored vendor element is fixed by adding an entry to
`EMPTIED_ELEMENTS` and re-running the tool, never by editing a
fixture. The prose list (`PROSE_ELEMENTS`) is a defect to fix in the
same way if it misses something.

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

## CI

| Workflow | Runs | What it does |
|----------|------|--------------|
| `ci.yml` | Pull requests, pushes to `develop`, dispatch | The pre-commit hooks, the unit tests and an sdist and wheel build, then the automated reviewer on pull requests. |
| `secret-scan.yml` | Pull requests, pushes to `develop`, dispatch | gitleaks over the history, after a positive control. `tools/gitleaks-scan.sh` runs the same scan locally. |
| `codeql-analysis.yml` | Pull requests, pushes, weekly | CodeQL. |
| `pr-re-review.yml` | A "please re-review" comment | Another automated review. |
| `pr-retest.yml` | A "please retest" comment | Dispatches the workflow named by the `RETEST_WORKFLOW` repository variable, which is `ci.yml` here. |
| `renovate.yml` | Hourly | Dependency and pre-commit hook bumps. |
| `export-repo-config.yml` | Daily | Exports the repository settings to `.github/exported-config/`. |
| `release.yml` | A `v*` tag | The release, as below. |

## Releasing

Pushing a `v*` tag triggers `release.yml`, which builds the
distribution, waits for approval in the `release` environment,
re-signs the tag with gitsign, and publishes to PyPI with
attestations. The version
comes from the tag through setuptools_scm. The one-time setup, and
how to verify a release, are in `RELEASE-SETUP.md`.

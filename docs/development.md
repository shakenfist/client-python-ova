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

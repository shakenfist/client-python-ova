# Agents Guide

## Project Overview

This is a plugin for
[sf-client](https://github.com/shakenfist/client-python), the command
line client for [Shaken Fist](https://github.com/shakenfist/shakenfist).
It adds an `ova` command group which imports OVA appliances: it parses
the OVF descriptor and uploads the disk images as artifacts. What an
import does, step by step, is in `docs/usage.md`; how the code is laid
out is in `ARCHITECTURE.md`.

## Quick Start

```bash
pip install -e .
sf-client ova --help
pre-commit run --all-files
tox -epy3
```

Unit tests live in `shakenfist_client_ova/tests/` (testtools and
stestr). `docs/development.md` covers setup, testing, linting, CI and
releasing.

## Code Conventions

- Python >= 3.7 compatibility, matching `shakenfist_client`. The
  floor is `requires-python` in `pyproject.toml` and
  `constraints.python` in `renovate.json`; change both together.
  Syntax newer than the floor fails only on the old interpreters,
  where nothing in CI runs -- an f-string nesting its own quote
  character, legal only from 3.12, once took the whole command group
  away there.
- Single quotes for strings, double quotes for docstrings.
- Max line length: 120 characters, enforced by flake8 through
  pre-commit.
- The plugin must never break `sf-client` startup. It is imported
  unconditionally by the plugin loader, so a syntax error or a failing
  top-level import takes every `sf-client` command down with it, not
  just `ova`. Check `python -c 'import shakenfist_client_ova'` after a
  change.
- The OVF parser is strict on purpose: each section it understands is
  deleted from the parsed descriptor as it is consumed, and anything
  left over stops the import. Supporting a new section means
  consuming and deleting it, never loosening the final check. See
  "When an import stops" in `docs/usage.md`.

## When Making Changes

- Document user-visible behaviour in `docs/usage.md`.
- Update `ARCHITECTURE.md` only when the shape of the import changes.
- Large `.ova` files used for manual testing are gitignored; keep it
  that way.
- Plans live in `docs/plans/`, start from `PLAN-TEMPLATE.md`, and are
  registered in `docs/plans/index.md`.

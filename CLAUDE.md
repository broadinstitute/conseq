# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Conseq ("con-SIK") is a Python workflow tool: a `.conseq` file declares artifacts (key/value property sets, optionally referencing files) and rules (inputs query → commands to run → output artifacts). Conseq repeatedly matches artifacts against rule inputs, runs executions, and records results in a SQLite state DB. The README documents the `.conseq` file syntax (let / add-if-missing / rule / etc.) and CLI in detail.

## Commands

- Install: `poetry install` (Python ^3.9; entry points `conseq` → `conseq.main:main`, `conseq-helper`)
- Run all tests: `poetry run pytest`
- Single test: `poetry run pytest tests/conseq/depexec_test.py::test_name`
- Randomized scheduler tests are excluded from a plain `pytest`; run them with `poetry run pytest -m fuzz` (see `doc/fuzz-testing.md`)
- Type check (CI uses a ratchet, errors may not increase): `poetry run pyright-ratchet run pyright` (baseline in `pyright-ratchet-errors.txt`)
- Regenerate parser after editing `conseq/parser/depfile.grako`: `./compile_grammar.sh` (runs `tatsu` to produce `conseq/parser/depfile.py`; the generated file is checked in)
- CLI: `conseq run file.conseq`, `conseq ls`, `conseq lsexec`, `conseq rm`, `conseq forget`, `conseq gc`, `conseq report`, `conseq export`, `conseq analyze`, etc. (subcommands defined in `conseq/cli/parser.py`, implemented in `conseq/cli/commands.py` / `conseq/commands.py`)

Note: `tests/conftest.py` (currently untracked) turns `DeprecationWarning` into errors.

## Architecture

- **Parsing** (`conseq/parser/`): TatSu grammar → generated `depfile.py`; `semantics.py` builds the model in `model.py`. `conseq/config.py` (`read_rules`) turns a parsed file into a `Rules` object (rules, variables, add-if-missing artifacts, remote/exec-profile config) and handles includes and `~/.conseq` settings.
- **State / matching** (`conseq/dep.py`): `Jobs` is the SQLite-backed store of objects (artifacts), rule executions and their status. `RuleSet`/`Template`/`ForEach`/`ForAll` implement matching artifacts against rule input queries to produce `RuleExecution`s. Reconciling the DB with the current conseq file (removing stale rules/artifacts and downstream results) happens here at `run` start.
- **Scheduling loop** (`conseq/depexec.py`): `main()` drives the run: reconcile rules, repeatedly ask `Jobs` for new executions, dispatch to an exec client, poll for completion, record outputs, and handle publishing/resolving.
- **Execution backends** (`conseq/exec_client.py`): `LocalExecClient` (local processes via wrapper scripts), `DelegateExecClient`/`AsyncDelegateExecClient` (delegate to an external executor such as sparkles/dsub, using a CAS "remote" to stage inputs/outputs and results), and `PublishExecClient`. Includes xref/URL resolution of inputs and output type validation.
- **Remote storage** (`conseq/helper.py`): `Remote` abstraction over local/S3/GCS used for content-addressable storage of files.
- **Other**: `static_analysis/` (`conseq analyze`), `template.py` (Jinja2 rendering of rule commands), `xref.py` (external reference resolvers), `report.py`/`ui.py`/`static/` (HTML report and UI), `timeline.py`.

## Tests

Tests live in `tests/conseq/` (`*_test.py` plus `test_*.py`); `functional_test.py` and `main_test.py` run end-to-end `.conseq` scripts. Example/sample pipelines are in `samples/` and `examples/`.

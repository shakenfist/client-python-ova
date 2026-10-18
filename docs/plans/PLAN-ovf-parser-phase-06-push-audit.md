# OVF parser phase 6: the push audit

## Prompt

Before responding to questions or discussion points in this document,
read the master plan, [PLAN-ovf-parser.md](PLAN-ovf-parser.md),
particularly decision 1, decision 8 and phase 6's section, which
carries the `plan-push-audit-phase` shared block and its checklist.
Then read the execution notes of every phase plan, from
[phase 1](PLAN-ovf-parser-phase-01-corpus.md) to
[phase 5](PLAN-ovf-parser-phase-05-corpus-ci.md). They record what
each phase found and declined, and this audit checks those records
against what landed.

This phase changes no code. It reads what the five phases put on
`develop`, records a verdict for each checklist item and each of the
plan's own questions, and decides what happens to anything it finds.
Fixes land afterwards, in their own pull request.

Two of the corpus's appliances may be held but not republished.
Everything this audit writes into this public repository is a verdict,
a path, a command or a count, never the content of a private file.

## Planning effort

High: this is the last check before the plan is called complete, and
it is the only phase whose own output could leak the private corpus.
Review effort: high for step 6c and for the record that 6e writes.
Medium for the rest.

## Scope

In scope:

* The five recorded landings on `develop`, each read against its first
  parent, and their accumulated diff `db7bdaa^1..248ecd3`, read for
  what the phases did to each other.
* The five checklist items in the shared block, and the four questions
  in the master plan's phase 6 section.
* Two questions this survey added: what reaches PyPI (survey finding
  6), and whether private corpus content reaches any public place
  other than the repository (survey finding 4).
* A verdict for each item, recorded in this plan, and a decision for
  each finding.

Out of scope:

* **Fixing findings.** They land as their own pull request against
  `develop`, after this phase merges. The shared block requires this.
* **The `instar-testdata` range `18a5ea5421..cf67642bbb`.** Phase 1
  audited it before pushing it (survey finding 2). This phase cites
  that audit rather than re-running it, as the shared block requires.
* **The two Renovate merges, #15 and #17.** They landed on `develop`
  between phases but are not plan work.
* **Code that predates the plan.** An observation about it is filed as
  an issue, not counted as a finding (decision 4).
* **Writing a `PUSH-AUDIT.md`.** The shared block says what a
  repository without one does. Whether this repository should have one
  is a question for after this audit, informed by what it found.
* **Issue #12** (a traceback from the trim tool). It is already filed.

## What the survey found

The master plan's phase 6 section was checked against the tree at
`248ecd3`. Its claims hold. The corrections below add to it rather
than contradict it, and they are made at the source in this phase's
planning commit.

### 1. Phase 5 is complete

* #18 merged as `248ecd3`, and the merge is an ancestor of `develop`.
* The master plan and `docs/plans/index.md` both read `In progress`.
* Three definition-of-done items were checked against `develop`:
  * `GITLAB_TESTDATA_TOKEN` appears once in `ci.yml`;
  * the credential grep over the fetch script prints nothing;
  * no `ova://` remains in the package or in `docs/usage.md`.
* The phase's worktree and branch were removed after the merge.
* What the phase declined or found outside its scope is recorded in
  its execution notes. #4557 is linked from phase 4's notes.
  shakenfist/shakenfist#4558 and #4559, and
  shakenfist/client-python#430, are upstream bugs found in passing
  during phase 5. They were filed, but no phase record links them
  (corrected by the audit; phase 5's execution notes now link them).

### 2. The recorded landings take the forms the checklist allows

Each of the five `Merged` cells names a merge commit with two parents.

| Phase | Merge | PR | Files | Insertions | Deletions |
|-------|-------|----|-------|------------|-----------|
| 1 | `db7bdaa` | #10 | 53 | 6033 | 13 |
| 2 | `97273c7` | #13 | 84 | 5637 | 565 |
| 3 | `b1f8894` | #14 | 64 | 9876 | 1810 |
| 4 | `a8f44bf` | #16 | 22 | 3677 | 295 |
| 5 | `248ecd3` | #18 | 19 | 2504 | 76 |

`git log --first-parent db7bdaa^1..248ecd3` lists these five merges
and two Renovate merges, #15 and #17, and nothing else. The
accumulated diff is 136 files, 25602 insertions and 634 deletions.

Phase 1 also landed `18a5ea5421..cf67642bbb` directly on
`instar-testdata`'s `main`. Its execution notes record that the range
passed the path and README-table audit before it was pushed. No later
phase committed to `instar-testdata`. Its remote `main` has moved on
since `cf67642bbb`, but only by commits from instar's nightly fuzzer,
which are not plan work (corrected by the audit; the survey read only
the local branch).

### 3. There is no `PUSH-AUDIT.md`

There is none at the root and none under `docs/`, as the section says.

### 4. The private hostname is where phase 5 put it

The `instar-testdata` remote's hostname appears in two files:
`tools/ci/fetch-appliance-corpus.sh` (twice) and
`tools/ci/test-fetch-appliance-corpus.sh` (four times). It already
appears in the public shakenfist/instar, for example in
`.github/workflows/coverage-fuzz.yml`, so the section's premise holds.

The section asks only about the repository. This repository's CI logs
are public too, and the `appliance-corpus` job runs the corpus test on
a public log. No step in `ci.yml` uploads a workflow artifact, so the
log is the only other public output. Phase 5 read one run's log by
hand. This audit reads every run's log by machine (step 6c).

### 5. The parser's imports look right, but a grep cannot settle it

Every top-level import under `shakenfist_client_ova/ovf/` is from the
standard library, `defusedxml`, or the package itself. A grep anchored
at the start of the line misses imports inside a function. Step 6a
settles the question with `ast` instead.

### 6. What a release publishes

`release.yml` builds an sdist and a wheel on a `v*` tag, checks them
with `twine check`, and publishes to PyPI. It runs no tests.
`pyproject.toml` keeps the three test packages out of the wheel.
`MANIFEST.in`, which predates the plan, prunes only `specifications/`
and `docs/plans/` from the sdist (the survey said it did not exist;
corrected by the audit), and `setuptools_scm` adds every other tracked
file. So the sdist presumably carries:

* the trimmed vendor fixtures;
* the curated corpus lists;
* the Glance archives and their `NOTICE`;
* both fetch scripts, including the private hostname.

That is not obviously wrong. The operator has said that trimmed
descriptors may be published, and the hostname is already public. But
PyPI is a more permanent place than a repository, and checklist item 5
asks what a broken change publishes. Step 6b builds the sdist and
reads its file list instead of presuming.

### 7. What runs unattended

The plan added no scheduled workflow. `renovate.yml` and
`export-repo-config.yml` run on a cron, but neither was touched by the
plan. Every CI job runs on each push to `develop`, and so does
`appliance-corpus`, whose `if:` excludes only fork pull requests. A
push to `develop` happens because someone merged. Whether that person
sees a failure is checklist item 2's question (step 6a).

### 8. Removed and renamed things

The five merges delete two files and rename none:

* `shakenfist_client_ova/tests/test_alloc_units.py`;
* `tools/pinned-requirements.txt`.

Both went in phase 3. The larger removals are inside files: phase 2
moved the parser out of `__init__.py`, and phase 5 dropped the
`ova://` source URL. Step 6a lists what each phase removed from the
package's importable names and its user-visible behaviour, and greps
for every consumer.

## Decisions

1. **The public record holds verdicts, paths, commands and counts,
   never private content.** The plan's private material is the corpus:
   the CyberOps appliances, whose provenance says `redistributable:
   false`, and every untrimmed descriptor. Suppose a finding involves
   private content, such as a CI log that quotes a descriptor. The
   public record then says that a finding exists, which file or run it
   concerns, and its decision. The detail goes to `instar-testdata`,
   as phase 1 did with its own audit. Sub-agents report the same way,
   because their reports pass through the management session into
   this file.

2. **Private exposure stops the audit; everything else waits for the
   record.** Suppose a step finds private content in a public place:
   * a public CI log;
   * the repository's history;
   * an sdist that would be published.

   The management session tells the operator at once, through
   AskUserQuestion, before writing anything about it anywhere. Removing
   it may mean deleting workflow runs or rewriting history, and both
   are the operator's to approve. Every other finding goes into the
   record and waits for the follow-up pull request.

3. **The audit has three readers, and they run in parallel.** Unlike
   phase 5's steps, 6a, 6b and 6c change nothing in the worktree, so
   running them together cannot collide. Each reads one class of
   question:
   * 6a, the shared block's floor;
   * 6b, what the plan copied from elsewhere and what it publishes;
   * 6c, the private corpus and the credential.

   6d asks what the phases did to each other. It runs after them,
   because it reads with their verdicts in hand. A single reader would
   be cheaper, but it would have to keep the provenance questions and
   the secrets questions in one context. Those are the two classes
   where a missed instance costs the most.

4. **A finding is something the plan's diff did.** The test is the
   respond-to-review skill's: is this a defect in code the plan added,
   or an observation about code that was already there? Only the first
   is a finding. The second is filed as an issue, linked from the
   record, and does not hold the plan open. This is the decision a
   reviewer is most likely to dispute, because an audit is a good
   moment to notice old problems. But a plan that cannot complete until
   the repository has no faults never completes. Older code had its own
   review when it landed.

5. **Every verdict carries the command that produced it.** The
   verdict "holds" says nothing that "not checked" does not. Each item
   in the record has one of three verdicts, each with what checks it:
   * **holds**, with the command or commands that show it;
   * **finding N**, with its decision;
   * **does not apply**, with the reason.

   The commands are written so that a later reader can re-run them
   against `248ecd3`.

6. **A finding is resolved by a fix, an issue, or a written decline.**
   * A fix lands in one follow-up pull request against `develop`,
     opened after this phase merges. That pull request records phase
     6's `Merged` cell and, once every finding is resolved, sets the
     row and the plan's index row to `Complete`.
   * A decline is a paragraph in the master plan's phase 6 section
     saying why, which is where the shared block puts it.
   * If the audit finds nothing, this phase sets its own row and the
     index row to `Complete` in its own pull request, and records no
     `Merged` cell.

7. **The detailed record lives here; the master plan gets a summary.**
   The full table of verdicts goes in this plan's *Audit results*
   section. The master plan's phase 6 section gains one paragraph:
   * how many items held;
   * how many findings there were, and what became of each;
   * a link to the table.

   Two copies of each verdict would drift.

## Step plan

| Step | Effort | Model | Isolation | Brief for sub-agent |
|------|--------|-------|-----------|---------------------|
| 6a | medium | opus | none | The shared block's checklist, items 1 to 5, over the five merges `db7bdaa 97273c7 b1f8894 a8f44bf 248ecd3`. Read this plan whole first, then the shared block in `docs/plans/PLAN-ovf-parser.md`'s phase 6 section. Survey findings 2, 5, 7 and 8 have done part of the work: confirm them, do not redo them blind. **Item 1:** confirm each merge has two parents and that `git log --first-parent db7bdaa^1..248ecd3` holds only these and Renovate's #15 and #17. Cite phase 1's execution notes for the `instar-testdata` range. **Item 2:** for every workflow, job or script the diff added or changed that runs without a person starting it, say where its failure is reported and who sees it. Include `appliance-corpus` on a push to `develop`. **Item 3** is step 6c's; write "see 6c". **Item 4:** list what each merge removed or renamed: files, names importable from `shakenfist_client_ova`, Click commands and options, environment variables, and behaviour such as the `ova://` source URL. Then grep for each across every repository under `/srv/kasm_profiles/mikal/vscode/src/shakenfist/` that is not a worktree (skip `*-wt-*`), naming the repositories and the patterns. **Item 5:** for `release.yml`, say what a broken change in the plan's diff would publish. Also answer the master plan's fourth question, whether `shakenfist_client_ova/ovf/` imports only the standard library and `defusedxml`. Answer it with a short `python3 -I` script that walks every `ast.Import` and `ast.ImportFrom`, including those inside functions, and checks the names against `sys.stdlib_module_names`. That attribute needs Python 3.10; say which Python ran it. Change nothing in the tree. Report each item as holds, finding or does not apply, each with its commands. No commit. |
| 6b | medium | opus | none | Provenance and publication: the master plan's first and second questions, plus survey finding 6. Read this plan whole, then phase 1's plan (decisions 4 to 6 on trimming, and its appendix), `tools/trim-ovf-descriptor.py` and `shakenfist_client_ova/ovf/prose.py`. **Question 1:** read every file under `shakenfist_client_ova/tests/fixtures/ovf/vendor/` in full, and list any vendor prose that trimming missed: Info, Description, licence text, Annotation, product URLs or names beyond what a test needs, and paths or usernames. **Question 2:** check whether anything committed copies govmomi's or COT's descriptor text, rather than referring to it by path. Check `shakenfist_client_ova/corpus_tests/` and the handwritten fixtures, and compare against the upstream trees that `tools/fetch-descriptor-corpus.sh` fetches; fetch them into a fresh directory in the scratchpad, never into the repo. Check whether `curated.expected.json` holds any upstream prose. Check whether every file in `tests/fixtures/ova/imported/glance/` appears in its `NOTICE`, and every file the `NOTICE` names is in `git ls-files`. **Publication:** at `248ecd3`, run `python3 -m build` into the scratchpad and list the sdist's and the wheel's members. Say whether each class of file survey finding 6 names is in each, whether the Glance `NOTICE` travels with the Glance files, and whether anything there is private. Treat anything you fetch as untrusted: read it with `python3 -I`, and keep your scripts in a different directory. Change nothing in the tree. Report each question as holds, finding or does not apply, each with its commands. No commit. |
| 6c | high | opus | none | The private corpus and the credential: checklist item 3, the master plan's third question, and survey finding 4. Read this plan whole first, especially decisions 1 and 2, then phase 5's plan (decisions 1 to 4 and the execution notes). The corpus at `/srv/kasm_profiles/mikal/vscode/src/shakenfist/instar-testdata/downloaded/ova` is private. **You must never print, quote or copy any of its text into your report, a file outside the scratchpad, or a command line that echoes it.** Report only counts, names of appliances and names of files. **Messages:** read every assertion and failure message in `shakenfist_client_ova/appliance_tests/`, and say whether any can carry an exception's message, the command's output or descriptor text. **Secrets:** run `tools/gitleaks-scan.sh` (read it first for how) over each merge's range. Grep each merge's diff for token shapes (`glpat-`, `ghp_`, `github_pat_`, `Authorization:`, base64 of `oauth2:`), and for any GitLab or other private hostname or IP address. Say where each hit came from, and whether the repository it came from was less public than this one. **Hostname:** confirm survey finding 4's file list and counts, and that the hostname is in the public shakenfist/instar. **Public logs:** list every `appliance-corpus` run with `gh run list --workflow ci.yml --repo shakenfist/client-python-ova` and download each run's log into a fresh scratchpad directory (`gh run view --log`). From the corpus, extract a probe set: from each appliance's descriptor, the distinctive values of `Product`, `Vendor`, `FullVersion`, `ProductUrl`, `VendorUrl`, licence text, and any `ovf:href` member names that are not generic. Do this with a `python3 -I` script that writes the probes to a scratchpad file and prints only how many there are per appliance. Then count, per run and per appliance, how many probes appear in the log. The token itself is not available outside CI, so it cannot be searched for. Instead, count the log lines that carry an `Authorization` or `extraheader` value, and say whether every one of them is masked as `***`. A hit is reported as run id, appliance and count, never the matched text. **Under decision 2, any hit in a public place makes you stop and report at once, without investigating further.** Change nothing in the tree. No commit. |
| 6d | high | opus | none | What the phases did to each other. Run after 6a to 6c, given their reports. Read this plan, the master plan, and every phase plan's execution notes. Then read the accumulated diff `git diff db7bdaa^1 248ecd3`, excluding the Renovate files, and the tree at `248ecd3`. Look for what one phase made wrong and a later one never revisited: documentation that states a fact differently from the code, or from another page, in `docs/`, `README.md`, `ARCHITECTURE.md` and `AGENTS.md`; a helper defined in two places; dead code or a test fixture nothing uses any more; a test tier described in one place and run differently in `tox.ini` or `ci.yml`; and an issue or Future work entry an earlier phase promised and nothing filed. For each claim a doc makes about behaviour, find the code that does it, and cite both. Apply decision 4: an observation about code that predates the plan is a filed issue, not a finding. Change nothing in the tree. Report findings with file and line, and say how many doc claims you checked. No commit. |
| 6e | high | opus | management session | The record. Verify every finding the four reports raise by reproducing it; drop any that do not reproduce, and say so. Write *Audit results* in this plan to decisions 5 and 7, and the master plan's summary paragraph. Decide each finding under decision 6. File issues for decision 4's observations and for findings that will be fixed later. Run 6c's probe set over every file this phase changes, and record that it found nothing. If there are no findings, set phase 6's row and the index row to `Complete` with no `Merged` cell. Run `pre-commit run --all-files` and `~/src/shakenfist/development/scripts/audit-check.py --repo-path . --repo-name client-python-ova`. Commit subject: `Record the OVF parser's push audit.` |

## Risks and mitigations

1. **A sub-agent's report quotes private content, and it is pasted into
   this public file.** Decision 1 and 6c's brief forbid it. The
   management session reads each report for quoted text before any of
   it reaches the worktree. 6e writes verdicts in its own words rather
   than pasting.
2. **The audit reads the wrong range and passes.** Survey finding 2
   lists the first-parent history exactly. 6a re-derives it. 6e checks
   that the five merges in the record match the Execution table.
3. **A verdict says "holds" without any evidence behind it.** Decision 5
   requires a command for each verdict. 6e re-runs at least one command
   per item before recording it.
4. **6c's probe set misses how a leak would look.** A log could carry a
   descriptor fragment that none of the chosen fields hold. The probe
   set covers the fields a test failure would be most likely to quote.
   It is backed by the corpus test's rule, stated in its docstring,
   that assertion messages carry only names and outcome names. 6c
   reads every assertion message in
   `shakenfist_client_ova/appliance_tests/` against that rule. The
   record says the log check was a probe set and not an exhaustive
   read.
5. **Fetching upstream trees and CI logs brings untrusted data into the
   scratchpad.** Each goes into a fresh directory and is read with
   `python3 -I`, and scripts live elsewhere, as the briefs say.
6. **Findings pile up and the plan never completes.** Decision 4 keeps
   pre-existing code out of the count. Decision 6 allows a written
   decline. The follow-up pull request is the only fix carrier, so its
   scope is visible in one diff.

## Definition of done

* *Audit results* holds a verdict for each of:
  * the five checklist items;
  * the master plan's four questions;
  * survey findings 4 and 6's two added questions.

  Each verdict is "holds", "finding N" or "does not apply", and each
  carries at least one command or a reason.
* 6c's probe set, run over every file this phase changes, finds no
  hit.
* Every finding has one of:
  * a decision under decision 6;
  * an issue link;
  * a decline paragraph in the master plan.
* The master plan's phase 6 section has one summary paragraph that
  links to *Audit results*, and states no verdict that differs from
  it.
* The master plan's Execution table and `docs/plans/index.md` agree.
  If there were no findings, both read `Complete`, and row 6 has no
  `Merged` cell.
* `pre-commit run --all-files` passes, and the consistency audit
  reports no failure.

## Corrections made to the master plan

Made in this phase's planning commit:

* Phase 6's section notes the two Renovate merges that sit inside the
  plan's first-parent range and are not audited as plan work.
* It adds the two questions this survey raised: what the sdist
  publishes, and whether private corpus content reaches a public CI
  log.
* Its hostname question now names the two files that carry the
  hostname, so the verdict has something to confirm.

## Back brief

Before executing any step of this plan, back brief the operator on
your understanding of the plan and how the work you intend to do
aligns with it. Two points need the operator's answer before 6a runs:

* whether, under decision 2, a hit in a public place may be described
  to the operator in this session's terminal. The terminal is private,
  but it is still a copy;
* if there are findings, whether this session may open the follow-up
  pull request once phase 6 merges, or should offer it and wait.

## Audit results

Read against `248ecd3`. The commands are the ones the steps ran, and
they can be re-run against that commit. Before recording, the
management session re-ran at least one command per row:

* the merges' parents and the first-parent list;
* the `develop` runs' actors;
* the `ovf/` import walk;
* the prose check;
* the `NOTICE` checksums;
* the consumer grep;
* the log probe match, which again found 0 hits, and every unmasked
  credential-header line was a `git config --name-only` or
  `--unset-all` command, carrying no value.

It also reproduced every finding below against the tree. Steps 6a to
6c raised no stop under decision 2.

### The shared block's checklist

| Item | Verdict | How it was checked |
|------|---------|--------------------|
| 1. Recorded landings | Holds | `git rev-list --parents -n1 <m> \| wc -w` prints 3 for each of the five merges. `git log --first-parent --oneline db7bdaa^1..248ecd3` lists them and Renovate's #15 and #17 only. The `instar-testdata` range is cited from phase 1's execution notes. |
| 2. Unattended work reports failure | Holds | `git diff --name-status <m>^1 <m> -- .github tools tox.ini pyproject.toml` per merge: no cron, timer or schedule was added. The new jobs run on a push to `develop`, which a merge starts, and GitHub reports a failed run to its actor. On all ten recent `develop` runs, that actor is the operator (`gh api 'repos/shakenfist/client-python-ova/actions/workflows/ci.yml/runs?branch=develop&event=push'`). |
| 3. No secret or private hostname | Holds | gitleaks 8.16.0, from its container, over each `<m>^1..<m>` and over all of history: no leaks. A planted key, as a positive control, was found. A grep of each merge's added lines for token shapes (`glpat-`, `ghp_`, `github_pat_`, `Authorization:`, and the base64 of `oauth2:` at each alignment) found only the placeholders in the fetch script. |
| 4. Removed names have no consumer | Holds | An AST diff of `__init__.py`'s names per merge gives the removed names: phase 2's parser helpers and constants, the `dpath` and `xmltodict` dependencies, and the `ova://` source URL. `git -C <repo> grep` for each, across the 34 non-worktree repositories under `src/shakenfist/`, finds no consumer outside this repository. |
| 5. A broken change fails closed | Does not apply to the plan's diff | The plan did not touch `release.yml`. The release workflow publishes untested, and its `release` environment does not exist. Both predate the plan, and are filed as #19 under decision 4. |

### The master plan's questions

| Question | Verdict | How it was checked |
|----------|---------|--------------------|
| 1. Vendor prose left in trimmed fixtures | Holds | All 16 vendor fixtures read in full. A `python3 -I` script loading `ovf/prose.py`'s list found 130 prose elements and none untrimmed. A grep for paths, e-mail addresses and URLs found only schema namespaces and provenance comments. Finding 2 is a gap in the list itself. |
| 2. Upstream text copied; curated expectations; Glance `NOTICE` | Holds | govmomi `79bc9d75` and COT `0811b963` were fetched by the fetch script's method. Every upstream line of 30 characters or more was matched against every tracked file. The 29 matches are schema boilerplate, the longest a six-line namespace block. `curated.expected.json` carries `TRIMMED` 93 times and no upstream prose. `sha256sum -c` over the `NOTICE`'s table passes for all five Glance files, and `git ls-tree` lists exactly those five and the `NOTICE`. |
| 3. Private hostname somewhere new | Holds | It appears only in `tools/ci/fetch-appliance-corpus.sh` (2) and `tools/ci/test-fetch-appliance-corpus.sh` (4), both added by phase 5. It is already in the public shakenfist/instar (`.github/workflows/coverage-fuzz.yml`). |
| 4. `ovf/` imports only the standard library and `defusedxml` | Holds | A `python3 -I` script walks every `ast.Import` and `ast.ImportFrom`, including those inside functions, and checks them against `sys.stdlib_module_names` (Python 3.13.5). It found no other module. |

### The survey's added questions

| Question | Verdict | How it was checked |
|----------|---------|--------------------|
| What a release publishes | Holds | `python -m build` in a detached worktree at `248ecd3`, with real git metadata as `release.yml` has. The sdist is every tracked file except the two pruned directories, so it is a subset of the public repository. The wheel holds only the package's modules and its licence. No untrimmed appliance content is in either. |
| Private corpus content in public CI logs | Holds | Every `appliance-corpus` job's log was read: four runs, every job in them. 591 probes were drawn from the private descriptors' prose and identifying fields, by a script that printed only counts. They gave no hit in any log. Every line carrying a credential value is masked. This was a probe set, not an exhaustive read (risk 4). |

### Findings

Each is a defect the plan's diff introduced, under decision 4. All nine
are to be fixed in one follow-up pull request against `develop`, under
decision 6.

1. **The trimmed fixtures are never checked against their originals.**
   Master plan decision 6 says the appliance tier asserts that the
   parser's model of each original descriptor equals its model of the
   trimmed fixture, apart from the placeholder. Phase 1 deferred this
   to phase 5, and phase 5's plan never mentions it.
   `shakenfist_client_ova/appliance_tests/test_appliance_corpus.py`
   never reads `tests/fixtures/ovf/vendor/`, and no decline was
   written. Fix: compare, per appliance, the scrubbed model, or the
   outcome name for a refused appliance, of the descriptor member and
   its vendor fixture.
2. **The prose list omits the deployment option text.**
   `shakenfist_client_ova/ovf/prose.py`'s `PROSE_ELEMENTS` lacks
   `DeploymentOptionSection/Configuration/Label` and `Description`.
   These are localisable, user-facing text like `Property/Label`, and
   the model reads them. Today they hold only generic sizing text, so
   nothing leaked, but a future fixture with marketing text there
   would pass `--check` untrimmed. Fix: add both, then re-trim and
   regenerate what changes.
3. **The rule for what the corpus test prints is narrower than what it
   prints.** The rule, stated in `test_appliance_corpus.py`'s
   docstring, `docs/development.md` and `AGENTS.md`, allows appliance,
   artifact and outcome names. But a mismatch of absent members prints
   the member names, and three calls outside `_attempt` can raise an
   error naming a member. Fix: keep the rule, and change the test.
   * The absent-members check reports how many members are missing or
     unexpected, not their names.
   * The three calls go through `_attempt`.

   Widening the rule was weighed and rejected. Every appliance in the
   corpus today has a trimmed fixture, so its member names are already
   public. But an appliance added later would have its member names
   reach a public CI log before anyone reviewed them, and a file name
   can carry a username or a build path.
4. **`ARCHITECTURE.md` misses phase 5's round trip to the server.** Its
   pipeline omits the lookup of every artifact name before the disks
   are read, the refusal of an artifact no upload made, and the
   `ova_file` and `ova_member` metadata.
5. **`ARCHITECTURE.md` says the quirk list lives only in
   `ovf/quirks.py`.** `docs/usage.md` lists all six quirks too. They
   agree today. Fix: keep the list for users, and correct the claim.
6. **`docs/usage.md` never names `ManifestError`.** It is the only
   refusal not named, although `ARCHITECTURE.md` says usage explains
   each one.
7. **The summary prints "Version: 1" when the descriptor states
   none.** Before the plan the command said it was assuming version 1.
   Phase 2 dropped the qualifier, and phase 3 began accepting OVF 2
   envelopes. Fix: derive the version from the envelope's namespace
   when none is stated.
8. **Phase 4 duplicated the synthetic archive helpers.** `_replace`,
   `_digest`, `_manifest` and the two-controller descriptor are defined
   identically in `tests/test_command.py` and
   `tests/test_ovf_package.py`. `tools/trim-ovf-descriptor.py` also
   repeats the envelope namespace URIs from `ovf/namespaces.py`,
   although it already imports `ovf.prose`. Fix: move the helpers into
   `tests/synthetic.py`, and have the trim tool import the namespaces.
9. **Four stale cross-references.**
   * `tools/classify-ovf-corpus.py`'s docstring points to shape
     counts in `docs/development.md` that are not there.
   * `tools/fetch-descriptor-corpus.sh` says to change a pin "here and
     in the plan", which contradicts the pins' single home.
   * `href-duplicate-member.ovf` says an archive case is still to be
     built, but phase 4 built it.
   * `ovf/model.py` says "as today" of a long-gone parser.

### Declined

* **`Disk.interface`, a field nothing fills.** Its comment in
  `ovf/model.py` says so, and that it is kept for the oVirt reader in
  Future work. Removing it would rewrite 27 fixture expected files
  and 25 curated entries, only for that reader to add it back.
* **Sharing `_not_found` between `tests/test_command.py` and the
  appliance tier.** The tiers are separate packages, and the appliance
  tier is deliberately kept out of the unit tier's collection. A
  shared helper would import across that line for four lines of code.
* **The namespace URIs in `tools/classify-ovf-corpus.py`.** The tool
  imports nothing from the package, so that it can survey a corpus
  without the package installed. A copied constant is the price of
  that.
* **Plan text that describes the parser as it was.** Plans record what
  was decided at the time. `docs/plans/` is history, and is not
  corrected for later phases.

### Filed under decision 4

Problems in code that predates the plan, raised by the audit and filed
rather than counted:

* #19: the release workflow publishes untested, and its `release`
  environment does not exist, so the first tag is ungated.
* #20: four of the import command's server calls let an API error
  escape as a traceback, and `ctx.obj['namespace']` is never read.

## Execution notes

* **Back brief, 2026-10-18.** The operator agreed that a hit in a
  public place could be described in the session's terminal, and that
  the management session may open the follow-up pull request itself
  once this phase merges.
* **6a, 6b and 6c ran in parallel, and 6d after them.** None raised a
  stop under decision 2.
* **Where each finding and decline came from.** 6a raised no
  candidate, 6b one, 6c two notes and 6d eight:

  | Raised by | Became |
  |-----------|--------|
  | 6b, the prose list | Finding 2 |
  | 6c, its two notes on the corpus test's output | Finding 3 |
  | 6d 1, the missing trimmed-against-original check | Finding 1 |
  | 6d 2, `ARCHITECTURE.md`'s pipeline | Finding 4 |
  | 6d 3, the quirk list's two homes | Finding 5 |
  | 6d 4, `Disk.interface` | Declined |
  | 6d 5, `ManifestError` unnamed | Finding 6 |
  | 6d 6, "Version: 1" | Finding 7 |
  | 6d 7, duplicated helpers | Finding 8; `_not_found` and the classify tool's URIs declined |
  | 6d 8, stale cross-references | Finding 9; the plan text declined |

  6d also noted that the output rule lives in three places, which
  finding 3 records. In review, the reviewer pointed out that widening
  the rule would not cover appliances added later. Finding 3 now keeps
  the rule and changes the test instead.

  Every finding kept was reproduced against the tree before it was
  recorded.
* **The survey had three facts wrong**, now corrected at their source
  above:
  * `instar-testdata`'s remote `main` has moved on;
  * `MANIFEST.in` exists;
  * phase 5's records do not link the upstream issues.
* **The probe set over this phase's own changes found nothing new.**
  It was run over every file the phase changes, and gave 0 hits in the
  text the phase added. The master plan already held five hits at
  `248ecd3`, all of them envelope identifiers the operator ruled
  publishable: two appliances' VirtualSystem ids, one product and
  vendor name, and one disk name.
* **This phase does not complete the plan.** There are findings, so
  phase 6 stays `In progress`. The follow-up pull request records this
  phase's merge commit, and sets the row and the index row to
  `Complete`.

# Plans index

This page registers every planning document in `docs/plans/`, oldest
first. New plans start from `PLAN-TEMPLATE.md` at the repository root,
and a plan that is not listed here is invisible: registering it is part
of writing it, not a tidy-up afterwards.

Master plans decompose their work into numbered phases. Where a phase
needs a plan of its own it gets a file named for its master plan with
`-phase-NN-descriptive` appended, linked from both the master plan's
Execution table and the Phases column here.

The `Status` column holds exactly one term from the shared vocabulary
in `PLAN-TEMPLATE.md`: `Proposed`, `Not started`, `In progress`,
`Blocked`, `Complete`, `Abandoned` or `Superseded`. Anything a reader
needs beyond that term belongs in the plan file, with a one line
summary in `Intent`.

## Master plans

| Date | Plan | Intent | Status | Phases |
|------|------|--------|--------|--------|
| 2026-10-15 | [OVF parser: a tested, specification-following descriptor parser](PLAN-ovf-parser.md) | Split the OVF parser out of the import command behind a boundary it could be published from, test it against a corpus of real descriptors from several producers, and fix where it has drifted from the specification, before instance creation is built on it | In progress | [1. Corpus and fixtures](PLAN-ovf-parser-phase-01-corpus.md), [2. Extract the parser](PLAN-ovf-parser-phase-02-extract.md), [3. ElementTree and the specification](PLAN-ovf-parser-phase-03-elementtree.md), 4. Archive correctness, 5. Corpus CI tier, 6. Push audit |

# OVF parser phase 2: extract the parser

## Prompt

Before responding to questions or discussion points in this document,
read the master plan, [PLAN-ovf-parser.md](PLAN-ovf-parser.md),
particularly decisions 1, 4, 5 and 7 and phase 2's section, and phase
1's plan, [PLAN-ovf-parser-phase-01-corpus.md](PLAN-ovf-parser-phase-01-corpus.md),
for the fixtures and tools this phase builds on. The master plan's
decisions are not restated here, except where this phase's survey
changed or sharpened them.

This phase moves the parser out of the Click command without changing
what it accepts. It still parses with `xmltodict` and `dpath`. Phase 3
replaces them, and everything this phase records is the baseline that
phase 3 is reviewed against.

## Planning effort

High. The phase is a refactor, but it fixes the shape of the model
that every expected file serialises. A model that turns out wrong in
phase 3 rewrites every expected file and the ledger, and buries phase
3's real behaviour changes in that churn. Review effort: high for
decisions 2 and 3, which are the model and the error mapping. Medium
for the rest.

## Scope

In:

* `shakenfist_client_ova/ovf/`: the error hierarchy, the model, the
  prose list, and the manifest and descriptor parsers, still on
  `xmltodict`.
* The command, rewired to call the parser, print its refusals and
  print a summary from the model.
* The unit-tier golden test over the 33 committed descriptor fixtures,
  with an expected file beside each.
* The descriptor corpus tier: `tox -edescriptor-corpus`, the ledger,
  the curated expected files, and a test that the classifier still
  reproduces `curated.txt`.
* A `descriptor-corpus` job in `ci.yml`.
* Exact pins for `xmltodict` and `dpath` in the test environments.
* `ARCHITECTURE.md`, `docs/development.md`, `docs/usage.md` and two
  `AGENTS.md` lines.

Out:

* Any change to what the parser accepts or refuses: phase 3. That
  includes #11, the refused `byte` allocation unit, which this phase's
  expected files record as a refusal.
* Glance's OVAs and every archive-level check: phase 4. The golden
  test reads descriptors only.
* Tests of the command beyond what step 2b needs to prove its output:
  phase 3 adds the `CliRunner` suite.
* Removing `xmltodict` and `dpath` from `pyproject.toml`: phase 3.

## What the survey found

The survey ran on 2026-10-17. It ran today's `ova import` from
`develop` (`db7bdaa`) over every committed descriptor fixture and every
descriptor in both pinned upstream collections. Each descriptor went in
as a one-member OVA, with the API client mocked, under `xmltodict`
1.0.4 and `dpath` 2.2.0. Findings 3, 4, 7 and 8 correct the master
plan, and the corrections are made at source in this phase's planning
commit (see "Corrections made to the master plan").

### 1. Phase 1 is complete

Phase 1 is merged as `db7bdaa`, and its last commit `c53a8b1` is an
ancestor of `develop`. These Definition of done items were
spot-checked against the tree: 16 vendor fixtures; 17 hand-written
fixtures; the five Glance OVAs and their `NOTICE` tracked; and the
leak grep finds nothing in `vendor/`. One deferred item lands here.
The automated review asked for tests of
`tools/classify-ovf-corpus.py`, and the reply deferred them to "the
corpus tier phase 2 adds". Decision 8 adds them.

### 2. What today's parser does with every descriptor we have

| Input | Count | Imports | Refused with a message | Unhandled exception |
|-------|-------|---------|------------------------|---------------------|
| `fixtures/ovf/vendor/` | 16 | 4 | 8 | 4: `PathNotFound` 2, `KeyError` 1, `TypeError` 1 |
| `fixtures/ovf/handwritten/` | 17 | 8 | 6 | 3: `PathNotFound`, `ValueError`, `KeyError` |
| govmomi `ovf/fixtures/` | 958 | 116 | 118 | 724: `KeyError` 519, `PathNotFound` 167, `TypeError` 21, `ExpatError` 15, `ValueError` 2 |
| COT `COT/tests/` | 10 | 2 | 3 | 5: `PathNotFound` 3, `KeyError` 2 |

Only four of the sixteen real appliances import today: both CyberOps
exports, VulnHub's `blogger` and Wazuh. These are the VirtualBox and
AWS exports. Every ovftool, oVirt and coreos-assembler appliance is
refused. The eight hand-written fixtures that import are the
archive-level cases (the five `href-*`, `gzip-reference`,
`chunked-reference`) plus `no-default-namespace` and
`two-controllers`. They import because nothing yet checks references
against archive members, which is phase 4's work.

The refusals with a message are, across all four rows: `Unknown
allocation unit: "byte"` 82, `Not all of the OVF file was parsed!` 46,
`Unknown hardware element` 6 and `Unhandled "other" element` 1.

### 3. An OVF 2.x descriptor dies at the first line, not at `References`

The master plan's Situation item 1 says a 2.x descriptor "gets past the
optional reads and then dies with an unhandled `KeyError` at
`References`". It dies earlier. The first thing the walk does is
`dpath.delete(ovf, '**/v1:Info')`. When nothing matches, that raises
dpath's `PathNotFound`, which is not a `KeyError`. The hand-written
`ovf2-envelope.ovf`, ArchiveTeam Warrior (OVF 2.0) and Tails (OVF 0.9)
all stop there.

### 4. Unhandled exceptions come in five classes, not one

The master plan's phase 2 section names one output change, for
"today's code dies with an unhandled `KeyError` traceback". Finding 2
shows five classes, with these sources:

| Class | Raised by |
|-------|-----------|
| `KeyError` | Any missing key in the walk. A `VirtualSystemCollection` has no `v1:VirtualSystem`. Photon 5.0's disk names a controller that is not an IDE, SCSI or AHCI one (`__init__.py:345`). |
| `PathNotFound` | dpath's `delete` with no match. It is an `Exception`, not a `KeyError`. |
| `TypeError` | A value that `xmltodict` made a dict because the element carries attributes. VyOS's `rasd:InstanceID` is the example (`__init__.py:336`). |
| `ExpatError` | A descriptor that is not well-formed XML. |
| `ValueError` | Two sources. `xmltodict` refuses an entity declaration with `entities are disabled` (`entity-declaration.ovf`). `int()` fails on a `${property}` capacity (govmomi's `uber.ovf` and `multiple_disks.ovf`, `__init__.py:237`). |

Converting `KeyError` alone would leave the master plan's own example,
an OVF 2.x descriptor, printing a traceback. Decision 3 covers all
five.

### 5. The `byte` allocation unit is refused

`_parse_alloc_units_to_bytes()` knows `byte * 2^N`, `MegaBytes` and
`GigaBytes`, and refuses plain `byte`, which is the base unit. That
refuses Fedora CoreOS, Flatcar and the Ubuntu cloud image, 78 govmomi
descriptors and COT's `iosv.ovf`. Filed as #11. It is out of scope
here, because this phase preserves behaviour.

### 6. Sections the model must hold as lists

Counted across both collections and the fixtures, virtual systems
carry more than one `ProductSection` 35 times and more than one
`EulaSection` 19 times. The specification allows several of each,
told apart by `ovf:class` and `ovf:instance`. Three govmomi
descriptors carry more than one `VirtualHardwareSection`, which OVF
allows so that a consumer can choose by `vssd:VirtualSystemType`. The
model holds all three as lists (decision 2).

### 7. The prose list names model fields for elements nothing reads

Phase 1's prose table maps `AnnotationSection/Annotation` to a model
field `annotation`, and `ProductSection/Info` to `product.info`.
Master plan decision 4 ignores `Info` and `AnnotationSection` unread,
so the model has no such fields. Both map to no field, like
`Strings/Msg`. Finding 6 also turns `product.` and `eula.` into
`products[].` and `eulas[].`. The field names are labels only: the
trim tool matches on element paths and ignores the field. So the
rename changes no fixture (decision 5).

### 8. Nothing bumps `xmltodict` or `dpath` for review

Decision 5 of the master plan expects that "a Renovate bump of
[`xmltodict`] may change the ledger, and that diff is reviewed".
`pyproject.toml` lists both with no version, and `renovate.json`
widens ranges for the `pep621` manager, so an unconstrained
dependency never gets a pull request. A new release would instead
change the ledger, and the unit-tier expected files, on whichever
unrelated pull request ran next. Decision 7 pins them for the test
environments.

### 9. Every job in this repository runs on the self-hosted pool

The master plan puts the `descriptor-corpus` job "on a GitHub-hosted
runner". No workflow here uses one. `ci.yml`'s header argues that the
static pool is acceptable for pull request code because the
repository requires approval before a fork's workflow runs, and that
argument covers this job too (decision 9).

### 10. Today's hardware summary loses a disk drive

The `hardware` dictionary is keyed by `rasd:AddressOnParent` alone, so
two drives at address 0 on different controllers collide. In
`two-controllers.ovf` the SCSI disk is overwritten by the IDE one. The
dictionary is only printed, so no import is affected. The model lists
every drive, and the printed summary changes accordingly (decision 4).

## Decisions

1. **The subpackage layout and its public API.**

   ```
   shakenfist_client_ova/ovf/
     __init__.py      # the public API, re-exported
     errors.py        # OVFError and its subclasses
     model.py         # the dataclasses, and to_json()
     prose.py         # PROSE_ELEMENTS, PLACEHOLDER, scrub()
     manifest.py      # parse_manifest(data: bytes) -> Manifest
     descriptor.py    # parse_descriptor(data: bytes) -> Envelope
   ```

   `descriptor.py` is today's walk, moved rather than rewritten. That
   includes `NAMESPACES`, `_coerce_to_list`, `_delete_if_empty` and
   `_parse_alloc_units_to_bytes`, which raises instead of exiting. The
   walk builds the model at the end from what it read. Phase 3 deletes
   this file's insides, so the move should be faithful, not tidy.
   Archive handling stays in the command until phase 4: listing
   members, choosing which to parse, and uploading.

   The boundary in master plan decision 1 is enforced by a unit test,
   `test_ovf_boundary.py`, not by review. It walks the AST of every
   module in `ovf/` and fails on three things:
   * an import outside an explicit allow-list: the standard library
     modules the package uses, `defusedxml`, and until phase 3,
     `xmltodict` and `dpath`, with a comment saying phase 3 removes
     them;
   * any call to `print`, `exit`, `quit` or `sys.exit`;
   * any import of `click` or `shakenfist_client`, named separately so
     that the failure message says which rule broke.

2. **The model, in its final shape.** Every field phase 3 will fill
   exists now and is left empty. Lists keep document order. Sizes are
   integers in bytes, and the command does any conversion to MiB or
   GiB. Python 3.7 needs `typing.List` and `typing.Optional`, and
   `field(default_factory=list)` for lists. The block shows the fields,
   not the order a dataclass needs: step 2a puts required fields first.

   ```python
   @dataclass
   class File:                    # References/File
       id: str
       href: str
       size: Optional[int] = None          # phase 3; phase 4 checks it
       compression: Optional[str] = None   # phase 3; phase 4 refuses gzip
       chunk_size: Optional[int] = None    # phase 3; phase 4 refuses it

   @dataclass
   class Disk:                    # DiskSection/Disk
       disk_id: str
       file_ref: Optional[str]
       capacity_bytes: int                 # ovf:capacity x its allocation units
       format: Optional[str]
       populated_size: Optional[int] = None  # phase 3
       interface: Optional[str] = None       # phase 3, master open question 4

   @dataclass
   class Network:                 # NetworkSection/Network
       name: str
       description: Optional[str]

   @dataclass
   class Controller:              # ResourceType 5, 6, and 20 with subtype AHCI
       instance_id: str
       bus: str                            # 'ide', 'scsi' or 'sata'

   @dataclass
   class DiskDrive:               # ResourceType 17
       parent: str                         # the controller's instance_id
       address_on_parent: int
       element_name: Optional[str]
       host_resource: Optional[str] = None # phase 3: which Disk it holds

   @dataclass
   class Nic:                     # ResourceType 10
       resource_subtype: Optional[str]
       connection: Optional[str]

   @dataclass
   class VirtualHardware:         # VirtualHardwareSection
       vcpus: Optional[int]
       memory_bytes: Optional[int]
       controllers: List[Controller]
       disk_drives: List[DiskDrive]
       nics: List[Nic]
       transport: List[str]                # phase 3: ovf:transport, split on spaces
       system_type: Optional[str] = None   # phase 3: vssd:VirtualSystemType
       system_identifier: Optional[str] = None  # phase 3: vssd:VirtualSystemIdentifier

   @dataclass
   class Property:                # ProductSection/Property, phase 3
       key: str
       type: str
       value: Optional[str]
       user_configurable: bool
       password: bool
       qualifiers: Optional[str]
       category: Optional[str]             # the Category element before it
       label: Optional[str]
       description: Optional[str]

   @dataclass
   class Product:                 # ProductSection, phase 3
       product_class: Optional[str]        # ovf:class
       instance: Optional[str]             # ovf:instance
       product: Optional[str]
       vendor: Optional[str]
       version: Optional[str]
       full_version: Optional[str]
       product_url: Optional[str]
       vendor_url: Optional[str]
       app_url: Optional[str]
       properties: List[Property]

   @dataclass
   class Eula:                    # EulaSection, phase 3
       license: str

   @dataclass
   class OperatingSystem:         # OperatingSystemSection, phase 3
       id: int
       version: Optional[str]
       os_type: Optional[str]
       description: Optional[str]

   @dataclass
   class DeploymentOption:        # DeploymentOptionSection/Configuration, phase 3
       id: str
       default: bool
       label: Optional[str]
       description: Optional[str]

   @dataclass
   class VirtualSystem:
       id: Optional[str]
       name: Optional[str]                 # phase 3: VirtualSystem/Name
       description: Optional[str]          # phase 3
       hardware: List[VirtualHardware]     # phase 2 fills exactly one
       products: List[Product]             # phase 3
       eulas: List[Eula]                   # phase 3
       operating_system: Optional[OperatingSystem]  # phase 3

   @dataclass
   class Envelope:
       namespace: str                      # the envelope namespace URI
       version: Optional[str]              # ovf:version, if stated
       files: List[File]
       disks: List[Disk]
       networks: List[Network]
       deployment_options: List[DeploymentOption]  # phase 3
       virtual_system: VirtualSystem

   @dataclass
   class ManifestEntry:
       name: str
       algorithm: str                      # lower case, as today
       digest: str

   @dataclass
   class Manifest:
       entries: List[ManifestEntry]        # every line, duplicates included
   ```

   What today's walk reads maps onto it like this:
   * `capacity_gb` becomes `capacity_bytes`.
   * `memory_mb` becomes `memory_bytes`. `vcpus` becomes an int: today
     it is the raw string. None of the 130 descriptors that import
     today has a non-integer vCPU or memory quantity, so the
     conversion refuses nothing that imports now.
   * The name fallback `Imported OVA VM` and the version fallback
     `v1` are the command's, not the model's. The model holds `None`.
   * `Manifest` keeps every line, where today's dictionary keeps the
     last entry for a repeated name. Phase 4 refuses duplicates, and
     needs to see them to do so.

   A virtual system has one `VirtualHardware` in this phase, because
   the walk reads one. The list exists for finding 6.
   `VirtualSystemCollection` is not modelled: phase 3 refuses it by
   name. Phase 3 may still add a field it finds it needs, with the
   reason in its plan. Every expected file then gains a `null` in one
   reviewable diff. What phase 3 must not do is reshape what is
   already here.

   `to_json(model)` is `json.dumps(dataclasses.asdict(model),
   sort_keys=True, indent=2, ensure_ascii=False)` plus a final newline.
   It is the only serialisation, and the tests use it too.

3. **Errors: named classes, and one wrapper for everything else.**

   | Class | Raised for | Message |
   |-------|-----------|---------|
   | `OVFError` | the base class; never raised itself | |
   | `ManifestError` | a manifest line that does not parse | `Failed to parse manifest line: <line>`, as today |
   | `UnknownAllocationUnitError` | an allocation unit it cannot convert | today's two lines, the second being the element's `repr` |
   | `UnsupportedHardwareError` | an unknown resource type, and a required type 1 ("Other") | today's line, `Unknown hardware element: ...` or `Unhandled "other" element: ...` |
   | `UnparsedContentError` | anything left after the walk | `Not all of the OVF file was parsed!`, a blank line, and today's JSON |
   | `MalformedDescriptorError` | `ExpatError` from `xmltodict.parse` | one line naming the expat error |
   | `EntityDeclarationError` | the `ValueError` `xmltodict.parse` raises for an entity | one line |
   | `UnsupportedDescriptorError` | any other exception inside `parse_descriptor` or `parse_manifest`: `KeyError`, `PathNotFound`, `TypeError`, the `int()` `ValueError`, `UnicodeDecodeError` | one line, `Could not parse the descriptor: <class>: <message>`, raised `from` the original |

   The `ExpatError` and entity mappings catch around the
   `xmltodict.parse` call only. The `int()` `ValueError` must not
   become an `EntityDeclarationError`. Phase 3 keeps the first five
   subclasses and deletes `UnsupportedDescriptorError`, so phase 3's
   ledger diff is the list of descriptors that stopped needing it.

   An outcome is named the same way in every expected file and in the
   ledger. A model is `model`. An error is its class name, followed by
   the cause's class name in brackets when its `__cause__` is not an
   `OVFError`, for example `UnsupportedDescriptorError(KeyError)`. That
   keeps the raw class visible, as the master plan's decision 5 wants,
   while the command never prints a traceback. One function,
   `outcome_name(exc)` in `errors.py`, computes it.

4. **Two output changes, not one.** The command catches `OVFError`,
   prints its message, and exits 1. For every refusal today's code
   prints, the lines it prints are unchanged. That is the master plan's
   requirement, and step 2b's equivalence check enforces it.

   The progress lines cannot be preserved, and this plan does not try.
   Today the walk prints as it goes: `Removed N unused info keys`, the
   version, the name, the `References` dictionary, and each disk,
   network and memory item as a raw `xmltodict` dictionary. Several of
   those are reprs of `xmltodict`'s own structures, which phase 3
   removes. A parser that never prints cannot produce them in place.
   So after a successful parse the command prints a summary from the
   model instead. It covers the same facts: version, system id, files,
   disks with capacity in GiB rounded up as today, networks, vCPUs,
   memory in MiB, controllers, NICs and disk drives. The stray
   `print(hardware)` in the upload loop prints the same summary of the
   hardware, in the same place. Phase 4 moves it. A refusal no longer
   follows a partial progress dump, because nothing is printed until
   the parse has finished.

   These are the phase's two output changes: tracebacks become one
   line (decision 3), and the progress lines become a summary. The
   pull request lists both. The master plan's phase 2 section is
   corrected to say so.

5. **The prose list moves to `ovf/prose.py`, with corrected field
   names.** `PROSE_ELEMENTS` keeps its element paths. Its model fields
   become paths relative to `VirtualSystem`, with `[]` meaning each
   element of a list:

   | Element | Model field |
   |---------|-------------|
   | `EulaSection/License` | `eulas[].license` |
   | `AnnotationSection/Annotation` | none: ignored unread |
   | `ProductSection/Info` | none: ignored unread |
   | `ProductSection/Product`, `Vendor`, `FullVersion`, `ProductUrl`, `VendorUrl`, `AppUrl` | `products[].product`, `.vendor`, `.full_version`, `.product_url`, `.vendor_url`, `.app_url` |
   | `ProductSection/Category` | `products[].properties[].category` |
   | `ProductSection/Property/Label`, `Property/Description` | `products[].properties[].label`, `.description` |
   | `VirtualSystem/Description`, `VirtualSystemCollection/Description` | `description` |
   | `Strings/Msg` | none |

   `PLACEHOLDER = 'TRIMMED'` moves with it. `scrub(virtual_system)`
   replaces every non-empty prose field with the placeholder, walking
   the paths above. Its test fails on any path in the table that names
   a field the model does not have, so the list and the model cannot
   drift apart. The trim tool imports both from
   `shakenfist_client_ova.ovf.prose`. It keeps its own bytes form of
   the placeholder (`PLACEHOLDER.encode()`), and keeps everything else
   it has. The tool runs under the `py3` tox environment's Python,
   where the package is installed, so the import resolves as
   `docs/development.md` already describes.

   In this phase `scrub` has nothing to replace, because no prose
   field is filled until phase 3. The curated test calls it anyway, so
   phase 3 inherits the protection rather than having to remember to
   add it.

6. **Expected files, the ledger, and how they are updated.**
   * The unit tier writes `<name>.expected.json` beside each of the 33
     `.ovf` files under `tests/fixtures/ovf/`. Each holds `to_json` of
     the model, or `{"error": "<outcome name>", "message_contains":
     "<fragment>"}`. The fragment is a stable phrase from the message,
     never a repr or a line number. One test module generates a test
     method per fixture at import time, because testtools has no
     parameterisation. Each fixture then passes or fails under its own
     name.
   * The curated subset's expected parses go in one file,
     `corpus_tests/curated.expected.json`. It is a JSON object keyed by
     the `<repo>:<path>` lines of `curated.txt`, with each value in
     the same form, the model scrubbed of prose first. One keyed file
     rather than 48 mirrored paths, because the upstream paths include
     spaces, a 140-character directory and `虚拟机.ovf`.
   * The ledger is `corpus_tests/ledger.txt`, one line per descriptor
     in both collections: `<repo>:<path>`, a tab, and the outcome
     name, sorted. It is text rather than JSON so that each changed
     outcome is a one-line diff. The tab follows the same rule as
     `curated-overrides.txt`.
   * `OVF_UPDATE_EXPECTED=1` makes each of these tests rewrite its
     file instead of comparing it, **and then fail**, with a message
     to review `git diff` and re-run without it. An update mode that
     passed could be left on in CI and pass forever. Both tox
     environments pass the variable through.

   Expected files are never edited by hand. A behaviour change is a
   regenerated file, reviewed as a diff, as master plan decision 7
   intends.

7. **`xmltodict` and `dpath` are pinned exactly for the test
   environments.** `tools/pinned-requirements.txt` holds
   `xmltodict==1.0.4` and `dpath==2.2.0`, with a comment explaining
   why (survey finding 8). `tox.ini`'s `[testenv]` sets
   `PIP_CONSTRAINT` to it, so both `py3` and `descriptor-corpus`
   install those versions, while the package's own dependencies stay
   unconstrained for users. The file name matches Renovate's
   `pip_requirements` manager, so a release arrives as a pull request
   whose test run shows any change in the ledger. Step 2c checks the
   default file pattern in Renovate's documentation, and adds a
   `managerFilePatterns` entry to `renovate.json` if the name does not
   match. Phase 3 drops both pins when it drops both dependencies, and
   decides then whether `defusedxml` needs one.

8. **The descriptor corpus tier.**
   * `corpus_tests/` gains an `__init__.py` and
     `test_descriptor_corpus.py`. It stays outside `.stestr.conf`'s
     `test_path`, so `py3` never collects it.
   * `[testenv:descriptor-corpus]` runs
     `{toxinidir}/tools/fetch-descriptor-corpus.sh`, then `stestr
     --test-path ./shakenfist_client_ova/corpus_tests run {posargs}`.
     The script goes in `allowlist_externals`.
   * The tests find the cache directories by reading `GOVMOMI_SHA`,
     `GOVMOMI_PATH`, `COT_SHA` and `COT_PATH` from the fetch script
     with a regular expression. The script stays the only place the
     pins are written. The classifier's docstring repeats them in its
     example command; step 2d changes that to point at the script
     rather than adding a third copy.
   * A missing cache directory, or one holding no `.ovf` files, fails
     every test in the module with a message naming the fetch script.
     It never skips.
   * Four tests: the ledger matches; every curated descriptor's scrubbed
     outcome matches `curated.expected.json`; every path in `curated.txt`
     exists in the cache; and `classify-ovf-corpus.py --curate`, run as
     a subprocess with the arguments in its docstring, reproduces
     `curated.txt` byte for byte. The last is the test phase 1's review
     asked for.
   * Master plan decision 5 asks for one pinned Python version in CI,
     because exception class names can differ between versions. The
     classes the ledger records are Python's built-in exceptions and
     those of the two pinned libraries. Decision 7's pin is what holds
     them stable. The job uses the runner's one `python3`, and
     contributors may use any version that installs the pins.

9. **The CI job runs on the static pool.** `descriptor-corpus` in
   `ci.yml` runs on `[self-hosted, static]`, like `lint-and-build`,
   with the same venv steps and `fetch-depth: 0` (tox builds the
   package, and setuptools_scm needs the tags). It runs on the same
   triggers: pull requests, pushes to `develop` and dispatch. `pr-retest`
   re-runs it with the rest of the workflow. `automated_reviewer`'s
   `needs` gains it, so a broken ledger holds back the review as a
   failing unit test does. The header comment, which says "One job",
   is rewritten to describe two. `actions/checkout` cleans ignored
   files, so every run fetches the collections afresh. That is a
   blob-filtered sparse fetch of about 30MB, accepted rather than
   cached.

10. **Equivalence is checked against today's command, not argued.**
    Step 2b writes a script outside the repository, in the session
    scratchpad. It loads `__init__.py` from `develop` (`git show
    db7bdaa:shakenfist_client_ova/__init__.py`) as one module and the
    branch's package as another. It runs both commands over every
    `.ovf` in the fixtures and both collections, each wrapped as a
    one-member OVA with `apiclient.Client` mocked, and requires:

    | Before | After |
    |--------|-------|
    | exit 0 | exit 0 |
    | exit 1 printing a refusal | exit 1, printing the same non-blank refusal lines |
    | an `ExpatError` traceback | exit 1, `MalformedDescriptorError` |
    | the entity `ValueError` traceback | exit 1, `EntityDeclarationError` |
    | any other traceback of class X | exit 1, one line, and `parse_descriptor` raises `UnsupportedDescriptorError` from an X |

    It then runs both commands over three synthetic OVAs. The first
    holds the Wazuh fixture and a few bytes named as its disk member,
    with `shakenfist_client.util` mocked. It requires the same upload
    calls, artifact names and source URLs from both. The other two
    hold a manifest each. One has a line in each of the ovftool,
    VirtualBox and AWS forms, a blank line and a CRLF line ending.
    The other has a malformed line. Both commands must agree on each.
    The script is not committed: once this phase lands there is no
    "before" to load. Its output, a table of before and after
    outcomes with counts, goes in the pull request body. The
    management session re-runs it after every later step that touches
    `ovf/` or the command.

## Step plan

| Step | Effort | Model | Isolation | Brief for sub-agent |
|------|--------|-------|-----------|---------------------|
| 2a | high | opus | none | Create `shakenfist_client_ova/ovf/` with `__init__.py`, `errors.py`, `model.py` and `prose.py`, exactly to decisions 1, 2, 3 and 5 of `docs/plans/PLAN-ovf-parser-phase-02-extract.md` (read it whole first, then master plan decisions 1 and 4). No parsing yet: this step is the shape. `model.py` holds the dataclasses in decision 2's code block, field for field, with Python 3.7-compatible annotations (`typing.List`, `typing.Optional`, `field(default_factory=list)` for every list and `None` for every `Optional`; no `list[str]`, no walrus, no positional-only parameters), and `to_json()`. A dataclass refuses a field without a default after one with a default, so put each class's required fields first; `to_json` sorts keys, so the order is invisible in every expected file. `errors.py` holds decision 3's classes and `outcome_name(exc)`. `prose.py` holds `PROSE_ELEMENTS` (moved from `tools/trim-ovf-descriptor.py:53`, with decision 5's field names), `PLACEHOLDER = 'TRIMMED'` and `scrub()`. Change the trim tool to `from shakenfist_client_ova.ovf.prose import PROSE_ELEMENTS` and to derive its bytes placeholder from `prose.PLACEHOLDER`; delete its own copies, and its comment saying phase 2 moves the list. Its `_PROSE_PATHS` uses only the paths, so no output changes. Prove it: all of `tests/test_trim_tool.py` still passes, including `CommittedFixturesTestCase` over the 16 vendor fixtures. Add `shakenfist_client_ova/tests/test_ovf_model.py`: `to_json` is deterministic (sorted keys, lists in insertion order, a final newline, non-ASCII kept); `outcome_name` gives `X` for an `OVFError` subclass `X`, `X(KeyError)` when it was raised `from` a `KeyError`, and plain `X` when its cause is itself an `OVFError`; `scrub` replaces every prose field on a fully populated synthetic `VirtualSystem` and leaves `None` and empty strings alone; every model path in `PROSE_ELEMENTS` names a real field (walk the dataclass fields, so a typo fails). Add `shakenfist_client_ova/tests/test_ovf_boundary.py` to decision 1's three rules, and mutation-check it before committing: add `import click` to `model.py`, then a `print()` to `errors.py`, then `sys.exit(1)`, and confirm each fails naming the rule; restore from a copy, not `git checkout`. Unit tests suffice; no cluster. Run `tox -epy3`, `pre-commit run --all-files` (stage new files first: pre-commit skips untracked files) and `python3 -c 'import shakenfist_client_ova'`. Commit subject: `Define the OVF model and error hierarchy.` |
| 2b | high | opus | none | Move today's descriptor and manifest parsing from `shakenfist_client_ova/__init__.py` (the manifest loop at lines 118-136 and the descriptor walk at 138-424) into `ovf/manifest.py` and `ovf/descriptor.py`, to decisions 1, 3 and 4 of the phase 2 plan. **Move, do not improve**: keep every `dpath` call, every `_coerce_to_list`, every deletion and its order, `NAMESPACES` and the `xmltodict.parse` arguments exactly; phase 3 rewrites all of it, and any improvement here is a behaviour change the expected files would silently bless. Replace each `print(...); sys.exit(1)` with a raise of decision 3's class carrying the same text; replace progress `print`s with nothing (the command prints a summary instead). Build the decision 2 model at the end of the walk from what was read; phase 3's fields stay empty. Wrap the walk as decision 3 says: `ExpatError` and the entity `ValueError` around `xmltodict.parse` only, then everything else not an `OVFError` as `UnsupportedDescriptorError` raised `from` it; the same wrapper around the manifest parse (a non-UTF-8 manifest raises `UnicodeDecodeError` today). Move `_parse_alloc_units_to_bytes` too, raising `UnknownAllocationUnitError`, and move `tests/test_alloc_units.py`'s cases to the new import path, its exit case becoming an `assertRaises` of that class. In the command: call `ovf.parse_manifest` per `.mf` member and `ovf.parse_descriptor` per `.ovf` member, keeping today's loops, so a second descriptor still replaces the first (phase 4 refuses it); catch `ovf.OVFError`, `print(str(e))`, `sys.exit(1)`; after the parse, print decision 4's summary; keep the fallbacks `Imported OVA VM` and version 1 in the command; keep the stray hardware print in the upload loop, printing the hardware summary. The command must no longer import `xmltodict`, `dpath` or `json`. Then write decision 10's equivalence script in the scratchpad path the management session gives you (not in the repository), run `tools/fetch-descriptor-corpus.sh` for the corpora, and run it: every row must match. A mismatch is a defect in the move: fix the move, never the script's rules. Report the counts table. Unit tests and the script suffice; no cluster. Commit subject: `Move the OVF parser out of the import command.` |
| 2c | medium | sonnet | none | Add the unit-tier golden test, `shakenfist_client_ova/tests/test_ovf_golden.py`, to decision 6 of the phase 2 plan, over every `.ovf` under `shakenfist_client_ova/tests/fixtures/ovf/` (33 files: `vendor/` and `handwritten/`), generating one test method per fixture at import time. Put the shared helpers (load a fixture's outcome as `to_json` or an error dict, compare, update mode) in `shakenfist_client_ova/tests/golden.py`, because step 2d's corpus tests import them too. Add `tools/pinned-requirements.txt` (decision 7) and, in `tox.ini`'s `[testenv]`, `PIP_CONSTRAINT={toxinidir}/tools/pinned-requirements.txt` in `setenv` and `OVF_UPDATE_EXPECTED` in `passenv`; confirm with `.tox/py3/bin/pip list` that the pinned versions installed. Check Renovate's documented default `pip_requirements` file pattern matches the file's name; if not, add a `managerFilePatterns` entry to `renovate.json`. Generate the 33 expected files with `OVF_UPDATE_EXPECTED=1 tox -epy3`, which must exit non-zero, then run `tox -epy3`, which must pass. Choose each `message_contains` by hand: a stable phrase such as `Not all of the OVF file was parsed` or `Unknown allocation unit: "byte"`, never a repr fragment. The outcomes must agree with the phase 2 plan's survey finding 2 per fixture (for example `vyos-1.2.1` is `UnsupportedDescriptorError(TypeError)`, `wazuh-4.9.1` a model). Mutation-check: change one expected file's `capacity_bytes`, then delete one expected file, and confirm the test for that fixture fails, naming it. Commit subject: `Add golden tests over the OVF fixtures.` |
| 2d | high | sonnet | none | Add the descriptor corpus tier to decision 8 of the phase 2 plan: `shakenfist_client_ova/corpus_tests/__init__.py`, `test_descriptor_corpus.py` with decision 8's four tests and its fail-closed guard, `ledger.txt` and `curated.expected.json` (decision 6's formats, generated with `OVF_UPDATE_EXPECTED=1`), and `[testenv:descriptor-corpus]` in `tox.ini`. Reuse `shakenfist_client_ova/tests/golden.py`. Read the pins from `tools/fetch-descriptor-corpus.sh` with a regular expression (decision 8), and change the example command in `tools/classify-ovf-corpus.py`'s docstring to take its directories from the script rather than repeating the SHAs. The ledger's outcome counts must equal survey finding 2: govmomi 116 `model`, 519 `UnsupportedDescriptorError(KeyError)`, 167 `UnsupportedDescriptorError(PathNotFound)`, 21 `UnsupportedDescriptorError(TypeError)`, 15 `MalformedDescriptorError`, 2 `UnsupportedDescriptorError(ValueError)`, and the 118 refusals as 78 `UnknownAllocationUnitError`, 36 `UnparsedContentError` and 4 `UnsupportedHardwareError`; COT 2 `model`, 3 refusals (1 `UnknownAllocationUnitError`, 2 `UnsupportedHardwareError`), 3 `UnsupportedDescriptorError(PathNotFound)` and 2 `UnsupportedDescriptorError(KeyError)`. Any difference is a defect in 2b; stop and report it. Verify the guard: with `.cache/ovf-corpora` moved aside, `stestr --test-path ./shakenfist_client_ova/corpus_tests run` must fail, not skip. Verify `tox -epy3` still collects no corpus test. Mutation-check: change one ledger line, one curated expected value, and one line of `curated.txt`, and confirm each fails. Unit tests and network suffice; no cluster. Commit subject: `Add the descriptor corpus test tier.` |
| 2e | medium | sonnet | none | In `.github/workflows/ci.yml`, add the `descriptor-corpus` job to decision 9 of the phase 2 plan, copying `lint-and-build`'s checkout, venv and PATH steps and its clean-up, then `tox -edescriptor-corpus`. Give it its own concurrency group, suffixed `-descriptor-corpus`. Add it to `automated_reviewer`'s `needs`. Rewrite the header comment's "One job" paragraph for two jobs, keeping its argument about the static pool and fork approval. `pre-commit run --all-files` runs actionlint over it. It can only be proven by the pull request's own run; say so. Commit subject: `Run the descriptor corpus tier in CI.` |
| 2f | medium | sonnet | none | Documentation for phase 2 of `docs/plans/PLAN-ovf-parser.md`. `ARCHITECTURE.md`: replace "All of the code is in `shakenfist_client_ova/__init__.py`" and the Import pipeline table's Descriptor and Manifest rows with the split between the command and `shakenfist_client_ova/ovf/`; add a short section on the subpackage, covering its import boundary and the test that enforces it, the `OVFError` hierarchy and the model. Keep "Parsing by consumption", which is still true until phase 3, but say it now happens inside `ovf/descriptor.py`. `docs/development.md`: under "Unit tests", the golden test, the expected files and `OVF_UPDATE_EXPECTED=1` (it rewrites, then fails); a "Descriptor corpus tier" subsection under "Test fixtures", covering `tox -edescriptor-corpus`, the ledger, the curated expected file, that it needs the network, and that its guard fails rather than skips; `tools/pinned-requirements.txt` and why; and the new job in the CI table. `docs/usage.md`: in "When an import stops", one sentence that a descriptor the parser cannot read stops the import with a one-line error naming the problem. Step 5's "Prints the hardware description" stays true. `AGENTS.md`: two bullets under Code Conventions. One: `shakenfist_client_ova/ovf/` never imports `click` or `shakenfist_client`, never prints and never exits, and a test enforces it. Two: expected files and the ledger are regenerated with `OVF_UPDATE_EXPECTED=1` and never hand-edited. Leave `README.md` alone. Commit subject: `Document the extracted OVF parser.` |

The management session reviews each step against the master plan's
checklist. After 2b, 2c and 2d it also re-runs decision 10's
equivalence script, because each touches code or data the script
verifies. After 2c it reads three expected files in full: one model,
one named refusal and one `UnsupportedDescriptorError`.

## Risks and mitigations

1. **The wrapper hides a defect in the moved code.** A `TypeError` from
   a slip in 2b's model construction would be reported as an
   unsupported descriptor, which is exactly what an unsupported
   descriptor looks like. Mitigation: decision 10's script compares
   cause classes descriptor by descriptor against today's command, so
   a new `TypeError` shows as a changed outcome. The management
   session re-runs it after 2b, 2c and 2d. 2d's ledger counts must
   also equal survey finding 2.
2. **Expected files become a rubber stamp.** Thirty-three expected
   files and 48 curated entries are generated, not written, and a
   reviewer will not read them all. That is acceptable here, because
   they record today's behaviour by design, and the review of that
   behaviour is decision 10's script, not a reading. Phase 3 is where
   reading matters: its plan already requires each newly successful
   vendor fixture to be checked field by field.
3. **The model's shape is wrong.** Every expected file would churn in
   phase 3. Mitigation: decision 2 is written out field by field here,
   so the shape is reviewed with this plan, before any code. The back
   brief makes that review the gate.
4. **Prose reaches a committed expected file.** Not in this phase,
   because no prose field is filled. In phase 3, fields such as
   `DeploymentOption.label` and `OperatingSystem.description` will be
   filled, and they are not on the prose list. Phase 1 judged them
   short and structural. Phase 3's plan should re-read the curated
   expected file for vendor text before committing it. Recorded under
   the master plan's phase 3 section.
5. **A GitHub outage fails the corpus job on an unrelated pull
   request.** The fetch is small, and `pr-retest` re-runs it. Accepted.
6. **The pins stop the test suite installing on Python 3.7.**
   `xmltodict` 1.0.4 may not install on the oldest Python the package
   supports. Nothing tests that floor today (master plan Future work),
   and the pin is gone in phase 3. Accepted, and noted in
   `tools/pinned-requirements.txt`.

## Definition of done

* `grep -nE '^import (xmltodict|dpath|json)' shakenfist_client_ova/__init__.py`
  finds nothing.
* `test_ovf_boundary.py` exists, and the three mutations in 2a's brief
  each make it fail.
* Decision 10's script reports no mismatch over 33 fixtures and 968
  upstream descriptors, and its counts table is in the pull request
  body.
* Every fixture has an expected file. This prints nothing:
  `find shakenfist_client_ova/tests/fixtures/ovf -name '*.ovf' | while read -r f; do [ -f "${f%.ovf}.expected.json" ] || echo "$f"; done`.
* Every ledger outcome is `model` or an `OVFError` subclass, with an
  optional cause in brackets. This prints nothing:
  `grep -vP '\t(model|[A-Za-z]+Error(\([A-Za-z]+\))?)$' shakenfist_client_ova/corpus_tests/ledger.txt`.
  The counts equal survey finding 2.
* `OVF_UPDATE_EXPECTED=1 tox -epy3` exits non-zero and leaves
  `git status --short` empty on an up-to-date tree.
* With `.cache/ovf-corpora` absent, the corpus tests fail, not skip.
  `tox -edescriptor-corpus` passes from an empty cache.
* `grep -n 'PROSE_ELEMENTS = ' tools/trim-ovf-descriptor.py` finds
  nothing, and `CommittedFixturesTestCase` passes.
* The pull request's checks include a passing "Descriptor corpus"
  job, and `automated_reviewer` needs it.
* `tox -epy3`, `pre-commit run --all-files` and
  `python3 -c 'import shakenfist_client_ova'` pass. The wheel contains
  `shakenfist_client_ova/ovf/` and neither `tests` nor `corpus_tests`.
* `grep -n 'All of the code is in' ARCHITECTURE.md` finds nothing.
* The master plan's Execution table and `docs/plans/index.md` agree,
  and this phase's Merged cell is left for phase 3's first commit.

## Corrections made to the master plan

Made in this phase's planning commit, so that the next reader does not
trip over them:

* Situation item 1: an OVF 2.x descriptor dies at the first
  `dpath.delete`, with `PathNotFound` (survey finding 3).
* Decision 5: the ledger names raw exception classes as causes in
  brackets; and `xmltodict` and `dpath` are pinned for the test
  environments, because nothing bumped them before (findings 4 and 8).
  The Python-version pin is replaced by the library pins (decision 8).
* Phase 2's section: the named output change covers all five
  exception classes, the progress output becomes a summary, and the CI
  job runs on the static pool (findings 4, 9 and decision 4).
* Phase 3's section: "Phase 2 will probably record most vendor fixtures
  as refusals" becomes the measured 12 of 16; #11 is named as phase 3's
  to fix; and risk 4's re-read of the curated expected file is added.

## Back brief

Before executing any step, back brief the operator on how the work
aligns with this plan. The gate is decision 2. The model's shape is
cheap to change in this file and expensive to change after 2c and 2d
have generated 81 expected outcomes and a 968-line ledger against it.
So step 2a does not start until the operator has reviewed decision 2,
and 2c does not start until the management session has confirmed that
2a's `model.py` matches decision 2 field for field.

# OVF parser phase 3: ElementTree and the specification

## Prompt

Before responding to questions or discussion points in this document,
read the master plan, [PLAN-ovf-parser.md](PLAN-ovf-parser.md),
particularly decisions 3, 4 and 7, its open questions 4 to 6, and phase
3's section. Then read phase 2's plan,
[PLAN-ovf-parser-phase-02-extract.md](PLAN-ovf-parser-phase-02-extract.md),
for the model, the error hierarchy and the test tiers this phase builds
on, and its execution notes. The master plan's decisions are not
restated here, except where this phase's survey changed or sharpened
them.

This is the phase where the parser's behaviour changes. Phase 2 kept
today's `xmltodict` walk, recorded what it does, and refused nothing new.
This phase replaces the walk with a parser that follows the
specification. Every changed expected file and ledger line is a
behaviour change, and the pull request has to explain each one.

## Planning effort

High, by the master plan's rule: this phase changes what the parser
accepts and refuses. Review effort: high for decisions 1 to 6, which
set the strictness tables. A wrong entry there either refuses a real
appliance or quietly ignores something that matters, and the corpus
only partly shows which. Medium for the rest.

## Scope

In:

* A new `ovf/descriptor.py` on `defusedxml.ElementTree`, with decision
  4's strictness, covering OVF 1.x and 2.x, OVF 2's `StorageItem` and
  `EthernetPortItem`, and the producer quirks decision 3 accepts.
* `ProductSection`, `EulaSection`, `OperatingSystemSection`,
  `DeploymentOptionSection`, `VirtualSystem/Name`, `vssd:System` and
  `ovf:transport` read into the model. Phase 2 left those fields empty.
* Allocation units parsed by DSP0004's programmatic-unit grammar, which
  fixes #11, and disk capacities given as `${property}` references.
* Named refusals: OVF 0.9 and other non-OVF envelopes,
  `VirtualSystemCollection`, and oVirt exports.
* The command's `--accept-eula` refusal and its warning for
  user-configurable properties, with `CliRunner` tests.
* Every changed expected file and ledger line, explained. Each vendor
  fixture that newly parses is checked field by field and gains a
  hand-written assertion.
* `UnsupportedDescriptorError` deleted, and the corpus tier asserting
  that no outcome carries a raw cause.
* `xmltodict` and `dpath` dropped, `defusedxml` made a runtime
  dependency, and `tools/pinned-requirements.txt` removed.
* `AGENTS.md`, `docs/usage.md`, `docs/development.md` and
  `ARCHITECTURE.md` updated for the new convention.

Out:

* Anything about the archive: references checked against members,
  manifest verification, compression and chunking. That is phase 4.
  The `href-*`, `gzip-reference` and `chunked-reference` fixtures
  still parse here, because they are descriptor-valid.
* A reader for oVirt's OVF dialect (decision 3). Future work.
* Delivering `ProductSection` properties to a guest as an OVF
  environment. Future work, as the master plan says. This phase warns.
* #12, the trim tool's traceback on an entity declaration, which is a
  tool fix rather than a parser one.

## What the survey found

The survey ran on 2026-10-17, over the 33 committed fixtures and the
968 upstream descriptors. It counted every element under its parent,
every attribute, every hardware item's children, resource types,
allocation units and capacity values, and which of them carry
`ovf:required="false"`. The script and its JSON output are in the
planning session's scratchpad, not the repository. Findings 3, 4 and 6
change the master plan, and the planning commit corrects them at source
(see "Corrections made to the master plan").

### 1. Phase 2 is complete

Phase 2 merged as `97273c7`. `tox -epy3` passes 128 tests and `tox
-edescriptor-corpus` passes 4 on `develop`. The master plan and the
index agree that the plan is in progress. Its deferred items are #11 (fixed here), #12, and the read
of `Network.description` in the curated file (step 3c here). Its
execution notes say nothing tests the corpus guard; the second review
round of #13 added that test, so the note is stale and is corrected in
the planning commit.

### 2. The namespaces that reach the parser

| Root namespace | Descriptors |
|----------------|-------------|
| OVF 1.x or 2.x (`schemas.dmtf.org/ovf/envelope/1`, `/2`) | 828 |
| OVF 0.9 (`www.vmware.com/schema/ovf/1/envelope`) | 151, including Tails |
| No namespace, `nosuchspec.com`, `ovf/envelope/3` | 6, all deliberately invalid |
| Not well-formed, or an entity declaration | 16 |

Phase 2's survey counted 149 OVF 0.9 descriptors, by matching the
namespace in the text. This count of 151 parses the root element.

### 3. VMware and VirtualBox write three things the schema does not allow

These are not one-offs. Taken literally, each would refuse a real
producer's output wholesale:

* **An unqualified attribute on an OVF element.** ovftool writes
  `<Item configuration="...">`. The schema's attributes are
  `ovf:`-qualified. This happens on 814 `Item`s, VyOS among them. ovftool
  also writes `Value@configuration`, `Value@value` and `License@msgid`
  unqualified.
* **`InstanceId` for `InstanceID`.** `rasd:InstanceId` appears 583
  times, in Tails and Oracle Linux among others. `vssd:InstanceId`
  appears 226 times.
* **`.xsd`-suffixed CIM namespaces.** VirtualBox's OVF 2.0 export, with
  ArchiveTeam Warrior as the example, uses these for `epasd` and `sasd`.
  This is master plan open question 5.

### 4. oVirt is a dialect, not three attributes

Master plan open question 4 found three oVirt attributes on `Disk`. The
Oracle Linux OLVM export carries far more:

* 33 oVirt elements in the OVF namespace under `VirtualSystem`, such as
  `TemplateId`, `MinAllocatedMem`, `MaxMemorySizeMb` and `TimeZone`;
* `VmInit`, whose `ovf:customScript` attribute holds the template's
  cloud-init configuration;
* five unqualified children of `Item`: `Type`, `Device`, `BootOrder`,
  `IsPlugged` and `IsReadOnly`;
* 13 non-CIM properties in the `rasd` namespace, such as
  `rasd:cpu_per_socket` and `rasd:UsbPolicy`;
* a resource type of 32768, which CIM does not define, for its video
  device;
* `ovirt:id` on `OperatingSystemSection`;
* five attributes on `Disk`, not three.

The recommendation in open question 4 was a closed ignore list, with
`ovf:disk-interface` read. On this evidence it does not scale. Decision
3 refuses oVirt exports by name instead.

### 5. What hardware items hold

| Resource type | Items | Marked not required | Today |
|---------------|-------|---------------------|-------|
| 3 CPU, 4 memory, 5 IDE, 6 SCSI, 10 Ethernet, 17 disk | thousands | almost none | read |
| 20 other storage controller | 87 | 0 | read only when the subtype is `AHCI`; otherwise ignored silently |
| 14 floppy, 15 CD, 23 USB, 24 video, 35 sound | 1,200 | 619 | ignored |
| 1 other | 86 | 84 | refused unless not required |
| 21 serial | 12 | 12 | refused |
| 31, 34, 89 | 4 | 1 | refused |
| 32768 | 1 (oVirt) | 0 | refused |

Type 20's subtypes are `vmware.sata.ahci` (60), `AHCI` and `ahci` (6),
`vmware.nvme.controller` (1), and `vmware.nvdimm.controller` and
`.device` (19). Today every subtype except `AHCI` is silently ignored. A
disk on such a controller then fails with a `KeyError`.

Items carry these CIM properties: `ResourceType`, `ElementName`,
`InstanceID`, `Description`, `AddressOnParent`, `Parent`,
`ResourceSubType`, `HostResource`, `Address`, `AutomaticAllocation`,
`VirtualQuantity`, `AllocationUnits`, `Connection`, `Caption`,
`Reservation`, `Weight`, `Limit` and `VirtualQuantityUnits`. There are
also oVirt's extras, and five `rasd:Unknown` elements in deliberately
invalid descriptors. `AllocationUnits` on a CPU item is `hertz * 10^6`
620 times. It is the unit of the item's `Reservation` and `Limit`, not of
its `VirtualQuantity`.

### 6. Allocation units and capacities

* **Allocation units.** The values seen are:
  * `byte`, the subject of #11;
  * `byte * 2^20`, with and without spaces, and as `byte * 2 ^ 20`;
  * `byte*1024*1024`;
  * `byte * 2^30` and `byte*2^30`;
  * `MegaBytes`;
  * `hertz * 10^6` and `hertz * 10^9`, and `Hertz*10^9`.

  Today's regular expression matches only `byte * 2^N` written exactly
  that way.
* **Capacities given as property references.** Twelve `ovf:capacity`
  values have the form `${name}`. The two that `int()` fails on today,
  in `uber.ovf` and `multiple_disks.ovf`, are among them. DSP0243
  defines this form: the value is taken from the `ProductSection`
  property of that key.
* **`ovf:configuration` on four elements.** It appears on `Item` (169
  qualified, 814 unqualified), `Property` (18), `Value` (39) and
  `Network` (1). A property's per-configuration values are `Value`
  children of the `Property`.
* **`ovf:bound`.** 20 items carry it, with the values `min`, `normal`
  and `max`.

### 7. Sections that are not marked optional

These would be refused by decision 4's rule as written, and nothing in
the master plan names them:

| Section | Not marked | Where |
|---------|------------|-------|
| `ovf:Strings`, with `ovf:msgid` on text elements | 74 | govmomi |
| `vmw:StorageGroupSection`, `vmw:StorageSection` | 32 | govmomi |
| `vmw:TagBasedPlacementGroupSection`, `vmw:TagBasedPlacementSection` | 46 | govmomi |
| `ovf:InstallSection` | 3 | govmomi |

None appears in a vendor fixture. `Strings` is the specification's
localisation mechanism for the text the parser ignores or holds as
labels. Decision 2 ignores it with them. The others are refused, as the
specification requires.

### 8. Sections that repeat

As phase 2 found, `ProductSection` and `EulaSection` repeat 35 and 19
times, and three descriptors carry more than one
`VirtualHardwareSection`. The model's lists hold them.

### 9. What the vendor fixtures should do afterwards

On decisions 1 to 6, 14 of the 16 vendor fixtures should parse to a
model:

* Tails is refused as OVF 0.9.
* Oracle Linux is refused as an oVirt export.

Phase 2 parsed four. That is the claim step 3b's ledger and step 3c's
field-by-field check test.

## Decisions

1. **What counts as an OVF envelope.** The root must be `Envelope` in
   the OVF 1.x or 2.x namespace. Anything else raises the new
   `UnsupportedEnvelopeError`, whose message names the root's namespace
   and says whether it is OVF 0.9. That covers OVF 0.9, a root with no
   namespace or an unknown one, and a root that is not `Envelope`. This
   settles master plan open question 6 as its recommendation proposed.
   Supporting 0.9 would need a second dispatch over generic `Section`
   elements typed by `xsi:type`, and the producers that write it can
   also write 1.0. Tails is refused with this error. An
   `Envelope/VirtualSystemCollection` raises the new
   `VirtualSystemCollectionError` before any other check, as the master
   plan requires. An envelope with no `VirtualSystem` raises the new
   `MissingContentError`.

2. **The strictness rule, made exact.** The parser records every
   element and attribute it reads. After the parse it walks the whole
   tree. Each element or attribute left unread is then either ignored
   or refused, by the first of these rules that applies:

   | Unread thing | Outcome |
   |--------------|---------|
   | An element carrying `ovf:required="false"`, and its whole subtree | ignored, as OVF permits |
   | `Info` anywhere; `AnnotationSection`; `Strings` | ignored: text for a person, which nothing reads. `Strings` joins the master plan's closed list (survey finding 7) |
   | Attribute `ovf:msgid`, or unqualified `msgid` on an OVF element | ignored: it only links text to `Strings` |
   | Attribute `xml:lang` or `xsi:schemaLocation` | ignored, as decision 4 says |
   | Any other attribute in a namespace that is not OVF's or CIM's | ignored: DSP0243 section 7.3 says custom attributes "shall not be required for correct behavior" |
   | A standard CIM property the parser does not use (decision 5) | ignored, by name, from a closed list |
   | Anything else | refused |

   A refusal raises `UnparsedContentError`. The message lists every
   unread element and attribute, each as a path such as
   `Envelope/VirtualSystem/vmw:StorageSection`. That replaces today's
   JSON dump, and serves the same purpose: it shows what to teach the
   parser next. The list is sorted and capped at 20 entries, with a
   count of the rest. A whole unread subtree is reported once, at its
   root.

   Namespace declarations are not attributes in ElementTree, so they
   need no rule.

3. **Producer quirks are accepted by name, in one table, and oVirt is
   refused.** `ovf/quirks.py` holds the accepted deviations. Each
   entry names its producer and the survey evidence:

   * **VirtualBox's suffixed CIM namespaces.**
     `.../CIM_EthernetPortAllocationSettingData.xsd` and
     `.../CIM_StorageAllocationSettingData.xsd` are read as the DMTF
     namespaces. This settles master plan open question 5 as its
     recommendation proposed.
   * **`InstanceId` for `InstanceID`.** Accepted in the `rasd`, `vssd`,
     `sasd` and `epasd` namespaces, from VMware, VirtualBox and others
     (survey finding 3).
   * **Unqualified attributes.** An unqualified attribute on an OVF
     element is read as the OVF attribute of the same name, wherever
     the parser reads that attribute: VMware's `configuration`, `value`
     and `msgid`. When both forms are present on one element, the
     element is refused, because they could disagree.

   oVirt exports raise the new `UnsupportedProducerError`, detected by
   the oVirt namespace `http://www.ovirt.org/ovf` declared anywhere in
   the descriptor. This settles master plan open question 4 against
   its recommendation, for survey finding 4's reasons. A closed ignore
   list built from one export would refuse the next one anyway, on
   whatever that export adds. The list would also have to decide,
   silently, to drop the template's cloud-init configuration and its
   memory policy. Refusing by name is honest, and the message says why.
   A real oVirt reader is Future work. The detection can be checked
   with a test that strips the namespace declaration from the Oracle
   fixture: it must then fail on the first oVirt element instead.

4. **Allocation units follow DSP0004's programmatic units.**
   `ovf/units.py` parses `base [* multiplier]...` and returns the factor
   in bytes:
   * spaces may appear anywhere;
   * the base is `byte`, case-insensitively;
   * each multiplier is `2^N`, `10^N` or an integer.

   The legacy names `KiloBytes`, `MegaBytes` and `GigaBytes` are also
   accepted, as powers of two, matching today's behaviour. That fixes
   #11. A unit with any other base, such as `hertz * 10^6`, is an
   `UnknownAllocationUnitError` where a byte count is required:

   * `ovf:capacityAllocationUnits` on `Disk`;
   * `AllocationUnits` or `VirtualQuantityUnits` on a memory item.

   On a CPU item, `AllocationUnits` is the unit of `Reservation` and
   `Limit`. The parser does not use those (decision 5), so it does not
   parse that unit either. `VirtualQuantityUnits`, where present, is
   used in preference to `AllocationUnits`, as CIM intends.

   A disk capacity of the form `${key}` is resolved from the
   `ProductSection` property with that key, in the default
   configuration (decision 6). If the key does not exist, or its value
   is not an integer, the new `InvalidValueError` is raised, naming the
   key. Any other value that does not parse, such as a non-integer
   capacity or a boolean that is neither `true` nor `false`, is also an
   `InvalidValueError`.

5. **Hardware items are read against the CIM class, not a guess.** The
   rules are:

   * **Resource types.** These are read: 3, 4, 5, 6, 10 and 17; 20 with
     subtype `AHCI`, `ahci` or `vmware.sata.ahci` as `sata`; and 20
     with `vmware.nvme.controller` as `nvme`. These are recognised and
     left to the instance's defaults, as today: 14, 15, 16, 23, 24 and
     35. Anything else, including type 20 with any other subtype, raises
     `UnsupportedHardwareError`, unless the item is marked not
     required. Type 1 ("Other") is no longer a special case, as master
     plan decision 4 says.
   * **CIM properties.** A child of an item in the `rasd`, `sasd` or
     `epasd` namespace is either read, or is one of that CIM class's
     standard properties that the parser deliberately does not use:
     `Caption`, `Description`, `Address`, `AutomaticAllocation`,
     `Reservation`, `Limit`, `Weight` and the like. Step 3a takes the
     property lists from the DMTF schemas (the
     `CIM_ResourceAllocationSettingData`,
     `CIM_StorageAllocationSettingData` and
     `CIM_EthernetPortAllocationSettingData` XSDs at
     `schemas.dmtf.org/wbem/wscim/1/cim-schema/2/`), and records in the
     module the URLs and the date they were taken. A name in those
     namespaces that is not in its class, such as `rasd:Unknown`, is
     refused like any other unread element. The same applies to
     `vssd:System`'s children, against
     `CIM_VirtualSystemSettingData`.
   * **Drives and disks.** A drive's `HostResource`, when it is
     `ovf:/disk/<id>`, must name a `Disk` in the `DiskSection`, and
     `ovf:/file/<id>` must name a `File`. An unknown id raises the new
     `BrokenReferenceError`. So does a disk drive whose `Parent` names
     no controller, which today is a `KeyError`. A disk whose
     `ovf:fileRef` names no `File` is a `BrokenReferenceError` too.
   * **Bounds.** Items with `ovf:bound="min"` or `"max"` are ranges for
     a deployment tool. The parser reads `normal` and unbounded items
     only, and treats the other two as read.
   * **More than one hardware section.** Every `VirtualHardwareSection`
     is parsed into `VirtualSystem.hardware`, in document order.
     Choosing one is left to the instance-creation plan.

6. **Deployment options resolve to the default configuration.** The
   default is the `Configuration` with `ovf:default="true"`, or else
   the first. Items, networks and properties carrying
   `ovf:configuration` (or VMware's unqualified `configuration`) apply
   only when the list names the default. A property's per-configuration
   `Value` children override its `ovf:value` for the default. Everything
   not chosen is still marked as read, so it is not refused.
   `Envelope.deployment_options` lists every configuration, with
   `default` set on the chosen one. Choosing another configuration is
   the instance-creation plan's business.

7. **The rest of the model.**

   * **`ProductSection`** is read into `Product`, with each `Property`
     and the `Category` before it. `ovf:userConfigurable` and
     `ovf:password` are booleans, and `ovf:isPassword` is a 2.x synonym
     of `ovf:password`. `ovf:runtimeConfigurable` is read for validity
     and not modelled. `Icon` is read and not modelled; no fixture
     carries one.
   * **`EulaSection`** is read into `Eula`.
   * **`OperatingSystemSection`** is read into `OperatingSystem`: `id`,
     `ovf:version`, `osType` (OVF 2's `ovf:osType`, or VMware's
     `vmw:osType` read by name as an exception to the custom-attribute
     rule) and `Description`.
   * **`vssd:System`'s** `VirtualSystemType` and
     `VirtualSystemIdentifier` are read into `VirtualHardware`.
   * **`ovf:transport`** is split on spaces into
     `VirtualHardware.transport`.
   * **`VirtualSystem/Name`** is read into `name`.
   * **`File`'s** `ovf:size`, `ovf:compression` and `ovf:chunkSize` are
     read. Phase 4 acts on them.
   * **`Disk`'s** `ovf:populatedSize` and `ovf:parentRef` are read.
     `parentRef` names a delta disk's parent, which the model has no
     field for. The model gains `Disk.parent_ref`, and every expected
     file gains one `null`, as phase 2's decision 2 allows for a field
     a later phase needs.
   * **`Disk.interface`**, added for oVirt, stays and is never filled,
     because a future oVirt reader would fill it. Dropping it would
     churn every expected file for nothing.

   `Disk.parent_ref` is the model's only change of shape.

8. **The command.** It prints every `EulaSection`'s licence and stops
   with exit 1 unless `--accept-eula` is given. The refusal says which
   flag accepts the licence. It runs before anything is uploaded, and
   after the parse, so that a descriptor that would be refused anyway
   is refused first. It then names each property with
   `ovf:userConfigurable="true"` and no value in the default
   configuration, in one warning: the appliance expects it at first
   boot, and Shaken Fist cannot deliver it yet. Step 3d tests all of
   this through `CliRunner`. It also tests every `OVFError` subclass
   becoming one line and exit 1, using the fixture that raises each.

9. **The ledger is the review.** In step 3b's diff the ledger shows
   every descriptor whose outcome moved. Phase 2 recorded 729 refusals
   that carried a raw cause. A script in the planning session's
   scratchpad turns `git diff` of the ledger into a table of
   transitions with counts, such as `UnsupportedDescriptorError(KeyError)
   -> model: N`. That table goes in the pull request body. Transitions
   from `model` to a refusal are listed path by path, with the reason
   for each. Those are the ones that could hide a regression.

10. **Pins and dependencies.** With `UnsupportedDescriptorError` gone,
    no outcome name comes from a library, and no `message_contains`
    fragment may come from one either. Step 3b chooses fragments from
    the parser's own text. So `tools/pinned-requirements.txt` and
    `PIP_CONSTRAINT` are removed. `defusedxml` moves from the `test`
    extra to the runtime dependencies, `xmltodict` and `dpath` are
    dropped, and the boundary test's allow-list loses all three of
    `xmltodict`, `dpath` and `xml.parsers.expat`.

## Step plan

| Step | Effort | Model | Isolation | Brief for sub-agent |
|------|--------|-------|-----------|---------------------|
| 3a | high | opus | none | Foundations, with no parser change, to decisions 1, 3, 4 and 5 of `docs/plans/PLAN-ovf-parser-phase-03-elementtree.md` (read it whole first, then phase 2's plan and `shakenfist_client_ova/ovf/`). In `ovf/errors.py`, add `UnsupportedEnvelopeError`, `VirtualSystemCollectionError`, `UnsupportedProducerError`, `MissingContentError`, `InvalidValueError` and `BrokenReferenceError`, each with a docstring saying when it is raised, and export them. Do not delete `UnsupportedDescriptorError` yet. Add `ovf/units.py`, implementing decision 4's grammar as `bytes_per_unit(text)`, which raises `UnknownAllocationUnitError`. Test it on every value in survey finding 6, and on `byte * 2^`, `bytes`, `byte * 2^-1`, an empty string and `hertz * 10^6`, all refused. Add `ovf/quirks.py`, holding decision 3's tables and the oVirt namespace, each entry with a comment naming its producer and evidence. Add `ovf/cim.py`, holding the property-name sets of `CIM_ResourceAllocationSettingData`, `CIM_StorageAllocationSettingData`, `CIM_EthernetPortAllocationSettingData` and `CIM_VirtualSystemSettingData`. Take them from the DMTF XSDs at `https://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/<class>.xsd`: fetch each into the scratchpad and read it with defusedxml, because it is downloaded data. Record each URL and the fetch date in the module. Each set also notes which names the parser reads (decision 5). Test that the sets contain every standard name survey finding 5 lists, and not `Unknown` or `cpu_per_socket`. Do not cite plan phases or decisions in code or comments; a consistency audit forbids it. Run `tox -epy3`, `pre-commit run --all-files` (stage new files first) and the audit script (`~/src/shakenfist/development/scripts/audit-check.py`). Unit tests suffice. Commit subject: `Add allocation units, CIM properties and quirks.` |
| 3b | xhigh | opus | none | Replace `ovf/descriptor.py`'s `xmltodict` walk with a parser on `defusedxml.ElementTree`, to decisions 1 to 7 and 10 of the phase 3 plan. Read the plan whole, then master plan decisions 3 and 4, then everything in `ovf/` and the tests. Build a small reader that marks each element and attribute it consumes. At the end of the parse it applies decision 2's table to everything unmarked, reporting each unread subtree once, at its root, sorted and capped. Map namespaces through one table keyed by URI: OVF 1.x and 2.x, the CIM namespaces, and decision 3's aliases. Write no lookup twice for the two envelope versions. Catch `ParseError` as `MalformedDescriptorError`, and defusedxml's `EntitiesForbidden`, `DTDForbidden` and `ExternalReferenceForbidden` as `EntityDeclarationError`, each with a one-line message in the parser's own words. Delete `UnsupportedDescriptorError` and the wrapper that raised it, `NAMESPACES`, `_coerce_to_list` and every `xmltodict`/`dpath` import. Remove them from `pyproject.toml`'s dependencies, and move `defusedxml` there from the `test` extra, keeping its licence comment. Delete `tools/pinned-requirements.txt` and tox.ini's `PIP_CONSTRAINT`. In `test_ovf_boundary.py`, remove `xmltodict`, `dpath` and `xml.parsers.expat` from the allow-list. Then regenerate the 33 golden files, `ledger.txt` and `curated.expected.json` with `OVF_UPDATE_EXPECTED=1`, choosing every `message_contains` from the parser's own wording. Run the ledger transition script the management session gives you, and stop and report before committing if any descriptor goes from `model` to a refusal without a decision in the plan that explains it. Expected vendor outcomes: 14 models, `tails-202607` `UnsupportedEnvelopeError`, `oracle-linux-9.8-olvm` `UnsupportedProducerError`. Expected hand-written outcomes: `unknown-required-extension` and `unknown-ovf-attribute` are `UnparsedContentError`, `entity-declaration` is `EntityDeclarationError`, `virtual-system-collection` is `VirtualSystemCollectionError`, and the other 13 are models. Any difference is reported with its reason, never fixed by editing the expectation. Add unit tests for the reader's rules: one each for an unread required element, a `required="false"` subtree, a custom-namespace attribute, an unqualified attribute read and refused, both attribute forms on one element, `Strings` and `msgid`, a capped message, configuration selection, `ovf:bound`, a `${}` capacity resolved and unresolved, each `BrokenReferenceError`, and the oVirt detection. For oVirt, also test that the Oracle fixture with its namespace declaration stripped fails on an oVirt element instead. Do not cite plan phases or decisions in code. Run `tox -epy3`, `tox -edescriptor-corpus`, `pre-commit run --all-files` and the audit script. Unit tests and the corpus suffice. Commit subject: `Parse OVF descriptors with ElementTree.` |
| 3c | high | opus | none | For each vendor fixture under `shakenfist_client_ova/tests/fixtures/ovf/vendor/` that step 3b took from a refusal to a model, read the descriptor and its `.expected.json` side by side, and check field by field: disk capacities and units, files, controllers and their buses, which drive sits on which controller and which disk it holds, NICs and their networks, vCPUs, memory and units, the operating system, products and properties, and deployment options. List every discrepancy in your report. A discrepancy is a parser defect, so describe it and stop; never edit an expected file to match. Then add `shakenfist_client_ova/tests/test_vendor_fixtures.py`, one test per vendor fixture that parses. Each test asserts those values by hand in plain Python, written from the descriptor and not from the expected file, so the expected file is not the only record of what correct looks like. Then read `shakenfist_client_ova/corpus_tests/curated.expected.json` whole for vendor prose in fields the prose list does not cover: `DeploymentOption.label` and `.description`, `OperatingSystem.description`, `Network.description`, `Product.version`. Report each value that reads as marketing or licence text rather than a short label. Unit tests suffice. Commit subject: `Assert each vendor fixture's parse by hand.` |
| 3d | high | sonnet | none | The command, to decision 8 of the phase 3 plan. In `shakenfist_client_ova/__init__.py`, add `--accept-eula` to `ova import`. After a successful parse and before anything is uploaded, print each EULA's licence and stop with exit 1 unless the flag is given, with a message naming the flag. Then print one warning naming each property with `user_configurable` true and no value, by key and label. It says the appliance expects them at first boot and Shaken Fist cannot deliver them yet. Extend the summary with the operating system and the products' names and versions. Extend `tests/test_command.py` with `CliRunner` tests, with `apiclient.Client` and `shakenfist_client.util` mocked as the file already does. Cover: `product-and-eula.ovf` refused without the flag, with the licence printed and nothing uploaded; the same accepted with the flag; the property warning; and, for each `OVFError` subclass, the fixture or synthetic descriptor that raises it printing one line and exiting 1. Mutation-check: remove the EULA check, then the warning, and confirm a test fails for each. Restore from a copy. Do not cite plan phases or decisions in code. Run `tox -epy3` and `pre-commit run --all-files`. Unit tests suffice; no cluster. Commit subject: `Refuse an unaccepted EULA and warn of properties.` |
| 3e | medium | sonnet | none | Documentation for the new parser. `AGENTS.md`: the strictness bullet says sections are "deleted from the parsed descriptor"; rewrite it for decision 2's rule, in three lines, pointing to `docs/usage.md`. `docs/usage.md`: "When an import stops" for the new rule, the named refusals (OVF 0.9, collections, oVirt, broken references), `--accept-eula` and the property warning. Also step 3's list of what is read. `ARCHITECTURE.md`: replace "Parsing by consumption" with a short section on reading with ElementTree and the end-of-parse check, and on the quirk and CIM tables in `ovf/`. `docs/development.md`: remove the pins paragraph, describe what to do when a new producer quirk turns up (an entry in `ovf/quirks.py`, with evidence), and keep everything else. Never write a plan phase number in these files; link `docs/plans/PLAN-ovf-parser.md` for Future work instead. Run `pre-commit run --all-files` and the audit script; `plan-phase-references`, `llm-doc-structure` and `readme-structure` must pass. Commit subject: `Document the specification-following parser.` |

The management session reviews each step. After 3b it reads:

* the transition table in full;
* every `model -> refusal` line;
* every vendor and hand-written expected file whose outcome changed.

Steps 3a to 3e are sequential. 3c and 3d touch different files but both
depend on 3b's model, so they may run in parallel after 3b.

## Risks and mitigations

1. **The CIM property lists accept something that matters.** A
   standard property such as `rasd:Limit` is ignored by name. If one of
   them changes what the appliance is, the import silently differs.
   Mitigation: decision 5 lists only labels and scheduling hints as
   unused, and 3a's review checks every name in the "not used" set
   against its CIM description. `VirtualQuantityUnits` is read, because
   it changes the meaning of a quantity.
2. **A quirk entry is too broad.** The unqualified-attribute rule could
   let a malformed descriptor through. Mitigation: it applies only
   where the parser reads the qualified form, it refuses when both forms
   are present, and 3b has a unit test for each.
3. **The ledger diff is too big to read.** Most of the 968 lines
   change. Mitigation: decision 9's transition table makes it countable,
   and the only transitions read path by path are those from `model`.
4. **Refusing oVirt disappoints.** Oracle Linux's OLVM template is a
   mainstream appliance. Mitigation: the refusal names oVirt and says
   why, and an oVirt reader is Future work with this survey's list as
   its starting point. The alternative, silently dropping the
   template's cloud-init, is the thing decision 4 exists to prevent.
5. **Vendor prose in the curated expected file.** Phase 3 fills string
   fields for the first time. Mitigation: `scrub()` covers the prose
   list, and 3c reads the file for the rest before it is committed.
6. **The expected count of 14 vendor models is wrong.** The survey
   reasons from inventories, not from a parser. Mitigation: 3b reports
   any difference with its reason, and 3c's field-by-field check is
   what decides whether a model is right.

## Definition of done

* `grep -rnE 'xmltodict|dpath|UnsupportedDescriptorError|PIP_CONSTRAINT' shakenfist_client_ova tools tox.ini pyproject.toml`
  finds nothing, and `tools/pinned-requirements.txt` does not exist.
* Every ledger outcome is `model` or a bare class name. This prints
  nothing:
  `grep -vP '\t(model|[A-Za-z]+Error)$' shakenfist_client_ova/corpus_tests/ledger.txt`.
  A corpus test asserts it too.
* The vendor fixtures' expected files give 14 models, plus Tails
  `UnsupportedEnvelopeError` and Oracle Linux `UnsupportedProducerError`,
  or the pull request explains each difference.
* `tests/test_vendor_fixtures.py` has a hand-written test for every
  vendor fixture that parses.
* The three expected files of #11's appliances (Fedora CoreOS, Flatcar,
  Ubuntu) are models, and the pull request says `Fixes #11`.
* `CliRunner` tests cover `--accept-eula` both ways, the property
  warning, and one line with exit 1 for every `OVFError` subclass.
* `grep -n 'deleted from the parsed\|removed from the parsed\|Parsing by consumption' AGENTS.md ARCHITECTURE.md docs/usage.md`
  finds nothing.
* `tox -epy3`, `tox -edescriptor-corpus`, `pre-commit run --all-files`
  and `.tox/py3/bin/python -c 'import shakenfist_client_ova'` pass, and
  the consistency audit reports no failure.
* The pull request body holds decision 9's transition table, and an
  explanation of every transition from `model`.
* The master plan's Execution table and `docs/plans/index.md` agree,
  and this phase's Merged cell is left for phase 4's first commit.

## Corrections made to the master plan

Made in this phase's planning commit:

* **Open questions 4 to 6** are settled by decisions 1 and 3, each in
  one line. Open question 4 is settled against its recommendation,
  with the reason (survey finding 4).
* **Phase 3's section** gains the items the survey added:
  * allocation units and #11;
  * property-reference capacities;
  * deployment configuration selection;
  * the quirk table;
  * the oVirt refusal;
  * removing the pins.
* **Future work** gains an oVirt reader.
* **Phase 2's execution notes** no longer say the corpus guard is
  untested.

## Back brief

Before executing any step, back brief the operator on how the work
aligns with this plan. Two gates:

* **Decisions 2, 3 and 5 are the shape of the strictness.** Step 3b
  does not start until the operator has reviewed them, because
  everything 3b regenerates follows from them. Decision 3's oVirt
  refusal especially.
* **3b's transition table.** The management session reads it before
  3b is committed. Any `model -> refusal` transition without a decision
  behind it stops the step.

## Execution notes

Phase 3 ran on 2026-10-17. Where it departed from the text above:

* **CIM properties.** Step 3a's review found that some standard CIM
  properties the brief would have left unused change what the guest
  sees: SASD's `Access` (a read-only disk) and
  `VirtualResourceBlockSize`, and EPASD's 22 switch-port policy
  properties (VLANs, promiscuous mode, MAC filters, bandwidth). They
  are in `cim.py`'s refused sets instead, so a descriptor carrying one
  is refused. None appears in the corpus. `Address` and
  `AutomaticAllocation` stay unused: they are common, and Shaken Fist
  assigns its own addresses and attaches every device.
* **`ovf:required="false"` on a section the parser reads** also covers
  unread content inside it. Without this, VMware's vCenter Server and
  NSX 9.1 appliances would be refused. Both put `vmw:Config` entries
  that are not marked optional inside a `VirtualHardwareSection`
  marked `required="false"`. The cost is that such a setting is
  ignored silently. Hardware resource-type refusals still look at each
  item's own attribute.
* **Decisions step 3b took that the plan left open.**
  * An `ovf:configuration` naming a configuration that does not exist
    is a `BrokenReferenceError`.
  * Both forms of one attribute on an element is an
    `UnparsedContentError`.
  * A `${key}` capacity is looked up by full key, then by the key
    alone, as DSP0243 2.x words it; `uber.ovf` needs the second.
  * An unknown declared encoding is a `MalformedDescriptorError`.
  * An `UnparsedContentError` message is a heading and one unread path
    per line, not one line. The command tests allow for that.
* **Vendor outcomes: 14 models, as planned.** Home Assistant OS 18.3
  carries `ovf:boot="True"` on its disk, an attribute in the OVF
  namespace that the schema does not define; oVirt writes it too. The
  parser first refused it with `UnparsedContentError`. The operator
  decided to read it into a new `Disk.boot` field, so that instance
  creation can know which disk the producer marks as the boot disk.
  It is a named quirk in `ovf/quirks.py`, read as `true` or `false` in
  any case because Home Assistant OS capitalises it, and any other
  value is an `InvalidValueError`. Every other undefined attribute in
  an OVF namespace is still refused. No upstream corpus descriptor
  carries it, so the ledger did not change.
* **Seven upstream descriptors went from a model to a refusal,** each by
  a stated rule. Five NVDIMM descriptors carry a required type 20 item
  of a subtype the parser refuses (decision 5). Two 2009 ovftool
  descriptors carry a non-standard `ovf:allocationUnits` on `Disk`
  (decision 2).
* **A fourth quirk.** Step 3c's field-by-field check found that
  VirtualBox writes a drive's `HostResource` as `/disk/<id>`, without
  `ovf:`. That form went unchecked, and 189 upstream descriptors use
  it, mostly VMware test templates. It is now a named quirk and is
  checked like the prefixed form. One upstream negative test moved from
  `UnparsedContentError` to `BrokenReferenceError`.
* **Step 3c found no discrepancy** between any newly parsing vendor
  fixture and its descriptor. The curated expected file holds no vendor
  prose, only short labels and three lines of generic network
  boilerplate.
* **Final ledger:**

  | Outcome | Descriptors |
  |---------|-------------|
  | model | 537 (118 before) |
  | `VirtualSystemCollectionError` | 165 |
  | `UnsupportedEnvelopeError` | 156 |
  | `MissingContentError` | 40 |
  | `UnparsedContentError` | 38 |
  | `MalformedDescriptorError` | 15 |
  | `InvalidValueError` | 7 |
  | `UnsupportedHardwareError` | 6 |
  | `BrokenReferenceError` | 4 |
* **Found and left for later:**
  * A drive's disk reference is checked, but the model does not link
    drives to disks by id. Instance creation will want that link.

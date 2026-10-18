# OVF parser: a tested, specification-following descriptor parser

## Prompt

Before responding to questions or discussion points in this
document, explore the client-python-ova codebase thoroughly. Read
relevant source files, understand existing patterns (the
`shakenfist_client.plugin` entry point and Click command group in
`__init__.py`, how the OVA archive is read member by member without
extracting it, how the OVF descriptor is parsed, and how disks are
checksummed and uploaded through `shakenfist_client.util`), and
ground your answers in what the code actually does today. Do not
speculate about the codebase when you could read it instead. Where a
question touches on external concepts (the DMTF OVF specifications
in `specifications/`, the CIM resource allocation schemas, VMDK
formats, the Shaken Fist API), research as needed to give a
confident answer. Flag any uncertainty explicitly rather than
guessing.

Consult `ARCHITECTURE.md` for the import pipeline and how the
descriptor is parsed. Consult `AGENTS.md` for build and test
commands and project conventions. Remember that an import can only
be fully validated against a live Shaken Fist cluster; unit tests
use descriptor fixtures and mock the API surface.

<!-- shared-block: plan-file-conventions v2 -->
Plan file conventions (shared block; do not edit -- the canonical
copy lives in shakenfist/development at
`templates/shared-blocks/plan-file-conventions.md`):

- All planning documents live in `docs/plans/`.
- Detailed planning gets one plan file per phase. Phase files are
  named for their master plan, sit in the same directory as it,
  and append `-phase-NN-descriptive` before the `.md` extension.
- The master plan tracks its phases in a table under its Execution
  section. `Merged` is last, and the push audit is the last row,
  for the reasons given in `plan-push-audit-phase`:

  | Phase | Plan | Status | Merged |
  |-------|------|--------|--------|
  | 1. Schema migration | PLAN-thing-phase-01-schema.md | Not started | |
  | 2. Public API | PLAN-thing-phase-02-api.md | Not started | |
  | 3. Push audit | - | Not started | |

- One commit per logical change, and at minimum one commit per
  phase. Unrelated changes are not batched into a single commit.
  Each commit is self-contained: it builds, passes tests, and has
  a message explaining what changed and why.
<!-- shared-block-end -->

## Situation

`ova import` is a single Click command in
`shakenfist_client_ova/__init__.py`. It classifies the archive's tar
members by suffix, reads the manifest, parses the OVF descriptor and
uploads each disk, all inline, talking to the user through `print()`
and stopping with `sys.exit(1)`. Because nothing below the command can
be called on its own, the only unit test in the repository covers
`_parse_alloc_units_to_bytes()`, which was pulled out to fix issue #1.

The descriptor is parsed with `xmltodict` and walked with `dpath`.
Each section the code understands is deleted from the parsed
dictionary as it is read, and anything left at the end stops the
import. That strictness is deliberate and documented (`AGENTS.md`,
"When an import stops" in `docs/usage.md`), and it is worth keeping:
an appliance the importer half-understands is worse than one it
refuses. But the parser has drifted from the specification it was
written against, in ways a survey of the code turned up:

1. **OVF 2.x descriptors cannot be imported.** `NAMESPACES` maps the
   `http://schemas.dmtf.org/ovf/envelope/2` namespace to `v2`, but
   every lookup is written against `v1:`. So a 2.x descriptor dies at
   the walk's first step, `dpath.delete(ovf, '**/v1:Info')`, which
   matches nothing and raises dpath's `PathNotFound` as a traceback
   (phase 2 survey finding 3). OVF 2 also moves Ethernet ports and
   storage onto `EthernetPortItem` and `StorageItem`, in the `epasd`
   and `sasd` CIM namespaces, which the dispatcher has never heard of.
2. **`ovf:required="false"` is ignored for sections.** OVF says a
   consumer may skip a section that carries it. The code instead hard
   codes lists of sections to delete unread, so any optional section
   from an unfamiliar producer stops the import. Only hardware items
   of resource type 1 ("Other") honour the attribute.
3. **The manifest is parsed but never verified.** Hashes are read into
   `element_hashes` and nothing reads them back.
4. **Disks are found by file suffix, not from the descriptor.** The
   upload loop walks archive members ending in `.vmdk` rather than the
   `References` the `DiskSection` points at, so a descriptor naming a
   disk in another format would be parsed and then never uploaded.
   `ovf:compression="gzip"` and `ovf:chunkSize` (a file split across
   several members) are not handled at all.
5. **One descriptor is assumed but not enforced.** An OVA carries
   exactly one descriptor. The code loops over every `.ovf` member,
   and a second one silently overwrites the first one's disks and
   networks.
6. **Smaller defects:** every disk artifact is given the VM's name;
   `print(hardware)` sits inside the per-disk upload loop; and the
   descriptor, which comes from an untrusted file, is protected
   against entity-expansion attacks only by a default. `xmltodict`
   0.12 and later refuse any entity declaration
   (`disable_entities=True`), but the code does not ask for that, no
   version floor guarantees it, and the refusal escapes as a
   `ValueError` traceback.

### Test data

The appliances the parser was developed against are two VirtualBox
6.1.10 exports, CyberOps Workstation and CyberOps Security Onion, which
exist only as untracked files in a working copy. In both, the manifest
is the *last* tar member, after the disks. OVF 1.1 section 5.3 allows
that order as well as the manifest straight after the descriptor, so
the importer must not assume either.

`instar-testdata` (a private GitLab repository, about 9.2GB of LFS)
holds disks taken from three vendor
OVAs: VyOS 1.2.1 and Splunk DCN 4.0.6, both written by VMware ovftool,
and Wazuh 4.9.1, written by AWS VM Export. instar does not parse OVA,
so only the disks were kept and the `.ovf` descriptors were thrown
away.

A survey on 2026-10-16, the day after this plan was first written,
looked for real descriptors and appliances to replace them. No
maintained OVF compatibility corpus exists: DMTF publishes the
specification and schemas but no conformance suite, and no OVF plugfest
results turned up. What exists instead:

- **govmomi's descriptor collection.** `vmware/govmomi` (Apache-2.0)
  carries 958 `.ovf` files under `ovf/fixtures/`, added in March 2026
  and still maintained. Most sit in about 180 directories under
  `external/` and are real exports from many products and years
  (`OVFToolTemplates`, `MultiVmVapps`, `SignedOVF`, `VM_with_nvram`,
  `NonAsciiChars`, Bitnami, Photon OS, SLES), alongside hand-made edge
  cases and negative cases. It has descriptors only: no OVAs, no
  manifests and no disks. The repository licence covers govmomi's
  work, but the descriptors were written by many third parties and no
  per-file licence is stated.
- **Small fixture sets in other importers.** Glance's
  `glance/tests/var/` has five small test OVAs under Apache-2.0: a
  valid one (`testserver.ova`) and four negative cases
  (`testserver-not-tar.ova`, `-no-ovf`, `-no-disk` and `-bad-ovf`).
  COT's `COT/tests/` has ten trimmed descriptors and two manifests,
  including OVF 0.9 and 2.0 and Cisco CSR1000v and IOSv appliances,
  under MIT. virt-v2v (GPL), VirtualBox's ValidationKit (GPL) and
  Proxmox's `ovf_manifests/` (AGPL) cannot be copied into an
  Apache-2.0 repository, but their designs are worth borrowing:
  virt-v2v pairs one tiny descriptor per feature with an expected
  output, and Proxmox tests a descriptor with no default namespace.
- **Public appliances.** These were confirmed downloadable, with no
  login, on 2026-10-15 and 2026-10-16:

| Appliance | Producer and shape | Size |
|-----------|--------------------|------|
| VyOS 1.2.1, `cdn.vyos.io/1.2.1.15500/vyos-1.2.1.ova` | ovftool, `.cert` member. Its disk is the one already in `instar-testdata` (`CID=9040bba6`); SHA-256 `fef225ae1f2aa21c1983e79f9cca7c1e575ca4e9984f9a2b2b67eecf8bffd16b` | 430MB |
| Photon OS 3.0 hw11, `packages.broadcom.com/photon/3.0/GA/ova/` | ovftool 4.2.0, `.cert`, `EulaSection`, `ProductSection` | 162MB |
| Photon OS 5.0 aarch64 UEFI hw14, `packages.broadcom.com/photon/5.0/GA/ova/` | ovftool 4.3.0, SHA256 manifest, `.cert`, `firmware=efi` | 294MB |
| Talos v1.14.3, `factory.talos.dev`, `vmware-amd64.ova` | ovftool output edited by hand, SHA256 manifest | 234MB |
| Oracle Linux 9.8 OLVM, `yum.oracle.com/templates/OracleLinux/` | oVirt: `ovirt:` namespace, a disk member with no extension, no manifest | 815MB |
| ArchiveTeam Warrior v4.1, `warriorhq.archiveteam.org/downloads/warrior4/` | VirtualBox, OVF 2.0 with `epasd` and `sasd` items | 173MB |
| Home Assistant OS 18.3, GitHub releases | both `vbox:` and `vmw:` namespaces | 575MB |
| Ubuntu 24.04 server cloud image, `cloud-images.ubuntu.com/releases/noble/release/` | `ProductSection` properties, `ovf:transport` | 595MB |
| Flatcar Container Linux, stable, `stable.release.flatcar-linux.net/amd64-usr/current/` | VMware | 590MB |
| Fedora CoreOS, stable, the stable stream's `vmware` artifact | VMware | 1.2GB |
| Wazuh 4.9.1, `packages.wazuh.com/4.x/vm/` | AWS VM Export | 3.95GB |
| Tails, `archive.org/download/tails_202607/Tails.ova` | VirtualBox writing OVF 0.9, an ISO member | 2.0GB |
| REMnux 202610b, `download.remnux.org` | ovftool 9.1.1, a gzip-compressed disk reference | 8.3GB |
| VulnHub `blogger.ova`, `download.vulnhub.com` | VirtualBox, several disk members | 761MB |

VulnHub is the only large collection of whole OVAs: its
`checksum.txt` index lists 934, mostly VirtualBox exports with some
from ovftool, most of them 0.6 to 5GB. It rate-limits hard and its
authors rarely state redistribution terms, so it is a place to pick
specific shapes from, not to mirror. Splunk's OVAs, including the DCN
4.0.6 original, are on Splunkbase behind a login, under terms that do
not allow redistribution, so the corpus does without them.

No public source was found for a SHA512 manifest, a chunked file
reference, a `VirtualSystemCollection` in a whole OVA, or exports from
Packer, Xen, Proxmox or virt-v2v. govmomi's descriptors and
hand-written fixtures cover the descriptor side of those.

DMTF publishes the envelope schemas at
`schemas.dmtf.org/ovf/envelope/1/dsp8023_1.1.0.xsd` (OVF 1.1) and
`schemas.dmtf.org/ovf/envelope/2/dsp8023.xsd` (2.0.1, the newest; OVF
2.1.1 did not revise the schema).

instar's CI reaches `instar-testdata` through
`tools/ci/prepare-testdata.sh`. That script clones over HTTPS with a
`GITLAB_TESTDATA_TOKEN` repository secret, caches the clone on the
runner, materialises the LFS objects explicitly, and then runs a guard that fails the job when a
required fixture is missing. instar learned in its issue #451 that
tests which skip when their file is absent quietly shrink the suite
when the checkout goes wrong.

### The server side

Shaken Fist identifies an uploaded image with `qemu-img info`
(`shakenfist/util/image.py`), and transcodes cached images to qcow2.
No allow-list of input formats turned up, so a streamOptimized VMDK
artifact is usable as it is. Phase 4's live import of the Ubuntu
cloud image proved it.

## Mission and problem statement

Turn the OVF parsing into a tested, specification-following component,
so that the next feature work (creating an instance from the parsed
hardware) builds on a parser we trust rather than on one we are afraid
to touch. Specifically:

- Separate parsing from the command, behind a boundary clean enough
  that the parser could be published as its own package later without
  a rewrite.
- Build a corpus of real descriptors from several producers, test
  every pull request against trimmed copies of them and against
  govmomi's and COT's descriptor collections, and test against the
  appliances in CI.
- Fix the gaps listed under Situation.

Out of scope, and deliberately so:

- **Creating an instance from the parsed hardware.** That is the
  feature this plan prepares for, and it gets its own plan.
- **Converting the guest** (installing virtio drivers, fixing the
  bootloader), which is what `virt-v2v -i ova` does. Whether the
  importer should offer it is a product question for the
  instance-creation plan.
- **Spinning the parser out into its own package.** The boundary is
  designed for it. The move waits until a second consumer exists.

## Decisions

1. **The parser lives in this repository, inside a boundary built for
   spin-out.** It goes in a `shakenfist_client_ova/ovf/` subpackage
   that imports only the standard library and `defusedxml`. It never
   imports `click` or `shakenfist_client`, never prints and never
   exits. It reports failure by raising subclasses of one `OVFError`,
   and returns plain dataclasses (available from Python 3.7). The
   command in `__init__.py` does all of the talking to the user.
   Spinning the parser out later is then a directory move and a
   `pyproject.toml`. A separate repository now was rejected: it would
   need the whole consistency-audit adoption (CI, renovate, release,
   CodeQL, documentation) before a line of parser code, for an API
   whose shape we will only know once instance creation uses it.
2. **No third-party OVF library.** The only real candidate on PyPI is
   `cot` (the Common OVF Tool). Its last release was in December 2019,
   it depends on `pyvmomi`, and its metadata targets Python 2.7
   through 3.7. The PyPI packages named `ovf`, `pyovf` and `ovf2io`
   read OOMMF micromagnetics files, an unrelated format that shares
   the name.
3. **`xml.etree.ElementTree` through `defusedxml` replaces `xmltodict`
   and `dpath`.** Namespace-aware element lookups remove the
   dictionary-or-list ambiguity that `_coerce_to_list()` exists to
   paper over, and make supporting both the OVF 1 and OVF 2 envelope
   namespaces a matter of a lookup table rather than of duplicated
   paths. ElementTree on its own expands internal entities, so the
   move to it needs `defusedxml` to keep refusing the DTD entity
   tricks an untrusted descriptor could otherwise use; no legitimate
   OVF descriptor declares entities. It is pure Python and supports 3.7.
   Its last stable release, 0.7.1, dates from 2021, which is a weakness,
   but it is still the package the Python documentation recommends for
   untrusted XML. This removes two runtime dependencies and adds one.
   ElementTree's `ParseError` and defusedxml's `DefusedXmlException` are
   both caught inside the parser and re-raised as named `OVFError`
   subclasses, so that a malformed or entity-declaring descriptor gets
   the same one-line refusal as any other.
4. **Strictness stays, but follows the specification.** An element
   the parser does not understand stops the import, unless the element
   carries `ovf:required="false"`, which OVF says a consumer may
   ignore. The only elements ignored unread are `Info`,
   `AnnotationSection` and `Strings` (with the `ovf:msgid` attributes
   that point into it, added by phase 3's survey). They describe the
   appliance to a person and nothing reads them; that list is closed
   and lives in one place in the code, with the reason. Three sections
   look informational but
   are not, so they are parsed into the model instead:
   - `ProductSection` carries `Property` elements. A property with
     `ovf:userConfigurable="true"` and no `ovf:value` is input the
     appliance expects at first boot. The Ubuntu cloud image OVA takes
     its cloud-init configuration this way. Shaken Fist has no way to
     deliver an OVF environment yet (see Future work), so the command
     names each such property in a warning, rather than either dropping
     it silently or refusing an import whose disks are still useful.
   - `EulaSection` carries a licence that OVF expects a consumer to
     present for acceptance. The command prints it and refuses to
     continue without `--accept-eula`, the same choice VMware's
     ovftool makes with `--acceptAllEulas`.
   - `OperatingSystemSection` carries the guest OS's CIM id and
     `osType`. Instance creation will need them, so they go into the
     model.

   Deleting from a dictionary is how today's code notices what it has
   not read. ElementTree has no equivalent, so the parser records every
   element and attribute it reads. At the end it walks the tree and
   refuses anything left unread that is neither marked
   `ovf:required="false"` nor on the closed ignore list.

   Attributes follow the specification's extensibility rule rather
   than the element rule. DSP0243 (1.1 section 7.3, 2.1.1 section 7.3)
   says the information in a custom attribute "shall not be required
   for correct behavior". An attribute from a namespace OVF does not
   define, such as `vmw:buildId`, is therefore ignored by rule.
   Attributes in the OVF and CIM namespaces, and unqualified attributes
   on OVF elements, are read or refused like elements. The ignore list
   adds the namespace declarations, `xml:lang` and
   `xsi:schemaLocation`, none of which carry data.

   Today's code deletes several things unread. Each one is decided
   here, not left for the implementer to discover:

   | What | Decision |
   |------|----------|
   | `vmware:buildId` and other custom attributes | Ignored by the attribute rule above |
   | `vbox:Machine`, `vmware:Config`, `vmware:IpAssignmentSection` and other custom elements | Ignored when marked `ovf:required="false"`, as VirtualBox marks `vbox:Machine`; refused otherwise, as the specification requires. Phase 1 records which producers mark them |
   | `ovf:transport` on `VirtualHardwareSection` | Read into the model. It names how the appliance expects to receive its OVF environment, which goes with the `ProductSection` properties |
   | `ovf:required` on `VirtualHardwareSection` | Read and honoured, like any other `ovf:required` |
   | `vssd:System` | Read into the model: the virtual system type (`vmx-13`, `virtualbox-2.2`) and identifier |
   | `VirtualSystem/Name` | Read into the model as the display name |
   | `DeploymentOptionSection` | Read into the model. Items carrying `ovf:configuration` apply only to the configurations they name, and today's code applies every item at once. The parser builds the default configuration (`ovf:default="true"`, else the first). Choosing another is the instance-creation plan's business |
   | `AnnotationSection`, `Info` | The closed ignore list |

   A hardware item of an unknown resource type stops the import unless
   it is marked not required. This changes a documented convention, so
   the phase that implements it updates `AGENTS.md` and "When an
   import stops" in `docs/usage.md` in the same pull request.
5. **There are three test tiers.**
   - The *unit* tier runs on every pull request, offline, and needs no
     secrets. It is what `tox -epy3` runs. It uses the fixtures
     committed to this repository (decision 6), plus small synthetic
     OVAs built by the tests themselves. The parser never reads disk
     contents, so a synthetic disk member can be a few bytes of
     anything.
   - The *descriptor corpus* tier parses every descriptor in govmomi's
     `ovf/fixtures/` and COT's `COT/tests/`, each fetched at a commit
     pinned in this repository rather than copied into it. Both
     collections hold descriptors written by third parties: govmomi's
     come from many vendors, and COT's include Cisco appliance
     descriptors. Fetching them leaves redistribution with their
     owners, and needs no secret, so the tier runs on every pull
     request, forks included. It needs the network, so it is not part
     of `tox -epy3`. It runs in its own tox environment, `tox
     -edescriptor-corpus`, which runs the fetch script into a
     gitignored cache and then only the corpus tests. Those live in
     `shakenfist_client_ova/corpus_tests/`, outside `.stestr.conf`'s
     `test_path`, so `py3` never collects them and their fail-closed
     guard cannot fire offline. Each corpus environment runs `stestr
     --test-path` on its own directory, and `pyproject.toml` excludes
     the directory from the wheel as it does `tests`. The exception
     class names the ledger records must not drift under it, so the
     test environments pin `xmltodict` and `dpath` exactly (phase 2
     decision 7). With nearly 1,000 descriptors,
     hand-written expected files for each are not realistic, so the
     tier asserts three things instead:
     - a committed ledger maps each descriptor's path to its outcome:
       `model`, or the class name of the exception raised. The test
       regenerates the ledger and fails on any difference, so a
       behaviour change across the whole collection shows up as a
       reviewed diff. In phase 2 the ledger records today's parser as
       it is. A descriptor that today ends in a raw exception is
       recorded as the named wrapper with that exception's class in
       brackets, such as `UnsupportedDescriptorError(KeyError)`. Until
       phase 3 removes `xmltodict`, a Renovate bump of the pinned
       version may change the ledger, and that diff is reviewed like
       any other.
     - from phase 3, every descriptor yields a model or a named
       `OVFError` subclass, never any other exception. Phase 3's
       ledger diff then shows exactly which descriptors that fixed.
     - a curated subset of about 50, chosen for shape coverage, has
       full expected files in decision 7's form, committed here and
       keyed by upstream path. They hold our parse, not the upstream
       text: before an expected file is written or compared, the test
       replaces every prose field in the model with the placeholder
       decision 6 uses. The list of prose fields is defined once, as
       pairs of OVF element and the model field it fills. Phase 1
       keeps it in the trim tool, the only user then. Phase 2 moves it
       into `shakenfist_client_ova/ovf/`, and the tool imports it from
       there. That direction is allowed: the import boundary of
       decision 1 limits what the parser imports, not what imports
       the parser.
   - The *appliance corpus* tier runs the importer's parse, archive and
     manifest paths over every appliance in `instar-testdata`, in CI on
     the self-hosted pool. It has its own tox environment too, `tox
     -eappliance-corpus`. It follows instar's `prepare-testdata.sh`
     pattern, including the guard that fails when a fixture is
     missing.

   The two corpus tiers fail the same way when their data is missing:
   the guard fails, it never skips. `docs/development.md` describes
   both environments from the phase that adds each.
6. **Committed fixtures from vendor appliances are trimmed copies.**
   This repository is public, and vendor descriptors carry licence and
   product prose. `tools/trim-ovf-descriptor.py` replaces the text of
   the prose elements (`License`, `Annotation`, `Description`, product
   and vendor strings) with a fixed placeholder, keeping every element
   and attribute. It reads vendor files, so it parses them through
   `defusedxml` like the importer does. Re-serialising can still lose
   things the parser might see (comments, namespace prefixes), so
   "structure unchanged" is checked rather than claimed: the appliance
   corpus tier asserts that the parser's model of each original
   descriptor equals its model of the trimmed fixture, apart from the
   placeholder text. Each trimmed fixture carries an XML comment,
   straight after its XML declaration (which must stay first, or the
   file stops being XML), recording where it came from, the SHA-256 of
   the original descriptor, and that it was trimmed. The full
   descriptors stay in the private `instar-testdata`.

   Two other kinds of committed fixture are not trimmed. Hand-written
   fixtures carry no vendor prose to remove. Glance's five test OVAs
   were written for Glance's own tests, contain no vendor descriptor,
   and are Apache-2.0, so they are committed verbatim under
   `shakenfist_client_ova/tests/fixtures/ova/imported/glance/`, with
   their origin and licence in a `NOTICE` file there instead of a
   comment. They are archives, so phase 4's archive tests use them; the
   descriptor golden test does not.
7. **Expected parses are data, not code.** Each fixture has a
   `<name>.expected.json` beside it: either the parser's model
   serialised to JSON, or, for a fixture meant to be refused,
   `{"error": "<OVFError subclass name>", "message_contains": "<a
   stable fragment of the message>"}`. Matching a fragment rather than
   the whole message lets wording improve without rewriting every
   expected file, while still pinning which failure it was. One test
   parameterises over the directory, so supporting a new appliance is
   a data change, and a behaviour change shows up as a reviewed diff
   to an expected file.
8. **The appliance corpus keeps a whole appliance only where the
   archive brings a shape nothing else does, and the descriptor and
   manifest of the rest.** Descriptor shapes are the descriptor corpus
   tier's job (decision 5). A whole appliance earns its place through
   what only a whole archive shows: a manifest's digest type checked
   against real disk bytes, a `.cert` member, a disk member with no
   extension, or no manifest at all. From the "Test data" table that
   is VyOS 1.2.1, both Photon OS images, Talos, Oracle Linux and
   ArchiveTeam Warrior, about 2.1GB in all. Every other appliance there
   is descriptor-only, and so are the two local VirtualBox 6.1.10
   exports (3.1GB and 3.8GB). Their one archive-level shape, the
   manifest stored last, after the disks, is reproduced by a synthetic
   OVA in phase 4's tests, and their descriptor-only copies keep the
   manifest. The same goes for the archive shapes of the other
   descriptor-only entries: Tails' ISO member and `blogger.ova`'s
   several disk members are synthetic OVAs in phase 4 too. This follows
   the precedent `instar-testdata` already set for the Wazuh and Splunk
   disks, and keeps the CI pull small. A descriptor-only entry records
   the original's full member listing, in order, in the provenance
   table, so the archive layout is still on record. It is re-tarred from
   the original's `.ovf` and `.mf` members. The descriptor's own
   manifest entry is still verified on every entry, while disk hashes
   are verified only on the whole ones. The importer will refuse a
   descriptor-only entry, because its `References` name disks that are
   absent, and that refusal has no opt-out. The appliance corpus tier
   instead asserts it: each descriptor-only entry declares, as test
   input, the members that are deliberately absent. The test checks that
   list against `References`, parses the descriptor, and requires the
   archive check to fail with the missing-member error, naming exactly
   those members. Tails is the exception: its descriptor is refused at
   the envelope, before any archive check runs, so the tier asserts that
   refusal for it instead (phase 4 plan, survey finding 8). The
   `instar-testdata` README gains a provenance table:
   URL, download date, original size, SHA-256 and producer.

## Open questions

1. **Resolved: does Shaken Fist boot an uploaded streamOptimized VMDK?**
   The server code suggested it did (see "The server side"), and phase 4
   ended with one live import of the Ubuntu cloud image OVA to settle
   it. It boots: the server transcodes the VMDK itself, so conversion
   does not move into the instance-creation plan (phase 4 plan,
   execution notes).
2. **Resolved: do the original VyOS 1.2.1 and Splunk DCN 4.0.6 OVAs
   still exist?** VyOS 1.2.1 does, at a new URL, and it is the same
   release: its disk matches the one in `instar-testdata`. Splunk's
   needs a Splunkbase login and may not be redistributed, so it is left
   out. Photon OS, Talos and REMnux add further ovftool output (see
   "Test data").
3. **Resolved: which runner labels reach the private GitLab with
   git-lfs installed?** `[self-hosted, debian-13, xl, instar]`, the set
   every instar job that reads the testdata uses. The `instar` label is
   what promises the fleet's pre-built testdata disk (phase 5 plan,
   survey finding 3). Adding `GITLAB_TESTDATA_TOKEN` as a secret on this
   repository is still the operator's step, not an agent's.

Phase 1's survey found three shapes the decisions above would refuse.
Each is for phase 3 to settle, before it writes the namespace and
attribute tables; the evidence is in the phase 1 plan's survey finding
4.

4. **Should oVirt's attributes in the OVF namespace be refused?**
   oVirt (and so Oracle Linux's OLVM templates) writes
   `ovf:disk-interface`, `ovf:disk-alias` and `ovf:disk-type` on
   `Disk`. Decision 4 refuses OVF-namespace attributes it does not
   read, which refuses every oVirt export. The recommendation is to
   read `ovf:disk-interface` into the model as the disk bus, which
   instance creation needs, and to ignore a closed, named list of the
   others, with oVirt given as the reason.
   **Settled by phase 3, against the recommendation:** oVirt exports
   are refused by name. The OLVM export carries 33 oVirt elements in the
   OVF namespace, cloud-init in `VmInit`, and non-CIM hardware
   properties, not three attributes (phase 3 plan, survey finding 4 and
   decision 3). An oVirt reader is Future work.
5. **Should VirtualBox's `.xsd`-suffixed CIM namespaces be accepted?**
   VirtualBox's OVF 2.0 export declares `epasd` and `sasd` with a
   `.xsd` suffix on the DMTF namespace URI. Taken literally, its
   `EthernetPortItem` and `StorageItem` contents are unknown custom
   elements, and every VirtualBox OVF 2.0 export is refused. The
   recommendation is to treat the two suffixed URIs as aliases of the
   DMTF ones, in the namespace table, with VirtualBox given as the
   reason. **Settled by phase 3, as recommended** (phase 3 plan,
   decision 3).
6. **Should OVF 0.9 be supported or refused by name?** The
   pre-standard `http://www.vmware.com/schema/ovf/1/envelope`
   namespace, with generic `Section` elements typed by `xsi:type`,
   appears in 149 of govmomi's 958 descriptors, in COT and in Tails'
   export. The recommendation is to refuse it with a named
   unsupported-version error. Supporting it means a second section
   dispatch, and the producers that write it today (VirtualBox's
   legacy export option) can also write 1.0. **Settled by phase 3, as
   recommended:** it is refused as `UnsupportedEnvelopeError` (phase 3
   plan, decision 1).

## Execution

| Phase | Plan | Status | Merged |
|-------|------|--------|--------|
| 1. Corpus and fixtures | [PLAN-ovf-parser-phase-01-corpus.md](PLAN-ovf-parser-phase-01-corpus.md) | Complete | instar-testdata 18a5ea5421..cf67642bbb; db7bdaa |
| 2. Extract the parser | [PLAN-ovf-parser-phase-02-extract.md](PLAN-ovf-parser-phase-02-extract.md) | Complete | 97273c7 |
| 3. ElementTree and the specification | [PLAN-ovf-parser-phase-03-elementtree.md](PLAN-ovf-parser-phase-03-elementtree.md) | Complete | b1f8894 |
| 4. Archive correctness | [PLAN-ovf-parser-phase-04-archive.md](PLAN-ovf-parser-phase-04-archive.md) | Complete | a8f44bf |
| 5. Corpus CI tier | [PLAN-ovf-parser-phase-05-corpus-ci.md](PLAN-ovf-parser-phase-05-corpus-ci.md) | Complete | 248ecd3 |
| 6. Push audit | [PLAN-ovf-parser-phase-06-push-audit.md](PLAN-ovf-parser-phase-06-push-audit.md) | Complete | c37b530 |

Phase plans are written when each phase starts, from this plan and
from what the previous phase learned, rather than all now.

### 1. Corpus and fixtures

This phase lands partly in `instar-testdata`, as direct commits, and
partly here as a pull request. Its `Merged` cell therefore holds both
records, as `instar-testdata <first>..<last>; <merge sha>`. This
departs from the shared block's `<repo> <sha> (#pr)` deliberately:
`instar-testdata` takes direct commits, so its record is a range, which
checklist item 1 accepts. A direct landing has no pull request to audit
it, so the `instar-testdata` range is audited as part of this phase's
own pull request. The things to check are that only `downloaded/ova/`,
`scripts/` (the fetch script and its test), `.gitattributes` (the
`*.ova` LFS rule) and the README changed, and that the provenance table
matches the files. This repository is public, so its record of that
audit holds only the verdict and the range. Detailed findings stay in
`instar-testdata`.

- Download the appliances in the "Test data" table, and the two local
  VirtualBox 6.1.10 exports, into `instar-testdata`'s
  `downloaded/ova/`, following decision 8, with a fetch script and the
  provenance table. Before committing VyOS 1.2.1, check its SHA-256
  against the Wayback Machine's 2019 capture of the same URL, since
  VyOS published no checksum for it. If that capture is missing or
  truncated, record so in the provenance table and rely on the disk
  matching the one already in `instar-testdata`. The descriptor is the
  first member of every OVA we have seen, so a descriptor-only copy of a
  large remote appliance can be taken by streaming the start of the
  download and stopping. The manifest may not be near the start (see the
  VirtualBox note under Situation), so check before relying on that for
  the `.mf`.
- Write the descriptor corpus fetch as a script in `tools/` that takes
  only govmomi's `ovf/fixtures/` and COT's `COT/tests/` (sparse,
  blob-filtered clones), so a contributor runs the same thing CI does.
  The pinned commits are variables at the top of that script and
  nowhere else. Bumping them is a deliberate, hand-made pull request
  whose ledger diff is the thing reviewed; Renovate does not track
  them, because a bump changes test expectations, not a dependency.
  COT is abandoned, so its pin should never need to move. Choose the
  curated subset for decision 5, covering at least
  OVF 0.9, 1.0, 1.1 and 2.0, `MultiVmVapps`, `SignedOVF`,
  `VM_with_nvram`, `NonAsciiChars`, the `property-types` and
  `virtualsystemcollection` cases and the invalid ones. Note in the
  phase plan which of them carry `DeploymentOptionSection`, and
  whether a hand-written one is still needed.
- Write `tools/trim-ovf-descriptor.py` and commit a trimmed fixture
  for every appliance corpus descriptor under
  `shakenfist_client_ova/tests/fixtures/ovf/`. Commit Glance's five
  test OVAs verbatim, with their `NOTICE` (decision 6). `.gitignore`
  ignores `*.ova` everywhere, and `AGENTS.md` says to keep it that way
  for large manual-testing files, so a plain `git add` would silently
  skip them. Add a negation for
  `shakenfist_client_ova/tests/fixtures/ova/**/*.ova` after that rule,
  with a comment saying why, and check `git ls-files` lists all five.
- Hand-write the edge cases neither corpus covers in a small, readable
  form:
  - an OVF 2.x envelope;
  - a descriptor with no default namespace, where every OVF element
    carries a prefix;
  - a `required="false"` extension section, and an unknown required
    one;
  - a gzip compressed file reference, and a chunked one, both of
    which phase 4 refuses;
  - two disks on different controllers;
  - a descriptor declaring an entity;
  - a `ProductSection` with a user-configurable property that has no
    default, and an `EulaSection`;
  - `References` hrefs that are an absolute URL, contain `../`, name a
    missing member, or name a duplicated member;
  - a `VirtualSystemCollection`, which phase 3 refuses by name;
  - an unknown OVF-namespace attribute on a known element, and a
    custom-namespace one, which are refused and ignored respectively;
  - an ovftool-style descriptor carrying `vmw:buildId`,
    `xsi:schemaLocation`, a `vmw:Config` marked not required,
    `ovf:transport` and a `DeploymentOptionSection` with two
    configurations. The real ovftool descriptors spread these across
    several files; this one puts them in one place a reviewer can read.

  Some archive-level cases are built as synthetic OVAs in phase 4's
  tests rather than committed: a manifest whose entry for the
  descriptor does not match, a manifest with no entry for a referenced
  file, no manifest at all, two manifests, a manifest listing the same
  file twice, a SHA512 manifest, a manifest stored last after the
  disks (the VirtualBox order, decision 8), a `.cert` member, hrefs
  naming a symlink, a hardlink and a directory member, and members
  stored as `./name`, including two that normalise to the same name.

### 2. Extract the parser

A behaviour-preserving refactor, with two named output changes. The
phase plan's survey corrected this section: see its "Corrections made
to the master plan".

- Move the descriptor and manifest parsing out of the Click command
  into `shakenfist_client_ova/ovf/`, still on `xmltodict`, returning
  the dataclass model and raising `OVFError` subclasses. The model is
  defined in its final shape here, including the `ProductSection`,
  `EulaSection` and `OperatingSystemSection` fields phase 3 fills, left
  empty for now. It is serialised deterministically, with sorted keys
  and lists in document order. Phase 3's expected-file diffs then show
  behaviour changes, not a change of shape. Where today's
  code prints a message and exits, the command catches the error and
  prints exactly that message. The first output change is where
  today's code dies with an unhandled traceback: `KeyError`, dpath's
  `PathNotFound`, `TypeError`, `ExpatError` or `ValueError`, such as
  on an OVF 2.x descriptor. There the parser raises a named `OVFError`
  subclass, chained from the original, and the command prints one
  line. The second is the progress output. Today the walk prints as it
  goes, much of it as reprs of `xmltodict`'s structures. A parser that
  never prints cannot reproduce that, so the command prints a summary
  from the model once the parse succeeds. The pull request lists every
  path each change affects.
- Add the parameterised golden test over the phase 1 fixtures, with
  expected files recording *today's* behaviour in decision 7's form,
  including today's failures on the OVF 2.x and `required="false"`
  fixtures. Add the descriptor corpus tier (decision 5) and its tox
  environment, with the ledger and curated expected files also
  recording today's behaviour, each formerly unhandled exception
  named in brackets after the wrapper that now carries it. They
  are not part of this phase's named output change: the ledger shows
  what today's parser does, and fixing it is phase 3's work. Those
  expected files and the ledger are the safety net phase 3 is reviewed
  against. Describe the new tox environment in `docs/development.md`.
- Add a `descriptor-corpus` job to `ci.yml` that runs `tox
  -edescriptor-corpus` on every pull request, forks included, on the
  static self-hosted pool like every other job here, so the safety net
  is in CI from the phase that builds it.
- Update `ARCHITECTURE.md` for the new shape: the subpackage and its
  import boundary, the error hierarchy, the model, and the split
  between parser and command. The document says all the code is in
  `__init__.py`, which stops being true in this phase.

### 3. ElementTree and the specification

- Reimplement the parser on `defusedxml.ElementTree` (decision 3),
  covering both envelope namespaces and the OVF 2 `EthernetPortItem`
  and `StorageItem`, with the strictness of decision 4.
- Parse `ProductSection`, `EulaSection` and `OperatingSystemSection`
  into the model. Add the command's property warning and its
  `--accept-eula` refusal (decision 4).
- Refuse a `VirtualSystemCollection` with a named error, instead of
  letting it fail as an unknown section. An envelope holding several
  systems is a multi-instance import, which belongs to the
  instance-creation plan.
- Test the command layer, not only the parser, with
  `click.testing.CliRunner` and the client and `shakenfist_client.util`
  mocked. Cover the `--accept-eula` refusal, the property warning, and
  the turning of each `OVFError` into one line and exit code 1.
- Every change to an expected file in this phase's diff is an intended
  behaviour change, explained in the pull request. Phase 2 records 12
  of the 16 vendor fixtures as refusals, so many expected files go
  from an error to a whole model, with nothing to compare against.
  Three of those refusals are #11, the `byte` allocation unit, which
  this phase fixes unless it has been fixed already. Each newly
  successful one is checked field by field against its descriptor:
  disk capacities, controllers, NICs and memory units. Each vendor
  fixture also gains a small hand-written assertion of those values,
  so the expected file is not the only record of what correct looks
  like. Before the curated expected file is committed, read it for
  vendor text in fields the prose list does not cover, such as
  deployment option labels: they are filled for the first time in this
  phase.
- Turn on the descriptor corpus tier's second assertion (decision 5):
  every descriptor yields a model or a named `OVFError` subclass, and
  phase 2's `UnsupportedDescriptorError` wrapper is deleted. The
  ledger diff in this phase's pull request lists each descriptor whose
  outcome changed, which is the review of what the reimplementation
  fixed and of anything it broke.
- Parse allocation units by DSP0004's programmatic-unit grammar,
  which fixes #11, and resolve `${property}` disk capacities. Select
  the default deployment configuration for items, networks and
  property values. Accept the producer quirks the phase plan's survey
  found (VMware's unqualified attributes, `InstanceId`, VirtualBox's
  `.xsd` namespaces) from one named table, and refuse oVirt exports by
  name.
- Drop `xmltodict` and `dpath` from `pyproject.toml`, and the test
  environments' pins of them with them. Update
  `AGENTS.md` and `docs/usage.md` for the new convention, and the
  parsing section of `ARCHITECTURE.md`, which still describes parsing
  by consumption.

### 4. Archive correctness

The phase plan's survey sharpened this section. It added rules the
section did not state:

- only a plain tar is opened;
- a `.cert` needs a manifest;
- an href may not name the descriptor, manifest or certificate, and two
  `File`s may not share one;
- `ovf:compression="identity"` means uncompressed;
- a chunked reference is refused before its member is looked for,
  because its href names no member;
- an `ovf:size` that differs from its member's size is refused;
- a delta disk (`ovf:parentRef`) is refused, because uploaded alone it
  cannot boot.

Glance's `testserver.ova` never reaches the archive checks. Its
`ResourceAllocationSection` sits outside a `VirtualSystemCollection`,
which DSP0243 9.3 does not allow, so the parser refuses it, and the
archive tests' passing cases are synthetic.

- Find disks from `References` and the `DiskSection`, not by suffix.
  An `ovf:href` is untrusted input that now selects archive members,
  so it must be a relative name that matches exactly one tar member,
  and that member must be a regular file (`TarInfo.isfile()`). Member
  names are compared after stripping a single leading `./`, which some
  tar writers add, and two members that strip to the same name are
  refused as duplicates.
  `extractfile()` follows symlink and hardlink members to *other*
  members, which would upload something other than what the manifest
  entry names, and it returns `None` for directories and devices. An
  absolute URL, a `../` component, a missing or duplicated member, and
  a member that is not a regular file are each an explicit refusal,
  never a `KeyError`, an `AttributeError` or a fetch. The importer
  never extracts to disk, so this is about refusing clearly, not about
  path traversal.
- Reject an archive with more than one descriptor, or more than one
  manifest, and a manifest that lists the same file twice. Today a
  later `.mf` entry silently replaces an earlier one, the same flaw
  as with descriptors, and the manifest is now what the descriptor and
  disks are checked against. A single manifest whose base name differs
  from the descriptor's gets a warning, not a refusal: OVF names them
  alike, but nothing is ambiguous when there is only one.
- Read the manifest before anything else, wherever it sits in the tar,
  and verify the descriptor against it *before* parsing. The
  descriptor decides which members are read as disks, so a corrupt
  descriptor that went unchecked would send the import after the wrong
  members.
  Refuse when a manifest is present but has no entry for the
  descriptor or for a referenced file. With no manifest at all, warn
  and continue: OVF makes the manifest optional, and refusing would
  reject appliances that are valid.
- Be explicit about what the manifest does not do, both here and in
  `docs/usage.md`. It detects corruption and accidental mismatch. It
  does not detect tampering: the manifest travels in the same unsigned
  archive, so anyone who can change the descriptor can rewrite the
  manifest to match, or remove it. Tamper evidence needs `.cert`
  verification, which is Future work. Nothing in the code, docs or
  output may describe the manifest check as a security control.
- Verify each disk's manifest digest in a single pre-upload pass that
  the plugin owns, computing the manifest's SHA-1 or SHA-256 alongside
  the SHA-512 that blob deduplication searches by. Then stop before
  any upload when a hash does not match. With `blob-search-by-hash`,
  this pass replaces the read `checksum_with_progress_from_file_like_object()`
  makes today, so there is no extra read. Without it, the pass costs
  one extra read of each disk. That is accepted, because the
  alternative cannot work with today's helper:
  `upload_artifact_with_progress_file_like_object()` uploads and
  creates the artifact in one call, so there is nowhere to stop
  between the two. It also seeks back on a retried chunk, which
  would corrupt a digest computed by a stream wrapper. Verifying
  during the upload is Future work, upstream in `client-python`.
- Ignore a `.cert` member with a printed notice that the signature was
  not checked, and document it in `docs/usage.md`. Verifying it is
  Future work.
- Refuse `ovf:compression="gzip"` and chunked (`ovf:chunkSize`)
  references with named errors, documented in `docs/usage.md`. These
  checks run after the member checks above, so a descriptor-only
  corpus entry such as REMnux still fails with the missing-member
  error decision 8 asserts. Both
  are rare in practice, and supporting either properly is a design of
  its own. The upload helpers need the size before they start, and for
  a gzip file only a full decompression gives it: the ISIZE trailer is
  the size modulo 2^32, so it is wrong for any disk over 4GiB. The
  manifest digest covers the compressed bytes while dedup needs the
  decompressed ones. Decompressing an untrusted file also needs a cap.
  Support waits until a corpus appliance needs it (see Future work).
- Name each disk artifact after its disk, as `<system id>-<disk id>`,
  and build its source URL from the OVA's real path, since the server
  identifies an artifact by its source URL. (Phase 5 replaced that URL
  with the server's `sf://upload/` default.) Move the hardware
  summary, which phase 2 left printing after every disk, out of the
  upload loop.
- Test with synthetic OVAs built in the tests, which needs no
  cluster. That includes `CliRunner` tests showing the no-manifest
  warning, the `.cert` notice, and that nothing is uploaded after a
  digest mismatch. Then perform the live import that answers open
  question 1, as an operator step recorded in the phase plan.

### 5. Corpus CI tier

This phase covers the appliance corpus tier only. The descriptor
corpus tier's job was added in phase 2; it needs no secret and is not
gated.

- Write a small fetch script in `tools/ci/`. instar's
  `prepare-testdata.sh` has grown into a contract with the runner
  fleet's pre-built testdata disk, and it leaves the token in the
  clone's remote URL, so it is not adapted (phase 5 plan, survey
  finding 2). On an `instar` runner the tree is that disk. The script
  updates it, and pulls only `downloaded/ova/`'s LFS objects, about
  2GB (`git lfs pull --include`). It passes the token in a header on
  each command, never in a URL or a file.
- Add a corpus test that runs the parse and the archive checks over
  every appliance, and a guard that fails when the corpus is missing,
  never one that skips. Run it as `tox -eappliance-corpus` (decision
  5), outside `py3`'s discovery, and describe that environment in
  `docs/development.md`.
- Add the job to `ci.yml` on the runner labels open question 3
  settled, after the operator has added the secret. Fork pull requests
  receive no secrets, so the job is gated at the workflow level
  (`if: github.event_name != 'pull_request' ||
  github.event.pull_request.head.repo.full_name == github.repository`)
  and does not run for them at all. Inside the job the guard stays
  fail-closed. The gate keeps forks out; it is never a reason to
  soften the guard. Same-repository branches run the job, and that
  includes Renovate's, since Renovate pushes its branches to this
  repository.
- A Renovate branch changes which dependency code the job installs and
  runs, so `GITLAB_TESTDATA_TOKEN` must never be visible to that code:
  - the token is a read-only deploy token scoped to `instar-testdata`
    alone, not a personal token;
  - the clone happens in its own step, before any `pip install`, and
    only that step's `env` carries the secret;
  - once the fetch is done, the credential is removed from the clone's
    remote URL. instar's script leaves it in `.git/config`, and in a
    runner cache that outlives the job, any later step could read it.

  These steps keep the token away from dependency code. They do not
  keep it from someone who can push a branch: the clone step runs
  `tools/ci/` from the branch under test, so anyone with write access
  can read the token. That is accepted, because the token is read-only
  and reaches one repository of test data. The private data then sits
  in a runner cache that other jobs on the pool can read. instar
  already accepts that exposure for the same data, and it is accepted
  here on the same terms. The phase plan records the token's scope,
  who rotates it, and every trigger that can reach the job: pull
  requests, `workflow_dispatch`, and the re-test workflow.
- Stop giving artifacts an `ova://` source URL. Phase 4's live import
  found that it boots only through the server's fallback for
  unreachable sources. The command sends no source URL, so the server
  applies `sf://upload/<namespace>/<name>`, and it records the OVA's
  path and the member name as artifact metadata instead. The operator
  added this after phase 4 merged.

### 6. Push audit

This repository has no `PUSH-AUDIT.md`, so the phase applies the
checklist in the `plan-push-audit-phase` block of `PLAN-TEMPLATE.md`
to the recorded ranges, plus four questions specific to this plan:

- Does any trimmed fixture still carry vendor prose that trimming
  missed?
- Does anything committed copy govmomi's or COT's descriptor text,
  rather than refer to it by path? Are the curated expected files free
  of upstream prose? Does every Glance file appear in its `NOTICE`,
  and does `git ls-files` list every file the `NOTICE` names?
- Does the corpus CI path put the private GitLab hostname anywhere
  new? It is in `tools/ci/fetch-appliance-corpus.sh` and
  `tools/ci/test-fetch-appliance-corpus.sh`. It already appears in the
  public `shakenfist/instar`, so carrying it here is not a new
  disclosure, but the audit records the verdict rather than assuming
  it.
- Does `shakenfist_client_ova/ovf/` still import nothing outside the
  standard library and `defusedxml` (decision 1)?

The phase plan's survey added two more questions:

- What does a release publish? `setuptools_scm` puts every tracked
  file into the sdist, so the trimmed fixtures, the Glance archives
  and the fetch scripts presumably reach PyPI. The audit checks
  whether that is right.
- Does private corpus content reach a public CI log? The repository's
  logs are public, and the `appliance-corpus` job runs the corpus test
  on them.

The plan's first-parent range on `develop`, `db7bdaa^1..248ecd3`, also
holds two Renovate merges, #15 and #17. They are not plan work, and
are not audited as such.

The audit ran on 2026-10-18 against `248ecd3`. There is no
`PUSH-AUDIT.md`, so it applied the checklist and the six questions
above instead. Its verdicts and declines are in the phase plan's
[Audit results](PLAN-ovf-parser-phase-06-push-audit.md#audit-results).

* The checklist items and the six questions held, with three
  exceptions:
  * Question 1, on vendor prose, holds today but raised finding 2.
  * The question on public CI logs holds today but raised finding 3.
  * Item 5 does not hold. The release workflow publishes untested.
    That code predates the plan, so it is filed as #19.
* No private content was found anywhere public. The probe set matched
  five strings already in this plan:
  * two are CyberOps VirtualSystem ids, envelope data that phase 1's
    open question 1 rules publishable;
  * three are names of freely downloadable appliances.

  The phase plan's execution notes list them.
* There were nine findings, all fixed in one follow-up pull request,
  which also closed this plan:
  * the trimmed-against-original model check that decision 6 promised
    was never built;
  * the prose list omits the deployment option text;
  * the corpus test can print member names, which its output rule
    does not allow;
  * six documentation, duplication and stale-reference fixes.
* Four smaller items were declined in writing, in *Audit results*.
* Two problems in older code were filed as #19 and #20.

<!-- shared-block: plan-push-audit-phase v4 -->
Push audit phase (shared block; do not edit -- the canonical
copy lives in shakenfist/development at
`templates/shared-blocks/plan-push-audit-phase.md`):

- Every master plan ends with a phase that runs the repository's
  `PUSH-AUDIT.md` over the whole plan's work. It is the last row of
  the Execution table and it is not optional. The rule binds every
  plan that carries the phase, which is decidable from the plan file
  alone: a plan that is already `Complete`, `Abandoned` or
  `Superseded` and does not carry the phase is not reopened to
  acquire one, and a plan that has the phase runs it even if it
  reaches `Complete` before the phase does.
- That phase audits the accumulated diff of every phase in the plan
  against the default branch, not the diff of the last phase alone.
  Auditing one phase at a time would miss what the phases did to
  each other -- the duplicated helper that only exists once phases
  three and six have both landed, the doc page that phase two made
  wrong and phase five never revisited.
- Once the plan's phases have merged, a diff against the default
  branch is empty and would read as a clean audit. The range is not
  reliably derivable after the fact either: unrelated work lands on
  the default branch between phases, so anything anchored on "since
  the plan file appeared" is far too wide. It has to be recorded. As
  each phase lands, what put it on the default branch goes into the
  plan: the merge commit of its pull request, whose diff against its
  first parent is the whole of what landed, or -- where the phase
  landed directly -- every commit of the phase, or its `first..last`
  range. A single commit is only ever enough when it is a merge
  commit.
- Where the Execution phases are a table, that record is a `Merged`
  column, added last so that a row which omits it still reaches
  `Status`; where they are prose sections it is a `Merged:` line in
  the phase's own section. The `Status` column keeps its single
  vocabulary term and nothing else (see `plan-status-vocabulary`).
  A phase that landed in another repository records `<repo> <sha>
  (#pr)` and is audited against that repository's default branch, as
  part of the pull request that lands it; the plan's own push-audit
  phase cites that audit rather than re-running it.
- Phases that landed before the plan started recording them are
  reconstructed rather than left blank. Recover what you can from
  `gh pr list --state merged` and `git rev-list --first-parent`, and
  say in the plan that the range was reconstructed. Do not trust a
  path-filtered `git log` on its own: it lists the commits that
  touched a path without saying which arrived directly and which
  arrived inside a pull request, and recording a commit that came in
  under a merge audits one commit of that pull request rather than
  the pull request. A reconstructed record may be a summary table in
  the audit phase's own section rather than a column or a line in
  the Execution table, which keeps retrospective archaeology out of
  a table that tracks live status. Where a phase accreted over
  months of unrelated commits and no range is recoverable, say that
  instead and name the paths the audit read -- an audit that says
  what it could not scope is a result; one that silently audits
  nothing is not.
- Findings land as their own pull request against the default
  branch, and the plan is not complete until they are resolved or
  explicitly declined in writing. A finding that is declined says
  why, in the plan, where the next reader will find it.
- Where the audit finds nothing, record that in the plan in one
  sentence. It is a real result, and a run of them is the evidence
  for making the phase conditional rather than mandatory.
- A repository with no `PUSH-AUDIT.md` still carries the phase, and
  the phase says that the runbook does not exist yet and what was
  done instead. Silently omitting it is what let the audit go
  untriggered for as long as it did. What is done instead is at
  least the checklist below, applied to the recorded ranges: it is
  a floor, not a substitute for a runbook, and a plan adds the
  questions its own repository's blast radius raises. Each item
  gets a verdict, or a sentence saying why it does not apply.
  Do not borrow another repository's runbook instead: a runbook is
  written for one repository's blast radius.
  1. Every recorded landing takes one of the forms above: a merge
     commit with two parents, whose diff is read against its first
     parent; every commit of a direct landing, or its `first..last`
     range; a landing in another repository, whose own audit is
     cited; or a statement that no range is recoverable, naming the
     paths the audit read.
  2. Anything the diff added that runs unattended -- cron, a timer,
     a scheduled workflow, a self-update -- reports its own failure
     somewhere a human sees, or is named as not doing so.
  3. No secret or token entered any repository, and no private
     hostname or IP address entered a repository more public than
     the one it came from.
  4. Anything the diff removed or renamed has no consumer left,
     checked by grep across every repository that could consume it
     rather than by assumption, with the greps stated.
  5. Where the repository publishes something -- an image, a
     release, a package -- a broken change fails closed: one that
     publishes nothing is recoverable, one that publishes something
     wrong is not.
<!-- shared-block-end -->

!!! note "In this project"

    The Execution phases are a table, so the record goes in a
    `Merged` column after `Status`. Phases here land as pull
    requests against `develop`, so the cell normally holds the
    single merge commit of that pull request.

<!-- shared-block: plan-phase-landing v1 -->
Phase landing (shared block; do not edit -- the canonical copy
lives in shakenfist/development at
`templates/shared-blocks/plan-phase-landing.md`):

A plan's status and a repository's review state both live in files
that every branch would otherwise rewrite. Left alone, that turns
each of them into a merge-conflict hot spot, and it spends a pull
request and a full CI run on a change that is entirely prose.
Three rules keep them out of the way.

- **A phase is closed out in the first commit of the next phase,
  not in a pull request of its own.** By the time the next phase
  branches, the previous one has merged, so its merge commit is
  known and its `Merged` cell can record the thing the push-audit
  phase actually needs. This is the only ordering that works: a
  phase cannot record its own merge commit, and a separate
  close-out pull request buys that record at the price of a round
  trip. The close-out sets the finished phase's `Status` and
  `Merged` cells and the plan's row in `docs/plans/index.md`, and
  it is committed before the next phase's own work, so that the
  branch never claims the plan is further along than the default
  branch is.

- **The last phase closes itself out.** The push-audit phase is
  the last row of every plan, so no next phase will carry its
  close-out. Where the audit raises findings, the plan is not
  complete until they are resolved or declined, and those land as
  their own pull request after the audit phase has merged -- so
  that pull request is the carrier, and it can record the audit
  phase's merge commit, which by then is known. Where the audit
  finds nothing there is no carrier, and no follow-up pull
  request is opened for the sake of one cell: the phase sets its
  own `Status`, and the plan's index row, to `Complete` in its
  own pull request, and records no `Merged` cell. It is the only
  row permitted to omit one. The column exists so that the
  push-audit phase can reconstruct what to audit; the audit phase
  is last, so nothing ever reads its own row.

- **`REVIEWS.md` is not pruned or regenerated in a pull request
  that changes code or documentation.** Editing a reviewed file
  stales its mark, and adding or removing an in-scope file moves
  the header count, but neither is the landing pull request's
  business. `prune` regenerates the file whether or not it dropped
  anything, so the `prune-reviews` workflow heals both on the next
  push to the default branch. Pruning from a branch is also wrong
  more often than it is right, though not for the reason it first
  appears: `prune` compares each stamp against `HEAD`, which on a
  branch is the branch tip, so it drops the marks for the files the
  pull request itself touched while keeping marks the default
  branch has already pruned. Committing that state merges a review
  file computed from a stale tree, and can resurrect marks
  `prune-reviews` has already removed. Accumulated staleness is
  reported by the `review-coverage` audit, which recomputes
  coverage against `HEAD` and raises an issue once the backlog is
  worth a review session.

  **A review session is the exception**, and it is not optional
  tidiness: `stamp` regenerates `REVIEWS.md` as well as writing the
  marks, and the rows, the sidecars and the marks are committed
  together (see `docs/code-review-tracking.md`). Where a repository
  requires a pull request to reach its default branch, that is how
  a review session lands, so "not in a pull request" is about the
  kind of change, not the mechanism.

These rules assume phases land one after another. Where two phase
branches are open at once, each closes out only the phase it
directly follows.
<!-- shared-block-end -->

!!! note "In this project"

    This repository does not deploy review tracking: there is no
    `REVIEWS.md` and no `prune-reviews` workflow, so the third rule
    has nothing to act on here. The first two apply as written.

<!-- shared-block: plan-status-vocabulary v1 -->
Plan status vocabulary (shared block; do not edit -- the canonical
copy lives in shakenfist/development at
`templates/shared-blocks/plan-status-vocabulary.md`):

A status cell -- in the master plan's own Execution phase table, and
in the row `docs/plans/index.md` carries for the plan -- holds
exactly one of these terms and nothing else:

- `Proposed` -- written down as a concept, not yet scheduled.
- `Not started` -- scheduled, but no work has begun.
- `In progress` -- work has begun and has not finished.
- `Blocked` -- cannot proceed until something outside the plan
  changes. Say what, in the plan.
- `Complete` -- the work is done.
- `Abandoned` -- deliberately dropped without being done.
- `Superseded` -- replaced by another plan, which the plan names.

The term is the whole cell. No dates, no phase arithmetic, no
parenthetical qualifiers, no summary of what happened: a status is
read to decide whether a plan still wants attention, and prose in
that column has repeatedly grown until it could no longer be read
either by a person scanning the table or by tooling. Detail belongs
in the plan file, and a one-line summary belongs in the index's own
Intent column.

Matching is case-insensitive, so `In Progress` is accepted, but the
spelling above is the one to write.
<!-- shared-block-end -->

## Agent guidance

### Execution model

<!-- shared-block: subagent-execution-model v1 -->
Sub-agent execution model (shared block; do not edit -- the
canonical copy lives in shakenfist/development at
`templates/shared-blocks/subagent-execution-model.md`):

All implementation work is done by sub-agents, never in the
management session. The management session is reserved for
planning, review, and decision-making. This keeps the management
context lean and avoids drowning it in implementation diffs.

The workflow is:

1. **Plan** at high effort in the management session.
2. **Spawn a sub-agent** for each implementation step with the
   brief from the plan, at the recommended effort level and model.
3. **Review** the sub-agent's output in the management session.
   Check the actual files -- the sub-agent's summary describes
   what it intended, not necessarily what it did.
4. **Fix or retry** if the output is wrong. Diagnose whether the
   brief was insufficient (improve it) or the model was too light
   (upgrade it), then re-run.
5. **Commit** once the management session is satisfied.

This applies to all steps, including high-effort ones. If a
sub-agent cannot succeed even with a detailed brief and the right
model, that is a signal the brief needs improving, not that the
management session should do the implementation itself.

Use `isolation: "worktree"` for sub-agents when the change is
risky or experimental; the worktree is discarded if the output is
unsatisfactory. For safe, well-understood changes, sub-agents can
work directly in the main tree.
<!-- shared-block-end -->

### Planning effort

<!-- shared-block: plan-planning-effort v1 -->
Planning effort (shared block; do not edit -- the canonical copy
lives in shakenfist/development at
`templates/shared-blocks/plan-planning-effort.md`):

The master plan itself is always created at **high effort** -- it
requires broad codebase understanding, cross-referencing several
source files, and judgment calls about scope and sequencing.

Each phase plan states the recommended effort level for planning
that phase. Phases that turn on design decisions, cross-component
coordination, protocol changes, or subtle correctness questions
should be planned at high effort. Phases that are mechanical, or
that follow a pattern already established elsewhere in the
codebase, can be planned at medium effort.
<!-- shared-block-end -->

!!! note "In this project"

    Phases that change what the OVF parser accepts or rejects,
    or how hardware maps onto a Shaken Fist instance, should be
    planned at high effort -- these are the places where a
    mistake shows up only with an appliance nobody has tried
    yet, or only against a live Shaken Fist cluster. Phases that
    mirror an already established pattern -- adding a fixture
    and its expected parse, for example -- can be planned at
    medium effort.

### Step-level guidance

<!-- shared-block: subagent-step-guidance v1 -->
Sub-agent step guidance (shared block; do not edit -- the
canonical copy lives in shakenfist/development at
`templates/shared-blocks/subagent-step-guidance.md`):

Each phase plan includes a table like this:

| Step | Effort | Model | Isolation | Brief for sub-agent |
|------|--------|-------|-----------|---------------------|
| 1a | medium | sonnet | none | One-sentence summary of what to do and which files to touch |
| 1b | high | opus | worktree | Why this needs high effort: requires understanding X to do Y |

**Effort levels**, from cheapest to most thorough:

- **low** -- Purely mechanical changes: rename, reformat, add a
  log line, regenerate generated code. The brief is a complete
  instruction.
- **medium** -- The plan provides enough context to follow a clear
  brief. The sub-agent may read a few files, but the approach is
  already decided.
- **high** -- Requires reading several files, making judgment
  calls, or understanding non-obvious invariants. The sub-agent
  needs to think about edge cases.
- **xhigh** -- The setting for hard coding and agentic steps:
  long-horizon changes, or steps where the sub-agent must both
  research and implement.
- **max** -- Correctness matters more than cost. Expect
  diminishing returns and occasional overthinking; reserve it for
  steps where a wrong answer would be expensive to detect.

**Brief for sub-agent:** this is the key field. Write it as if
briefing a colleague who has never seen the codebase. Include what
to change, which files to touch, what patterns to follow, and any
non-obvious constraints.

A good brief front-loads the research the planner already did, so
the implementing agent does not repeat it. Instead of "add storage
functions for the new object", name the functions to add, the file
they belong in, the existing equivalent to mirror (with line
numbers), and any registration the change also needs.

The better the brief, the lower the effort level needed and the
lighter the model that can succeed.
<!-- shared-block-end -->

!!! note "In this project"

    A brief should say explicitly whether a step can be verified
    by unit tests alone or needs a live cluster, because the
    sub-agent cannot reach one and should not pretend otherwise.

    A worked brief for this codebase: instead of "support
    another appliance", write "add the trimmed descriptor for the
    appliance to `shakenfist_client_ova/tests/fixtures/ovf/`, record
    its expected parse beside it, and extend the parser in
    `shakenfist_client_ova/ovf/` until it matches. Fail on any
    section the parser does not understand and the descriptor does
    not mark `ovf:required="false"`."

### Model choice

<!-- shared-block: subagent-model-roster v1 -->
Sub-agent model roster (shared block; do not edit -- the canonical
copy lives in shakenfist/development at
`templates/shared-blocks/subagent-model-roster.md`):

The planner recommends which model is best suited to each step.
This is a judgment call, not a rigid rule -- the right model
depends on what the step requires, not on whether it is "planning"
or "implementation". The models available to sub-agents are:

- **fable** -- The most capable model available, for the hardest
  reasoning and the longest-horizon work: multi-step changes a
  single sub-agent must carry end to end, or steps whose
  correctness depends on holding a whole subsystem in mind at
  once. It costs materially more than opus, so reserve it for
  steps that have already defeated opus or are expected to.
- **opus** -- The default for steps needing deep reasoning,
  architectural understanding, subtle correctness judgment
  (locking, state machines, migrations), or intricate
  implementation that would be costly to debug if it were wrong.
- **sonnet** -- A good default for well-briefed implementation
  work. Faster and cheaper than opus, and effective when the plan
  front-loads the research and the brief leaves no broad judgment
  calls to make.
- **haiku** -- Suitable for purely mechanical tasks:
  search-and-replace, regenerating generated code, adding log
  lines, running commands. The brief must be a near-complete
  instruction.

Model choice interacts with effort level and brief quality. A
detailed brief compensates for a lighter model -- sonnet at medium
effort with a thorough brief often matches opus at medium effort
with a vague brief. The planner's job is to write briefs good
enough that the recommended model can succeed.

The model also determines the context window: fable, opus and
sonnet have 1M tokens, haiku has 200K. A step that must hold many
files in context at once may need one of the larger-context models
for that reason alone, even when the reasoning itself is
straightforward.

**When in doubt, skew to the more capable model.** Saving money
only matters if the outcome is still acceptable. A failed or
low-quality implementation wastes more time -- and therefore more
money -- than the heavier model would have cost. Recommend a
lighter model only when you are confident the brief is detailed
enough for it to succeed.
<!-- shared-block-end -->

### Management session review checklist

<!-- shared-block: plan-review-checklist v1 -->
Management session review checklist (shared block; do not edit --
the canonical copy lives in shakenfist/development at
`templates/shared-blocks/plan-review-checklist.md`):

After a sub-agent completes, the management session verifies:

- [ ] The files that were supposed to change actually changed --
      read them, do not trust the summary.
- [ ] No unrelated files were modified.
- [ ] The changes match the intent of the brief: not merely
      syntactically correct, but semantically right.
- [ ] The project's own pre-merge checks pass, including any
      generated code that has to be regenerated and committed
      (see the project-specific checks below).
- [ ] The commit message follows project conventions, including
      the `Co-Authored-By` line recording model, context window,
      and effort level.
<!-- shared-block-end -->

!!! note "In this project"

    The project-specific checks referred to above are:

    - [ ] The code passes `tox -epy3` and
          `pre-commit run --all-files`.
    - [ ] The plugin still imports cleanly (`python3 -c 'import
          shakenfist_client_ova'`) -- a broken import takes the
          whole `sf-client` CLI down.

## Administration and logistics

### Success criteria

We will know when this plan has been successfully implemented
because the following statements will be true:

* The code passes `tox -epy3` and `pre-commit run --all-files`.
* New code is compatible with Python >= 3.7 and the plugin still
  imports cleanly (`python3 -c 'import shakenfist_client_ova'`) --
  a broken import takes the whole `sf-client` CLI down.
* There are unit tests for new parsing and error-handling
  behaviour, in the existing testtools/stestr style, driven by
  descriptor fixtures with external APIs mocked.
* Lines are wrapped at 120 characters, single quotes for strings,
  double quotes for docstrings, no triple single quotes.
* Behaviour which can only be validated against a live Shaken
  Fist cluster has been exercised there (manually or via the
  functional CI) before merge.
* Documentation follows the rules in `AGENTS.md`: user-visible
  behaviour in `docs/`, and `ARCHITECTURE.md` only when the shape of
  the import changes.

!!! note "In this project"

    The close-out sections below apply as written, with one
    addition: when scanning the issue tracker for related bugs,
    remember that issues for this plugin sometimes belong
    upstream (for example `shakenfist/shakenfist` or
    `shakenfist/client-python`). Reference cross-repository
    issues explicitly.

<!-- shared-block: plan-closeout-sections v1 -->
Plan close-out sections (shared block; do not edit -- the
canonical copy lives in shakenfist/development at
`templates/shared-blocks/plan-closeout-sections.md`):

### Future work

We should list obvious extensions, known issues, unrelated bugs we
encountered, and anything else we should one day do but have
chosen to defer to here, so that we do not forget them.

- Create an instance from the parsed hardware: the feature this plan
  prepares for, with its own plan.
- Decide whether the importer should offer guest conversion through
  `virt-v2v -i ova`, which matters most for Windows and for appliances
  without virtio drivers.
- Map an OVF environment onto Shaken Fist user data. The Ubuntu cloud
  image OVA, for one, takes its cloud-init configuration through
  `ProductSection` properties.
- Validate the hand-written fixtures against the DMTF envelope schemas
  (1.1 and 2.0.1, see "Test data"), so that our idea of a valid
  descriptor is checked against the specification's.
- Broaden the appliance corpus from VulnHub when a shape is needed
  that the current appliances lack. Pick specific files, and keep them
  in `instar-testdata` only, since their authors rarely state
  redistribution terms.
- Publish `shakenfist_client_ova/ovf/` as its own package once a
  second consumer needs it.
- Verify manifest digests during the upload, to save the extra read
  phase 4 accepts on servers without `blob-search-by-hash`. That needs
  `shakenfist_client.util`'s upload helper to offer a hook between
  uploading and creating the artifact, and digesting that survives its
  seek-back on retry: an upstream change in `client-python`.
- Verify an OVA's `.cert` signature over the manifest, which phase 4
  ignores with a notice. Until then the manifest is corruption
  detection, not tamper evidence.
- Support gzip compressed and chunked file references, which phase 4
  refuses. The design has to settle three things: the digest is taken
  over the compressed bytes, the decompressed size comes from one
  decompressing pass capped at `ovf:size` or the disk's capacity (not
  from ISIZE), and that pass must not cost a second full read.
- Read oVirt's OVF dialect, so that Oracle Linux's OLVM templates
  import. Phase 3 refuses it by name; its plan's survey finding 4 lists
  what one export carries, including cloud-init in `VmInit`.
- Link each disk drive in the model to the `Disk` it holds, by id.
  Phase 3 checks that a drive's `HostResource` names a disk, but keeps
  only the reference's text, and instance creation will need the link.
- Test the declared `requires-python` floor, which nothing exercises
  today. client-python-k3s#82 has the same gap.

### Bugs fixed during this work

This section should list any bugs we encounter during development
that we fixed. You should also scan the project's issue tracker,
where one exists, for directly related issues that we should
either resolve as part of this master plan or at least be aware of
while planning it.

- #1, allocation units of the form `byte * 2^N` computed with XOR, was
  fixed before this plan began, by the pull request that also
  introduced the unit-test suite. It is listed because it is the only
  issue the tracker held when the plan was written.

### Back brief

Before executing any step of this plan, please back brief the
operator as to your understanding of the plan and how the work you
intend to do aligns with that plan.
<!-- shared-block-end -->

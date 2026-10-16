# OVF parser phase 1: corpus and fixtures

## Prompt

Before responding to questions or discussion points in this document,
read the master plan, [PLAN-ovf-parser.md](PLAN-ovf-parser.md),
particularly decisions 5 to 8 and phase 1's section. This phase builds
the data every later phase tests against. The master plan's decisions
are not restated here, except where this phase's survey changed or
sharpened them.

This phase adds no parser code. It adds test data, the tools that make
and fetch it, and a record of where each piece came from. It lands in
two repositories: `instar-testdata`, by direct commits, and this one,
by a pull request.

## Planning effort

Medium, by the master plan's rule: this phase follows an established
pattern (fixtures and their provenance) and changes nothing the parser
accepts. The survey below was done before the plan was written,
because the archives' real layouts decide how the fetch tool has to
work, and guessing them would have produced the wrong tool. Review
effort: medium. The trim tool is the one place to read closely,
because a mistake there publishes vendor or private text from a
public repository.

## Scope

In:

* `instar-testdata`: the appliance corpus under `downloaded/ova/`, a
  fetch script, a machine-readable provenance record per entry, the
  README section, and the LFS rule for `*.ova`.
* This repository:
  * `tools/trim-ovf-descriptor.py` and a trimmed fixture for each of
    the 16 appliance descriptors;
  * Glance's five test OVAs, with a `NOTICE` and a `.gitignore`
    negation;
  * the hand-written fixtures the master plan lists;
  * the descriptor corpus fetch script, its pins, a classification tool
    and the curated list of 51;
  * the `docs/development.md` section and one `AGENTS.md` line.

Out:

* Expected parse files and every test that reads a fixture: phase 2.
  Nothing in this phase can assert what the parser does with these
  files, because the parser cannot yet be called on its own.
* The descriptor corpus tox environment and CI job: phase 2.
* The appliance corpus test and CI job: phase 5.

## What the survey found

The survey ran on 2026-10-16, against every appliance the master plan
lists and both upstream descriptor collections. It read each OVA's tar
headers, descriptor and manifest with HTTP range requests, which took
two or three requests per appliance and downloaded no disks. VyOS 1.2.1
was downloaded whole, twice.

### 1. VyOS 1.2.1 is verified

The live `cdn.vyos.io` file and the Wayback Machine's 2019 capture of
the same URL have the same SHA-256,
`fef225ae1f2aa21c1983e79f9cca7c1e575ca4e9984f9a2b2b67eecf8bffd16b`.
Its disk has `CID=9040bba6`, matching the disk already in
`instar-testdata`. The master plan's fallback for an unusable capture
is not needed.

### 2. Seven of sixteen archives store the manifest after the disks

| Appliance | Member order | Manifest | Producer |
|-----------|--------------|----------|----------|
| VyOS 1.2.1 | ovf, mf, cert, vmdk | SHA1 | ovftool |
| Photon OS 3.0 hw11 | ovf, mf, cert, vmdk | SHA1 | ovftool 4.2.0 |
| Photon OS 5.0 aarch64 hw14 | ovf, mf, cert, vmdk | SHA256 | ovftool 4.2.0 |
| Talos 1.14.3 | ovf, mf, vmdk | SHA256 | ovftool 4.3.0, edited |
| Oracle Linux 9.8 OLVM | ovf, disk with no extension | none | oVirt |
| ArchiveTeam Warrior 4.1 | ovf, vmdk, **mf** | SHA256 | VirtualBox, OVF 2.0 |
| Home Assistant OS 18.3 | ovf, vmdk, **mf** | SHA256 | VirtualBox and ovftool elements |
| Ubuntu 24.04 (20260926) | ovf, mf, vmdk | SHA256 | Canonical |
| Flatcar 4757.2.1 | ovf, mf, vmdk | SHA1 | Flatcar |
| Fedora CoreOS 44.20260928.3.1 | ovf, vmdk | none | coreos-assembler |
| Wazuh 4.9.1 | ovf, vmdk, **mf** | SHA1 | AWS VM Export |
| Tails 202607 | ovf, vmdk, iso, **mf** | SHA1 | VirtualBox, OVF 0.9 |
| REMnux 202610b | ovf, mf, vmdk.gz | SHA256 | ovftool 9.1.1 |
| VulnHub blogger | ovf, vmdk, vmdk, **mf** | SHA1 | VirtualBox |
| CyberOps Workstation | ovf, vmdk, vmdk, **mf** | SHA1 | VirtualBox 6.1.10 |
| CyberOps Security Onion | ovf, vmdk, **mf** | SHA1 | VirtualBox 6.1.10 |

The master plan's idea of taking a descriptor-only copy by "streaming
the start of the download and stopping" would miss the manifest on
every VirtualBox and AWS export. The fetch tool here reads each archive
in one streaming pass instead (decision 2).

Two appliances ship no manifest at all, and Fedora CoreOS is one of
them, so the master plan's no-manifest warning will fire on a mainstream
appliance, not only on oddities.

### 3. Every vendor extension element in the corpus is marked optional

Decision 4's table left phase 1 to record which producers mark their
custom elements `ovf:required="false"`. All of them do, in all 16:
VirtualBox marks `vbox:Machine` and `vbox:OSType`; ovftool marks
`vmw:Config`, `vmw:ExtraConfig`, `vmw:CoresPerSocket` and
`vmw:IpAssignmentSection`. The strict element rule refuses none of
these appliances for a custom element.

### 4. Three shapes the master plan's rules would refuse

Each of these is a decision for phase 3, recorded as a new open question
in the master plan rather than settled here:

* **oVirt writes its own attributes in the OVF namespace.** Oracle
  Linux's `Disk` carries `ovf:disk-interface="VirtIO"`,
  `ovf:disk-alias` and `ovf:disk-type`. Decision 4 reads or refuses
  OVF-namespace attributes, so as written it refuses every oVirt
  export. `ovf:disk-interface` is also the disk bus, which instance
  creation will want.
* **VirtualBox's OVF 2.0 export gets the CIM namespaces wrong.**
  ArchiveTeam Warrior declares `epasd` and `sasd` as
  `.../CIM_EthernetPortAllocationSettingData.xsd` and
  `.../CIM_StorageAllocationSettingData.xsd`, with a `.xsd` suffix the
  DMTF namespaces do not have. COT's `ubuntu.2.0.ovf` does the same.
  Taken literally, the `EthernetPortItem` and `StorageItem` children
  are unknown custom elements with no `ovf:required="false"`, so every
  VirtualBox OVF 2.0 export would be refused.
* **OVF 0.9 is common.** Tails declares
  `http://www.vmware.com/schema/ovf/1/envelope`, the pre-standard
  namespace, with generic `<Section xsi:type="...">` elements. So do 149
  of govmomi's 958 descriptors and COT's `v0.9.ovf`. The master plan
  supports the 1.x and 2.x DMTF namespaces only.

### 5. VirtualBox's machine element leaks the exporter's host

`vbox:Machine` is the exporting host's VirtualBox configuration. In
`blogger.ova` it contains `/home/elliot/projects/vuln_iso/...` paths
and shared folder definitions. It is marked not required, so the
parser ignores it, which means the trim tool can empty it without
changing any parse. It has to: replacing only prose elements, as
decision 6 describes, would publish another person's home directory
layout.

### 6. The upstream collections, classified

govmomi at `79bc9d75e5c930649bc1b3e86bb0cfe76d60fdbe` (2026-10-15) has
958 descriptors, 27MB:

| Shape | Count |
|-------|-------|
| OVF 1.x root namespace | 788 |
| OVF 0.9 root namespace | 149 |
| OVF 2.x root namespace | 1 (and 21 OVF 1.x files that mention 2.x) |
| Unknown root namespace (deliberately invalid) | 5 |
| Not well-formed XML | 15 |
| `VirtualSystemCollection` | 165 |
| `ovf:required="false"` somewhere | 521 |
| `ProductSection` / `EulaSection` | 202 / 82 |
| `DeploymentOptionSection` with `ovf:configuration` items | 29 |
| `ovf:compression` / `ovf:chunkSize` | 13 / 2 |
| `DOCTYPE` or entity declarations | 0 |

COT has no development since 2019 on any branch, so its pin is master
at `0811b96311881a8293f28f2e300f6bed1b77ee31`. It has ten descriptors
(OVF 0.9, 1.x, 2.x and a deliberate "3.0") and two manifests.

Neither collection declares an entity anywhere, so the "descriptor
declaring an entity" fixture stays hand-written. About a sixth of
govmomi's descriptors are `VirtualSystemCollection`, which phase 3
refuses by name, so its ledger will show that refusal often. That is
expected, not a defect.

## Decisions

1. **The appliance corpus layout.** In `instar-testdata`:

   ```
   downloaded/ova/
     sources.json                 # what to fetch, pinned
     <name>.ova                   # whole, or descriptor-only
     <name>.provenance.json       # what was fetched, and what it held
   scripts/fetch-ova-corpus.py
   ```

   `<name>` is the appliance and version as in the table above, for
   example `photon-5.0-aarch64-uefi-hw14`. Whole and descriptor-only
   entries share a directory and differ by the `kind` field in their
   provenance, so the phase 5 test enumerates one directory. `*.ova`
   joins `.gitattributes` as an LFS pattern; no `.ova` is tracked in
   `instar-testdata` today, so nothing existing changes.

2. **One streaming pass per appliance.** The fetch script reads each
   source once, as a stream, through Python's `tarfile` in stream mode
   (`r|`). In that pass it:
   * hashes the whole file with SHA-256, and also with the vendor's
     algorithm (any `hashlib` name: MD5, SHA-1, SHA-512) where
     `sources.json` records a vendor checksum, which it checks;
   * records every member's name, type, size, offset and mtime, and its
     SHA-1 and SHA-256;
   * keeps the descriptor, manifest and certificate members in memory;
   * writes the whole file to disk, for a whole entry only.

   At the end it checks the archive's own manifest against the member
   digests it computed and records the result. A mismatch fails the
   fetch, since a corrupt original is not test data. Producers write
   three manifest line forms: ovftool's `SHA1(name)= hex`, VirtualBox's
   `SHA1 (name) = hex` and AWS's `SHA1(name) = hex`. The script accepts
   exactly `^(SHA1|SHA256|SHA512) ?\((.+)\) ?= ?([0-9a-fA-F]+)$` after
   trimming the line. Any other non-blank line is an error, never a
   skip, and a manifest with no verified entry fails the fetch, so the
   check cannot pass by verifying nothing. For a
   descriptor-only entry it then writes a new tar holding the
   descriptor and manifest, in their original relative order, with
   their original header metadata (name, mode, mtime, uid and gid), in
   ustar format. Two runs give identical bytes.

   This downloads about 20GB once (REMnux alone is 8.3GB) to keep about
   2.1GB, almost all of it the six whole entries. Range requests would
   avoid that, but they cannot hash the original, and the provenance
   table promises its SHA-256. The fetch is a one-off, run on the
   operator's workstation, not in CI.

3. **Provenance is data, and the README is generated from it.** Each
   `<name>.provenance.json` holds:
   * the source URL, or `local` with a description for the two CyberOps
     exports;
   * the download date, the original size and its SHA-256, and the
     vendor checksum and whether it matched;
   * `local_sha256`, the SHA-256 of the `.ova` as committed. For a whole
     entry it equals the original's; for a descriptor-only entry it is
     the re-tar's. The script skips a source when its `.ova` matches
     `local_sha256`, so a re-run after a partial failure fetches only
     what is missing, and rewrites nothing, download date included;
   * the producer, the full member listing in order, and the manifest
     check result;
   * `kind` (`whole` or `descriptor-only`) and, for descriptor-only
     entries, `absent_members`: the members removed.

   Decision 8 of the master plan wants each descriptor-only entry to
   declare its absent members as test input. This file is that
   declaration, so phase 5 reads it rather than keeping a second copy
   in this repository. The provenance holds facts about the archives
   only. What this repository's parser is expected to do with an entry
   is a fact about the parser, and it changes in this repository's
   review flow: where phase 5 needs an outcome other than the
   missing-member error (Tails, if master plan open question 6 is
   decided as a refusal), it goes in
   `shakenfist_client_ova/corpus_tests/appliances.expected.json`, added
   by phase 5. The script's `--readme` mode writes the README's
   provenance table from the provenance files, so the two cannot
   drift.

4. **The trim tool empties `vbox:Machine` as well as replacing
   prose** (survey finding 5). The prose list, as pairs of element and
   the model field it fills:

   | Element | Model field |
   |---------|-------------|
   | `EulaSection/License` | `eula.license` |
   | `AnnotationSection/Annotation` | `annotation` |
   | `ProductSection/Product`, `Vendor`, `FullVersion`, `ProductUrl`, `VendorUrl`, `AppUrl`, `Category` | `product.<field>` |
   | `ProductSection/Property/Label`, `Property/Description` | `product.properties[].label`, `.description` |
   | `VirtualSystem/Description`, `VirtualSystemCollection/Description` | `description` |
   | `Strings/Msg` (localised message bundles) | none |

   The model fields are the names phase 2 will use, recorded here so
   the list moves into the parser package without a rename. `Info`,
   `Version`, `rasd:ElementName`, `rasd:Caption` and
   `rasd:Description` stay. They are short, generic and structural,
   and a parser that reads them should see the real thing. XML comments
   stay, because ovftool's `Generated by` comment is producer evidence.
   That comment sits in the prolog, before the root element, where an
   ElementTree cannot hold it, so the tool reads the prolog's comments
   (and any processing instructions) from the raw bytes before the root start tag and writes them back, in
   order, after the provenance comment. `vbox:Machine` keeps its
   attributes except `vbox:uuid`, loses all its children, and keeps
   `ovf:required="false"`.

   `--check ORIGINAL TRIMMED` compares the two files three ways:
   * the element trees: the same elements in the same order, with the
     same attributes (apart from `vbox:uuid`) and the same text, except
     where the list above says the text was replaced, and except the
     `vbox:Machine` subtree;
   * the prolog comments, in order;
   * the namespace declarations, collected with
     `iterparse(events=('start-ns',))`. Every prefix the original
     declares must be declared in the trimmed copy with the same URI.
     Comparing resolved names alone would miss a prefix used only
     inside an attribute value, such as OVF 0.9's
     `xsi:type="ovf:VirtualHardwareSection_Type"`, which ElementTree's
     serialiser drops when no element or attribute name uses it.

   This is phase 1's version of the master plan's "structure unchanged
   is checked rather than claimed". Phase 5's model-equality assertion
   still comes later, because it needs the parser.

   The tool needs Python 3.8 or newer (`TreeBuilder(insert_comments=)`
   arrived in 3.8). The 3.7 floor binds the plugin package, not the
   tooling, so its unit test skips itself below 3.8 and says why.

5. **`defusedxml` joins the `test` extra now and the runtime
   dependencies in phase 3.** The trim tool reads vendor files, and
   decision 6 of the master plan says it reads them as the importer
   will. It cannot wait for phase 3's runtime dependency.

6. **The unit-tier fixtures are split by origin:**

   ```
   shakenfist_client_ova/tests/fixtures/
     ovf/vendor/<name>.ovf          # trimmed, one per appliance
     ovf/handwritten/<case>.ovf     # the master plan's edge cases
     ova/imported/glance/*.ova      # verbatim, with NOTICE
   ```

   Phase 2's golden test parameterises over `ovf/`. The split lets the
   push audit's prose question apply to `vendor/` alone, and makes the
   origin of each file obvious from its path. Each hand-written fixture
   opens with a comment, after the XML declaration, naming the case it
   exercises and the master plan clause it tests.

7. **The curated list is chosen by a rule, and the rule is a tool.**
   `tools/classify-ovf-corpus.py` classifies descriptors by the shapes
   in survey finding 6. With `--curate N` it proposes, for each shape,
   the N smallest examples from distinct upstream directories, plus one
   from each directory named for a feature (`SignedOVF`,
   `VM_with_nvram`, `NonAsciiChars`, `MultiVmVapps` and so on). The
   committed list is `shakenfist_client_ova/corpus_tests/curated.txt`:
   exactly the tool's output at N=2 for govmomi and N=1 for COT. A
   review never edits it. To add or drop a descriptor, the reviewer
   edits `curated-overrides.txt` beside it, a committed list of `+path`
   and `-path` lines with a reason each, which the tool applies. So
   the tool always reproduces `curated.txt`, and a pin bump shows what
   the rule chose separately from what a person changed. That is 45
   govmomi and 6 COT descriptors, listed in the appendix, with no
   overrides.

   Two requirements the master plan sets for this list:
   * **OVF 1.1.** It has no representative of its own, because none
     can be told apart. 1.0 and 1.1 share a namespace, and the only
     marker is the optional `ovf:version` attribute. Across both
     collections that attribute says `0.9` 140 times, `1.0` 22 times,
     `2.0` once and an invalid `1.3` twice, and never `1.1`. The 1.x
     namespace entries cover 1.0 and 1.1 together.
   * **Deployment options.** Three curated entries carry
     `DeploymentOptionSection` with `ovf:configuration` items. No file
     in either collection also carries `vmw:buildId` and
     `ovf:transport`, so the hand-written `ovftool-style.ovf` is still
     needed for the combination.

8. **The descriptor corpus pins are fetched by commit hash.** The fetch
   script does `git init`, a sparse checkout of the one directory, and
   `git fetch --depth 1 --filter=blob:none origin <sha>`. GitHub
   serves any reachable commit, so the pin is exact even after the
   branch moves. The cache is `.cache/ovf-corpora/<repo>-<sha>/`,
   gitignored, and is reused when the hash matches.

## Step plan

Steps 1a to 1c land in `instar-testdata` and the rest in this
repository. Steps 1d to 1h need 1c's local corpus to exist, but not
pushed.

| Step | Effort | Model | Isolation | Brief for sub-agent |
|------|--------|-------|-----------|---------------------|
| 1a | high | opus | none | In `~/src/shakenfist/instar-testdata`, write `scripts/fetch-ova-corpus.py` to decision 2 and 3 of `docs/plans/PLAN-ovf-parser-phase-01-corpus.md` in shakenfist/client-python-ova (read it first). Python 3, standard library only, in the style of the other `scripts/*.py` there: argparse, a module docstring, and `main()`. It reads `downloaded/ova/sources.json`, a list of `{name, url or local_path, kind, producer, vendor_checksum: {algorithm, value} or null}`, where `algorithm` is a `hashlib` name and `value` a literal hex digest; never fetch a checksum file at run time. Stream each source with `urllib` (local paths with `open`) into `tarfile.open(fileobj=..., mode='r|')`, wrapping the stream in a reader that updates a SHA-256, and the vendor algorithm's hash where there is one, of everything read; hash each member's data as it is read; keep the members whose names end in `.ovf`, `.mf` or `.cert` (case-insensitive) in memory; for `kind: whole`, tee the stream to `<name>.ova.partial` and rename it on success. Parse manifests with the exact grammar in decision 2, which accepts the ovftool, VirtualBox and AWS forms; a non-blank line that does not match is an error, a mismatch or an entry naming no member fails the fetch, and so does a manifest that verified no entry. Unit-test the parser on one line of each form and on a malformed line, in `scripts/` beside the script if instar-testdata has no test directory. Write the descriptor-only tar with `tarfile` in `USTAR_FORMAT`, copying `name`, `mode`, `mtime`, `uid`, `gid`, `uname` and `gname` from the originals and keeping their order. Write `<name>.provenance.json` with sorted keys and indent 2, including `local_sha256` (decision 3). Make the script idempotent: skip a source whose `.ova` hashes to its provenance's `local_sha256`, rewriting nothing, unless `--force`. Add `--readme`, which prints the provenance table for the README from the JSON files. Add `*.ova filter=lfs diff=lfs merge=lfs -text` to `.gitattributes`. Write `sources.json` from the table in survey finding 2, using these pinned URLs: `https://cdn.vyos.io/1.2.1.15500/vyos-1.2.1.ova`; `https://packages.broadcom.com/photon/3.0/GA/ova/photon-hw11-3.0-26156e2.ova`; `https://packages.broadcom.com/photon/5.0/GA/ova/photon-uefi-hw14-5.0-dde71ec57.aarch64.ova`; `https://factory.talos.dev/image/376567988ad370138ad8b2698212367b8edcb69b5fd68c80be1f2ec7d603b4ba/v1.14.3/vmware-amd64.ova`; `https://yum.oracle.com/templates/OracleLinux/OL9/u8/x86_64/OL9U8_x86_64-olvm-b293.ova`; `https://warriorhq.archiveteam.org/downloads/warrior4/archiveteam-warrior-v4.1-20240906.ova`; `https://github.com/home-assistant/operating-system/releases/download/18.3/haos_ova-18.3.ova`; `https://cloud-images.ubuntu.com/releases/noble/release-20260926/ubuntu-24.04-server-cloudimg-amd64.ova` (vendor SHA-256 `513a22ebe3982b9387b038f8a2a6dad1af980d4623dca03511312e55ba620b1a`); `https://stable.release.flatcar-linux.net/amd64-usr/4757.2.1/flatcar_production_vmware_ova.ova` (vendor SHA-512 `db357ecb13c0d7cd9950e73a6b0672dd27a0d7c43f0ce1c4d2c540a4c48ca09d6037df7662f670bcb565bd773b35ccaefa4ff294933046d0d049903bfa8d11d8`, from the `.DIGESTS` file beside it); `https://builds.coreos.fedoraproject.org/prod/streams/stable/builds/44.20260928.3.1/x86_64/fedora-coreos-44.20260928.3.1-vmware.x86_64.ova` (vendor SHA-256 `032351294cb7ac34ca6944ec621c3b6f1eb9d8c7b507634a6483b7cf0f331ad8`); `https://packages.wazuh.com/4.x/vm/wazuh-4.9.1.ova` (vendor SHA-512 `449d60feb38f4132a4703ae6058c2695c6876d716e13b3337e349c62dcf30e06547e5e385d9077f61e9708072e1ec2c1e81c2936623f9b4d6fb0b99dcfc430c1`, from `packages.wazuh.com/4.x/checksums/wazuh/4.9.1/`); `https://archive.org/download/tails_202607/Tails.ova` (SHA-1 `01b7711b383b21943325a294990e231fb122ca22`, from the item's `_files.xml`); `https://download.remnux.org/202610b/remnux-noble-amd64.ova`; `https://download.vulnhub.com/blogger/blogger.ova` (SHA-1 `bb22a3a5577a26db969b415f84701b143a27d4cc`, from VulnHub's `checksum.txt`); and two local paths, `cyberops_workstation.ova` and `security_onion.ova` in the operator's client-python-ova clone. The Photon images publish SHA-256 beside them (`.sha256`): 3.0 hw11 `c421446371d26c35645b4d3fdd5b77dcb268f140fe5f694fe3565b70f7a29b4b`, 5.0 aarch64 `37a30fd762d6b07120ed03ccf747594644b58de2bf5f34b4945da423e3fe513d`. Home Assistant's GitHub release gives SHA-256 `938408c5bd0f5fe3a8f10ca0a985d611f5d4e74f9ace12bda33d950a9617ca12`. No published checksum was found for VyOS (verified instead against the Wayback Machine, survey finding 1), Talos, Oracle Linux, Warrior or REMnux; look once more for Oracle Linux and REMnux, and record `null` with a note for any still missing. `kind` is `whole` for VyOS, both Photon images, Talos, Oracle Linux and Warrior, and `descriptor-only` for the rest. Do not run the full fetch in this step: test it on Talos (234MB, whole) and Warrior (173MB, whole, manifest last), then on the local Security Onion export as descriptor-only. Confirm a second run is a no-op and that two runs give identical descriptor-only bytes. Commit subject: `Add a fetch script for the OVA appliance corpus.` |
| 1b | low | sonnet | none | In `instar-testdata`, run `scripts/fetch-ova-corpus.py` for every source. It downloads about 20GB and keeps about 2.1GB; run it with `run_in_background`. Any manifest mismatch or vendor checksum mismatch stops the step and is reported, never worked around. Check `git lfs status` shows the `.ova` files as LFS objects before committing. Commit the corpus and provenance files. Commit subject: `Add the OVA appliance corpus.` |
| 1c | medium | sonnet | none | In `instar-testdata`'s `README.md`, add a section "OVA Appliances", after "VMDKs Unpacked from Vendor OVA Appliances" (around line 209), and add `downloaded/ova/` to the directory tree at line 49. Say what the corpus is for (shakenfist/client-python-ova's parser tests), the whole versus descriptor-only rule (master plan decision 8, summarised in two sentences), that each entry's `<name>.provenance.json` is the record, and that the table below is generated by `scripts/fetch-ova-corpus.py --readme` and must not be edited by hand. Paste the generated table. Note that the VyOS 1.2.1 OVA's disk is the same one as `ova-derived/vyos-1.2.1-disk1-streamoptimized.vmdk`. Commit subject: `Document the OVA appliance corpus.` Then push 1a to 1c to `main`, as this plan authorises, and record the commit range `<first>..<last>` for the master plan's Merged cell. Finally file an issue on shakenfist/instar (risk 3): its `tools/ci/prepare-testdata.sh` runs a bare `git lfs pull`, which now also fetches about 2.1GB under `downloaded/ova/` that instar never reads; propose `git lfs pull --exclude downloaded/ova`. |
| 1d | high | opus | none | In this repository, write `tools/trim-ovf-descriptor.py` to decision 4. It uses `defusedxml.ElementTree` to parse (add `defusedxml` to the `test` extra in `pyproject.toml`, with the licence comment the other entries carry: `# psf`). Serialise with `xml.etree.ElementTree`, registering every namespace prefix the original declares, so prefixes survive. Keep the XML declaration first, then a comment: `Trimmed from <url> (SHA-256 <hex> of the original descriptor) by tools/trim-ovf-descriptor.py; prose replaced with the placeholder "TRIMMED".` ElementTree drops comments by default; parse with a `TreeBuilder(insert_comments=True)` so that ovftool's comments survive. Read prolog comments from the raw bytes before the root start tag and write them back, in order, after the provenance comment (decision 4). Usage: `trim-ovf-descriptor.py --source-url URL ORIGINAL OUTPUT` and `trim-ovf-descriptor.py --check ORIGINAL TRIMMED`, which compares element trees, prolog comments and namespace declarations as decision 4 says, and exits non-zero naming the first difference. Keep the prose list as a module-level constant of `(element path, model field)` pairs, with a comment saying phase 2 moves it into `shakenfist_client_ova/ovf/`. Test the tool with a small unit test in `shakenfist_client_ova/tests/test_trim_tool.py`, loading the tool with `importlib` from its path. The tool needs Python 3.8 or newer; the test module skips itself below 3.8 with that reason. Cover: prose replaced; `vbox:Machine` emptied with `ovf:required` kept; a comment before the root element kept, and one inside it; the declaration kept; prefixes kept, including one used only inside an `xsi:type` value; `--check` passing on a correct trim, and failing with the element or prefix named when a non-prose element's text, an attribute, a prolog comment or a namespace declaration differs. Unit tests suffice. Single quotes, wrap at 120. Commit subject: `Add a tool that trims vendor OVF descriptors.` |
| 1e | medium | sonnet | none | For each of the 16 entries in `instar-testdata/downloaded/ova/`, extract the `.ovf` member and run `tools/trim-ovf-descriptor.py --source-url <url from its provenance.json>` into `shakenfist_client_ova/tests/fixtures/ovf/vendor/<name>.ovf`, then `--check` it against the original. Use `python3 -I` and work on copies in a scratch directory: these are downloaded files. Then read every trimmed file and confirm by eye that no licence text, product marketing, personal path or e-mail address remains. Grep for `/home/`, `C:\\`, `@`, `http` outside namespace declarations and `ovf:href`, and `Copyright`. Anything found that the prose list misses is a defect in 1d's list: fix the list, re-run, and say so in the commit message. Do not hand-edit a fixture. Commit subject: `Add trimmed descriptors from 16 appliances.` |
| 1f | low | sonnet | none | Download the five OVAs in `glance/tests/var/` of `opendev.org/openstack/glance` at commit `76306ffdb15a76456bc6106a659250e1ae69f4e1` (`testserver.ova`, `testserver-bad-ovf.ova`, `testserver-no-disk.ova`, `testserver-no-ovf.ova`, `testserver-not-tar.ova`) into `shakenfist_client_ova/tests/fixtures/ova/imported/glance/`. Write a `NOTICE` there with the source repository, the commit, the path, the Apache-2.0 licence and the SHA-256 of each file. In `.gitignore`, after `*.ova` (line 139), add `!shakenfist_client_ova/tests/fixtures/ova/**/*.ova`, with a comment that test fixtures are small and deliberate while the global rule keeps manual-testing appliances out. Confirm with `git ls-files` that all five are tracked. Commit subject: `Import Glance's OVA test fixtures.` |
| 1g | high | opus | none | Hand-write the fixtures in the master plan's phase 1 list (`docs/plans/PLAN-ovf-parser.md`, "Hand-write the edge cases") into `shakenfist_client_ova/tests/fixtures/ovf/handwritten/`, one case per file, named for the case (`ovf2-envelope.ovf`, `no-default-namespace.ovf`, `required-false-extension.ovf`, `unknown-required-extension.ovf`, `gzip-reference.ovf`, `chunked-reference.ovf`, `two-controllers.ovf`, `entity-declaration.ovf`, `product-and-eula.ovf`, `href-absolute-url.ovf`, `href-parent-dir.ovf`, `href-missing-member.ovf`, `href-duplicate-member.ovf`, `virtual-system-collection.ovf`, `unknown-ovf-attribute.ovf`, `custom-namespace-attribute.ovf`, `ovftool-style.ovf`). Start from the smallest well-formed descriptor and change only what the case needs, so each file differs from a plain one by its case alone. Use the real DMTF namespaces, not VirtualBox's `.xsd` ones. Each opens, after the XML declaration, with a comment naming the case and the master plan clause it tests. `entity-declaration.ovf` declares one internal entity and uses it once; it must not be a billion-laughs payload, because the unit tier runs it on every pull request. Check every file except that one is well-formed with `python3 -c 'import defusedxml.ElementTree as E, sys; E.parse(sys.argv[1])'`. No test reads these files until phase 2. Commit subject: `Add hand-written OVF edge-case fixtures.` |
| 1h | medium | sonnet | none | Add `tools/fetch-descriptor-corpus.sh` to decision 8: two pins as variables at the top (`GOVMOMI_SHA=79bc9d75e5c930649bc1b3e86bb0cfe76d60fdbe`, path `ovf/fixtures`; `COT_SHA=0811b96311881a8293f28f2e300f6bed1b77ee31`, path `COT/tests`), fetched into `.cache/ovf-corpora/<repo>-<sha>/` with `set -euo pipefail` and nothing else that needs network. It must pass shellcheck. Add `.cache/` to `.gitignore`. Add `tools/classify-ovf-corpus.py` (decision 7), parsing with `defusedxml` and counting `ParseError` and refused entity declarations as their own shapes. Give the tool `--curate N` and `--overrides FILE` (decision 7). Write `shakenfist_client_ova/corpus_tests/curated.txt` as the tool's output, one `<repo>:<path>` per line, and an empty `curated-overrides.txt` beside it with a comment explaining the `+path reason` / `-path reason` format. Confirm the output matches this plan's appendix; any difference means the tool or the appendix is wrong, so find out which rather than editing the list. Add `shakenfist_client_ova.corpus_tests*` to the `exclude` list in `pyproject.toml`'s `[tool.setuptools.packages.find]`. Do not add an `__init__.py` or any test; that is phase 2. Commit subject: `Pin and classify the upstream descriptor corpora.` |
| 1i | medium | sonnet | none | Add a "Test fixtures" section to `docs/development.md`. It covers the three fixture directories and what each holds; that `vendor/` files are trimmed by `tools/trim-ovf-descriptor.py` and never hand-edited; how to add an appliance (a `sources.json` entry in instar-testdata, run the fetch script, trim, check); and the descriptor corpus fetch script and its pins. Add one line to `AGENTS.md` under conventions: vendor descriptors are committed only as trimmed copies made by the tool, because this repository is public. Leave `ARCHITECTURE.md` and `README.md` alone: nothing here changes the shape of the importer or the pitch. Commit subject: `Document the OVF test fixtures.` |

The management session reviews each step. It runs `tox -epy3`,
`pre-commit run --all-files` and `python3 -c 'import
shakenfist_client_ova'`, then commits. After 1e it reads every vendor
fixture itself, not only the sub-agent's report, because a missed
string there is published.

## Risks and mitigations

1. **The trim tool misses something private or proprietary.** Survey
   finding 5 found a home directory path in a place decision 6 did not
   anticipate, so the list in decision 4 may not be the last word.
   Mitigations: 1e's grep and full read, the management session's
   second read, and the push audit's prose question. The fixtures are
   public from the moment the pull request is opened, not from merge,
   so the reads happen before the push.
2. **An upstream URL changes or disappears before 1b runs.** The pins
   are exact versions, so a missing file fails loudly. Talos's factory
   builds on demand and may change its bytes for the same schematic and
   version. If it does, 1b records the new hash and says so. The
   provenance file, not the URL, is the record.
3. **`instar` pulls the whole of `instar-testdata`'s LFS.** Its
   `tools/ci/prepare-testdata.sh` runs a bare `git lfs pull`, so this
   phase adds about 2.1GB to every cold instar runner cache, on top of
   9.2GB. instar reads none of it: its tests list files explicitly in
   `tests/manifest.json`, and `scripts/generate-baselines.py` only
   resparsifies image extensions, not `.ova`. 1c files an issue on
   shakenfist/instar proposing `git lfs pull --exclude
   downloaded/ova`, and this phase does not wait for it.
4. **The CyberOps exports' origin and terms are not recorded
   anywhere.** They are the operator's local copies of Cisco Networking
   Academy course appliances. See open question 1.
5. **The upstream corpora move under the pins.** They cannot: a commit
   hash is immutable. The risk is the reverse, a pin going stale, and
   the master plan accepts that (pins are bumped by hand).

## Open questions

1. **Where did the two CyberOps appliances come from, and on what
   terms?** The provenance records `local`, plus whatever the operator
   can say about where they were downloaded. Only their descriptor and
   manifest are kept, and only trimmed descriptors are published, so
   this does not block the phase. It is recorded so that nobody has to
   ask again.

The survey's three new questions for phase 3 (survey finding 4) are
recorded in the master plan as its open questions 4 to 6.

## Definition of done

* `instar-testdata` has 16 entries in `downloaded/ova/`: 6 whole
  (about 2.1GB) and 10 descriptor-only. Each has a provenance file
  whose manifest check passed, and whose vendor checksum matched or
  is recorded as unpublished. `git lfs ls-files` lists every `.ova`.
* A second run of `fetch-ova-corpus.py` changes nothing.
* The README table equals `fetch-ova-corpus.py --readme` output.
* `shakenfist_client_ova/tests/fixtures/ovf/vendor/` has 16 files,
  and `--check` passes for each against its original.
* `grep -rlE '/home/|C:\\\\|Copyright' shakenfist_client_ova/tests/fixtures/ovf/vendor/`
  finds nothing.
* `git ls-files shakenfist_client_ova/tests/fixtures/ova/` lists the
  five Glance files, and its `NOTICE` names each with its SHA-256.
* The hand-written directory has one file per case in the master
  plan's list, and each says which case it is.
* `tools/fetch-descriptor-corpus.sh` fetches both pins from an empty
  cache, and `classify-ovf-corpus.py --curate` reproduces `curated.txt`.
* `tox -epy3`, `pre-commit run --all-files` and
  `python3 -c 'import shakenfist_client_ova'` pass, and the wheel
  contains neither `tests` nor `corpus_tests`.
* The master plan's Execution table, its Merged cell for this phase
  (`instar-testdata <first>..<last>; <merge sha>`, filled in phase 2's
  first commit) and `docs/plans/index.md` agree.

## Back brief

Before executing any step, back brief the operator on how the work
aligns with this plan. Step 1b is the shape gate: it is the expensive
download, and once its output is pushed to `instar-testdata` it is
awkward to take back, so confirm 1a's test runs before starting it.
The other judgement call is 1e's read of the trimmed fixtures.

## Appendix: the curated descriptor list

Produced by `classify-ovf-corpus.py --curate 2` over govmomi at
`79bc9d75`, and `--curate 1` over COT at `0811b963`. The shape after
each path is why it was chosen.

| Path | Chosen for |
|------|------------|
| govmomi `disk-capacity-property.ovf` | product properties with a transport |
| govmomi `external/BitnamiTomcat/bitnami-tomcatstack-8.0.36-x86_64.ovf` | a real Bitnami appliance |
| govmomi `external/DeleteHDTestdata/PvScsis_old/descriptor.ovf` | unknown root namespace |
| govmomi `external/ImportOvf2014/empty_vsc.ovf` | an empty `VirtualSystemCollection` |
| govmomi `external/ImportOvf2014/eula.ovf` | `EulaSection` |
| govmomi `external/ImportOvf2014/properties_filtering.ovf` | deployment options |
| govmomi `external/ImportOvf2014/scaleoutStartup.ovf` | `StartupSection` |
| govmomi `external/ImportOvf2014/scaleoutVApp.ovf` | OVF 1.x mixed with 2.x |
| govmomi `external/ImportOvf2014/unknownsections.ovf` | unknown sections marked not required |
| govmomi `external/MultiVmVapps/MultiVmVapps.ovf` | a multi-VM vApp |
| govmomi `external/NonAsciiChars/chinese/虚拟机.ovf` | a non-ASCII file name |
| govmomi `external/OVFCerts/Valid Cert/Nostalgia.ovf` | a signed appliance's descriptor |
| govmomi `external/OVFToolTemplates/OVF/xmltestfiles/DeltaDiskCompression/Pos/nvapp-disks-0.ovf` | product properties |
| govmomi `external/OVFToolTemplates/OVF/xmltestfiles/DeltaDiskCompression/Pos/nvapp-disks-3.ovf` | several disks |
| govmomi `external/OVFToolTemplates/OVF/xmltestfiles/Envelope/Neg/invalid_empty_env.ovf` | OVF 0.9, an empty envelope |
| govmomi `external/OVFToolTemplates/OVF/xmltestfiles/Envelope/Pos/section_extensibility.ovf` | section extensibility |
| govmomi `external/OVFToolTemplates/OVF/xmltestfiles/Envelope_1_0/Neg/invalid_namespace.ovf` | an invalid namespace |
| govmomi `external/OVFToolTemplates/OVF/xmltestfiles/Envelope_1_0/Neg/invalid_version.ovf` | an invalid version |
| govmomi `external/OVFToolTemplates/OVF/xmltestfiles/Envelope_1_0/Neg/section_compatibility_neg.ovf` | not well-formed |
| govmomi `external/OVFToolTemplates/OVF/xmltestfiles/RASection_1_0/Neg/ras_sec_elsewhr.ovf` | `ResourceAllocationSection` misplaced |
| govmomi `external/OVFToolTemplates/OVF/xmltestfiles/VirtualAppliances/Pos/nvapp003.ovf` | deployment options |
| govmomi `external/OVFToolTemplates/ovftoolresources/identity_compression.ovf` | `ovf:compression` |
| govmomi `external/OvfWithSpaceInFileName/SpaceInVmdkName/haoUnOS2VMs.ovf` | a space in a file name |
| govmomi `external/PhotonOS/photon.ovf` | an older Photon OS export |
| govmomi `external/SignedOVF/dsl-with-cert.ovf` | a signed appliance |
| govmomi `external/VM_with_nvram/newVM-with-nvram.ovf` | an NVRAM file reference |
| govmomi `external/VappWithFlexibleNicAdapter/FlexibleNic.ovf` | vCloud extensions |
| govmomi `external/invalid_ovf/path1/testLonCharacterPathLimit/testDBpathLimitwwwwwwwwwwwwwww/descriptor.ovf` | not well-formed |
| govmomi `external/nostalgia-chunkdisk.ovf` | `ovf:chunkSize` |
| govmomi `external/nostalgia-read-only-disk.ovf` | several disks |
| govmomi `external/nostalgia_small/nostalgia.ovf` | vCloud extensions |
| govmomi `external/oldOvfs/sun-ovfEnv/sun-ovfEnv.ovf` | `InstallSection` |
| govmomi `external/ovftoolresources/identity_compression.ovf` | `ovf:compression` |
| govmomi `external/ovftoolresources/nvapp008.ovf` | `ResourceAllocationSection` |
| govmomi `external/ovftoolresources/nvm001.ovf` | OVF 0.9 |
| govmomi `external/standard_ovas/eula-vm/eula-vm.ovf` | `EulaSection` |
| govmomi `external/standard_ovas/eula/eula.ovf` | `VirtualSystemCollection` |
| govmomi `external/standard_ovas/nostalgia-chunkdisk/Nostalgia.ovf` | `ovf:chunkSize` |
| govmomi `external/sun-ovfEnv/sun-ovfEnv.ovf` | `InstallSection` |
| govmomi `external/trivial.ovf` | a plain OVF 1.0 descriptor |
| govmomi `external/vbs/vapp/extra-config-complete-vapp.ovf` | `StartupSection` |
| govmomi `property-types.ovf` | every property type |
| govmomi `qualifiers.ovf` | property qualifiers |
| govmomi `virtualsystemcollection.ovf` | OVF 2.x, `EthernetPortItem` and `StorageItem` |
| govmomi `vmware/esxvmovf-25262174.ovf` | a current ESX export |
| COT `ersatz_ovf_3.0.ovf` | an unknown future version |
| COT `invalid.ovf` | deployment options, invalid |
| COT `minimal.ovf` | the smallest valid descriptor |
| COT `ubuntu.2.0.ovf` | VirtualBox OVF 2.0 with `.xsd` namespaces |
| COT `v0.9.ovf` | OVF 0.9 |
| COT `vmware.ovf` | a VMware export |

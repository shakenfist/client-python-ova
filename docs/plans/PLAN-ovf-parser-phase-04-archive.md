# OVF parser phase 4: archive correctness

## Prompt

Before responding to questions or discussion points in this document,
read the master plan, [PLAN-ovf-parser.md](PLAN-ovf-parser.md),
particularly decisions 1, 5 and 8, open question 1, and phase 4's
section. Then read phase 3's plan,
[PLAN-ovf-parser-phase-03-elementtree.md](PLAN-ovf-parser-phase-03-elementtree.md),
for the parser this phase builds on, and its execution notes. The master
plan's decisions are not restated here, except where this phase's
survey changed or sharpened them.

Phase 3 made the descriptor trustworthy. The archive around it is still
read the way the first prototype read it: members are sorted by suffix,
the manifest's hashes are collected and never compared, and every
`.vmdk` member is uploaded whether or not the descriptor names it. This
phase makes the descriptor decide what is read, checks what is read
against the manifest, and refuses an archive it cannot account for. It
does not change the descriptor parser: `ovf/descriptor.py` and the
descriptor corpus ledger are untouched.

## Planning effort

High, by the master plan's rule: this phase changes what the importer
accepts and refuses. Review effort: high for decisions 2 to 8, which
set the refusals and their order. A wrong rule there either refuses a
real appliance or uploads a file the descriptor did not mean. Medium
for the rest.

## Scope

In:

* A new `ovf/package.py`, inside the spin-out boundary, that opens an
  OVA, checks its layout, verifies the descriptor against the manifest
  before parsing it, parses it, and resolves each `References/File` to
  exactly one regular archive member (decisions 1 to 6).
* The manifest parser held to the specification's grammar: known
  algorithms, digests of the right length, no repeated entries
  (decision 4).
* Eleven new `OVFError` subclasses, one per refusal (decision 7).
* The command rewritten around the package: disks found from
  `DiskSection` and `References`, every disk verified in one pass
  before any upload, one artifact per disk named after it, the no
  manifest warning and the `.cert` notice (decisions 8 to 10).
* Synthetic OVAs built by the tests, covering the archive shapes the
  master plan's phase 1 section lists, and Glance's five OVAs used as
  they are (decision 11).
* `docs/usage.md`, `ARCHITECTURE.md`, `docs/development.md` and one
  line of `AGENTS.md`, for the new checks and for what the manifest
  does not do.
* The live import that answers open question 1, as an operator step.

Out:

* Any change to the descriptor parser. The descriptor corpus ledger
  must not change in this phase.
* Supporting gzip-compressed or chunked file references, verifying a
  `.cert` signature, and verifying digests during the upload. All
  three are Future work in the master plan already.
* The appliance corpus tier, which runs this phase's checks over
  `instar-testdata` in CI. That is phase 5. This phase runs the same
  checks over a local checkout once, in the management session, and
  records the outcomes.
* Creating an instance from the uploaded disks.

## What the survey found

The survey ran on 2026-10-17. It covered:

* the code on `develop` at `b1f8894`;
* `shakenfist_client.util` and `apiclient` at client-python `ec7de87`;
* the server's artifact upload handler at shakenfist `ea39dff7c9`;
* DSP0243 1.1.0 and 2.1.1, from `specifications/`;
* the 16 appliances in a local `instar-testdata` checkout at
  `cf67642bbb`, and Glance's five committed OVAs;
* the upstream descriptor corpus at the pinned commits.

The survey scripts and their output are in the planning session's
scratchpad, not the repository. Findings 4, 6 and 8 change the master
plan, and the planning commit corrects them at source (see
"Corrections made to the master plan").

### 1. Phase 3 is complete

Phase 3 merged as `b1f8894`, and #11 closed with it. `tox -epy3` passes
304 tests, and `tox -edescriptor-corpus` passes on `develop`. Every
item in phase 3's Definition of done that the tree can check holds:

* no `xmltodict`, `dpath`, `UnsupportedDescriptorError` or
  `PIP_CONSTRAINT` remains;
* every ledger outcome is a bare name;
* 14 vendor models, plus Tails and Oracle Linux refused by name.

Phase 3's one deferred item, which is that the model does not link a
drive to its disk by id, was recorded only in its execution notes. The
close-out commit adds it to the master plan's Future work.

### 2. The command still reads the archive the prototype's way

`shakenfist_client_ova/__init__.py` (`ova_import`, from line 132):

* sorts members by suffix (`.ovf`, `.vmdk`, `.mf`) through
  `getnames()`, so a duplicated name is silently listed twice and
  `getmember()` later returns the last copy;
* reads every `.mf` member into one `element_hashes` dict that nothing
  reads back, a later entry replacing an earlier one;
* parses every `.ovf` member in turn, a later one replacing the
  earlier's envelope. The comment above that loop cites the master plan
  and goes when the loop does;
* uploads every `.vmdk` member, whether or not the descriptor names it,
  and nothing else. Oracle Linux's disk member has no extension, so it
  would not be uploaded at all, if its descriptor parsed;
* names every artifact after the virtual system's id;
* builds the source URL as `ova://{source}/{member}`, from the path as
  the user typed it;
* opens the archive with `tarfile.open(source)`, which also opens gzip,
  bzip2 and xz compressed tar files, and lets `tarfile.ReadError`
  escape as a traceback for anything else. Glance's
  `testserver-not-tar.ova` gets that traceback today.

The stray `print(hardware)` the master plan's phase 4 section mentions
is gone: phase 2 replaced it with `_hardware_summary()`. But the summary
is still printed after every disk inside the upload loop (line 245),
although "VM description:" has already printed it once.

`ovf/manifest.py` accepts any algorithm name and any digest text, keeps
a repeated entry, and keeps a carriage return as part of a digest. Its
module docstring cites the master plan for rules it does not yet follow.

### 3. The upload helpers are as the master plan describes

client-python's `checksum_with_progress_from_file_like_object()`
(`shakenfist_client/util.py:122`) computes SHA-512 only and then calls
`client.get_blob_by_sha512()`. `upload_artifact_with_progress_file_like_object()`
(line 143) creates an upload, sends it, seeks back to the last good
offset on a retried chunk, and only then calls `client.upload_artifact()`.
There is no point between the upload and the artifact's creation at
which the plugin could stop. Both claims in the master plan hold, so the
plugin computes its own digests and calls `get_blob_by_sha512()`
itself.

`apiclient.upload_artifact()` and `blob_artifact()` refuse a name
containing `/` with `InvalidException`, but `upload_artifact()` is only
called after the whole disk has been sent.

### 4. The server keys an artifact on its source URL, not its name

The upload handler (`shakenfist/external_api/artifact.py`, from line
584) looks the artifact up with `Artifact.owned_from_url()` on the
source URL, and only uses the name when it creates a new one. So two
disks with one name do not overwrite each other: they are two artifacts
that a person cannot tell apart. Naming each disk after itself is about
legibility, not data loss.

The source URL is the identity, though. `ova://<path as typed>/<member>`
makes `./appliance.ova` in two directories the same artifact, so
importing the second adds a version to the first. The plugin has never
been released (no tags, nothing on PyPI), so no existing artifact
depends on today's form, and decision 10 makes the path absolute.

### 5. Real archives are tidy

Over the 16 `instar-testdata` appliances and Glance's OVAs:

* every member is a regular file with a plain name. None has a `./`
  prefix, a directory entry, a link or a PAX header;
* every OVA opens as a plain tar;
* every manifest uses LF line endings, lower-case hex, and digests of
  the algorithm's length. Each has exactly one entry for the descriptor
  and one per `File`, and no other entries. SHA1 and SHA256 both occur;
* the descriptor's digest matches its manifest entry in all 13
  appliances that have a manifest;
* in the five whole appliances that have a manifest (ArchiveTeam
  Warrior, both Photon OS images, Talos and VyOS), every disk's digest
  matches, and so does `ovf:size` where it is given;
* VirtualBox puts the descriptor's manifest entry last, and the manifest
  after the disks. ovftool puts the manifest and `.cert` straight after
  the descriptor. DSP0243 allows both, in 1.1 (section 5.3, items 5 and
  6) as well as 2.x. The master plan's "Test data" said VirtualBox's
  order breaks 1.1's, which is wrong;
* Photon OS 3.0, Photon OS 5.0 and VyOS carry a `.cert`;
* Fedora CoreOS and Oracle Linux have no manifest;
* REMnux's only `File` is `ovf:compression="gzip"`, and it is a
  descriptor-only entry, so its disk member is absent.

The synthetic OVAs therefore carry most of the weight: `./` names,
duplicate members, links, directories, SHA512, repeated entries and
digest mismatches all come only from them.

### 6. Glance's "valid" OVA is refused by the parser, correctly

`testserver.ova` is refused with `UnparsedContentError`, naming
`Envelope/VirtualSystem/ResourceAllocationSection`. DSP0243 9.3 (1.1 and
2.1.1) makes `ResourceAllocationSection` valid only in a
`VirtualSystemCollection`, and govmomi's two `ras_sec_elsewhr` negative
tests, the only other descriptors with one outside a collection, are
refused the same way. The other four behave as their names say:

| OVA | Outcome today, at the descriptor | After this phase |
|-----|----------------------------------|------------------|
| `testserver.ova` | `UnparsedContentError` | unchanged |
| `testserver-bad-ovf.ova` | `MalformedDescriptorError` | unchanged |
| `testserver-no-disk.ova` | a model; its one disk member is absent | `MissingMemberError` |
| `testserver-no-ovf.ova` | nothing parsed, nothing uploaded, exit 0 | `PackageLayoutError` |
| `testserver-not-tar.ova` | `tarfile.ReadError` traceback | `NotAnArchiveError` |

So no Glance OVA reaches an upload, and the end-to-end tests that do are
synthetic, built from the hand-written fixtures.

### 7. What the descriptors say about references

From the upstream corpus:

* **Hrefs are written literally.** Two govmomi descriptors carry a `%`
  in an href, one of them `url%24encoded%a-1.vmdk`, which is not valid
  percent-encoding. ovftool writes the name as it is, so hrefs are
  compared with member names as text, never percent-decoded.
* **Subdirectories occur.** `disks/disk1.vmdk` and
  `data/ArchLinux-disk1.vmdk` are relative paths a tar can hold.
* **`..` occurs** in about 230 govmomi test templates, such as
  `../../../vmdk/valid_disk.vmdk`, which are directory-mode descriptors
  sharing disks. DSP0243 7.1 forbids it, and in an OVA it cannot name a
  member.
* **`http://` occurs** twice.
* **`ovf:compression="identity"`** occurs five times. DSP0243 7.1 says it
  means uncompressed, the same as omitting the attribute. The model
  keeps the value as written, so the package treats `identity` as no
  compression.
* **`ovf:parentRef`** occurs three times. A delta disk is meaningless
  without its parent chain, and Shaken Fist has no way to express one.
* **The largest descriptor** is 6.3 MB (govmomi's
  `UnOS2-large-descriptor.ovf`), and it parses.

The parser already refuses two `Disk`s naming one `File` and a
repeated `File@ovf:id` (phase 3). It does not refuse two `File`s with
one href, which DSP0243 7.1 forbids. Phase 3 classed govmomi's
`fileelements_samefile` as an archive matter for this phase, and the
committed `href-duplicate-member.ovf` is the same shape.

### 8. The specification adds three rules the master plan does not state

* DSP0243 1.1 5.1: "If no certificate file is present, the manifest file
  is also optional". A `.cert` signs the manifest, so a `.cert` without
  a manifest is a malformed package.
* DSP0243 7.1: the manifest and certificate "shall not be included in
  the References section". An href naming the descriptor, manifest or
  certificate is refused.
* DSP0243 7.1, on chunking: a chunked `File`'s href names no member, and
  its chunks are `<href>.000000000` onwards. Checking such an href for
  its member would report a missing member, which is the wrong reason.
  So the chunked refusal comes before the member check. The gzip
  refusal stays after it, as the master plan says, because REMnux is a
  descriptor-only entry whose missing-member error decision 8 asserts.

Master plan decision 8 also says every descriptor-only entry's archive
check fails with the missing-member error. Tails is a descriptor-only
entry, but its descriptor is refused at the envelope
(`UnsupportedEnvelopeError`), before any archive check runs. Phase 5
asserts that outcome for it instead.

## Decisions

1. **The archive code lives in `ovf/package.py`, inside the spin-out
   boundary.** Opening an OVA and matching it to its descriptor is OVF
   (DSP0243 clause 5), not Shaken Fist, so a spun-out parser should
   carry it. The module imports `tarfile`, `hashlib` and `posixpath`,
   which join `test_ovf_boundary.py`'s allow-list with a comment each.
   It never prints: what the command must say is returned as data.
   `open_package(path)` is a context manager yielding a `Package`
   dataclass that holds, at least:
   * the descriptor's, manifest's and certificate's member names, the
     last two optional;
   * the `Envelope` and the `Manifest`;
   * for each `File` id, its member name;
   * the uploads: one per `Disk` with an `ovf:fileRef`, in
     `DiskSection` order, each with its `Disk`, `File` and member;
   * the `Disk`s with no file, the `File`s no `Disk` names, the regular
     members nothing references (directories left out), and the
     manifest entries that name neither the descriptor nor a `File`.

   A `Package` method streams a member through `hashlib` for a list of
   algorithms in 1 MiB reads, calling an optional progress callback
   with each read's length. A short read, which a truncated archive
   gives, is a `NotAnArchiveError`, not a traceback. A second method
   opens a member for the upload, so the command never touches
   `tarfile`. `Package` is not serialised to JSON, and `model.py` is
   unchanged.

2. **Only a plain tar is opened.** The archive is opened with mode
   `'r:'`. DSP0243 5.3 says an OVA is a USTAR tar. Every OVA surveyed is
   plain. A compressed tar would also make each `extractfile()` seek,
   which the upload's retry does, decompress from the start. Any
   `tarfile.TarError`, `EOFError` or `OSError` while opening or
   listing is a `NotAnArchiveError`, whose message says an OVA must be
   an uncompressed tar.

3. **The layout is checked before anything is read.**
   * Each member's name loses one leading `./`.
   * Two members anywhere in the archive with the same name after that
     are refused. DSP0243 5.3 says entries "shall exist only once".
   * The top-level members, those whose name has no `/`, that end in
     `.ovf`, `.mf` and `.cert` are the descriptor, the manifest and the
     certificate. There must be exactly one descriptor, at most one
     manifest and at most one certificate, and a certificate needs a
     manifest (survey finding 8). Members in subdirectories with those
     suffixes are ordinary files, as DSP0243 5.1 allows.
   * The descriptor may be at most 16 MiB and the manifest at most
     1 MiB, so an untrusted member cannot exhaust memory before it is
     parsed. The corpus' largest descriptor is 6.3 MB.
   * Member order is not checked. DSP0243's order exists so that a
     consumer can stream the archive, which the importer does not do,
     and refusing a misordered archive would protect nothing.

   Each of these is a `PackageLayoutError`.

4. **The manifest follows the grammar, with one tolerance.** Each line
   is `ALGORITHM(name)= digest`, with the spacing today's expression
   accepts. The algorithm is `SHA1`, `SHA256` or `SHA512`, in any case.
   2.x allows only the first two, but ovftool writes SHA512 when asked,
   and refusing it would gain nothing. The digest is hex of the
   algorithm's length, in either case, and is compared without regard
   to case. A carriage return before a line's newline is tolerated,
   because nothing is ambiguous, and otherwise it would make the digest
   invalid. A repeated name is refused. Every failure is a
   `ManifestError`, as today, and `Manifest` still keeps every entry in
   order.

5. **The descriptor is verified before it is parsed.** When there is a
   manifest, it is read and parsed first, wherever it sits in the tar.
   It must have an entry for the descriptor's member name
   (`UnlistedFileError`), and that digest must match the descriptor's
   bytes (`DigestMismatchError`). Only then is the descriptor parsed.
   When there is no manifest, the package says so and the command warns
   (decision 9). A manifest whose base name differs from the
   descriptor's gets a warning, as the master plan says.

6. **References are resolved in a fixed order, after the parse.** Each
   step runs over every `File` before the next starts, so a refusal
   reports the first rule broken:
   1. **The href.** It is refused when it is empty, has a URL scheme
      (`^[A-Za-z][A-Za-z0-9+.-]*:`), starts with `/`, or has a `.` or
      `..` segment after one leading `./` is removed. It is also refused
      when two `File`s name one href, or when an href names the
      descriptor, manifest or certificate (survey findings 7 and 8).
      Each is a `FileReferenceError`. Hrefs are compared as text,
      never percent-decoded.
   2. **Chunking.** A `File` with `ovf:chunkSize` is a
      `ChunkedFileError` (survey finding 8).
   3. **The member.** Every `File`'s member must exist, whether or not
      a `Disk` uses it, because DSP0243 7.1 says "The referenced file
      shall exist". The fixed order is what lets master plan decision
      8's missing-member assertion hold. All missing members are
      reported in one `MissingMemberError`, in `References` order,
      which carries them as a `members` tuple for phase 5 to compare.
      A member that is not
      a regular file (`TarInfo.isfile()`) is a `MemberTypeError` naming
      its type: symbolic link, hard link, directory, device or FIFO.
      `extractfile()` would otherwise follow a link to another member,
      or return `None`.
   4. **The size.** An `ovf:size` that differs from the member's size is
      a `FileSizeError`, naming both. DSP0243 says the sizes "should"
      match. Every surveyed size does, and without a manifest it is the
      only sign that the member is not the file the descriptor
      describes.
   5. **Compression.** `ovf:compression` other than absent or `identity`
      is a `CompressedFileError`, naming the value.
   6. **Manifest coverage.** When there is a manifest, every `File`
      needs an entry (`UnlistedFileError`). Entries naming nothing the
      package references are returned for a warning, not refused: they
      protect nothing the import reads.
   7. **Delta disks.** A `Disk` with `ovf:parentRef` is a
      `DeltaDiskError`. Uploaded alone, a delta disk is an artifact
      that cannot boot.

7. **Eleven new errors, all `OVFError` subclasses in `ovf/errors.py`:**
   `NotAnArchiveError`, `PackageLayoutError`, `FileReferenceError`,
   `ChunkedFileError`, `MissingMemberError`, `MemberTypeError`,
   `FileSizeError`, `CompressedFileError`, `UnlistedFileError`,
   `DigestMismatchError` and `DeltaDiskError`. Each docstring says when
   it is raised. One class per refusal is what the expected outcomes,
   the RAISERS table in `tests/test_command.py` and the appliance corpus
   tier assert on, so merging two would hide which rule fired. Each
   message is one line, quotes member names and hrefs through the
   command's `_printable()`, and states the rule in the parser's own
   words.

8. **Every disk is verified before any is uploaded.** After the EULA
   check and the property warning, the command makes one pass over the
   uploads.
   * With a manifest, each disk is read once, computing its manifest
     algorithm's digest, and SHA-512 too when the server has
     `blob-search-by-hash`. A mismatch is a `DigestMismatchError`
     naming the member and both digests, and nothing has been uploaded.
   * Without a manifest, the pass reads only when the server has
     `blob-search-by-hash`, for SHA-512.

   Then a second pass uploads, looking each disk up with
   `client.get_blob_by_sha512()` where it has a SHA-512, and calling
   `client.blob_artifact()` or
   `util.upload_artifact_with_progress_file_like_object()` as today.
   `util.checksum_with_progress_from_file_like_object()` is no longer
   used. The pass shows progress with `tqdm`, as the upload helpers do,
   and `tqdm` becomes a declared dependency rather than an inherited one.
   The cost is the one the master plan accepts: one extra read of each
   disk when there is a manifest and no `blob-search-by-hash`.

9. **What the command says.** The member listing becomes a short
   archive summary:
   * which members are the descriptor, manifest and certificate;
   * each `File` and its member;
   * the files no disk uses, which are neither verified nor uploaded,
     such as an ISO;
   * the disks with no file, which are created empty at deployment and
     not uploaded;
   * the members nothing references, which are ignored.

   Three warnings are printed: no manifest ("the disks cannot be
   checked for corruption"), a manifest named differently from the
   descriptor, and manifest entries naming nothing. A `.cert` gets a
   notice that its signature was not checked. Nothing printed, in the
   code or in the documentation, calls the manifest check a security
   control. It detects corruption and accidental mismatch, and anyone
   who can change the descriptor can rewrite or remove the manifest.

10. **One artifact per disk, named after it, with an absolute source
    URL.**
    * The name is `<VirtualSystem ovf:id>-<Disk ovf:diskId>`. A name
      containing `/` stops the import with one line before anything is
      read, because the server only refuses it after the whole disk has
      been sent (survey finding 3).
    * The source URL is `ova://<absolute path of the OVA>/<member>`
      (survey finding 4).
    * The hardware summary leaves the upload loop.

11. **Tests build their own archives.** A helper in
    `shakenfist_client_ova/tests/` builds an OVA in a temporary directory
    from a list of members, each of them bytes, a symbolic link, a hard
    link, a directory or a FIFO, under any name including `./`
    prefixed ones. It can also write the archive gzip compressed.
    The package tests and the command tests both use it. The synthetic
    cases are:
    * from the master plan's phase 1 section: a manifest whose
      descriptor entry does not match; a manifest with no entry for a
      referenced file; no manifest; two manifests; a manifest listing
      one file twice; a SHA512 manifest; a manifest stored last after
      the disks; a `.cert`; hrefs naming a symbolic link, a hard link
      and a directory; and `./`-prefixed members, two of which strip to
      one name;
    * from this survey: a `.cert` without a manifest; two
      certificates; two descriptors; a disk whose digest does not
      match; an `ovf:size` that differs; a referenced ISO no disk uses;
      a disk with no file; a delta disk; a gzip-compressed tar; a
      truncated tar; `identity` compression; an href in a
      subdirectory; and two disks, as `vulnhub-blogger` has.

    The hand-written `href-*`, `gzip-reference` and `chunked-reference`
    descriptors, which phase 1 wrote for this phase, are wrapped into
    OVAs by the tests and refused with the errors decision 6 gives
    them. Glance's five OVAs are asserted as survey finding 6's table
    says. None of these is committed as a new binary.

## Step plan

| Step | Effort | Model | Isolation | Brief for sub-agent |
|------|--------|-------|-----------|---------------------|
| 4a | high | opus | none | Errors, the manifest parser and the test helper, to decisions 4, 7 and 11 of `docs/plans/PLAN-ovf-parser-phase-04-archive.md` (read it whole first, then `shakenfist_client_ova/ovf/` and `tests/test_ovf_manifest.py`). In `ovf/errors.py`, add the eleven classes decision 7 names, each with a docstring saying when it is raised; give `MissingMemberError` a `members` tuple attribute. Export them from `ovf/__init__.py`. Rewrite `ovf/manifest.py` to decision 4 and replace its module docstring, which cites the plan, with one describing the rules. Extend `tests/test_ovf_manifest.py`: SHA1, SHA256 and SHA512 in either case, an unknown algorithm, a digest of the wrong length or with a non-hex character, upper-case hex, a CR before LF, a repeated name, a missing final newline, and today's VirtualBox spacing (`SHA1 (name) = digest`). Add the archive builder of decision 11 as `shakenfist_client_ova/tests/synthetic.py`, with a docstring and a test of each member kind it builds. The new errors have no raiser yet, so `tests/test_command.py`'s `test_every_error_has_a_raiser` will fail. Add each new class to an `ARCHIVE_ERRORS` set the test excludes, with a comment that the package step fills it. Do not cite plan phases or decisions in code or comments; a consistency audit forbids it. Run `tox -epy3`, `pre-commit run --all-files` (stage new files first) and `~/src/shakenfist/development/scripts/audit-check.py --repo-path . --repo-name client-python-ova`. Unit tests suffice. Commit subject: `Check manifests against the specification.` |
| 4b | xhigh | opus | none | `ovf/package.py`, to decisions 1 to 7 of the phase 4 plan. Read the plan whole, then master plan decision 8, then everything in `ovf/`, `tests/synthetic.py` and `tests/test_ovf_boundary.py`. Implement `open_package(path)` and the `Package` dataclass as decision 1 describes, running decision 3's layout checks, decision 5's descriptor verification, `parse_descriptor()`, and decision 6's seven reference steps in that order, each over every `File` before the next. Wrap every `tarfile.TarError`, `EOFError` and `OSError` from opening, listing or reading in `NotAnArchiveError`, and check that a truncated member read raises it and not a traceback. Add `tarfile`, `hashlib` and `posixpath` to the boundary test's allow-list, each with a comment. Do not change `ovf/descriptor.py` or `ovf/model.py`. Add `tests/test_ovf_package.py`, building every synthetic case in decision 11 with `tests/synthetic.py` and asserting the exact error class, and for `MissingMemberError` its `members`. Wrap the hand-written `href-*`, `gzip-reference` and `chunked-reference` fixtures into OVAs and assert decision 6's errors. Assert Glance's five OVAs as survey finding 6's table says. Assert one passing package from `handwritten/two-controllers.ovf` with both disks and a SHA256 manifest, field by field. Mutation-check at least these, restoring from a copy each time, and list the result in your report: drop the `./` strip; drop the duplicate-member check; let a hard link through; skip the descriptor digest; move the gzip check before the member check; report only the first missing member. Do not cite plan phases or decisions in code. Run `tox -epy3`, `tox -edescriptor-corpus` (the ledger must not change), `pre-commit run --all-files` and the audit script. Unit tests suffice. Commit subject: `Check the archive against its descriptor.` |
| 4c | high | opus | none | The command, to decisions 8 to 10 of the phase 4 plan. Read the plan whole, then `shakenfist_client_ova/__init__.py`, `ovf/package.py` and `tests/test_command.py`. Rewrite `ova_import` around `ovf.open_package()`, deleting the suffix sorting, `element_hashes`, the descriptor loop and the comment citing the plan. Print the archive summary, warnings and notice of decision 9 through `_printable()`. Keep the EULA and property checks where they are. Then build each artifact name and stop on a `/` before reading anything, make decision 8's verification pass, and then the upload pass. Add `tqdm` to `pyproject.toml`'s dependencies with its licence comment, in the file's style. Move the hardware summary out of the upload loop. In `tests/test_command.py`, make `_import` add a member for every referenced file, since a missing one is now refused, and use `tests/synthetic.py` where it helps. Move every class from 4a's `ARCHIVE_ERRORS` into `RAISERS`, delete the set, and make `_message` raise archive errors through `open_package()`. Add `CliRunner` tests for: the no-manifest warning; the `.cert` notice; a manifest named differently; that nothing is uploaded, `get_blob_by_sha512` included, after a digest mismatch on the second of two disks; one read per disk with a manifest and `blob-search-by-hash`, checked by counting reads; the blob reuse path; artifact names and absolute source URLs for two disks; a `/` in a name refused before any read; and Glance's `testserver-not-tar.ova` printing one line with no traceback. Mutation-check the verify-before-upload order and the `/` check, restoring from a copy. Do not cite plan phases or decisions in code. Run `tox -epy3`, `pre-commit run --all-files`, `.tox/py3/bin/python -c 'import shakenfist_client_ova'` and the audit script. Unit tests suffice; no cluster. Commit subject: `Verify every disk before uploading any.` |
| 4d | medium | sonnet | none | Documentation for the archive checks. `docs/usage.md`: rewrite "What an import does today" for the package (the archive summary, manifest first, descriptor verified before it is parsed, disks from `DiskSection` and `References`, one verification pass, artifacts named `<system>-<disk>`, absolute source URLs). In "When an import stops", add the eleven archive refusals, each with its one-line cause, and say that a plain tar is required. Add a short section, "What the manifest does and does not do", saying that it detects corruption and accidental mismatch and not tampering, that the `.cert` is not checked, and that without a manifest nothing is verified. `ARCHITECTURE.md`: replace the "Import pipeline" table and "Disk upload" section with the package's stages and the two passes, and add `package.py` to "The OVF subpackage". `docs/development.md`: describe `tests/synthetic.py` under "Test fixtures". `AGENTS.md`: one line in Code Conventions saying the manifest check is never described as a security control, linking `docs/usage.md`. Read the code, not the plan, for anything the docs state. Never write a plan phase number in these files. Run `pre-commit run --all-files` and the audit script; `plan-phase-references`, `llm-doc-structure` and `readme-structure` must pass. Commit subject: `Document the archive and manifest checks.` |
| 4e | - | operator | - | Answer open question 1. Download the Ubuntu 24.04 cloud image OVA from the master plan's "Test data" table into a scratch directory, and check it against the SHA-256 in `instar-testdata`'s provenance file. Then run `sf-client ova import` on it against a live Shaken Fist cluster, create an instance from the artifact, and record in this plan's execution notes whether it boots. If it does not, conversion moves into the instance-creation plan, as open question 1 says. |

The management session reviews each step. After 4b, and again after 4c,
it runs `open_package()`, and after 4c the verification pass too, over
every OVA in a local `instar-testdata` checkout. It records only each
OVA's outcome in the execution notes, never descriptor text. The
expected outcomes are:

* the five whole appliances that parse pass, with every digest
  matching;
* Oracle Linux gives `UnsupportedProducerError` and Tails
  `UnsupportedEnvelopeError`;
* every other descriptor-only entry gives `MissingMemberError`, naming
  exactly the members its provenance listing has and the OVA lacks.

4a to 4d are sequential. 4e needs 4c's command and can run while 4d is
reviewed.

## Risks and mitigations

1. **The size rule refuses a real appliance.** DSP0243 says sizes
   "should" match, not "shall". Mitigation: every surveyed size matches,
   the message names both sizes, and phase 5 runs the rule over every
   appliance in CI. If a producer turns out to write wrong sizes, the
   rule becomes a warning for that producer through the quirk table,
   with evidence, rather than for everyone.
2. **A plain-tar requirement refuses compressed OVAs.** Mitigation: no
   surveyed producer writes one, DSP0243 says USTAR, and the message
   says what is needed. Supporting one would be a separate decision,
   because a compressed tar makes the upload's retry seek expensive.
3. **The verification pass doubles the read** without
   `blob-search-by-hash`. Accepted by the master plan. Future work
   records verifying during the upload.
4. **The command tests churn.** `_import` built archives with no disk
   members, which this phase refuses. Mitigation: 4c changes the
   harness once, and the RAISERS table keeps every error covered.
5. **A broad wrap of `tarfile` errors hides a bug** as
   `NotAnArchiveError`. Mitigation: the wrap is limited to the tar calls
   in `package.py`, never around the parser or the command, and each
   wrapped error is raised from the original, so `outcome_name()` shows
   the cause.
6. **The boundary widens.** `tarfile`, `hashlib` and `posixpath` join
   the allow-list. They are standard library, and the boundary test
   still refuses `click` and `shakenfist_client`.
7. **The live import cannot run in CI or in a sub-agent.** Mitigation:
   4e is an operator step, and the pull request says whether it has
   run. The phase's code does not depend on its answer.

## Definition of done

* `git diff b1f8894 -- shakenfist_client_ova/ovf/descriptor.py shakenfist_client_ova/ovf/model.py shakenfist_client_ova/corpus_tests/`
  prints nothing.
* `grep -nE "endswith\('\.(vmdk|ovf|mf)'\)|element_hashes|checksum_with_progress|docs/plans" shakenfist_client_ova/__init__.py shakenfist_client_ova/ovf/*.py`
  prints nothing.
* `test_every_error_has_a_raiser` passes with no exclusion set, so all
  23 `OVFError` subclasses have a raiser and a one-line, exit-1 test.
* A `CliRunner` test shows that a digest mismatch on the second disk
  uploads nothing, including no `get_blob_by_sha512` call.
* Every synthetic case in decision 11 has a test asserting its exact
  outcome, and Glance's five OVAs match survey finding 6's table.
* The management session's `instar-testdata` run matches the expected
  outcomes above, and its table is in the execution notes.
* `grep -rniE 'secur|tamper|authentic' docs/usage.md shakenfist_client_ova/__init__.py shakenfist_client_ova/ovf/`
  finds only text saying what the manifest does not protect against.
* `tox -epy3`, `tox -edescriptor-corpus`, `pre-commit run --all-files`
  and `.tox/py3/bin/python -c 'import shakenfist_client_ova'` pass,
  and the consistency audit reports no failure.
* The execution notes say whether 4e has run, and if so, whether the
  Ubuntu image booted.
* The master plan's Execution table and `docs/plans/index.md` agree,
  and this phase's Merged cell is left for phase 5's first commit.

## Corrections made to the master plan

Made in this phase's planning commit:

* **Phase 4's section:**
  * The stray `print(hardware)` line now describes the hardware
    summary printed in the upload loop (survey finding 2).
  * It gains the items the survey added: plain tar only, a `.cert` that
    needs a manifest, hrefs naming the manifest, `identity`, chunked
    files refused before the member check, the size check, delta disks
    and the absolute source URL.
  * It says that Glance's `testserver.ova` is refused by the parser,
    so the archive tests' passing cases are synthetic.
* **Decision 8** notes that Tails, being refused at the envelope,
  cannot reach the missing-member check, and that phase 5 asserts its
  envelope refusal instead.
* **"Test data"** no longer says VirtualBox's manifest-last order
  breaks OVF 1.1, which allows it (survey finding 5). Decision 8's
  synthetic OVA for that order stays, as a shape worth testing.

Made in this phase's close-out commit, for phase 3:

* **Future work** gains linking each drive to its disk by id, which
  phase 3 found and recorded only in its execution notes.

## Back brief

Before executing any step, back brief the operator on how the work
aligns with this plan. Two gates:

* **Decisions 3, 6 and 7 fix the refusals, their order and their
  names.** Step 4a does not start until the operator has reviewed
  them, because every test the later steps write pins them. The size
  rule (decision 6, step 4) and the delta-disk refusal especially, as
  the two that refuse something the specification does not forbid
  outright.
* **The `instar-testdata` run after 4b.** Any outcome that differs
  from the expected list stops the phase until it is explained.

## Execution notes

Phase 4 ran on 2026-10-17, after a back brief in which the operator
approved decisions 3, 6 and 7 as written. `tox -epy3` went from 304
tests to 474, and the descriptor corpus ledger did not change. Where it
departed from the text above:

* **`ovf/model.py` changed by one comment.** `Manifest.entries` said it
  kept "every line, duplicates included", which stopped being true when
  repeated names were refused. So the Definition of done's diff of
  `model.py` prints that one comment line, and nothing else.
* **OVF 1.1 is stricter about sizes than risk 1 says.** DSP0243 1.1
  section 7.1 says `ovf:size` "shall match" the file's size, and only
  2.x weakens it to "should". The size refusal therefore follows 1.1
  exactly.
* **A truncated archive is refused when it is listed.** tarfile seeks
  past each member's data as it lists the archive, so a short archive
  fails in `getmembers()`, before any member is read. A short read
  while hashing can happen only if the file changes after it is
  opened. The tests cover both, the second by shrinking the file after
  opening it.
* **Decisions the steps took that the plan left open:**
  * A descriptor, manifest or certificate that is not a regular file
    is a `PackageLayoutError`, because it is a layout check made before
    anything is read. `MemberTypeError` is kept for `File`s.
  * Manifest entry names are not stripped of `./`. An entry must name
    the member as normalised, and no surveyed manifest uses `./`.
  * Digests are kept as written in the model and compared without
    regard to case.
  * `unreferenced_members` lists every member nothing references
    except directories, including links and devices, so that the
    summary shows everything ignored.
  * `Package` gained `member_size()`, and `open_member()` returns a
    wrapper that turns a tar or OS error during the upload's reads and
    seeks into `NotAnArchiveError`. Without it, an OVA changing during
    the import would have escaped as a traceback from the upload
    helper.
  * `_printable()` escapes a lone surrogate, which a member name that
    is not UTF-8 holds, instead of failing to print it.
  * A blob is looked up only when the server has
    `blob-search-by-hash`, even when a SHA512 manifest already gives the
    digest.
  * The source URL is `ova://` followed by the absolute path, so it has
    three slashes, such as `ova:///home/me/appliance.ova/disk1.vmdk`.
* **Mutation checks.** Step 4b ran 40 mutations of `package.py`, and
  step 4c ran 8 of the command and the member wrapper, including
  checking each disk just before its upload rather than all of them
  first. The tests caught every one.
* **`instar-testdata`, at `cf67642bbb`.** Run after 4b with
  `open_package()` and the digest checks, and after 4c with the command
  itself and the client mocked. Every outcome matched:

  | Appliance | Kind | Outcome |
  |-----------|------|---------|
  | `archiveteam-warrior-4.1` | whole | verified (SHA256) and imported |
  | `photon-3.0-hw11` | whole | verified (SHA1) and imported, `.cert` notice |
  | `photon-5.0-aarch64-uefi-hw14` | whole | verified (SHA256) and imported, `.cert` notice |
  | `talos-1.14.3` | whole | verified (SHA256) and imported |
  | `vyos-1.2.1` | whole | verified (SHA1) and imported, `.cert` notice |
  | `oracle-linux-9.8-olvm` | whole | `UnsupportedProducerError` |
  | `tails-202607` | descriptor-only | `UnsupportedEnvelopeError` |
  | the other nine | descriptor-only | `MissingMemberError`, naming exactly the provenance file's absent members |

* **Step 4e ran after the merge, and the image boots.** It ran on
  2026-10-17, against `develop` at a8f44bf, so it is recorded here by
  phase 5's close-out.
  * The Ubuntu 24.04 cloud image OVA (release-20260926, 594,800,640
    bytes) matched the vendor SHA-256 recorded in `instar-testdata`
    (`513a22eb...`).
  * `sf-client ova import` verified the VMDK against the manifest and
    uploaded it as `ubuntu-noble-24.04-cloudimg-20260926-vmdisk1`.
  * The server recorded the blob as a streamOptimized VMDK, with the
    SHA-256 the provenance file gives for the member (`58001251...`).
  * An instance with that blob as its base (2 vCPUs, 2 GiB, no network)
    booted to a login prompt. cloud-init finished from Shaken Fist's
    config drive, which also set the hostname.

  Open question 1 is answered: Shaken Fist transcodes the
  streamOptimized VMDK itself, and the importer needs no conversion.
* **A disk base names an artifact by its URL, not its bare UUID.** A
  bare UUID was taken as an internet URL, and the fetch failed with
  `MissingSchema`. `sf://artifact/<uuid>` and `sf://blob/<uuid>` work.
  The artifact's `ova://` source URL also booted, but only through the
  server's cached-version fallback, which logged "updating image
  failed, using already cached version". Phase 5 replaces that scheme
  with the server's own `sf://upload/` default. Refusing an unfetchable
  base at create time is shakenfist/shakenfist#4557.

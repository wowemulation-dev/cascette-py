# cascette-py vs. Verified Agent Install Workflow — Differences

Comparison of cascette-py's `install_to_casc` / `install_containerless` /
`update` against the verified workflow in `docs/combined-install-workflow.md`
(grounded in the battle.net-agent reimplementation and the management RE
docs). Each item lists the divergence and the fix required.

## A. Structural / orchestration differences

### A1. No operation/state-machine layer

**Original**: `StartUpdateRequest` → `InstallOperation` (target state
`kInstalled`=4) → `AsyncInstanceInitializeState` (15 stages) →
`AsyncBuildUpdateState` (fetch → patch → finalize). Every step is an
async state with explicit terminal/error semantics, driven by
`TactPipeline` (setup → step until terminal).

**cascette-py**: linear Click command (`install_to_casc`) with numbered
steps; no operation registry, no product-state transitions, no
`kInProgress`/`kInstalled` tracking. Errors are exceptions, not
state-machine results.

**Fix**: introduce an install state machine mirroring the agent's stages;
at minimum, make the 15 instance-init stages explicit so the containerless
decision point (stage 4, ConfigInit) and CDN-index ordering (stages 8-11)
are structurally guaranteed. Full fidelity requires an operation layer.

### A2. No unified mode dispatch on `build-file-db` — RESOLVED (2026-08-15)

**Original**: the build config's `build-file-db` key is the single
discriminator; the agent (once wired) dispatches to the container or
containerless pipeline from that.

**Fix (landed, refined)**: the dispatch is now **automatic in all entry
points** — the mode is decided by the build config, not by which command
is invoked:

- `install-to-casc`: after parsing the build config, routes to
  `install_containerless` via `ctx.invoke` when `build-file-db` is
  present; otherwise stays in container mode.
- `install-containerless`: routes to `install_to_casc` when `build-file-db`
  is absent (previously hard-errored).
- `install-product`: the explicit unified entry; delegates to
  `install_to_casc`, which auto-routes.

Verified: running any of the three commands against 1.13.2.31650 selects
container mode and runs the full pipeline including Step 5.5 patch fetch
(3 configs, 739 indices = 606 data + 133 patch).

Note: `ctx.invoke` is required — the Click command functions cannot be
called as plain functions (Click wraps them with parameter injection).

### A3. Update path hardcodes container mode

**Original**: `update` can run either mode based on the new build config.

**cascette-py**: `update` (line 2410) is CASC-only — it loads old ecache,
compares encodings, patches/downloads into `LocalStorage`. There is a
separate `update_containerless`, but the container `update` never checks
whether the *new* build config switched modes (container → containerless
or vice versa). Mode switches are unsupported.

**Fix**: `update` must read the new build config's `build-file-db` and
route to the corresponding update pipeline; handle cross-mode migration.

### A4. No BGDL (background download) support

**Original**: `async_containerless_bgdl_state` for background download
without a base build; `UpdateFlags::kBGDL` (bit 9) implies `kApplyPatch`
(bit 2), and `kDisablePatchApplication` (bit 3) is deprecated → converted
to BGDL.

**cascette-py**: no BGDL concept anywhere. Flags are absent.

**Fix**: add the flags and the BGDL state machine for containerless
installs; honor the flag implications in `BuildUpdateInstance::validate_flags`.

## B. Container-mode (install_to_casc) differences

### B1. Patch config + patch indices never fetched on fresh install — RESOLVED (2026-08-15)

**Original**: the client fetches the patch config (`patch-config` key,
e.g. `f93f08d2...`) and the patch archive indices into `Data/config/` +
`Data/indices/` (741 indices vs cascette-py's 606).

**Fix (landed)**: `install_to_casc` Step 5.5 now calls
`_fetch_patch_config_and_indices()` which fetches the patch config to
`Data/config/` and all patch-related `.index` files to `Data/indices/`:

- 131 patch-archive indices (CDN config `patch-archives`)
- `file-index` — fetched from the DATA content type (`/data/...`)
- `patch-file-index` — fetched from the PATCH content type (`/patch/...`)
- `archive-group` and `patch-archive-group` — NOT CDN files: locally
  generated mega-indices. cascette-py now generates them via
  `generate_group_index` / `build_merged_archive_group` in
  `formats/cdn_archive.py` (mirrors cascette-rs `archive_group::build_merged`;
  verified byte-identical against the client-built 31650 store).

Verified: helper saves 133 indices (131 + file-index + patch-file-index)
with byte-exact sizes matching the client-built store (119,508 and 53,588
bytes), plus generates the two archive-group files. The group hashes always
404 on the CDN and every mirror — that is expected (locally generated), not
a mirror gap. See `build-iteration-runbook.md` §Missing files.

### B2. No check for `CASCRepair.mrk` / repair-marker state

**Original**: `tact::clienthandler::Create` checks `data/CASCRepair.mrk`
first; presence returns `TACT_REPAIR_REQUIRED` (0x1c) and blocks startup.
The client (1.13.2) writes the marker itself on damage detection
(contradicts an earlier RE claim; observed 2026-08-14).

**cascette-py**: never checks or handles the marker.

**Fix**: before install/update, check `Data/data/CASCRepair.mrk`; if
present, either run repair or refuse, matching the client's semantics.

### B3. `LocalStorage.write_content` store is rejected by the client — RESOLVED (2026-08-15)

**Original**: client-built store validates: 130,303 entries, 0 checksum
failures, 0 key mismatches, 0 gaps, 64 reconstruction headers, ratio
1.0000 (verified with cascette-rs `dump_cas_container`).

**Root cause (byte-diff)**: cascette-py wrote the 480-byte segment header
(16 reconstruction headers) into `data.000` but never indexed those
headers in the KMT. The client indexes all 64 reconstruction entries
(4 segments x 16 buckets) in the `.idx` files: key = generated segment
key, archive_id = segment, archive_offset = bucket*30, size = 30, stored
in the **seed-1 bucket** idx file (`compute_bucket(key, seed=1)`).
checksum_b was a red herring — it is correct in both stores, just at
different offsets (the client writes patch-manifest → encoding → root
first; cascette-py writes in download-manifest order).

**Fix (landed)**: `LocalStorage.write_content` now, when creating a new
data file, iterates the 16 segment-header `LocalHeader`s and adds each as
a `LocalIndexEntry` to `bucket_entries[compute_bucket(recon_key, seed=1)]`.
Implementation gotcha: the loop variable must not be named `bucket` — it
clobbers `write_content`'s bucket variable, sending real entries to
bucket 0x0f (breaks dedup). Renamed to `recon_slot`.

**Verified**: fresh full install (131,456 files, 0 failures) now has 64
reconstruction entries in correct buckets. Full rerun with first client
start: no `CASCRepair.mrk`, `Client Initialize`, login screen, 1 CDN
request (the patch manifest `68a64c98`), store untouched (16 gen-1 idx,
no re-index). Warm restart: login screen, **0 CDN requests**, store
untouched. Run-2 client later exited after an extended period
(`dispatch_exception assertion` storm + "configure double buffering" D3D
hint in WINE) — treated as a WINE/D3D display issue, not a store
rejection.

**Remaining non-blocking divergences** (do NOT trigger rejection):

- Patch data: the client writes the patch manifest (`68a64c98`) and 6
  ZBSDIFF blobs during bootstrap; cascette-py downloads full files
  instead. Byte-exact replication requires patch application on install.
- 1,227 extra KMT entries: cascette-py indexes install/download manifests
  and tag-excluded files that the client does not index. Byte-exact
  replication requires excluding those.

### B4. shmem written with wrong version/path/size (fixed to not write)

**Original**: client writes `Data/data/shmem`, v4, size 0x2C10, path
`Global\../Data/data` (relative), data_size 0x150, generations at 0x110.
cascette-rs reads v4 correctly but writes no path.

**cascette-py**: `LocalStorage.initialize` no longer creates
`Data/shmem`/`Data/ecache` and `flush_indices` no longer writes shmem
(fixed 2026-08-15, see `installation-verification.md` §9). Previously it
wrote v5, absolute path, wrong data_size — a client-rejection trigger.

**Fix**: keep not-writing (client recreates). If shmem writing is ever
needed, implement the exact v4 layout; document in §9.

### B5. ecache relocated out of the client install (fixed)

**Original**: `Data/ecache/` is client-managed; the client ignores a
foreign ecache.

**cascette-py**: ecache now lives in
`~/.local/share/cascette-tools/ecache/<install-hash>/` (fixed 2026-08-15).

**Fix**: none — correct as-is.

### B8. Encoding file not written to store on the ecache path — RESOLVED (2026-08-15)

**Original**: when an ecache existed, `install_to_casc` Step 2 skipped the
encoding file download entirely — including `storage.write_content()`. The
encoding file never landed in the CASC store, so cascette-rs C3
(`read_file_by_encoding_key`) failed and the client would re-fetch the
encoding from CDN. Caught on the second 1.13.2.31687 install (the first
install had no ecache, so the bug was latent).

**Fix (landed)**: Step 2 now always fetches the encoding file and writes it
into the store; the ecache is used only as a CKey→EKey lookup accelerator
(skipping `_populate_ecache` when it already has entries). Verified on
1.13.2.31687: encoding file present in the KMT, cascette-rs C3 passes,
client makes 0 CDN requests on cold start.

### B9. AsyncClient reused across asyncio.run loops — RESOLVED (2026-08-15)

**Original**: `install_to_casc` runs Step 5 (archive index download) and
Step 7 (file download) in separate `asyncio.run()` calls. The httpx
AsyncClient is a lazy singleton on `CDNClient`, so the client created in
Step 5's loop was reused inside Step 7's loop. httpx AsyncClients are bound
to the event loop they were created in; reuse in a second loop raises
`RuntimeError('Event loop is closed')` (and `asyncio.TimeoutError` with an
empty message on retries). Caught on 1.13.2.31830: 18 range-request
failures (54 warnings = 18 keys x 3 retries), each falling back to the
loose path which 404s because those files live only inside archives.

**Fix (landed, 2 parts)**: (1) `CDNClient.async_client` now tracks the loop
it was created in and rebuilds the client when a different running loop is
detected. Verified on 1.13.2.31830 fresh install: 131,456 files, 0 failed,
0 integrity errors (previously 18 failed). (2) A residual 1-file failure on
1.13.2.31882 revealed a second issue: a stalled keep-alive connection in
the httpx pool could poison all retries (the range server answered 206 but
the client timed out reading, on every retry). `CDNClient.reset_async_client`
drops the pool; `CdnArchiveFetcher` calls it on any range-request exception
so retries open fresh connections. Verified on 1.13.2.31882 fresh install:
131,456 files, 0 failed, 0 warnings.

**Gotcha**: resuming an interrupted install after this fix is not
recommended if the prior run wrote data files — the resume path rewrote
data.000/data.002 to ~21 MB/3.3 MB in testing (segment state restored
incorrectly), so a fresh install is the reliable path.

### B10. Step 5.5 skipped on builds without a patch-config key — RESOLVED (2026-08-16)

**Original**: `_fetch_patch_config_and_indices` returned early when the
build config had no `patch-config` key. Some 1.13.3 builds (e.g.
1.13.3.33155) omit `patch-config`/`patch`/`patch-size` entirely, but their
CDN config still lists `patch_archives`, `file_index`, `patch_file_index`,
`archive_group`, and `patch_archive_group` — all of which the client
fetches on first start. The early return skipped the entire step, so the
client re-fetched 36 index files from the CDN during the first run
(observed on 1.13.3.33155).

**Fix (landed)**: Step 5.5 now always runs the CDN-config-driven parts
(patch archive indices, file-index, patch-file-index, locally-generated
archive-groups). The patch config fetch and the patch-manifest write run
only when the build config carries the corresponding keys. Verified on
1.13.3.33155: install saves 40 patch-related indices (36 patch archives +
file-index + patch-file-index + 2 groups); the client's first run makes
**0 index requests** (previously 36).

### B6. No 3-phase fetch/patch/finalize structure

**Original**: `AsyncBuildUpdateState` = `fetch_files → apply_patches →
finalize`; finalize = make-resident, verify, cleanup.

**cascette-py**: single `_download_casc_files` loop writes content
directly; patching only exists in `update`; no explicit residency/verify
phase in `install`.

**Fix**: separate download, patch, and finalize phases; add residency
marking and post-install verification as an explicit finalize step.

### B7. Priority filter instead of tag-query semantics

**Original**: tag query built from target tags combined into a bitmask
(`FUN_006bb843`); selection via `is_file_selected`. Containerless uses
`base_tag_query`/`target_tag_query` with fallback.

**cascette-py**: `install_to_casc` uses the download-manifest `priority`
integer (default 255) plus platform/arch/locale tag filter; no
base/target tag-query pair.

**Fix**: support base + target tag queries per the agent's
`UpdateInstanceConfig` (`target_tag_query`, `base_tag_query`), falling
back to target when base is empty; keep priority as an additional
filter if desired.

## C. Containerless-mode (install_containerless) differences

### C1. File DB decryption unsupported (0x45 Salsa20)

**Original**: `tact::FileDb::Decode` decrypts the blob: magic `0x45`,
8-byte key ID (key getter callback), IV (≤ 8 bytes), algorithm byte
`0x53` (Salsa20), then the payload. Error codes 4/8/13.

**cascette-py**: `FileDatabaseParser` detects `0x45` and raises
"decryption not yet supported". Salsa20 exists in `cascette_tools/crypto`
for BLTE 'E' chunks but is not wired to file DB decoding.

**Fix**: implement `FileDb::Decode` using the TACT key getter + Salsa20;
handle IV/counter semantics (`XorIvWithCounter`).

### C2. No hard-link limitation handling

**Original**: "Hard links are not currently supported for containerless
builds. Falling back to residency container." Containerless never uses
hard links.

**cascette-py**: `ContainerlessStorage` always copies (no hard links) —
safe, but the RE behavior (explicit fallback message, residency
container) is not modeled.

**Fix**: document/encode the no-hard-links rule; optionally model the
residency-container fallback.

### C3. No sparse-file handling

**Original**: Windows sparse file attributes for not-yet-downloaded
regions; cleared on update; set on new files; cleared before delete on
repair failure.

**cascette-py**: no sparse-file logic anywhere.

**Fix**: add sparse-flag set/clear on Windows for containerless writes;
portable no-op elsewhere.

### C4. No E-header fetch phase

**Original**: `async_containerless_headers_fetch_state` fetches E-headers
for all files in the update set (batch download, skip status-2/fetched).

**cascette-py**: `_download_containerless_files` fetches full content per
file directly; no separate header pass.

**Fix**: add the headers-fetch phase before file updates (needed for the
block mover and for patch-aware updates).

### C5. No block mover / block-level updates

**Original**: `ContainerlessBlockMover::Initialize` (needs target + base
headers) + `async_containerless_block_extract_state` decode blocks and
write through `ResidencyContainer` (reserve → open → async write);
duplicate files copied on disk with residency tracking.

**cascette-py**: whole-file download + `ContainerlessStorage.write_content`
(copy). No base/target delta, no block-level precision.

**Fix**: implement the block mover for updates (base+target headers);
for fresh installs whole-file download is acceptable.

### C6. File DB stored on disk as `.cascette/file_db.sqlite`

**Original**: file DB loaded entirely into memory
(`sqlite3_open(":memory:")` + `sqlite3_deserialize`); not persisted in
the install (agent keeps it only in memory; preservation uses the CDN
blob).

**cascette-py**: persists the raw blob to
`{install_path}/.cascette/file_db.sqlite` (a cascette-py-only artifact,
plus `install_containerless` Step 10 writes product state files).

**Fix**: keep in-memory only (matching the agent); move any persistence
need to cascette-py's own data dir (like the ecache relocation in B5).

### C7. `.cascette/` directory pollutes the install

Related to C6: the agent produces no `.cascette/` directory. The client
does not expect it.

**Fix**: stop writing `.cascette/` under the install path.

## D. Update-specific differences

### D1. Delta via ecache comparison vs. manifest-driven

**Original**: `ContainerlessBuildUpdateInitState::Execute` reads target +
base file DBs, verifies file sizes (unless `checksizeonly`), builds the
update list from the file DBs, sorts, prepares block moves; zero-size
entries created as empty files.

**cascette-py**: `classify_files` diffs old/new encoding tables via the
ecache. Container and containerless updates are separate commands.

**Fix**: for containerless updates, drive from the file DBs (target vs.
base) per the RE init state; honor `containerless_checksizeonly` /
`containerless_checksizeonly_on_init` flags.

### D2. Obsolete handling: residency vs. delete

**Original**: `AsyncBuildPreserveState` / `ContainerlessBuildPreserveState`
(6-state machine: preservation set, file scan, header collect, file DB
query, DLM query) preserves files during GC; stale residency cleared;
sparse flags cleared.

**cascette-py**: `update` Step 10 marks obsolete entries non-resident in
the KMT; `update_containerless` optionally deletes obsolete paths
(`--delete-obsolete`). No preservation-set semantics, no GC pass.

**Fix**: add preservation-set computation (DLM + file DB) and a GC pass
matching the agent's preserve state machine.

## E. State files (both modes)

### E1. `.cascette/` + agent state files

**Original**: no `.cascette/`; state files are `.build.info`,
`.patch.result`, `.product.db`, `Launcher.db`, `_classic_/.flavor.info`.

**cascette-py**: `install_to_casc` writes all the expected state files
(verified: `.build.info` matches the reference, `.product.db` 384 bytes
vs. the 407-byte reference target, `Launcher.db` 4 bytes vs. a real
launcher DB). `install_containerless` writes `.build.info` +
`.product.db` + `Launcher.db` + `.cascette/file_db.sqlite`.

**Fix**: verify `.product.db` (384 vs 407 bytes) and `Launcher.db`
against the reference; drop `.cascette/`.

## F. What is already aligned (verified)

- `install_to_casc` tag filtering: platform/arch/locale bitmask via
  `apply_tag_query` / `is_file_selected` matches `FUN_006bb843`.
- IDX v7 layout, local headers, segment headers, checksums — verified
  byte-identical against the client store by cascette-rs.
- `.build.info` 14-column PSV with correct CDN hosts for the local mirror
  (`CASCETTE_RIBBIT_BASE_URL` fix).
- shmem/ecache non-pollution (2026-08-15 fixes).
- File DB SQLite schema understanding (`meta`/`tags`/`files`) matches RE.

## Priority order for alignment

1. ~~**B1** patch config/indices in `install_to_casc`~~ — **DONE (2026-08-15)**
2. ~~**A2** unified `build-file-db` dispatch~~ — **DONE (2026-08-15)**
3. ~~**B3** client acceptance of the non-polluting store~~ — **DONE (2026-08-15)**
   (root cause: missing KMT reconstruction-header entries)
4. **B6-patch: PARTIAL (2026-08-15)** — patch manifest now written into the
   store during install (build config `patch` key, raw `PA` file keyed by
   content key). Verified on 1.13.2.31687: cold start makes **0 CDN
   requests** (previously 1). Remaining: writing the 6 ZBSDIFF patch blobs
   (the client does not request them for login acceptance; byte-exact
   replication requires patch application on install).
5. **C1** file DB decryption (blocks real containerless installs)
6. **B6** fetch/patch/finalize phases + verification finalize
7. **B2** repair-marker check
8. **D1/D2** manifest-driven updates, preservation set, GC
9. **A1/A3/A4** operation layer, mode-switch updates, BGDL

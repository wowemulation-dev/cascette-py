# Combined Containerless + Container Install Workflow

Exact step-by-step install workflow for a WoW-family product that can be
either a CASC container product or a containerless product, grounded in:

- **RE docs**: management repo `src/reverse-engineering/battle.net/agent/2.39.3/9370/tact/containerless-mode.md`
  and `.../wow-classic/1.13.2/31650/tact/cas-initialization.md`
- **Agent reimplementation**: `~/Repos/git.sr.ht/danielsreichenbach/battle.net-agent/`
  (`install_manager.cpp`, `async_instance_initialize_state.cpp`,
  `tact/containerless/*`, `tact/async_state/*`)
- **cascette-py**: `install_to_casc`, `install_containerless`

## 0. Mode Selection — the single discriminator

The product's **build config** decides the storage backend. If the build
config contains the `build-file-db` key, the install runs in
**containerless mode**; otherwise it runs in **container mode** (CASC).

```text
build config parsed:
  has "build-file-db"  → containerless mode
  else                → container mode (CASC archives)
```

Verified: 1.13.2.31650 has no `build-file-db` (container mode). The agent's
`config_reader.cpp` parses `build-file-db` + `build-file-db-size` into
`Config.build_file_db`; cascette-py's `BuildConfig.get_file_db_info()` reads
the same key. Containerless also checks the following flags (RE
containerless-mode.md §Configuration): `containerless_do_clean_up`,
`containerless_do_real_cancel`, `containerless_checksizeonly`,
`containerless_checksizeonly_on_init`.

## 1. Entry: StartUpdateRequest → InstallOperation

Agent (`install_manager.cpp:203` `on_start_update`):

1. Receive `StartUpdateRequest` (msg type 55), carrying product UID,
   version, channel.
2. Validate product exists in the product registry (`FUN_0047ba3e`,
   error 0x975 if missing).
3. Reject if a duplicate/conflicting operation is active for the UID
   (error 0x96A).
4. Create a `FetchRequest` (0x88 bytes), mark active, arm a 60 s timer
   (`kUpdateTimeoutMs`).
5. Enqueue the operation. `InstallOperation` (type 1) targets product
   state `kInstalled` (4); `UpdateOperation` (type 2) targets `kInProgress`
   (5). Dispatch transitions the product registry to the target state.

## 2. Resolve versions and CDN endpoints (VersionFetcher)

1. Fetch the Ribbit `versions` BPSV for the product + region.
2. Extract `build_config_key`, `cdn_config_key`, `versions_name` for the
   region row.
3. Fetch the `cdns` BPSV; resolve CDN hosts for the region
   (`cdn_host`, `cdn_path` e.g. `tpr/wow`).
4. Populate `TactContext`: product, region, cdn_host, cdn_path,
   build_config_key, encoding_key (from build config), first_archive_key
   (from CDN config), root_key, install_key, install_size.

## 3. Instance initialization — 15-stage state machine

`AsyncInstanceInitializeState` (`async_instance_initialize_state.cpp`),
driven by `TactPipeline` (setup → step until terminal). Stages:

| Stage | Work | Containerless note |
|-------|------|--------------------|
| 3  | `DownloadQueueInit` — queue init | same |
| 4  | `ConfigInit` — fetch+parse build config via `AsyncConfigInitializeState` | **discriminator read here** |
| 5  | `ConfigComplete` — pass-through | — |
| 6  | `ContainerInit` — create dynamic/static container, CDN key resolver, DNS resolver | containerless skips CASC container creation |
| 7  | `ContainerCollect` — `CollectForArtifacts`, compare artifact hashes | — |
| 8  | `CdnIndexInit` — `AsyncCdnIndexInitializeState` (encoding type: static=2, else patch?1:0) | containerless instead reads file DB |
| 9  | `CdnIndexRead` — pass-through | — |
| 10 | `CdnIndexGroupRead` — archive index groups | — |
| 11 | `CdnIndexGroupDone` — pass-through | — |
| 12 | `ManifestInit` — size manifest / file manifest cache, root manifest parse | containerless: `async_file_db_read_state` reads SQLite file DB |
| 13 | `ManifestDone` — pass-through | — |
| 14 | `CdnFinalize` — patch manifest init | — |
| 15 | `Done` — terminal | — |

On failure at any stage: `kFailed` (255) with the specific
`k*Failed` result; the agent logs the stage and returns.

## 4. Branch: container mode (CASC archives)

Driven by `AsyncBuildUpdateState` (type 0x0b, `async_build_update_state.cpp`),
master orchestrator: **fetch_files → apply_patches → finalize**.

1. **Config init** — build + CDN configs written to `Data/config/`
   (`{hash[0:2]}/{hash[2:4]}/{hash}`).
2. **Encoding table** — `AsyncETableInitState` downloads the encoding
   file, builds the CKey→EKey table.
3. **CDN indices** — `AsyncCdnIndexReadState` + `AsyncCdnIndexGroupReadState`
   download archive indices into `Data/indices/`.
4. **Manifests** — install manifest (loose files), download manifest
   (archive content), size manifest, root manifest.
5. **Tag filter** — combine target tags into a bitmask
   (`FUN_006bb843`); select install/download entries.
6. **Download** — `AsyncBatchDownloadContainerState` fetches archive
   blocks; `AsyncFileDownloadState` per file; write into the dynamic
   container (`Data/data/data.NNN` + `.idx` KMT).
7. **Loose files** — `AsyncLooseFileExtractState` writes install-manifest
   executables into the product subfolder (`_classic_/`).
8. **Patch** — `AsyncFileBlockPatchState` / `AsyncFileBsdiffPatchState`
   apply patch-manifest deltas; `AsyncFileReencodePatchState` re-encodes.
9. **Finalize** — `AsyncFileMakeResidentState` marks residency, verify,
   cleanup. `.build.info`, `.product.db`, `Launcher.db` written last.

Client-visible layout produced (verified against the 1.13.2.31650
client-built store): `Data/config/` (3 files incl. patch config),
`Data/indices/` (606+135), `Data/data/` (data.NNN + per-bucket idx
generations + shmem + wow_classic-us), `_classic_/` loose files.

## 5. Branch: containerless mode (loose files + SQLite file DB)

Activated by `build-file-db`. `ContainerlessUpdate::Initialize` validates
(RE `containerless_update.cpp`): file DB present in build config, product
name, install directory, target/base tag queries, task scheduler
(min 8 cores). Hard links are NOT supported in containerless builds —
falls back to a residency container.

Pipeline (`async_containerless_build_update_state.cpp`, phase 10
terminal; logs `C-Update: %llu Complete`):

1. **Read file DB** — `async_file_db_read_state`: download the
   `build-file-db` blob, decrypt (magic `0x45`, key ID, IV, Salsa20
   per RE §File Database Encryption), deserialize into an in-memory
   SQLite DB (`sqlite3_deserialize`). Schema: `meta` (entry count),
   `tags` (binary blob, parsed like size-manifest tags), `files`
   (index, E-key, C-key, encoded size, decoded size, flags, relative
   path).
2. **Build update init** — `async_containerless_build_update_init`:
   check base build availability, iterate target + base file DBs,
   verify file sizes (unless `checksizeonly`), build the update file
   list, register zero-size empty files.
3. **Headers fetch** — `async_containerless_headers_fetch_state`:
   collect container state, fetch E-headers for all files in the update
   set (batch download), skip already-fetched (status 2).
4. **File updates** — `async_containerless_file_update_state` per file:
   `ContainerlessBlockMover::Initialize` (needs target + base headers),
   move/copy blocks, `AsyncContainerlessBlockExtractState` decodes
   blocks via `Codec::DecodeBlock` and writes to the target loose file
   through `ResidencyContainer` (reserve → open handle → async write).
   Duplicate files are copied on disk with residency tracking.
5. **Make resident** — `async_containerless_file_make_resident_state`.
6. **BGDL** (optional) — `async_containerless_bgdl_state` for background
   download without a base build.

Loose files land directly at `{install_dir}/{relative_path}` per the file
DB's path column — no `Data/data` archives, no KMT. Sparse files are used
on Windows for not-yet-downloaded regions.

## 6. Product state files (both modes)

Regardless of mode, the install ends with the product state files the
client/launcher read:

- `.build.info` — 14-column PSV; `Active=1`, version string must match
  the client's hardcoded version, build/cdn keys matching `Data/config/`.
- `.patch.result` — ASCII `0`, prevents online update check.
- `.product.db` — protobuf product database (launcher artifact, not read
  by the game exe).
- `Launcher.db` — launcher state.
- `_classic_/.flavor.info` — product flavor (`wow_classic`).

## 7. Post-install verification

1. Format checks against the store (cascette-py F1-F6: segment headers,
   local headers, idx guarded blocks, reversed keys, bucket hashes).
2. cascette-rs `local_verification` (C1-C5) and `dump_cas_container`
   (full ordered walk: 0 checksum failures, 0 key mismatches, 0 gaps).
3. Client run: fresh WINEPREFIX, empty `Data/data`, patched exe against
   the local mirror. Run 1 bootstraps from CDN; runs 2/3 must be
   0-request (see `installation-verification.md` §4).

## Notes and open items

- **1.13.2.31650 is container mode.** The mirror lacks a
  `build-file-db` build; the containerless leg is implemented in the
  agent (all 15 RTTI classes) and cascette-py (`install_containerless`)
  but not yet exercised end-to-end against a real containerless build.
- **cascette-py's `install_to_casc` does not fetch the patch config or
  patch indices on fresh installs** (the client does; see
  `installation-verification.md` §7).
- The agent's `InstallManager` currently hardcodes
  `ContainerType::kDynamic` in `init_tact_instance`; the containerless
  branch is dispatched separately (`ConcreteContainerlessIo`) and is not
  yet wired into the same `on_start_update` path — the decision point
  (§0) is implemented in the config reader, not yet in the operation
  dispatch.

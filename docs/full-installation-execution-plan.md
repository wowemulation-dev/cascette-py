# Full Installation Execution Plan

Execution plan for implementing the complete TACT/CASC installation
process in cascette-py, from product discovery to functional local
CASC storage.

**Baseline**: cascette-py v0.2.0 with working `install-to-casc` POC
**Reference**: Agent.exe 3.13.3 reverse engineering (management repo)
**Target**: Produce a local CASC installation readable by game clients

## Design Principle: Multi-Version Format Support

cascette-py is a research and educational tool. Every format and
protocol that has multiple versions must support all known versions,
not just the latest. This lets users explore format evolution across
WoW's 20-year history and across different Blizzard products.

When implementing any format handler:

- Support all known versions (parse and build/serialize)
- Expose version detection and selection in the API
- Include version-specific test vectors
- Document version differences in code comments
- CLI commands should accept `--version` flags where applicable

Known multi-version formats relevant to this plan:

| Format | Versions | Notes |
|--------|----------|-------|
| Local index (.idx) | V7, V8 | V7 simpler, V8 adds KMT sorted+update sections |
| Shmem protocol | V4, V5 | V5 adds exclusive access + PID tracking |
| Root file | V1, V2, V3, V4 | Already supported in `formats/root.py` |
| Encoding table | V1 | Single version, but ESpec codecs evolve |
| Download manifest | V1, V2, V3 | Header format changes per version |
| Install manifest | V1, V2 | Header format changes |
| Size manifest | V1, V2 | Header format changes |
| CDN index footer | V1 | Single version but field layout varies |
| TVFS | V1 | Single version, magic 0x53465654 |
| Patch index | V2, V3 | Block-based format, entry parsers differ |
| BLTE | Single | But 6 compression modes (N/Z/L/E/F + recursive) |
| KMT | V7, V8 | V8 adds sorted section + update pages |
| BPSV | V1, V2 | Protocol format versions |
| Build config | Dynamic | Field set grows over time |

## Current State

### Working

- Product discovery via Ribbit (versions/CDNs endpoints)
- Build config and CDN config fetching and parsing
- Encoding file download, BLTE decompression, CKey/EKey lookup
- Install and download manifest parsing with tag-based filtering
- CDN archive index download and in-memory IndexMap building
- File extraction from CDN archives via HTTP range requests
- Basic local CASC storage (16 buckets, V7 index, data files)
- `.build.info` creation and resume detection
- Product state files (`.product.db`, `Launcher.db`, `.patch.result`)
- BLTE decompression (modes N/Z/L/E/F)
- Jenkins hash (lookup3) for index verification

### Missing

Ordered by dependency and priority. Each gap references the
reverse-engineered Agent.exe behavior it should match.

1. Content hash verification (MD5 on downloaded data)
2. Concurrent/async download pipeline
3. Priority-ordered download queue
4. Encoding cache (ecache directory)
5. V8 KMT index format
6. Shared memory (shmem) protocol v4/v5
7. Incremental update / build update flow
8. Patch application (ZBSDIFF integration)
9. Containerless mode
10. CASC maintenance (compaction, repair)

## Execution Phases

### Phase 1: Download Integrity and Verification

**Goal**: Every downloaded file is verified against its expected hash
before being written to local storage. Without this, installations
can silently corrupt.

**Files to modify**:

- `cascette_tools/core/cdn.py`
- `cascette_tools/core/cdn_archive_fetcher.py`
- `cascette_tools/core/local_storage.py`
- `cascette_tools/commands/install_poc.py`

**Tasks**:

1. Add MD5 verification to `CDNClient.fetch_data()`:
   - After BLTE decompression, compute MD5 of content
   - Compare against the content key (CKey) from the encoding file
   - Raise `IntegrityError` on mismatch
   - Add `verify=True` parameter (default on) to allow bypassing
     for raw/diagnostic fetches

2. Add verification to `CdnArchiveFetcher.fetch_file_via_cdn()`:
   - Verify extracted archive data matches expected size from index
   - Verify BLTE-decompressed content matches CKey when available

3. Add verification to `LocalStorage.write_content()`:
   - Compute and store MD5 of written data
   - Track written keys in a set for deduplication (skip if already
     stored with matching size)

4. Add a `core/integrity.py` module:
   - `verify_content_key(data: bytes, expected_ckey: bytes) -> bool`
   - `verify_ekey_size(data: bytes, expected_size: int) -> bool`
   - `IntegrityError` exception class

**Tests**:

- Unit tests for `verify_content_key` with known good/bad data
- Unit test for `verify_ekey_size`
- Integration test: fetch a known file, verify hash matches
- Test that `IntegrityError` is raised on tampered data

**Acceptance criteria**:

- All downloaded files verified before storage write
- Verification failures logged with key, expected hash, actual hash
- No silent corruption possible in the install path

---

### Phase 2: Concurrent Download Pipeline

**Goal**: Download files in parallel using async I/O. The current
sequential approach is the primary bottleneck. Agent.exe uses 12
concurrent connections with 3 per-host limit.

**Files to create**:

- `cascette_tools/core/download_queue.py`

**Files to modify**:

- `cascette_tools/core/cdn.py`
- `cascette_tools/core/cdn_archive_fetcher.py`
- `cascette_tools/commands/install_poc.py`

**Tasks**:

1. Create `DownloadQueue` class in `core/download_queue.py`:
   - Priority queue (heapq) ordered by download manifest priority
   - Configurable concurrency limit (default 12)
   - Per-host connection limit (default 3)
   - `async def submit(entry: DownloadEntry) -> None`
   - `async def drain() -> AsyncIterator[DownloadResult]`
   - Progress callback support (completed count, total bytes)

2. Create `DownloadResult` dataclass:
   - `ekey: bytes`
   - `data: bytes | None`
   - `error: str | None`
   - `source: str` (archive hash or "loose")
   - `attempts: int`

3. Add retry logic with exponential backoff:
   - Match Agent.exe behavior: 3 retries max
   - Backoff weights by HTTP status (404=2.5x, 5xx=5.0x)
   - Rotate to next CDN mirror on failure
   - Track per-server error counts

4. Add `CDNClient.fetch_data_async()` method:
   - Async variant using httpx.AsyncClient
   - Shares mirror fallback logic with sync version

5. Integrate `DownloadQueue` into `install-to-casc` command:
   - Replace sequential download loop in Step 7
   - Show real-time progress (files/sec, MB/sec, ETA)

6. Add concurrent archive index download:
   - Replace sequential index download in Step 5
   - Use semaphore-limited async downloads (already partially
     implemented in `download_indices_async`)

**Tests**:

- Unit tests for `DownloadQueue` priority ordering
- Unit tests for retry logic and backoff calculation
- Integration test: download 10 files concurrently
- Test that per-host limit is respected

**Acceptance criteria**:

- Archive index download 5-10x faster than sequential
- File download throughput limited by bandwidth, not serialization
- Failed downloads retried with mirror rotation
- Progress reporting shows real-time throughput

---

### Phase 3: Priority-Ordered Installation

**Goal**: Download files in priority order matching Agent.exe behavior.
Priority 0 files (executables, shaders) download first, enabling
play-while-downloading.

**Files to modify**:

- `cascette_tools/commands/install_poc.py`
- `cascette_tools/core/download_queue.py` (from Phase 2)

**Files to create**:

- `cascette_tools/core/install_state.py`

**Tasks**:

1. Create `InstallState` class in `core/install_state.py`:
   - Persists to `{install_path}/Data/.install_state.json`
   - Tracks per-file download status:
     - `pending`: not yet downloaded
     - `downloaded`: fetched and verified
     - `failed`: all retries exhausted
   - Tracks per-priority-level completion:
     - `{priority: {total: N, completed: M, bytes_total: X, bytes_done: Y}}`
   - Supports resume: on restart, skip already-downloaded files
   - Atomic writes (write to temp file, rename)

2. Modify `install-to-casc` to use priority ordering:
   - Sort download entries by priority (ascending)
   - Group by priority level for progress display
   - Download priority 0 files first, then priority 1, etc.
   - After each priority level completes, log summary

3. Add install manifest file extraction ordering:
   - Install manifest files (executables, DLLs) are priority 0
   - Download and extract these before any CASC data files
   - Match Phase 6 from battlenet-install-process.md

4. Add per-priority progress display:
   - Rich table showing completion per priority level
   - Update in real-time during download

**Tests**:

- Unit tests for `InstallState` persistence and resume
- Test priority ordering (0 before 1 before 2)
- Test resume: interrupt and restart preserves progress
- Test atomic write (no partial state files)

**Acceptance criteria**:

- Files download in priority order
- Resume works after interruption
- Progress shows per-priority completion
- Install manifest files extracted before CASC data

---

### Phase 4: Encoding Cache (ecache)

**Goal**: Implement the `Data/ecache/` directory matching Agent.exe
Phase 4. The encoding cache stores CKey→EKey mappings locally,
avoiding re-download of the encoding file for content resolution.

**Reference**: Agent.exe creates `Data/ecache/` with the same 16-bucket
index structure as `Data/data/`, containing encoding table entries.

**Files to create**:

- `cascette_tools/core/encoding_cache.py`

**Files to modify**:

- `cascette_tools/core/local_storage.py`
- `cascette_tools/commands/install_poc.py`

**Tasks**:

1. Create `EncodingCache` class in `core/encoding_cache.py`:
   - Directory: `{install_path}/Data/ecache/`
   - Same 16-bucket .idx format as local storage
   - Stores encoding table entries (CKey → EKey mapping)
   - `write_entry(ckey: bytes, ekey: bytes, espec_index: int) -> None`
   - `lookup(ckey: bytes) -> tuple[bytes, int] | None` (ekey, espec_index)
   - `flush() -> None` writes indices

2. Populate encoding cache during installation:
   - After parsing encoding file, extract all CKey→EKey mappings
   - Write to ecache for future lookups
   - Subsequent runs can skip encoding file download if ecache exists

3. Add ecache initialization to `LocalStorage.initialize()`:
   - Create `Data/ecache/` directory
   - Write empty index files

4. Add ecache lookup to content resolution:
   - Before querying the full encoding file, check ecache
   - Fall back to full encoding file if ecache miss

**Tests**:

- Unit tests for encoding cache write/read roundtrip
- Test that ecache entries match encoding file entries
- Test ecache lookup performance (should be faster than full parse)
- Test ecache creation during install flow

**Acceptance criteria**:

- `Data/ecache/` created during installation
- CKey→EKey lookups work from ecache
- Encoding file not re-downloaded when ecache exists
- Format matches Battle.net agent output

---

### Phase 5: Multi-Version Index Format and Key Mapping Table

**Goal**: Support both V7 and V8 local index formats for reading
and writing. V7 is the simpler format used by older clients. V8
(KMT) adds sorted sections and update pages for incremental
modifications. Users should be able to generate either format.

**Reference**: Agent.exe `key_state.cpp`, `index_tables.cpp`.
KMT V8 uses two-tier LSM-tree: sorted 0x12-byte entries + update
0x200-byte pages. Jenkins lookup3 hash for bucket assignment.

**Files to modify**:

- `cascette_tools/core/local_storage.py`
- `cascette_tools/crypto/jenkins.py`

**Files to create**:

- `cascette_tools/core/key_mapping_table.py`

**Tasks**:

1. Create `KeyMappingTable` class in `core/key_mapping_table.py`:
   - Sorted section: entries sorted by 9-byte EKey prefix
   - Entry format: 9-byte EKey prefix + 5-byte storage offset + 4-byte
     encoded size (0x12 = 18 bytes per entry)
   - Storage offset packing: segment index (bits 30-39) | file offset
     (bits 0-29)
   - Update section: 0x200-byte pages with 0x19 entries each
   - Minimum update section size: 0x7800 bytes
   - Binary search in sorted section using Jenkins lookup3

2. Refactor `LocalIndexHeader` to support both versions:
   - `IndexHeaderV7`: current format (version=7)
   - `IndexHeaderV8`: adds sorted section header with bucket count,
     update section header with page count
   - Common base class or protocol for shared fields

3. Update `LocalStorage` with configurable index version:
   - `__init__(..., index_version: int = 8)` parameter
   - `_write_index_file_v7()`: current behavior, preserved
   - `_write_index_file_v8()`: sorted entries + update section
   - Both write methods calculate Jenkins hash per guarded block

4. Add `LocalStorage.read_index_file()`:
   - Auto-detect version from header
   - Parse both V7 and V8 formats into a common `IndexData` model
   - Support reading installations created by Battle.net or
     older cascette-py versions

5. Add CLI option for index version selection:
   - `install-to-casc --index-version {7,8}` (default 8)
   - `install-state scan` should report detected index version

6. Verify Jenkins hash (lookup3) correctness:
   - `hashlittle2()` from `crypto/jenkins.py` already implemented
   - Add test vectors from Agent.exe to confirm compatibility

**Tests**:

- Unit tests for KMT entry serialization/deserialization
- Test sorted section binary search
- Test storage offset packing/unpacking
- Test V7 index write/read roundtrip
- Test V8 index write/read roundtrip
- Test cross-version reading (write V7, read as generic; write V8,
  read as generic)
- Test that `--index-version 7` produces V7 output
- Verify Jenkins hash against known Agent.exe outputs

**Acceptance criteria**:

- Both V7 and V8 can be written and read
- Default is V8 for new installations
- Existing V7 installations detected and read correctly
- Entries sorted by EKey prefix in V8 sorted section
- Index files pass Jenkins hash verification
- CLI exposes version selection

---

### Phase 6: Shared Memory Protocol (V4 and V5)

**Goal**: Implement the shmem control file (`Data/data/shmem`)
supporting both protocol V4 and V5. V4 is the base protocol. V5
adds exclusive access and PID tracking. Both versions must be
readable and writable for exploring older and newer installations.

**Reference**: Agent.exe `shmem_control.win32.cpp`. Protocol versions
4 (base) and 5 (exclusive access + PID tracking).

**Files to create**:

- `cascette_tools/core/shmem.py`

**Files to modify**:

- `cascette_tools/core/local_storage.py`

**Tasks**:

1. Create `ShmemControl` class in `core/shmem.py`:
   - Configurable protocol version: `version: int = 5`
   - V4 layout (base):
     - Byte 0x00: protocol version (4)
     - Byte 0x02: initialization flag
     - DWORD 0x42: free space table size (must = 0x2AB8)
     - DWORD 0x43: data size (non-zero)
     - Generation numbers: 16 x 4-byte LE
     - Archive count tracking
     - Free space table (0x2AB8 bytes)
   - V5 layout (extends V4):
     - All V4 fields plus:
     - DWORD 0x54: exclusive access flags
       - Bit 0: exclusive mode
       - Bit 1: PID tracking enabled
     - PID slot array

2. Implement PID tracking (V5 only):
   - Slot array: process ID + access mode (1=read-write, 2=read-only)
   - State machine: 1=idle, 2=modifying
   - Generation counter increment per add
   - Crash recovery: recount on startup if state==2

3. Implement lock file protocol:
   - `.lock` file with 10-second backoff retry
   - Cross-platform file locking (fcntl on Linux, msvcrt on Windows)
   - Exclusive access check before container bind

4. Update `LocalStorage._write_shmem_file()`:
   - Replace current stub with proper ShmemControl output
   - Accept protocol version parameter
   - Write generation numbers at correct offsets
   - Set initialization and data size fields

5. Add `ShmemControl.read()` for parsing existing shmem files:
   - Auto-detect protocol version from first byte
   - Parse V4 or V5 fields accordingly
   - Extract generation numbers
   - Check exclusive access flags (V5 only)

6. Add CLI option for protocol version:
   - `install-to-casc --shmem-version {4,5}` (default 5)
   - `install-state scan` should report detected shmem version

**Tests**:

- Unit tests for shmem V4 write/read roundtrip
- Unit tests for shmem V5 write/read roundtrip
- Test protocol version auto-detection
- Test PID tracking add/remove (V5)
- Test that V4 file has no PID tracking fields
- Test lock file creation and cleanup
- Test exclusive access flag behavior (V5)
- Compare output against real Battle.net shmem file (if available
  in test_data/)

**Acceptance criteria**:

- Both V4 and V5 shmem files can be written and read
- Version auto-detected when reading
- PID tracking works for V5 multi-process scenarios
- Lock file prevents concurrent writes
- CLI exposes version selection

---

### Phase 7: Incremental Build Updates

**Goal**: Support updating an existing installation to a new build
version without re-downloading unchanged files.

**Reference**: Agent.exe `BuildUpdateInitState` (9 states), file
classification at entry +0x4e (0=no update, 1=needs download,
2=needs patch, 5=special, 6=obsolete).

**Files to create**:

- `cascette_tools/core/build_update.py`

**Files to modify**:

- `cascette_tools/commands/install_poc.py`
- `cascette_tools/core/install_state.py` (from Phase 3)

**Tasks**:

1. Create `BuildUpdate` class in `core/build_update.py`:
   - Compare old and new encoding files
   - Classify each file:
     - `unchanged`: CKey matches → skip
     - `needs_download`: new CKey, no patch available
     - `needs_patch`: patch entry exists in patch config
     - `obsolete`: in old build but not new build
   - Return classification as dict[bytes, FileStatus]

2. Implement config comparison:
   - `compare_build_configs(old: str, new: str) -> BuildDelta`
   - Detect changed encoding, root, install, download keys
   - Detect CDN config changes (new archives)

3. Implement file classification pipeline:
   - Load old encoding file (from ecache or local storage)
   - Load new encoding file (from CDN)
   - Diff CKey sets to find added/removed/changed entries
   - Check patch config for patchable entries
   - Output: prioritized download list (only changed files)

4. Add `update` subcommand to install-poc:
   - `install-poc update <install_path> --product <product>`
   - Auto-detect current build from `.build.info`
   - Query Ribbit for latest build
   - Run classification and download only changed files
   - Update `.build.info` and shmem on completion

5. Handle obsolete file cleanup:
   - Mark obsolete entries as non-resident in KMT
   - Do not delete data immediately (compaction handles this)

**Tests**:

- Unit tests for file classification (all 5 states)
- Test config comparison with known old/new configs
- Test that unchanged files are skipped
- Test update from one real build to the next (integration)

**Acceptance criteria**:

- Update downloads only changed files
- Classification matches Agent.exe behavior
- Old installations are not corrupted during update
- `.build.info` reflects new build after update

---

### Phase 8: Patch Application

**Goal**: Apply ZBSDIFF1 patches instead of full re-downloads when
patches are available. Reduces bandwidth for incremental updates.

**Reference**: Agent.exe `bsdiff_patcher.cpp`, `FileBlockPatch`
and `FileReEncodePatch` state machines.

**Files to create**:

- `cascette_tools/core/patcher.py`

**Files to modify**:

- `cascette_tools/formats/zbsdiff.py` (extend if needed)
- `cascette_tools/core/build_update.py` (from Phase 7)

**Tasks**:

1. Create `Patcher` class in `core/patcher.py`:
   - `apply_patch(base_data: bytes, patch_data: bytes) -> bytes`
   - Uses ZBSDIFF1 format from `formats/zbsdiff.py`
   - Verify output size and CKey match expected values
   - Delete base file after successful patch
   - Re-encode patched content if needed (match ESpec)

2. Integrate with build update flow:
   - For files classified as `needs_patch`:
     - Download patch data from CDN patch archives
     - Read base file from local storage
     - Apply patch to produce new content
     - Write patched content to local storage
     - Update index entries

3. Add patch index parsing (V2 and V3):
   - Fetch patch config from build config `patch` field
   - Parse patch archive indices
   - Support both V2 and V3 entry formats (block-based, parsers
     differ per version)
   - Support patch manifest "PA" magic with block shift 12-24
   - Map (old_ckey, new_ckey) → patch_ekey
   - Expose version detection in API and CLI

4. Add patch priority:
   - Patches are faster than full downloads for large files
   - Prefer patch when available and base file is local
   - Fall back to full download if base file missing

**Tests**:

- Unit tests for ZBSDIFF1 patch application
- Test patch + verify output hash
- Test fallback to full download when patch fails
- Integration test with real patch data (if available)

**Acceptance criteria**:

- Patches applied correctly (output matches expected CKey)
- Base files cleaned up after successful patch
- Fallback to full download on patch failure
- Bandwidth savings measurable vs full download

---

### Phase 9: Containerless Mode

**Goal**: Support installations that store files as individual loose
files on disk rather than in CASC containers. Some products and
older builds use this mode.

**Reference**: Agent.exe `ContainerlessBlockExtractState`,
`ContainerlessHandle` (temp file → verify size → rename with
3 retries).

**Files to create**:

- `cascette_tools/core/containerless.py`

**Files to modify**:

- `cascette_tools/commands/install_poc.py`

**Tasks**:

1. Create `ContainerlessStorage` class in `core/containerless.py`:
   - Stores files as individual files on disk
   - File naming: `{ekey_hex[:2]}/{ekey_hex[2:4]}/{ekey_hex}`
   - Write protocol: temp file → verify size → atomic rename
   - 3-retry rename on failure (matching Agent.exe)
   - Track stored files for deduplication

2. Add container type detection:
   - Read build config `install-mode` or product config
   - Container types: 0=containerless, 1=direct, 2=CASC
   - Default to CASC (type 2) for current products

3. Add containerless install path:
   - Fork in `install-to-casc` based on container type
   - Containerless: decode BLTE, write individual files
   - CASC: existing behavior (write to data archives)

4. Add containerless file reading:
   - `read_file(ekey: bytes) -> bytes | None`
   - Used by build update to read base files for patching

**Tests**:

- Unit tests for containerless write/read/rename
- Test atomic rename with retry
- Test container type detection from config
- Integration test: containerless install of small product

**Acceptance criteria**:

- Containerless installations produce correct file layout
- Files verified before final rename
- Retry logic handles transient failures
- Container type auto-detected from product config

---

### Phase 10: CASC Maintenance Operations

**Goal**: Support post-installation maintenance: compaction (defrag),
repair, and garbage collection.

**Reference**: Agent.exe `Compactor` (two-phase: archive merge +
extract-compact), `Repair` (resident file repair + container span
validation).

**Files to create**:

- `cascette_tools/core/compactor.py`
- `cascette_tools/core/repair.py`

**Files to modify**:

- `cascette_tools/core/local_storage.py`
- `cascette_tools/commands/install_poc.py` (add maintenance commands)

**Tasks**:

1. Create `Compactor` class in `core/compactor.py`:
   - Scan data archives for fragmentation
   - Phase 1: Merge small/fragmented archives
   - Phase 2: Extract-compact (rewrite non-contiguous segments)
   - Update indices after compaction
   - Delete empty archives

2. Create `Repair` class in `core/repair.py`:
   - Validate all index entries point to valid data
   - Verify content hashes for stored files
   - Re-download corrupted or missing files from CDN
   - Report repair results (fixed, unfixable, skipped)

3. Add garbage collection:
   - Identify entries not referenced by current encoding file
   - Mark as non-resident in KMT
   - Reclaim space during compaction

4. Add CLI commands:
   - `install-poc compact <install_path>`
   - `install-poc repair <install_path> --product <product>`
   - `install-poc gc <install_path>`

**Tests**:

- Unit tests for fragmentation detection
- Test compaction produces valid archives
- Test repair detects and fixes corrupted entries
- Test garbage collection identifies orphaned entries

**Acceptance criteria**:

- Compaction reduces archive fragmentation
- Repair fixes corrupted entries by re-downloading
- GC frees space from obsolete builds
- All operations preserve installation integrity

---

## Phase Dependencies

```text
Phase 1 (Integrity)
  └─> Phase 2 (Concurrent Downloads)
        └─> Phase 3 (Priority Ordering)
              └─> Phase 7 (Build Updates)
                    └─> Phase 8 (Patch Application)

Phase 4 (Encoding Cache) -- independent, can parallel with 2-3
Phase 5 (V8 KMT) -- independent, can parallel with 2-3
Phase 6 (Shmem) -- depends on Phase 5

Phase 9 (Containerless) -- independent, can parallel with 4-8
Phase 10 (Maintenance) -- depends on Phases 1, 5, 6
```

Phases 1-3 are the critical path. They transform the POC into a
functional installer. Phases 4-6 produce Battle.net-compatible
storage format. Phases 7-10 add operational features.

## Testing Strategy

Each phase includes its own unit and integration tests. In addition:

- **End-to-end test**: Install WoW Classic Era (smallest product)
  with `--max-files 100` and verify:
  - All index files parseable
  - All data files decompressible
  - Content hashes match encoding file
  - Directory structure matches Battle.net layout

- **Roundtrip test**: Install → read back → verify all entries

- **Resume test**: Interrupt at 50%, restart, verify completion
  without re-downloading finished files

- **Update test**: Install build N, update to build N+1, verify
  only changed files downloaded

## Estimated Scope per Phase

| Phase | New Files | Modified Files | New Tests | Lines (est) |
|-------|-----------|----------------|-----------|-------------|
| 1 | 1 | 4 | 8 | 200 |
| 2 | 1 | 3 | 8 | 400 |
| 3 | 1 | 2 | 6 | 300 |
| 4 | 1 | 2 | 6 | 250 |
| 5 | 1 | 2 | 10 | 400 |
| 6 | 1 | 1 | 8 | 350 |
| 7 | 1 | 2 | 8 | 400 |
| 8 | 1 | 2 | 6 | 300 |
| 9 | 1 | 1 | 6 | 250 |
| 10 | 2 | 2 | 8 | 500 |
| **Total** | **11** | **~15** | **74** | **~3,350** |

## Format Version Coverage

Throughout all phases, ensure the following format versions are
supported for both reading and writing. This is a cross-cutting
concern that applies whenever a format is touched.

Version details cross-referenced from cascette-rs source code
(`cascette-formats` crate) and Agent.exe reverse engineering.

### Already Supported (verify coverage during implementation)

- **Root file**: V1 (no magic, WoW 6.0-7.2, interleaved 28-byte
  entries), V2 (MFST/TSFM magic, WoW 7.2.5-8.1, separated arrays),
  V3 (WoW 8.2-9.1, extended header), V4 (WoW 9.1+, 40-bit content
  flags). All 4 in `formats/root.py`. Classic skipped V2 entirely.
- **BLTE**: Single-chunk (header_size=0), multi-chunk standard
  (flags 0x0F, 24-byte chunk info), multi-chunk extended (flags
  0x10, 40-byte chunk info with decompressed checksum). Block
  compression modes: N (none), Z (zlib), 4 (LZ4), E (encrypted),
  F (frame/recursive, deprecated). In `formats/blte.py`.
- **Build config**: Dynamic field set (13 fields early builds →
  1600+ fields with VFS). In `formats/config.py`.

### Must Be Verified or Extended During This Plan

- **Download manifest (DL)**: V1 (11-byte header), V2 (12 bytes,
  adds `flag_size` for per-entry flags), V3 (16 bytes, adds
  `base_priority` signed byte + 3 reserved). Entry uses 40-bit
  (5-byte) big-endian file size. Check `formats/download.py`
  handles all three. Add version-specific test vectors.

- **Install manifest (IN)**: V1 (10-byte header: magic + version +
  ckey_length + tag_count + entry_count), V2 (16 bytes, adds
  `loose_file_type`, `extra_entry_count`, explicit `entry_size`).
  Tag bit masks use MSB-first ordering (bit 7 = index 0). Check
  `formats/install.py`. Add version-specific tests.

- **Size manifest (DS)**: V1 (19-byte header, variable esize width
  1-8 bytes, 64-bit total_size), V2 (15-byte header, fixed 4-byte
  esize, 40-bit total_size). Key hash rejects 0x0000 and 0xFFFF.
  Check `formats/size.py`. Add version-specific tests.

- **Patch archive (PA)**: V1 (10-byte header, basic patch entries),
  V2 (same header size, extended header support). Block size bits
  12-24 (block sizes 4KB-16MB). Compression info format:
  `b:{11=n,4813402=n,793331=z}`. Check `formats/patch_archive.py`.
  Add version-specific tests.

- **CDN archive index**: Footer is 28 bytes (8-byte TOC hash +
  20-byte validated section). Version field ≤1. Footer fields:
  version, page_size, offset/size/key lengths, element count,
  checksum. Verify `formats/cdn_archive.py` handles all field
  layout variations.

- **BPSV (pipe-separated values)**: Text-based, no explicit
  versioning. Field types: STRING, HEX, DEC. Sequence number
  parsing supports 3 delimiter styles (`=`, `:`, space). Verify
  parsing in CDN client response handling.

- **Encoding table (EN)**: V1 only (22-byte big-endian header).
  Validation: version=1, hash sizes 1-16, page counts non-zero,
  unk_11 must be 0. ESpec codec letters: n=1, z=2/3, c=4(stub),
  e=5, b=6(invalid), g=7(stub). Verify `formats/encoding.py`.

- **TVFS**: V1 only (magic 0x54564653, 38-46 byte header depending
  on flags). Flags: 0x01=content keys, 0x02=write support (EST
  table), 0x04=patch support. Variable-width size encoding (1-4
  bytes). Verify `formats/tvfs.py`.

### New in This Plan

- **Local index (.idx)**: V7 and V8. Phase 5.
  - V7: 16-byte header (version, bucket, field sizes, segment_size),
    flat 18-byte entries
  - V8: adds sorted section (0x20-byte buckets) + update section
    (0x400-byte pages, 0x19 entries, min 0x7800 bytes)
- **Shmem protocol**: V4 and V5. Phase 6.
  - V4: base protocol (generation numbers, free space table)
  - V5: adds exclusive access flags + PID tracking
- **KMT**: V7 (flat entries) and V8 (sorted + update sections).
  Phase 5.

Each phase that touches a multi-version format must include tests
for all known versions of that format. Use cascette-rs test vectors
where available.

## Non-Goals

These are intentionally excluded:

- **Battle.net Agent HTTP API**: The REST API on port 1120 is for
  inter-process communication. Not needed for a standalone tool.
- **Telemetry**: Agent.exe telemetry system is Blizzard-specific.
- **Armadillo DRM**: Key validation is a commercial protection system.
- **bts product bootstrap**: The nested `.battle.net/` installation
  is Agent-specific infrastructure.
- **GDeflate/BCPack codecs**: Stubs in Agent.exe 3.13.3. Implement
  when a product ships content using these codecs.

## References

### cascette-py (this repository)

- `docs/battlenet-install-process.md` -- 7-phase timestamp analysis
- `docs/full-install-poc-plan.md` -- POC findings and statistics

### management repository (reverse engineering)

- `src/reverse-engineering/agent-3.13.3/` -- Agent.exe RE documentation
- `src/reverse-engineering/cascette-rs/implementation-mapping.md` -- Feature matrix

### cascette-rs (Rust implementation, cross-reference for format specs)

All format header structures, validation rules, and version
constants documented in `cascette-formats` crate source:

- `cascette-formats/src/root/version.rs` -- Root V1-V4 detection
- `cascette-formats/src/install/header.rs` -- Install V1-V2 headers
- `cascette-formats/src/download/header.rs` -- Download V1-V3 headers
- `cascette-formats/src/size/header.rs` -- Size V1-V2 headers
- `cascette-formats/src/encoding/header.rs` -- Encoding V1 header
- `cascette-formats/src/blte/header.rs` -- BLTE single/standard/extended
- `cascette-formats/src/tvfs/header.rs` -- TVFS V1 header and flags
- `cascette-formats/src/patch_archive/header.rs` -- Patch V1-V2 headers
- `cascette-formats/src/espec/` -- ESpec codec letters and parameters
- `cascette-formats/src/bpsv/` -- BPSV text format parsing
- `cascette-formats/src/config/` -- Build/CDN/patch config parsing

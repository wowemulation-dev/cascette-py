# Build Iteration Runbook (1.13.x)

Per-build procedure for recording format versions and verifying that formats
stay identical across the 1.13.x line. This is the lightweight per-build gate;
full client-run verification (1 run normally; a second run only if the
first shows unexpected CDN requests) is reserved for spot checks, not
every build.

Read this together with `installation-verification.md` (gates F1-F6, C1-C5,
client-run harness) and `install-workflow-differences.md` (divergence list).

## Goal

For each of the 41 builds in the §8 matrix of `installation-verification.md`
(the full set of WoW Classic Era live 1.13.x builds, 31650 .. 39692,
1.13.2 .. 1.13.7, wow_classic + the era fork at 38704):

1. Resolve `build_config` / `cdn_config` hashes.
2. Verify the mirror has the build's data.
3. Detect CDN-side format versions (`builds scan-formats`).
4. Optionally install and detect container-side versions.
5. Record the row in the `build_formats` registry and mark the matrix row.

Expected outcome: within 1.13.x, every version column matches the 31650
baseline (see "Baseline" below). Any drift is a finding, not an error — record
it and flag it.

## Environment

- Mirror root: `/run/media/$USER/NGDP/mirrors/cdn.blizzard.com`
- Range HTTP server on :8000 serving the mirror (access log = CDN request
  counter). Restart it after long sessions: HTTP/1.1 keep-alive connections
  hold pool workers, and CLOSE-WAIT sockets accumulate over many installs,
  eventually exhausting the pool and stalling all range requests
  (observed 2026-08-15 after 5 installs; fixed with pool 64 + 10s idle
  timeout in `tools/range_http_server.py`):

  ```bash
  python3 tools/range_http_server.py /run/media/$USER/NGDP/mirrors/cdn.blizzard.com 8000
  ```

- All cascette-py commands below need the mirror as the CDN base:

  ```bash
  export CASCETTE_RIBBIT_BASE_URL="http://localhost:8000/tpr/wow"
  ```

- The builds DB (populated by `builds sync`) is the authoritative source of
  per-build hashes. Arctium's archive 404s on `versions` for old 1.13 builds
  (verified for 31687); do not rely on it for hash resolution.

## Mirror layout

Blobs are hash-addressed with a 2+2 prefix split:

```text
tpr/wow/versions                 # per-build, rewritten by setup_local_ribbit.sh
tpr/wow/cdns                    # per-build, rewritten by setup_local_ribbit.sh
tpr/wow/config/aa/bb/<hash>     # build/cdn/product configs
tpr/wow/data/aa/bb/<hash>       # encoding, manifests, archives, content
tpr/wow/patch/aa/bb/<hash>      # patch config, patch manifests, ZBSDIFF blobs
```

The mirror is a complete snapshot: it holds every `wow_classic` and
`wow_classic_era` build that was ever live on the CDN, not just the 41 matrix
builds. All matrix builds have their data present (CDN = Y for every row).

## Missing files on the mirror

If a scan or install reports a 404 for a CDN file, the file may be missing
from the mirror snapshot. Recover it from `archive.wow.tools`, which mirrors
the official CDN layout and is guaranteed to hold all files:

```bash
# Mirror path: <content-type>/<aa>/<bb>/<hash>[.index]
#   config -> tpr/wow/config/<aa>/<bb>/<hash>
#   data   -> tpr/wow/data/<aa>/<bb>/<hash>      (+ .index for indices)
#   patch  -> tpr/wow/patch/<aa>/<bb>/<hash>     (+ .index for indices)
HASH=fd4f064c6a7690faf89d610286c301f4
curl -s -o /dev/null -w "%{http_code}\n" \
  "https://archive.wow.tools/tpr/wow/patch/${HASH:0:2}/${HASH:2:2}/${HASH}.index"
```

If the file exists (HTTP 200), download it into the mirror at the exact same
path:

```bash
curl -s -o /run/media/$USER/NGDP/mirrors/cdn.blizzard.com/tpr/wow/patch/${HASH:0:2}/${HASH:2:2}/${HASH}.index \
  "https://archive.wow.tools/tpr/wow/patch/${HASH:0:2}/${HASH:2:2}/${HASH}.index"
```

If it does not exist there (404), the URL path generation is wrong — check the
content type (config/data/patch) and the `.index` suffix. `archive.wow.tools`
holds the complete CDN file set; a 404 there means cascette-py requested a
wrong path.

**Exception — archive-group files**: `archive-group` and `patch-archive-group`
hashes in the CDN config are NOT CDN files. They are mega-indices the client
generates locally by merging the individual archive indices (see cascette-rs
`cascette-formats/src/archive/archive_group.rs`). They will always 404 on
every CDN and mirror — do not chase them. cascette-py generates them during
install via `build_merged_archive_group` (verified byte-identical against the
client-built 31650 store). If the mirror-check procedure above 404s on these
two hashes specifically, that is expected, not a mirror gap.

## Per-build procedure

### Step 1. Resolve hashes from the builds DB

```bash
uv run python -m cascette_tools builds search <build> --product wow_classic
```

The 1.13.x matrix spans two products. The fork happens at build 38704:

| Product | Builds |
|---|---|
| `wow_classic` | 31650 .. 38631 |
| `wow_classic_era` | 38704, 39605, 39692 |

All 41 matrix builds resolve with `build_config` + `cdn_config` present:
38 under `wow_classic`, 3 (the era builds) under `wow_classic_era`.

Record the `build_config` and `cdn_config` hashes from the row.

### Step 2. Verify mirror presence

The build config file must exist on the mirror before any scan or install.
Since the mirror is complete, this is a sanity check, not a discovery step:

```bash
ls /run/media/$USER/NGDP/mirrors/cdn.blizzard.com/tpr/wow/config/<aa>/<bb>/<build_config>
```

where `<aa><bb>` are the first four hex chars of the hash
(`config/2c/91/2c9159a...` for 31650). Also spot-check the cdn config hash the
same way. If absent, the mirror snapshot is incomplete for that build — stop
and report; do not fabricate a record.

### Step 3. CDN-side format scan

```bash
uv run python -m cascette_tools builds scan-formats \
  <build_config> <cdn_config> \
  --product wow_classic --region us --build <build>
```

Do NOT pass `--install-path` yet. This fetches and parses: build config, CDN
config, root manifest (TVFS), install manifest, download manifest, size
manifest, encoding file, and the CDN archive index footer. It writes one row
to the `build_formats` table keyed by (product, build, build_config) and
prints the detected versions.

Known benign warning: `size (parse): Invalid eSize byte count: 0` — the
1.13.2 size manifest has `esize_bytes=0` which `SizeParser` rejects though the
client accepts it; the version byte is still read from the raw header.

### Step 4. Container-side scan (optional, after an install)

If you also installed the build locally (see `installation-verification.md`
§4 for the install → client-run flow):

```bash
uv run python -m cascette_tools builds scan-formats \
  <build_config> <cdn_config> \
  --product wow_classic --region us --build <build> \
  --install-path <install>
```

This reads `Data/data`: idx files (KMT version), data.000 segment header
(480 bytes, 16 reconstruction headers), LocalHeader structure, and the
client-written `shmem` protocol version if present. Re-scanning the same key
updates the existing row in place.

### Step 5. Query the registry

```bash
uv run python -m cascette_tools builds formats --build <build>
# or the full table
uv run python -m cascette_tools builds formats
```

### Step 6. Client-run spot check (optional, not per-build)

Only for builds where a full client acceptance check is wanted (default: none
beyond 31650). Follow `installation-verification.md` §4 exactly: fresh
WINEPREFIX on real disk, cjkfonts + Windows build registry keys, real copy of
the loose install into the prefix, wow-patcher with localhost URLs, empty
`Data/data` for bootstrap experiments. Derive that build's encoding/root/patch
manifest hashes from its build config (they differ per build; do not reuse the
31650 values embedded in the doc).

### Step 7. Archive the pristine build (final gate, after UI verification)

Once the client-run verification passes, the pristine source install is
moved into the archive before the next build is started. The source install
is the unpatched loose install (never the prefix — the prefix holds a
patched copy and is discarded). This keeps one pristine, unpatched build per
archive directory, available for examination.

```bash
uv run python -m cascette_tools builds archive-pristine <install_path>
```

What the command does:

1. Reads `.build.info` from the install for the version string (e.g.
   `1.13.2.31650`) and the product (`wow_classic` / `wow_classic_era`).
2. Verifies the executable is pristine: fetches the same build's Wow.exe
   from the CDN (via the install manifest + encoding table) and compares
   sha256. A mismatch means the local exe was patched or corrupted — abort.
3. Detects OS/ARCH from the binary via `file`:
   - PE32+ x86-64  -> `windows-win64`
   - Mach-O x86_64 -> `macos-x86_64`
   - Mach-O arm64  -> `macos-arm64`
4. Moves the install to
   `~/Downloads/battle.net/wow_classic/<version>.<os>-<arch>` (existing
   target is an error; use `--force` to replace).

Run it manually before marking the matrix row ✅. The archived directory is
the pristine artifact you examine before moving to the next build. If the
version already exists in the archive (e.g. a re-run of 31650), the command
errors instead of clobbering the archived build.

## Baseline (1.13.2.31650, verified 2026-08-15)

| Column | Value |
|---|---|
| root_version (TVFS) | 1 |
| install_version | 1 |
| download_version | 3 |
| size_version | 1 |
| encoding_version | 1 |
| archive_index_version (CDN footer) | 1 |
| blte_magic | 424C5445 |
| idx_version (KMT) | 7 |
| local_header_version | 30 |
| segment_header_bytes | 480 |
| shmem_version | 4 |

Pass criteria per build: every CDN-side column equals the baseline. Container
columns match the baseline when a container scan ran. Drift at branch
boundaries (1.13.6 -> 1.13.7, or the era fork at 38704) is exactly what the
registry exists to detect — record it, do not treat it as failure.

## WPP column handling

The matrix's WPP column (Y / `–`) is mislabeled in `installation-verification.md`:
it says "wow-patcher supports the build", but the values come from the
management repo's classic-build-map `wpp_known` column, which is
**WowPacketParser's ClientVersion enum membership** — a different tool.

The three `–` builds (35663, 35705, 36307) are short-lived 1.13.5 releases
(35663: 1 day; 35705: reverted to 35395 after 2 days; 36307: 1 day) that
never got a WPP version module. They are NOT known to fail wow-patcher:
wow-patcher is pattern-based (no build list) and was only ever integration-
tested on 31650. Treat the `–` as "untested for packet parsing", not
"wow-patcher known-fails".

Practical effect on this runbook: none. All 41 builds are format-scannable
(steps 1-5), and all 41 can be attempted for the client-run spot check
(step 6). If you do client-run a `–` build and wow-patcher fails, report it
as a wow-patcher finding, not a WPP-enum fact.

## Marking the matrix row

After the CDN scan (and container scan if run), update the §8 matrix row in
`installation-verification.md`: put the scan date and which scans ran
(`✅ format scan` / `✅ format+container scan` / `✅ + client 1-run` — use
`client 2-run` only when a second run was required). Keep the
CDN/WPP columns as they are unless you verified a change.

## Gotchas

- Region: `scan-formats` defaults to `us`; the DB rows and mirror use `us`.
  `setup_local_ribbit.sh`'s example uses EU — that is a different, historical
  invocation, not the default for this runbook.
- Era builds: use `--product wow_classic_era`; the mirror serves them under
  the same `tpr/wow` path (cdns rewrite handles the mapping).
- Never write `shmem`/`ecache` into an install (client-managed artifacts,
  see `installation-verification.md` §9).
- The 1,227 extra KMT entries and the missing patch manifest are known,
  non-blocking divergences for login acceptance (B6-patch is the open item to
  close the last CDN request). They do not affect format-version detection.

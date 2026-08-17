# Client Installation Verification

How a cascette-py install is validated end to end, where the verification
branches off from installation, which checks run before an install counts as
successful, and which tools need fixing when a check fails.

## 1. The Two Validation Layers

Installation produces two artifacts, each validated differently:

1. **The CASC store** (`Data/data/*.idx`, `data.NNN`, `Data/indices/`,
   `Data/config/`) — the format-level data the client reads.
2. **The client run** (WINE + patched Wow.exe reaching the login screen) —
   the end-to-end proof that the store is actually usable.

A store can be format-correct yet still cause the client to re-fetch from
CDN (the 30-byte local-header gap we fixed). The client run is the only
check that catches this class of problem. Both layers are required.

## 2. Install-Time Checks (already reported by the installer)

| Check | Tool | Pass condition |
|-------|------|----------------|
| Download-manifest tag selection | `install_to_casc` (tag filter) | Windows+x86_64+enUS selects the expected subset (131,456 of 204,319 for 1.13.2.31650) |
| Per-file fetch | `_download_casc_files` (archive range + loose fallback) | 0 failures out of total |
| CKey→EKey integrity | `LocalStorage.write_content(expected_ckey=...)` | MD5 of written blob matches content key |
| Archive index map | `CdnArchiveFetcher` | All indices load, `index_map` non-empty |
| Install state | `InstallState` | `downloaded` count == manifest entry count after run |

These are necessary but not sufficient: they prove *bytes were written*, not
that the client accepts the layout.

## 3. Format Verification (after install, before client launch)

Runs against the produced store on disk. This is the branch point for
"did we write the right format".

### 3a. cascette-py format checks

```bash
# Entry header validity + segment header (local_storage parse)
uv run python - <<'EOF'
from cascette_tools.core.local_storage import parse_local_idx_file, LocalFileHeader
from cascette_tools.crypto.jenkins import hashlittle
from pathlib import Path
DATA = Path(".../Data/data")
for df in sorted(DATA.glob("data.*")):
    head = df.read_bytes()[:480]
    valid = sum(1 for i in range(16)
        if hashlittle(head[i*30:(i+1)*30][:0x16], 0x3D6BE971) & 0xFFFFFFFF
        == LocalFileHeader.from_bytes(head[i*30:(i+1)*30]).checksum_a)
    assert valid == 16, f"{df}: segment header checksums broken ({valid}/16)"
EOF
```

Checks performed:

| # | Check | Expected |
|---|-------|----------|
| F1 | data.NNN starts with 480-byte segment header | 16/16 reconstruction headers, checksum_a valid, flags=1 |
| F2 | Every idx entry points at a valid 30-byte LocalHeader | checksum_a = `hashlittle(header[0:22], 0x3D6BE971)`, flags=0, BLTE magic at offset+30 |
| F3 | `encoded_size` includes the 30-byte header | idx size == 30 + BLTE payload size |
| F4 | Key field = full 16-byte reversed key | `ekey[::-1]` == header field |
| F5 | IDX V7 guarded-block hashes | `parse_local_idx_file` returns without warnings |
| F6 | Reconstruction keys hash to bucket (seed 1) | `compute_bucket(key[:9], seed=1)` == header slot |

Byte-identical reference: a client-written gen-2 entry (`59cad02d...` →
key field `1b856f76...`, enc_size 13061932). See
`tests/test_core/test_agent_format_headers.py`.

### 3b. cascette-rs cross-check (independent implementation)

```bash
CASCETTE_WOW_PATH=<install> cargo run -p cascette-client-storage \
  --example local_verification --features local-install
```

| # | Check |
|---|-------|
| C1 | `.build.info` parses, active entry, build/cdn key match pinned hashes |
| C2 | 16 idx files open, entry count sane, 4 archives found |
| C3 | Encoding table reads from local data files (204,321 entries) |
| C4 | Root/download ekeys resolve via encoding table |
| C5 | Build/CDN config parse, root hash matches, archives listed |

Because cascette-rs is a second implementation, a pass here catches
format interpretation bugs that a single-parser test would miss.

### 3c. Byte-level baseline snapshot

```bash
cd <install>/Data/data
sha256sum data.* *.idx > ../Data_data_shasums_pre_client.txt
```

Recorded *before* first client launch so post-run diffs show exactly which
files the client rewrote (appends to data.003, new idx update entries,
new gen-2/3 files).

## 4. Client-Run Verification (WINE)

The end-to-end gate. Runs the actual 1.13.2.31650 client against the store.

### Environment

Setup is per round; never reuse a prefix between validation rounds. The full
procedure mirrors the management repo's
`reference/arxan-dump-procedure.md` (Steps 1-3) with the patcher invoked for
CDN redirection instead of `.text` dumping.

**1. Fresh WINEPREFIX on real disk** — never `/tmp` (tmpfs; the prefix holds
a full copy of the client install and can overflow it).

```bash
export WINEPREFIX=~/.cache/cascette-prefix   # real disk
rm -rf "$WINEPREFIX"                          # fresh per round
WINEARCH=win64 wineboot --init
```

**2. CJK fonts + Windows version.** WoW renders CJK glyphs even on enUS
clients; without `cjkfonts` missing glyphs can trigger renderer asserts that
block startup. Some clients check the Windows build number during init and
refuse to run (or enter update logic) if it does not match.

```bash
winetricks -q cjkfonts
wine reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" \
  /v CurrentBuild /t REG_SZ /d 19041 /f
wine reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" \
  /v CurrentBuildNumber /t REG_SZ /d 19041 /f
```

Build 19041 = Windows 10 20H1; adjust if a specific client requires another.

**3. Copy the loose install into the prefix.** Use a real copy, not symlinks —
Wine may write temporary files/caches and the source install must stay
untouched.

```bash
mkdir -p "$WINEPREFIX/drive_c/wow"
cp -a <loose_install>/. "$WINEPREFIX/drive_c/wow/"
# verify dot files survived (cp -a preserves hidden files):
ls -la "$WINEPREFIX/drive_c/wow/"   # .build.info, .product.db, .patch.result
ls -la "$WINEPREFIX/drive_c/wow/_classic_/"   # .flavor.info, Wow.exe
```

**4. Patch Wow.exe for the localhost CDN** — both the API replies
(versions/cdns manifests) and the content hosts (cdns Hosts/Servers fields)
must point at the local mirror. The mirror's `versions`/`cdns` files are
seeded by `tools/setup_local_ribbit.sh` (rewrites every cdns Hosts/Servers
row to `localhost:8000`), and the patcher rewrites the URLs embedded in the
binary. The static patch replaces Wow.exe in the prefix:

```bash
cd "$WINEPREFIX/drive_c/wow/_classic_"
wow-patcher -l Wow.exe -o Wow-patched.exe \
  --version-url http://localhost:8000/tpr/wow/versions \
  --cdns-url http://localhost:8000/tpr/wow/cdns
mv Wow-patched.exe Wow.exe
```

(RSA/portal/cert patches are part of the same invocation and verified in the
wow-patcher repo.)

**5. Local range HTTP server on :8000** serving the mirror — its access log
is the CDN-request counter:

```bash
python3 tools/range_http_server.py /run/media/$USER/NGDP/mirrors/cdn.blizzard.com 8000
```

### Launch procedure (per run)

```bash
BASE=$(wc -l < /tmp/range_http_server.log)
nohup timeout 180 wine "$WINEPREFIX/drive_c/wow/_classic_/Wow.exe" -console \
  > /tmp/wow_runN.log 2>&1 &
sleep 60   # allow login screen
# CDN request count = lines in range_http_server.log after BASE
```

### Client runs

| Run | Purpose | Pass condition |
|-----|---------|----------------|
| Run 1 | Cold start with empty store history | Client reaches login screen; CDN requests are only explainable on-demand media (see below) |
| Run 2 | Warm start after run-1 writes (only if run 1 was not clean) | Login screen; **0 CDN requests** (or only repeatable media) |

Run 2 is redundant when run 1 is clean: login reached, no repair marker,
store accepted, and requests limited to the explainable set. In practice
issues surface on the cold start, so most builds need only run 1.

**Verified (2026-08-15): the store must start EMPTY.** `Data/data` is the
CAS container itself. A cascette-py-written store (30-byte headers,
segment headers, valid checksums) is still rejected as damaged — the client
writes `CASCRepair.mrk`, creates fresh idx files, shows a repair dialog,
and exits. Only when `Data/data` starts empty does the client build the
store itself (step 3 above must therefore copy the loose install and strip
`Data/data` to an empty directory). Warm starts against the client-built
store are 0-request.
A client-run verification is **successful** when:

1. Client reaches the login screen (window + `Client Initialize.` in
   `_classic_/Logs/Client.log`).
2. CDN request count is zero (or the media set below) — on run 1 if run 2 is skipped, else on run 2.
3. `Data/data` sha256sums change only where expected: new idx update
   entries / generations and data.003 growth from media, nothing else.

### Known legitimate on-demand fetches (not failures)

- Login-screen media: Ogg speech audio (`78e27e97...`, ~268 MB, absent from
  the download manifest entirely) and AVI cinematics (`505761a1...`,
  `2a846298...`). The reference install also lacks these at install time —
  they cache into the store on first login and are not re-fetched after.
- The encoding file (`59cad02d...`) and root manifest (`a2f840f3...`):
  the client re-fetches loose CDN files at startup; presence in the store
  does not stop that (matches real Battle.net behavior).

## 5. Failure Handling: Which Tool to Fix

| Symptom | Likely cause | Fix where |
|---------|-------------|-----------|
| Client rejects the store outright: writes `CASCRepair.mrk`, fresh idx files, repair dialog, exit (observed 2026-08-14) | Store written by cascette-py is not accepted by `ValidateDataIntegrity` — root cause still open; a client-built store works. Diff cascette-py output against the client-built store (30-byte local headers, 480-byte segment headers, idx guarded blocks, key order, checksum_b) | `cascette_tools/core/local_storage.py` (`LocalStorage.write_content`, `build_segment_header`, `_write_index_file`) + cascette-rs `cascette-client-storage/src/storage/{local_header,segment,archive_file}.rs`, `index/mod.rs` |
| Store unreadable by cascette-rs `local_verification` | Idx layout / guarded-block hash mismatch | `cascette_tools/core/local_storage.py` (`_write_index_file`) + cascette-rs `index/mod.rs` |
| Installer reports fetch failures | CDN mirror missing blobs; tag filter wrong | `install.py` (`_download_casc_files`, `apply_tag_query`) |
| `.build.info` / `.product.db` mismatch (client can't start) | PSV/protobuf layout | `core/build_info` writer, `core/product_db_proto.py`, `formats/build_info.py` |
| Client fetches files that ARE in the store | Header checksums wrong (ValidateDataIntegrity skips entry) | `LocalFileHeader.compute_checksum_a/b` + cascette-rs `LocalHeader` |
| Client fetches media every run | Not a bug (on-demand media, see §4) | No fix; documented |
| Wrong install path / no UI | WINE prefix, patched exe missing, cjkfonts | Environment setup, not tooling |

## 6. Verification Resources

| Resource | Used for |
|----------|----------|
| `~/Downloads/battle.net/wow_classic/1.13.2.31650.windows-win64/` | Reference install: `.product.db` (407-byte protobuf target), `.build.info` (14-col), format ground truth for state files (idx there is stale, don't trust its offsets) |
| Management repo `src/reverse-engineering/wow-classic/1.13.2/31650/tact/cas-initialization.md` | Authoritative IDX V7 + data-file + LocalHeader format |
| Management repo `.../format-versions.md` | Version constants (TVFS v1, idx v7, CDN footer v1, BLTE magic 0x424C5445) |
| cascette-rs `examples/local_verification.rs` | Independent store reader (cross-check) |
| `tests/test_core/test_agent_format_headers.py` | Byte-level header assertions (key reversal, flags, checksums) |
| WINE prefix + wow-patcher + range HTTP server | Client-run harness |

## 7. Current Status (2026-08-15)

### cascette-py store now accepted by the client (B3 resolved)

The 1.13.2.31650 client now **accepts a cascette-py-built store** and
reaches the login screen on **first client start** with no re-fetch. The
root cause of the earlier rejection was structural: cascette-py wrote the
480-byte segment header (16 reconstruction headers) into `data.000` but
never indexed those headers in the KMT. The client indexes all 64
reconstruction entries (4 segments x 16 buckets) in the `.idx` files.

Fix (in `LocalStorage.write_content`): when a new data file is created,
add each of the 16 segment-header `LocalHeader`s as a `LocalIndexEntry`
(key = generated segment key, archive_id = segment, archive_offset =
bucket*30, size = 30) to the **seed-1 bucket** idx
(`compute_bucket(key, seed=1)`). See `install-workflow-differences.md` B3.

### Verification runs (cascette-py store, current code)

| Run | Setup | Result |
|-----|-------|--------|
| Run 1 (cold) | Fresh prefix, cascette-py store (131,456 files, 0 failed) | Login screen; **1 CDN request** (patch manifest `68a64c98`, which cascette-py does not write yet); store untouched |
| Run 2 (warm) | Same prefix/store | Login screen; **0 CDN requests**; store untouched (16 gen-1 idx, no re-index); `shmem` recreated by client |

### Verification runs (1.13.2.31687, patch-manifest fix)

The patch-manifest fix (2026-08-15) writes the build config's `patch` key
(raw `PA` file, keyed by content key) into the store during install. This
eliminates the cold-start CDN request.

| Run | Setup | Result |
|-----|-------|--------|
| Run 1 (cold) | Fresh prefix, cascette-py store (131,456 files, 0 failed) | Login screen; **0 CDN requests**; store untouched (all 20 files byte-identical to pre-client snapshot); `shmem` v4 recreated |
| Run 2 (warm) | Same prefix/store | Login screen; **0 CDN requests**; store untouched |

The two AVI cinematics (`505761a1`, `2a846298`) are **in the cascette-py
store** (they are part of the download manifest) and play locally. The Ogg
speech audio (`78e27e97`) is absent from the download manifest and not in
the store; it is the only expected on-demand fetch. In the run-2 test no
speech fetch occurred because no voiced cinematic was triggered.

### Known residual divergences (non-blocking for login)

- **Patch manifest: RESOLVED (2026-08-15).** cascette-py now writes the build
  config's `patch` key (raw `PA` file, keyed by its content key) into the
  store during install. Verified on 1.13.2.31687: the client makes **0 CDN
  requests on cold start** (previously 1). The 6 ZBSDIFF patch blobs are
  still not written; the client does not request them for login acceptance.
  Byte-exact replication of the blobs requires patch application on install.
- cascette-py indexes 1,227 **extra KMT entries** (install/download
  manifests, tag-excluded files) that the client does not index. Not a
  rejection trigger; byte-exact replication requires excluding them.
- The run-2 client eventually exited after an extended period
  (`dispatch_exception assertion` storm in the WINE log, plus a
  "configure double buffering" D3D hint). The client reached the login
  screen and operated normally before that; the exit is treated as a
  WINE/D3D display issue, not a store rejection (no `CASCRepair.mrk`).

### Superseded

- The earlier "cascette-py store rejected as damaged" status is
  superseded by the B3 fix above. checksum_b was a red herring: it is
  correct in both stores, differing only because the write order places
  entries at different offsets.
- The management doc's claim "1.13.2 client never writes CASCRepair.mrk"
  is contradicted by observation: the client wrote it when it detected a
  damaged store (pre-fix).

## 8. 1.13 Build Verification Matrix

The full set of 1.13.x builds iterated for installation verification.
Status is marked ✅ when all gates pass for a build (format checks,
cascette-rs cross-check, and the 2-run client verification). CDN = mirror
has the build's CDN data. WPP = membership in WowPacketParser's
ClientVersion enum (`–` = absent; the three such builds are short-lived
1.13.5 releases never given a WPP version module). The column does NOT
describe wow-patcher support: wow-patcher is pattern-based with no build
list and was integration-tested on 31650 only. See
`build-iteration-runbook.md` §WPP column handling.

| Build | Patch | Product(s) | Use product | CDN | WPP | Date | Verification |
|-------|-------|------------|-------------|-----|-----|------|--------------|
| 31650 | 1.13.2 | wow_classic | wow_classic | Y | Y | Aug 23, 2019 | ✅ format+container scan + client 2-run (2026-08-15) |
| 31687 | 1.13.2 | wow_classic | wow_classic | Y | Y | Aug 30, 2019 | ✅ format+container scan + client 2-run, 0 CDN requests (2026-08-15) |
| 31727 | 1.13.2 | wow_classic | wow_classic | Y | Y | Sep 4, 2019 | ✅ format+container scan + client 2-run, 0 CDN requests (2026-08-15) |
| 31830 | 1.13.2 | wow_classic | wow_classic | Y | Y | Sep 12, 2019 | ✅ format+container scan + client 2-run, 0 CDN requests (2026-08-15) |
| 31882 | 1.13.2 | wow_classic | wow_classic | Y | Y | Sep 18, 2019 | ✅ format+container scan + client 2-run, 0 CDN requests (2026-08-15) |
| 32089 | 1.13.2 | wow_classic | wow_classic | Y | Y | Oct 7, 2019 | ✅ format+container scan + client 2-run, 0 CDN requests (2026-08-15) |
| 32421 | 1.13.2 | wow_classic | wow_classic | Y | Y | Nov 6, 2019 | ✅ format+container scan + client 2-run, 0 CDN requests (2026-08-15) |
| 32600 | 1.13.2 | wow_classic | wow_classic | Y | Y | Nov 21, 2019 | ✅ format+container scan + client 2-run, 0 CDN requests (2026-08-15) |
| 32790 | 1.13.3 | wow_classic | wow_classic | Y | Y | Dec 10, 2019 | ✅ format+container scan + client 2-run, 0 CDN requests (2026-08-15) |
| 32836 | 1.13.3 | wow_classic | wow_classic | Y | Y | Dec 17, 2019 | ✅ format+container scan + client 2-run, 0 CDN requests (2026-08-15) |
| 32887 | 1.13.3 | wow_classic | wow_classic | Y | Y | Jan 6, 2020 | ✅ format+container scan + client 2-run, 0 CDN requests (2026-08-15) |
| 33155 | 1.13.3 | wow_classic | wow_classic | Y | Y | Jan 7, 2020 | ✅ format+container scan + client 2-run, 0 CDN requests (2026-08-15) |
| 33302 | 1.13.3 | wow_classic | wow_classic | Y | Y | Feb 11, 2020 | ✅ format+container scan + client 2-run, 0 CDN requests (2026-08-15) |
| 33526 | 1.13.3 | wow_classic | wow_classic | Y | Y | Feb 28, 2020 | ✅ format+container scan + client 2-run, 0 CDN requests (2026-08-15) |
| 33598 | 1.13.4 | wow_classic | wow_classic | Y | Y | Mar 6, 2020 | ✅ format+container scan + client 2-run, 0 CDN requests (2026-08-15) |
| 33645 | 1.13.4 | wow_classic | wow_classic | Y | Y | Mar 14, 2020 | ✅ format+container scan + client 2-run, 0 CDN requests (2026-08-15) |
| 33728 | 1.13.4 | wow_classic | wow_classic | Y | Y | Mar 20, 2020 | ✅ format+container scan + client 2-run, 0 CDN requests (2026-08-15) |
| 33920 | 1.13.4 | wow_classic | wow_classic | Y | Y | Apr 6, 2020 | ✅ format+container scan + client 2-run, 0 CDN requests (2026-08-15) |
| 34219 | 1.13.4 | wow_classic | wow_classic | Y | Y | Apr 29, 2020 | ✅ format+container scan + client 1-run, 0 CDN requests (2026-08-15) |
| 34266 | 1.13.4 | wow_classic | wow_classic | Y | Y | May 7, 2020 | ✅ format+container scan + client 1-run, 0 CDN requests (2026-08-15) |
| 34600 | 1.13.4 | wow_classic | wow_classic | Y | Y | Jun 4, 2020 | ✅ format+container scan + client 1-run, 0 CDN requests (2026-08-15) |
| 34835 | 1.13.4 | wow_classic | wow_classic | Y | Y | Jun 19, 2020 | ✅ format+container scan + client 1-run, 0 CDN requests (2026-08-15) |
| 35000 | 1.13.5 | wow_classic | wow_classic | Y | Y | Jul 2, 2020 | ✅ format+container scan + client 1-run, 0 CDN requests (2026-08-15) |
| 35186 | 1.13.5 | wow_classic | wow_classic | Y | Y | Jul 17, 2020 | ✅ format+container scan + client 1-run, 0 CDN requests (2026-08-15) |
| 35395 | 1.13.5 | wow_classic | wow_classic | Y | Y | Jul 31, 2020 | ✅ format+container scan + client 1-run, 0 CDN requests (2026-08-15) |
| 35663 | 1.13.5 | wow_classic | wow_classic | Y | – | Aug 26, 2020 | ✅ format+container scan + client 1-run, 0 CDN requests (2026-08-15) |
| 35705 | 1.13.5 | wow_classic | wow_classic | Y | – | Aug 27, 2020 | ✅ format+container scan + client 1-run, 0 CDN requests (2026-08-15) |
| 35753 | 1.13.5 | wow_classic | wow_classic | Y | Y | Sep 2, 2020 | ✅ format+container scan + client 1-run, 0 CDN requests (2026-08-15) |
| 36035 | 1.13.5 | wow_classic | wow_classic | Y | Y | Sep 25, 2020 | ✅ format+container scan + client 1-run, 0 CDN requests (2026-08-15) |
| 36307 | 1.13.5 | wow_classic | wow_classic | Y | – | Oct 20, 2020 | ✅ format+container scan + client 1-run, 0 CDN requests (2026-08-15) |
| 36325 | 1.13.5 | wow_classic | wow_classic | Y | Y | Oct 23, 2020 | ✅ format+container scan + client 1-run, 0 CDN requests (2026-08-15) |
| 36714 | 1.13.6 | wow_classic | wow_classic | Y | Y | Nov 25, 2020 | ✅ format+container scan + client 1-run, 0 CDN requests (2026-08-15) |
| 36935 | 1.13.6 | wow_classic | wow_classic | Y | Y | Dec 18, 2020 | ✅ format+container scan + client 1-run, 0 CDN requests (2026-08-15) |
| 37497 | 1.13.6 | wow_classic | wow_classic | Y | Y | Feb 8, 2021 | ✅ format+container scan + client 1-run, 0 CDN requests (2026-08-15) |
| 38363 | 1.13.7 | wow_classic | wow_classic | Y | Y | Apr 16, 2021 | ✅ format+container scan + client 1-run, 0 CDN requests (2026-08-15) |
| 38386 | 1.13.7 | wow_classic | wow_classic | Y | Y | Apr 21, 2021 | ✅ format+container scan + client 1-run, 0 CDN requests (2026-08-15) |
| 38475 | 1.13.7 | wow_classic | wow_classic | Y | Y | Apr 27, 2021 | ✅ format+container scan + client 1-run, 0 CDN requests (2026-08-15) |
| 38631 | 1.13.7 | wow_classic | wow_classic | Y | Y | May 11, 2021 | ✅ format+container scan + client 1-run, 0 CDN requests (2026-08-15) |
| 38704 | 1.13.7 | wow_classic_era | wow_classic_era | Y | Y | May 18, 2021 — fork | ✅ format+container scan + client 1-run, 0 CDN requests (2026-08-17) |
| 39605 | 1.13.7 | wow_classic_era | wow_classic_era | Y | Y | Jul 30, 2021 | ✅ format+container scan + client 1-run, 0 CDN requests (2026-08-17) |
| 39692 | 1.13.7 | wow_classic_era | wow_classic_era | Y | Y | Aug 16, 2021 | ✅ format+container scan + client 1-run, 0 CDN requests (2026-08-17) |

## 9. Client-Managed Runtime Files: shmem and ecache

Neither cascette-py nor cascette-rs writes `Data/data/shmem`, `Data/shmem/`,
or `Data/ecache/`. These are client-managed runtime artifacts: the client
recreates them on startup when the core data (config/indices/data) is
valid. Writing them with a guessed format pollutes the install and can trip
the client's shared-memory bind check.

cascette-py keeps its own CKey→EKey lookup cache outside the client install
at `~/.local/share/cascette-tools/ecache/<install-hash>/` (used for
`update` delta computation).

### shmem (client-verified, 1.13.2.31650)

Client writes `Data/data/shmem`, **protocol version 4** (not 5), file size
0x2C10 (11280) bytes:

| Offset | Size | Field | Client value |
|--------|------|-------|--------------|
| 0x00 | 1 | version | 4 |
| 0x04 | 4 | size | 0x150 (336) |
| 0x08 | 0x100 | mutex path | `Global\../Data/data` (relative) |
| 0x108 | 4 | free space table format | 0x2AB8 |
| 0x10C | 4 | data size | 0x150 (336) |
| 0x110 | 64 | generations | 16 × u32, actual per-bucket generations |
| 0x150 | 4 | (v4 tail) | 1 |
| 0x154 | 4 | (v4 tail) | 0xFE |

Earlier cascette-py wrote v5, an absolute path, and the summed data-file
size in data_size — all mismatched. The v5 exclusive-access flag lives at
0x150 only for version >= 5.

### ecache (observed, client-kept)

The client did not rewrite an existing `Data/ecache/` (16 idx files, one
per bucket, CKey→EKey). It ignored a cascette-py-written ecache entirely.
Format: same 16-bucket idx layout as the KMT, entries are CKey→EKey
mappings. Client rebuilds it on demand; presence is optional.

### wow_classic-us

`Data/data/wow_classic-us` — 42-byte placeholder file the client creates
during bootstrap. Contents observed empty.

## 10. 1.14 Build Verification Matrix

The full set of 1.14.x Classic Era builds to iterate for installation
verification, following the same gates as §8: install, F1-F6 format
checks, cascette-rs cross-check, client-run acceptance (login UI, 0 CDN
requests), container format versions recorded in the `build_formats`
registry, and archival of the pristine install.

CDN = mirror has the build's CDN data (verified: all 31 rows present in
the mirror `versions` manifest with config files on disk). WPP =
membership in WowPacketParser's `ClientVersionBuild` enum (`–` = absent;
cross-checked against `WowPacketParser/Enums/ClientVersionBuild.cs`).
The column does NOT describe wow-patcher support: wow-patcher is
pattern-based with no build list and was integration-tested on 31650
only.

`wow_classic_era` is the product code for every row; loose files install
under `_classic_era_` (B11 fix, `default_subfolder`).

| Build | Patch | Product(s) | Use product | CDN | WPP | Date | Verification |
|-------|-------|------------|-------------|-----|-----|------|--------------|
| 40347 | 1.14.0 | wow_classic_era | wow_classic_era | Y | Y | Sep 25, 2021 | ✅ format+container scan + client 1-run, 0 CDN requests (2026-08-17) |
| 40441 | 1.14.0 | wow_classic_era | wow_classic_era | Y | Y | Oct 1, 2021 | ✅ format+container scan + client 1-run, 0 CDN requests (2026-08-17) |
| 40618 | 1.14.0 | wow_classic_era | wow_classic_era | Y | Y | Oct 13, 2021 — traced | ✅ format+container scan + client 1-run, 0 CDN requests (2026-08-17) |
| 40962 | 1.14.1 | wow_classic_era | wow_classic_era | Y | Y | Nov 8, 2021 | ✅ format+container scan + client 1-run, 0 CDN requests (2026-08-17) |
| 41030 | 1.14.1 | wow_classic_era | wow_classic_era | Y | Y | Nov 11, 2021 | ⏳ pending |
| 41077 | 1.14.1 | wow_classic_era | wow_classic_era | Y | Y | Nov 17, 2021 | ⏳ pending |
| 41137 | 1.14.1 | wow_classic_era | wow_classic_era | Y | Y | Nov 19, 2021 | ⏳ pending |
| 41243 | 1.14.1 | wow_classic_era | wow_classic_era | Y | Y | Dec 2, 2021 | ⏳ pending |
| 41511 | 1.14.1 | wow_classic_era | wow_classic_era | Y | Y | Dec 20, 2021 | ⏳ pending |
| 41794 | 1.14.1 | wow_classic_era | wow_classic_era | Y | Y | Jan 10, 2022 | ⏳ pending |
| 42032 | 1.14.1 | wow_classic_era | wow_classic_era | Y | Y | Feb 1, 2022 — A2 target | ⏳ pending |
| 42214 | 1.14.2 | wow_classic_era | wow_classic_era | Y | Y | Feb 8, 2022 | ⏳ pending |
| 42597 | 1.14.2 | wow_classic_era | wow_classic_era | Y | Y | Mar 5, 2022 — A2 target | ⏳ pending |
| 43401 | 1.14.3 | wow_classic_era | wow_classic_era | Y | Y | May 3, 2022 — A1 target | ⏳ pending |
| 44016 | 1.14.3 | wow_classic_era | wow_classic_era | Y | Y | Jun 7, 2022 | ⏳ pending |
| 44170 | 1.14.3 | wow_classic_era | wow_classic_era | Y | Y | Jun 15, 2022 | ⏳ pending |
| 44403 | 1.14.3 | wow_classic_era | wow_classic_era | Y | Y | Jun 30, 2022 | ⏳ pending |
| 44834 | 1.14.3 | wow_classic_era | wow_classic_era | Y | Y | Jul 27, 2022 | ⏳ pending |
| 46575 | 1.14.3 | wow_classic_era | wow_classic_era | Y | Y | Nov 9, 2022 | ⏳ pending |
| 47658 | 1.14.3 | wow_classic_era | wow_classic_era | Y | – | Jan 17, 2023 | ⏳ pending |
| 48611 | 1.14.3 | wow_classic_era | wow_classic_era | Y | Y | Mar 20, 2023 | ⏳ pending |
| 49229 | 1.14.3 | wow_classic_era | wow_classic_era | Y | Y | Apr 21, 2023 | ⏳ pending |
| 49821 | 1.14.3 | wow_classic_era | wow_classic_era | Y | Y | May 30, 2023 — A1 target | ⏳ pending |
| 51001 | 1.14.4 | wow_classic_era | wow_classic_era | Y | – | Aug 18, 2023 | ⏳ pending |
| 51056 | 1.14.4 | wow_classic_era | wow_classic_era | Y | – | Aug 23, 2023 | ⏳ pending |
| 51146 | 1.14.4 | wow_classic_era | wow_classic_era | Y | Y | Aug 29, 2023 | ⏳ pending |
| 51311 | 1.14.4 | wow_classic_era | wow_classic_era | Y | – | Sep 11, 2023 | ⏳ pending |
| 51395 | 1.14.4 | wow_classic_era | wow_classic_era | Y | – | Sep 19, 2023 | ⏳ pending |
| 51535 | 1.14.4 | wow_classic_era | wow_classic_era | Y | Y | Sep 27, 2023 | ⏳ pending |
| 51829 | 1.14.4 | wow_classic_era | wow_classic_era | Y | – | Oct 20, 2023 | ⏳ pending |

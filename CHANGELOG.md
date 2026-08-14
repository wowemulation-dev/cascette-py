# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `cascette builds ribbit-files <product> <build>` command: generates the
  simulated `versions`/`cdns` BPSV replies a wow client and cascette tooling
  expect, from the build database. Replaces the Arctium archive fetch used
  by `tools/setup_local_ribbit.sh`, which does not carry versions files for
  historical builds. Hosts are rewritten to the chosen mirror (`--host`).
- `--loose-only` and `--subfolder` options on `install install-to-casc`:
  stage-1 installs write only the install-manifest loose files (Wow.exe,
  DLLs, locale packs) plus layout metadata, and place them under the product
  subfolder (e.g. `_classic_`) matching Agent.exe's LooseFileHandler.
- `keyring`, `regions`, `seqn` columns on the wago build database, populated
  from Ribbit and BlizzTrack syncs; additive migration for existing DBs.
- `TACTClient` `base_url` override (also via `CASCETTE_RIBBIT_BASE_URL`) so
  Ribbit fetches can be pointed at a local mirror serving seeded
  versions/cdns files.
- `tools/range_http_server.py` and `tools/setup_local_ribbit.sh`, imported
  from cascette-rs for local CDN mirror serving.


- `LocalStorage` now writes the agent-format local data files the 1.13.2
  client accepts: a 480-byte segment header (16 reconstruction headers, one
  per KMT bucket) at `data.000` offset 0, and a 30-byte `LocalHeader`
  (full 16-byte reversed key, `encoded_size` including the header,
  checksum_a = `hashlittle(header[0:22], 0x3D6BE971)`, checksum_b = XOR/LUT
  scramble) before every BLTE entry. Previously cascette-py wrote raw
  headerless blobs; the client's `ValidateDataIntegrity` flagged the whole
  store invalid and re-fetched files on first launch. Verified byte-identical
  against a client-written entry (ekey `59cad02d...` header key field
  `1b856f76...`, `enc_size` 13061932 = 30 + payload).
- `LocalStorage.read_content` skips the 30-byte local header when present,
  mirroring cascette-rs.
- `LocalStorage.load_existing_entries` restores the archive write position
  so resumed installs append after existing data instead of overwriting it.
### Fixed

- `.build.info` writer now emits the 14-column Agent.exe header (no KeyRing
  column). The previous 15-column header would misalign Product during the
  client's PSV parse. Product is now the requested TACT product code
  (`wow_classic`), not the build-config display name (`WoW`); Install Key is
  the install manifest encoding key; CDN Hosts/Servers are split correctly.
- `apply_tag_query` now implements OR-within-group / AND-between-groups tag
  semantics matching Agent.exe and cascette-rs. Previously additive tags
  were OR'd across groups, selecting all files for queries like
  `Windows,x86_64,enUS`.
- `.patch.result` is written as ASCII text (`"0\n"`, matching the reference
  installation) instead of the binary byte `0x01`. The client reads it on
  startup; a missing or non-zero file triggers the online update check.
- Catalog sync no longer fails when a root fragment ref gates on a bare
  boolean `requires` (build 4957 emits `"requires": true` for fragments
  without a gating condition); the boolean normalizes to the
  `{"always": ...}` criteria form.

## [0.3.0] - 2026-08-01

### Added

- TPR product catalog support for the `catalogs` Ribbit product (`tpr/catalogs`):
  - `cascette catalog` command group (`sync`, `list`, `programs`, `show`,
    `licenses`, `installs`, `stats`) for inspecting products, entitlement
    rules, license requirements, and install configurations
  - Catalog JSON fragment parser (`formats/catalog.py`) covering both the
    v23 (flat dict) and v30 (`definitions` list) schemas; preserves raw JSON
    for byte-exact round-trips
  - SQLite catalog database with per-fragment tables for products, programs,
    rules, license IDs, installs, categories, and types
  - 24-hour local fragment cache (same pattern as wago.tools)
  - Encrypted fragment metadata recorded (decryption key id, encrypted hash)
    without downloading content the CDN does not serve
  - `catalogs` product code added to the `Product` enum
- `bts` (Battle.net Setup) product code in the `Product` enum
- `cascette inspect download` command for download manifest examination
- Ribbit live-version sync source for the builds database (deduplicated on
  import by product, build, and build config)
- Hatchling build backend and GitHub Actions CI workflow
- Tests for CLI commands, CDN archive fetcher, and BlizzTrack client
- `cascette config mirror` CLI command group for managing CDN mirror configuration
  (add, remove, list, reset subcommands)
- `ProductFamily` enum and `PRODUCT_FAMILY_MAP` in `core/types.py` mapping each
  `Product` to its family (wow, diablo, starcraft, battlenet, etc.)
- `MirrorConfig` and `MirrorSettings` models for user-configurable CDN mirrors
  with per-family and per-product-code granularity
- `resolve_mirrors_for_product()` function implementing a 4-level resolution chain:
  product override, family config, built-in family defaults, generic fallback
- `AppConfig.create_cdn_config()` method that builds a `CDNConfig` with mirrors
  resolved for a specific product
- BlizzTrack API client (`BlizzTrackClient`) for fetching historical and current
  NGDP manifest data across all TACT products
- Consolidated CLI command structure:
  - `cdn` command: Download data from Blizzard's NGDP CDN infrastructure
  - `inspect` command: Examine and analyze NGDP/CASC format files
  - `install` command: Install and manage game content via the NGDP/CASC pipeline
- ZBSDIFF patch triplet downloader script (`scripts/download_zbsdiff_triplets.py`)
  for Rust verification
- Product codes `wow_classic_titan` and `wow_anniversary` across all modules
- mise hint in README.md Prerequisites section
- `.markdownlint-cli2.jsonc` and `.markdownlintignore` for markdown linting config
- `.build.info` parser (`BuildInfoParser`) with parse/build methods for round-trip support
- `LocalBuildInfo` model representing complete `.build.info` file structure
- `LocaleConfig` type in `core/types.py` for locale configuration with speech/text flags
- Resume detection in `install-to-casc` command via `--resume/--no-resume` flags
- `--force` flag to override existing `.build.info` during installation
- Early `.build.info` creation before downloads to lock configuration
- Tag configuration display table showing platform, architecture, locale, and region
- Bob Jenkins' lookup3 hash functions (`hashlittle`, `hashlittle2`) for CASC index
  file checksum validation
- New `crypto` module providing cryptographic hash utilities
- Product state file generation (`product_state.py`) for Battle.net compatible installations
- Local .idx file parser (V7/V8 format) for scanning existing installations
- Multi-locale tag parsing from `.build.info` with speech/text content flags
- Test suite for `BuildInfoParser` with 24 tests
### Changed

- CDN mirror selection moved from hardcoded `_get_cdn_mirrors_for_product()` in
  `cdn.py` and `download_zbsdiff_triplets.py` to centralized `resolve_mirrors_for_product()`
  in `core/config.py`
- All CDN command callsites now use `AppConfig.create_cdn_config(product)` instead
  of manually constructing `CDNConfig` with inline mirror lists
- `CDNConfig.fallback_mirrors` defaults to empty list; mirrors are resolved
  per-product at construction time instead of carrying WoW-only defaults
- `CDNConfig` no longer has `base_url` property, `COMMUNITY_MIRROR_CDN_PATH`
  class variable, or `get_fallback_mirrors_for_cdn_path()` method
- `CDNClient` reads `config.fallback_mirrors` directly instead of calling
  `get_fallback_mirrors_for_cdn_path()` per request
- **BREAKING**: CLI commands restructured into agent.exe workflow:
  - Deleted: `analyze`, `examine`, `fetch`, `install_analyzer`, `install_poc`, `archive_search`
  - New consolidated commands: `cdn`, `inspect`, `install`
  - `archive` and `builds` commands updated to match new structure
- Patch archive parser now correctly handles extended header with encoding info
- ZBSDIFF parser fixed to use little-endian signed integers (was incorrectly using big-endian)
- TACT key sync uses batched `executemany` instead of per-key transactions
- Listfile sync drops FTS triggers during bulk load, rebuilds index once at the end
- Listfile sync now downloads from GitHub release asset instead of raw repo content
- TACT key sync URL updated to explicit `refs/heads/master` path
- TACT key parser fixed to use space-separated format (was incorrectly splitting on semicolons)
- CDN client now fetches servers from Ribbit endpoint dynamically instead of using hardcoded list
- Community mirrors (arctium, wago, archive.wow.tools) are now fallback-only after Ribbit servers
- Installation workflow now creates `.build.info` at start (Step 1.5) rather than end
- `install_analyzer.py` uses `BuildInfoParser` instead of inline parsing
- `LocaleConfig` moved from `install_analyzer.py` to `core/types.py` for reuse
- Installation scanner now displays all installed locales with content type flags
- Dependencies updated to current versions; switched from `cryptography` to `pycryptodome`
- Removed unused dev dependencies (`pytest-asyncio`, `pytest-mock`, `types-aiofiles`,
  `mypy-extensions`, `pathspec`, `packaging`)
- Added `beautifulsoup4` to dev dependencies for wiki scraping scripts
- Renamed `mise.toml` to `.mise.toml` (hidden config convention)
- Expanded `.markdownlint.jsonc` with stricter rules and allowed language list
- Switched markdown linting from `markdownlint-cli2` to `markdownlint` (DavidAnson/markdownlint);
  removed `.markdownlint-cli2.jsonc` (config now lives solely in `.markdownlint.jsonc`)
- Scripts now use `httpx` instead of `requests`
- `import_missing_builds.py` uses generic product matching instead of hardcoded product list
- Whole-project `ruff format` applied (124 files)
- Pyright now runs over `tests/` in addition to `cascette_tools`
- Console output is TTY-aware: piped output renders plain text without ANSI
  escape sequences
### Fixed

- Patch archive parser incorrectly rejecting extended header flag (now properly parses encoding info)
- ZBSDIFF parser using wrong byte order for size fields (changed from big-endian >Q to little-endian <q)
- ZBSDIFF control entry parsing using two's complement instead of sign-magnitude encoding
- TACT key sync returning 0 keys due to semicolon-split parser on space-separated data
- Tag parsing now correctly extracts all locales from colon-separated groups
- Pyright type errors in `install_analyzer.py` resolved
- Bare `except` in `import_missing_builds.py` replaced with `except ValueError`
- Builds deduplicated by natural key `(product, build, build_config)` instead
  of `(id, product)`
- Catalog build selection orders by build number (`VersionsName`); Ribbit's
  `BuildId` is not monotonic across catalog versions
- Pre-existing pyright errors in `tests/test_commands/test_config_cmd.py`
  resolved (typed `_invoke` return as `click.testing.Result`)

## [0.2.0] - 2025-09-24

### Added

- CDN archive index parser supporting both regular archives and archive-groups
- New `archive` CLI command for examining CDN archive indices and archive-groups
- Battle.net agent/app examination support
- Enhanced Wago.tools database integration for agent builds
- Download manifest parser improvements for handling agent files
- New script for fetching all builds (`scripts/fetch_all_builds.py`)
- Improved import scripts for missing builds

### Fixed

- Pyright and ruff linting issues resolved
- Type hints corrections across multiple modules
- Test compatibility improvements

### Changed

- Documentation updated to reflect current CLI commands and coverage statistics
- Migrated from mypy to pyright for type checking
- Updated Python version requirement to 3.12+
- Command references updated (`cascette builds sync` instead of deprecated commands)
- Removed marketing language in favor of factual descriptions

## [0.1.0] - 2025-09-19

### Added

- Initial release of cascette-tools
- BLTE format parser with compression modes (N, Z, L, E, F)
- Encoding file parser with page-based architecture
- Root file parser supporting versions 1-4
- CDN client for fetching files from Blizzard/mirror services
- CLI commands: examine, fetch, analyze, validate
- Wago.tools API integration with SQLite caching
- TACT key database management
- FileDataID to path mapping (listfile) support
- Build database management commands
- Comprehensive test suite with 80% coverage requirement

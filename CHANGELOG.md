# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
- Scripts now use `httpx` instead of `requests`
- `import_missing_builds.py` uses generic product matching instead of hardcoded product list

### Fixed

- TACT key sync returning 0 keys due to semicolon-split parser on space-separated data
- Tag parsing now correctly extracts all locales from colon-separated groups
- Pyright type errors in `install_analyzer.py` resolved
- Bare `except` in `import_missing_builds.py` replaced with `except ValueError`

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

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

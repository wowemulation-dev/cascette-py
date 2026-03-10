# Cascette Tools

Python tools for NGDP/CASC format analysis.

<div align="center">

[![Discord](https://img.shields.io/discord/1394228766414471219?logo=discord&style=flat-square)](https://discord.gg/Jj4uWy3DGP)
[![Sponsor](https://img.shields.io/github/sponsors/danielsreichenbach?logo=github&style=flat-square)](https://github.com/sponsors/danielsreichenbach)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE-APACHE)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE-MIT)

</div>

## Overview

Python package for working with Blizzard's NGDP (Next Generation
Distribution Pipeline) and CASC (Content Addressable Storage Container)
formats. Provides command-line tools and programmatic APIs for analyzing
and parsing game data files.

## Features

- **Format Support**: Parsers for BLTE, Encoding, Root, Install, Download,
  and Archive formats
- **CDN Integration**: Direct access to Blizzard CDN and mirror services
- **Type Safety**: Full type hints and Pydantic models for data validation
- **Async Support**: Efficient concurrent operations for network requests
- **Caching**: Multi-layer caching for improved performance
- **CLI Interface**: Rich command-line interface with comprehensive subcommands
- **Test Coverage**: 48 test files with 80% minimum coverage enforced

## Installation

### Development Installation

```bash
# Clone the repository
git clone https://github.com/wowemulation-dev/cascette-py.git
cd cascette-py

# Install dependencies (requires uv: https://docs.astral.sh/uv/)
uv sync --all-extras
```

### Production Installation

```bash
uv pip install cascette-tools
```

## Quick Start

### Command Line Usage

```bash
# Show help
cascette --help

# Check version
cascette version

# Inspect CASC format files
cascette inspect blte <file>             # Examine BLTE compressed files
cascette inspect encoding <hash>         # Examine encoding files
cascette inspect config <file>           # Examine build/CDN config files
cascette inspect archive <file>          # Examine archive index files
cascette inspect download --product wow  # Examine download manifest
cascette inspect stats <file>            # Show file statistics
cascette inspect compression <file>      # Analyze BLTE compression
cascette inspect coverage <files...>     # Analyze content coverage
cascette inspect dependencies <file>     # Trace content key dependencies

# Download data from CDN
cascette cdn config <hash>               # Fetch configuration files
cascette cdn encoding <hash>             # Fetch encoding files
cascette cdn data <hash>                 # Fetch data archives
cascette cdn patch <hash>                # Fetch patch files
cascette cdn build <product> <version>   # Fetch complete build data
cascette cdn manifests <product>         # Fetch TACT manifests (versions/cdns)
cascette cdn batch <file>                # Batch fetch from hash list

# Work with archive indices
cascette archive examine <file>          # Examine archive index files
cascette archive find <key> <file>       # Find entry by encoding key
cascette archive find-key <key> <dir>    # Find which archive contains a key
cascette archive extract-key <key> <dir> # Extract data for an encoding key
cascette archive scan <directory>        # Scan for archive-groups
cascette archive validate-mapping <dir>  # Validate archive index mapping

# Validate formats
cascette validate format <file>          # Validate individual files
cascette validate integrity <file>       # Check checksums
cascette validate relationships <files>  # Validate cross-references
cascette validate roundtrip <file>       # Test parse/build cycle
cascette validate batch <directory>      # Batch validate files

# Install and manage game content
cascette install resolve-manifests ...   # Resolve all manifests from a build
cascette install discover-latest <prod>  # Discover latest build for a product
cascette install scan-state <dir>        # Scan a local installation
cascette install progress <dir>          # Show installation progress

# Manage TACT keys
cascette tact list                       # List known TACT keys
cascette tact search <key_id>            # Search for a specific key
cascette tact sync                       # Sync with wowdev/TACTKeys repository
cascette tact export <file>              # Export keys to JSON file
cascette tact stats                      # Show key database statistics

# Manage listfiles
cascette listfile search <pattern>       # Search for file paths
cascette listfile lookup <fdid|path>     # Lookup by FDID or path
cascette listfile sync                   # Sync with wowdev/wow-listfile
cascette listfile export <file>          # Export listfile to file
cascette listfile stats                  # Show listfile statistics
```

### Python API Usage

```python
from cascette_tools.core.types import Product, BuildInfo
from cascette_tools.core.config import AppConfig

# Configure the application
config = AppConfig()

# Use the types for validation
product = Product.WOW_CLASSIC
build_info = BuildInfo(
    build_config="1234567890abcdef1234567890abcdef12345678",
    cdn_config="abcdef1234567890abcdef1234567890abcdef12"
)
```

## Package Structure

```text
cascette_tools/
├── __main__.py              # CLI entry point, registers 8 command groups
├── core/                    # Shared functionality
│   ├── types.py             # Pydantic models (BuildInfo, Product, CDNConfig, etc.)
│   ├── config.py            # AppConfig with CDN URLs, timeouts, paths
│   ├── cdn.py               # CDN client (Ribbit primary, community mirror fallback)
│   ├── cdn_archive_fetcher.py  # Archive index downloading, HTTP range extraction
│   ├── cache.py             # Multi-layer disk caching
│   ├── build_update.py      # Build update orchestration
│   ├── containerless_storage.py  # Containerless CASC storage mode
│   ├── containerless_update.py   # Containerless update logic
│   ├── download_queue.py    # Prioritized download queue management
│   ├── encoding_cache.py    # Encoding file caching layer
│   ├── install_state.py     # Installation state tracking
│   ├── integrity.py         # Data integrity verification
│   ├── local_storage.py     # Local CASC directory structure
│   ├── product_state.py     # Battle.net agent state files
│   ├── shmem.py             # Shared memory segment handling
│   ├── tact.py              # TACT encryption key handling
│   └── utils.py             # Hex conversion, MD5, Jenkins96 hash
├── formats/                 # Binary format parsers
│   ├── base.py              # FormatParser[T: BaseModel] abstract base
│   ├── blte.py              # BLTE compression (modes: N/Z/L/E/F)
│   ├── blte_integration.py  # BLTE integration helpers
│   ├── encoding.py          # Encoding file (CKey/EKey lookup)
│   ├── root.py              # Root file (versions 1-4)
│   ├── config.py            # Build/CDN/product/patch config parsers
│   ├── build_info.py        # .build.info file parser
│   ├── archive.py           # CDN archive index
│   ├── cdn_archive.py       # CDN archive format
│   ├── file_db.py           # File database format
│   ├── install.py           # Install manifest
│   ├── download.py          # Download manifest
│   ├── patch_archive.py     # Patch archive (PA) format
│   ├── size.py              # Size-related format parsing
│   ├── zbsdiff.py           # ZBSDIFF binary diff
│   └── tvfs.py              # TVFS virtual file system
├── commands/                # Click CLI command groups (8 groups)
│   ├── archive.py           # archive: examine, scan, find, find-key, extract-key, validate-mapping
│   ├── builds.py            # builds: sync, list, search, stats, export, import
│   ├── cdn.py               # cdn: config, data, build, encoding, batch, patch, manifests
│   ├── inspect.py           # inspect: blte, encoding, config, archive, stats, compression, coverage, dependencies
│   ├── install.py           # install: resolve-manifests, discover-latest, scan-state, progress, and more
│   ├── listfile.py          # listfile: sync, search, lookup, export, stats, import
│   ├── tact.py              # tact: sync, list, search, export, stats, import
│   └── validate.py          # validate: format, integrity, roundtrip, relationships, batch
├── database/                # External data integrations
│   ├── wago.py              # Wago.tools API client
│   ├── tact_keys.py         # TACT key database
│   └── listfile.py          # FileDataID-to-path mapping
└── crypto/                  # Cryptographic utilities
    └── jenkins.py           # Bob Jenkins lookup3 hash

tests/                       # Test suite (48 test files, 80% coverage minimum)
├── conftest.py              # Shared fixtures for CLI mocking and CDN responses
├── test_cli.py              # Main CLI integration tests
├── test_core/               # Core module tests
├── test_formats/            # Format parser tests
├── test_commands/           # CLI command tests
├── test_database/           # Database tests
└── test_crypto/             # Cryptographic utility tests
```

## Development

### Prerequisites

- Python 3.12 or higher
- [uv](https://docs.astral.sh/uv/) package manager

Optionally, [mise](https://mise.jdx.dev/) can manage Python versions and
development tools like `uv` per-project. With mise installed, run `mise install`
in the repository root to set up the pinned toolchain automatically.

### Development Setup

```bash
# Install development dependencies
uv sync --all-extras

# Run tests (80% coverage minimum enforced)
uv run pytest

# Run tests with HTML coverage report
uv run pytest --cov-report=html

# Type checking
uv run pyright cascette_tools

# Code formatting
uv run black cascette_tools tests

# Linting
uv run ruff check cascette_tools tests
```

## Code Quality and Validation

### Python Code Validation

All Python code in the cascette-tools package must pass these validation steps:

```bash
# Linting and code quality checks
uv run ruff check cascette_tools tests

# Type checking and static analysis
uv run pyright cascette_tools

# Code formatting (auto-fix)
uv run black cascette_tools tests

# Test coverage requirements (80% minimum enforced via pyproject.toml)
uv run pytest
```

### Pre-commit Workflow

Before committing changes:

```bash
# Run all quality checks
uv run ruff check cascette_tools tests && \
uv run pyright cascette_tools && \
uv run pytest

# Auto-fix formatting issues
uv run black cascette_tools tests
uv run ruff check --fix cascette_tools tests
```

### Type Safety

The package enforces strict typing:

- All functions have type hints
- Pydantic models for data validation
- `pyright` in strict mode catches type errors
- Generic types for format parsers

### Testing Strategy

```bash
# Unit tests only
uv run pytest -m unit

# Integration tests (may require network)
uv run pytest -m integration

# Exclude slow tests for quick feedback
uv run pytest -m "not slow"

# Run specific test files
uv run pytest tests/test_formats/test_blte.py

# Run with verbose output
uv run pytest -v

# Generate HTML coverage report
uv run pytest --cov-report=html
# Open htmlcov/index.html in browser
```

## Foundation: Wago.tools Build Database

**CRITICAL**: Our entire format evolution analysis depends on the comprehensive
build database maintained by [Wago.tools](https://wago.tools). This database
contains 1,900+ WoW builds from 6.0.x (Warlords of Draenor) through current
versions across all products.

### First-Time Setup (Essential)

```bash
# Fetch TACT manifests for a product (required for analysis)
cascette cdn manifests wow

# Or fetch specific build data
cascette cdn build wow 11.0.2.56461

# This downloads build metadata and manifest files for analysis
# Products include: wow, wow_classic, wow_classic_era, wow_classic_titan, wow_anniversary, wowt, wow_beta
```

Wago.tools data provides:

- Complete build history from WoD 6.0.x onward

- Coverage for retail, classic, PTR, and beta branches

- Regular updates with new builds

- Access to build metadata with good availability

### Quick Start

After fetching build data:

```bash
# Validate downloaded files
cascette validate batch test_data/

# Analyze file statistics
cascette inspect stats <file>

# Check compression effectiveness
cascette inspect compression <blte_file>
```

## Command Categories

### Essential Foundation Commands

**Start here - these provide the data for all other analysis:**

| Command | Purpose | Usage |
|---------|---------|--------|
| **`cascette builds sync`** | **Fetch build database from Wago.tools and BlizzTrack** | **`cascette builds sync`** |

### Core Inspection Commands

These commands examine individual files:

| Command | Purpose | Usage |
|---------|---------|--------|
| `cascette inspect blte` | BLTE decompression and analysis | `cascette inspect blte <input.blte> -o <output.dat>` |
| `cascette inspect encoding` | Encoding file analysis and content key lookup | `cascette inspect encoding <encoding_hash>` |
| `cascette inspect config` | Build and CDN configuration analysis | `cascette inspect config <file>` |
| `cascette inspect archive` | Archive index file analysis | `cascette inspect archive <file>` |
| `cascette inspect download` | Download manifest priority and platform tags | `cascette inspect download --product wow` |
| `cascette inspect stats` | Show file statistics and metadata | `cascette inspect stats <file>` |
| `cascette inspect compression` | Analyze BLTE compression effectiveness | `cascette inspect compression <blte_file>` |
| `cascette inspect coverage` | Analyze content coverage across files | `cascette inspect coverage <files...>` |
| `cascette inspect dependencies` | Trace content key to encoding key to archive | `cascette inspect dependencies <file>` |

### Verification Suite

These commands validate format files:

| Command | Purpose | Usage |
|---------|---------|--------|
| `cascette validate format` | Validate individual format files | `cascette validate format <file>` |
| `cascette validate integrity` | Check file checksums and integrity | `cascette validate integrity <file>` |
| `cascette validate relationships` | Validate cross-file references | `cascette validate relationships <files>` |
| `cascette validate roundtrip` | Test parse/build cycle correctness | `cascette validate roundtrip <file>` |
| `cascette validate batch` | Batch validate multiple files | `cascette validate batch <directory>` |

### CDN Download Commands

Commands for downloading data from Blizzard's CDN:

| Command | Purpose | Usage |
|---------|---------|--------|
| `cascette cdn config` | Fetch configuration files from CDN | `cascette cdn config <hash>` |
| `cascette cdn encoding` | Fetch encoding file by hash | `cascette cdn encoding <hash>` |
| `cascette cdn data` | Fetch data archives from CDN | `cascette cdn data <hash>` |
| `cascette cdn patch` | Fetch patch files from CDN | `cascette cdn patch <hash>` |
| `cascette cdn build` | Fetch complete build information | `cascette cdn build <product> <version>` |
| `cascette cdn manifests` | Fetch TACT manifests (versions and cdns) | `cascette cdn manifests <product>` |
| `cascette cdn batch` | Batch fetch from a list of hashes | `cascette cdn batch <file>` |

### Utility Commands

| Command | Purpose | Usage |
|---------|---------|--------|
| `cascette tact list` | List known TACT encryption keys | `cascette tact list` |
| `cascette tact sync` | Sync TACT keys from repository | `cascette tact sync` |
| `cascette listfile search` | Search FileDataID to path mappings | `cascette listfile search <pattern>` |
| `cascette listfile sync` | Sync listfile from repository | `cascette listfile sync` |
| `cascette version` | Show version information | `cascette version` |

## Output Directory Structure

All analysis results are saved to the `results/` directory:

```text
~/.local/share/cascette-tools/   # XDG data directory
├── wago_builds.db               # SQLite build database
├── wago_cache/                  # Wago API response cache (24-hour)
├── tact_keys.db                 # TACT key database
└── listfile.db                  # FileDataID mapping database

test_data/                       # Downloaded CASC files (gitignored)
├── wago-builds-*.json
└── wow_*_*.dat/txt              # Cached CASC files
```

## Recommended Usage Workflow

### Complete End-to-End Example

Here's the recommended sequence for a complete download, examination, and
verification process:

```bash
# Step 1: Fetch build database (one-time setup)
cascette builds sync

# Step 2: Validate downloaded files
cascette validate batch test_data/

# Step 3: Analyze file statistics
cascette inspect stats <file>

# Step 4: Check compression effectiveness
cascette inspect compression <blte_file>

# Step 5: Validate file integrity
cascette validate integrity <file>

# Step 6: Review data storage
ls -lh ~/.local/share/cascette-tools/
```

### 0. Essential First Step - Get Build Database

**REQUIRED** before any analysis:

```bash
# Fetch build database from Wago.tools and BlizzTrack
cascette builds sync

# This creates a local SQLite database with build metadata
# All other commands automatically detect and use this data
```

Without this step, format evolution analysis is impossible.

### 1. Initial Setup and Verification

Verify the tools are working correctly:

```bash
# Fetch Wago build database
cascette builds sync

# Test fetching a config file
cascette cdn config <hash>

# Validate a downloaded file
cascette validate format <file>
```

This validates our format documentation against real WoW builds and caches
files for future analysis. The test suite ensures all tools are functioning
properly with appropriate timeouts for network operations.

### 2. Individual Build Analysis

To examine a specific build:

```bash
# Fetch a complete build (downloads ~50MB of data)
cascette cdn build wow_classic_era 1.13.7.38704

# Examine specific files from that build
cascette inspect encoding bbf06e74  # Encoding file hash from build output
```

### 3. Format Analysis

To analyze format characteristics:

```bash
# Analyze file statistics
cascette inspect stats <file>

# Analyze BLTE compression effectiveness
cascette inspect compression <blte_file>

# Analyze content coverage across files
cascette inspect coverage <encoding_file> <root_file>

# Trace file dependencies
cascette inspect dependencies <file>
```

These scripts examine builds chronologically to identify when format changes
occurred. The specialized trackers provide detailed analysis of specific format
aspects and generate comprehensive reports in the `results/` directory.

### 4. Patch System Analysis

Examine the NGDP patch system:

```bash
# Fetch patch files
cascette cdn patch <hash>

# Fetch patch index files
cascette cdn patch <hash> --index

# Validate patch file format
cascette validate format <patch_file>
```

These tools examine PA (Patch Archive) format, ZBSDIFF1 patch format, and
the patch-entry structure in patch configurations.

### 5. Individual File Analysis

For detailed examination of specific file formats:

```bash
# Decompress BLTE files
cascette inspect blte compressed_file.blte -o decompressed.dat

# Examine encoding files
cascette inspect encoding <encoding_hash>
```

### 6. Data Management

Manage downloaded data:

```bash
# List downloaded files
ls -la test_data/

# Check database status
ls -lh ~/.local/share/cascette-tools/wago_builds.db

# View Wago cache status (24-hour cache)
ls -la ~/.local/share/cascette-tools/wago_cache/
```

## Data Sources

### Primary Source: Wago.tools API

**The foundation of all format analysis:**

- **API Endpoint**: `https://wago.tools/api/builds`

- **Coverage**: 1,900+ builds from WoD 6.0.x through current

- **Products**: wow, wow_classic, wow_classic_era, wow_classic_titan,
  wow_anniversary, wowt, wow_beta, and more

- **Freshness**: Updated regularly as new builds are released

- **Reliability**: Maintained by WoW development community

**Data Structure**: Each build includes:

- `build_config`: Hash for build configuration file

- `cdn_config`: CDN configuration hash

- `product_config`: Product-specific configuration

- `version`: Version string (e.g., "11.2.0.62706")

- `created_at`: Build timestamp

- `is_bgdl`: Background download flag

### CDN Access for File Downloads

Tools fetch CDN server lists from Blizzard's Ribbit endpoint dynamically.
Community mirrors (`cdn.arctium.tools`, Wago, `archive.wow.tools`) serve as
fallback when Ribbit servers are unavailable:

- Ribbit servers are the primary source for file retrieval

- Community mirrors provide fallback availability

- Uses hashes from Wago.tools data to fetch actual files

### Legacy Build Information

Fallback sources (no longer primary):

- `../docs/builds-20250821-133310.json` - Old archived build list

- Manual build configuration hashes from known sources

- Strategic builds selected across WoW expansion history

## File Format Support

### Supported Formats

| Format | Parser | Status | Notes |
|--------|--------|---------|--------|
| BLTE | `formats/blte.py` | Working | Compression modes N, Z, L, E, F |
| Encoding | `formats/encoding.py` | Working | Content key lookup, ESpec support |
| Root | `formats/root.py` | Working | Versions 1-4, TSFM/MFST magic detection |
| TVFS | `formats/tvfs.py` | Working | Header parsing, table analysis, version 1 format |
| Build Config | `formats/config.py` | Working | All field types, space-separated values |
| Build Info | `formats/build_info.py` | Working | .build.info parse/build round-trip |
| Install | `formats/install.py` | Basic | Magic detection, header parsing |
| Download | `formats/download.py` | Basic | Magic detection, header parsing |
| Archive | `formats/archive.py` | Working | CDN archive index, archive-groups |
| Patch Archive | `formats/patch_archive.py` | Working | PA format parsing |
| ZBSDIFF | `formats/zbsdiff.py` | Working | Binary diff format |

### Format Versions Detected

- **Root Files**: Versions 1-4 with automatic version detection

- **BLTE**: All known compression modes and block structures

- **Encoding**: Page-based architecture with ESpec integration

- **Config Files**: Evolution from WoD (6.0.x) through TWW (11.x)

## Cache System

### Storage Location

All downloaded files are cached in `test_data/` directory:

- Automatically created on first run

- Completely ignored by git (see `.gitignore`)

- Organized with descriptive filenames

### Cache Naming Convention

Files are named as: `{product}_{version}_{file_type}_{hash_prefix}.{extension}`

Examples:

- `wow_classic_era_1.13.7.38704_root_b98595f5.dat`

- `wow_11.2.0.62706_encoding_bbf06e74.dat`

- `wow_classic_era_1.13.7.38704_build_config_ae66faee.txt`

### Cache Benefits

- **Performance**: Subsequent runs use cached data instead of re-downloading

- **Offline Development**: Work with cached files when network unavailable

- **Bandwidth Conservation**: Avoid redundant downloads of large files

- **Analysis Traceability**: Filenames show exact build provenance

## Dependencies

### Installation

The package uses Python packaging with pyproject.toml:

#### Standard Installation

```bash
uv pip install cascette-tools
```

#### Development Installation

```bash
uv sync --all-extras
```

#### Core Dependencies

The package requires:

- `click` - CLI framework
- `pydantic` - Data validation
- `httpx` - Async HTTP client
- `rich` - Terminal formatting
- `structlog` - Structured logging
- `lz4` - LZ4 compression
- `pycryptodome` - Encryption support (Salsa20, ARC4)

### System Requirements

- Python 3.12+ (uses type hints and match statements)

- Internet connection for initial downloads

- ~200MB disk space for full cache

### Development Dependencies

For development and testing:

- `pytest` - Testing framework
- `pytest-cov` - Coverage reporting
- `pyright` - Type checking
- `ruff` - Fast Python linter
- `black` - Code formatting
- `beautifulsoup4` - Wiki scraping scripts

## Error Handling and Troubleshooting

### Common Issues

**CDN Connection Timeouts**:

```bash
# Use longer timeouts for slow connections
cascette cdn build --timeout 60 wow 11.2.0.62706
```

**Cache Corruption**:

```bash
# Remove cached data and retry
rm -rf ~/.local/share/cascette-tools/cache/
cascette builds sync
```

**Missing Build Data**:

- Ensure you've run `cascette builds sync` first

- Verify build configuration hashes are correct

- Some older builds may not be available on CDN

### Debugging Options

Most commands support verbose output:

```bash
cascette cdn build --verbose wow 11.2.0.62706
cascette inspect encoding <hash>
cascette --debug <command>  # Enable debug mode globally
```

## Development Workflow

### Adding New Analysis

1. Create new command module in `cascette_tools/commands/`
2. Use existing format parsers from `cascette_tools/formats/`
3. Register command group in `__main__.py` via `main.add_command()`
4. Add tests to `tests/` directory

### Testing Changes

```bash
# Run test suite (80% coverage minimum enforced)
uv run pytest

# Type checking
uv run pyright cascette_tools

# Linting
uv run ruff check cascette_tools tests
```

### Cache Management During Development

```bash
# Check database status
ls -lh ~/.local/share/cascette-tools/

# View downloaded test data
ls -la test_data/
```

## Format Examination Methodology

The examination tools use systematic analysis methods to understand NGDP/CASC
formats:

### Strategic Build Selection

Analysis targets key builds across WoW version transitions rather than
examining all 1,900+ builds. Selected builds represent:

- **Major Expansion Boundaries**: 6.0.x (WoD), 7.x (Legion), 8.x (BfA),

  9.x (Shadowlands), 10.x (Dragonflight), 11.x (TWW)

- **Format Transition Points**: Builds identified through version analysis as

  containing format changes

- **Cross-Product Coverage**: Retail (wow), Classic (wow_classic), and

  Classic Era (wow_classic_era) variants

- **Stability Focus**: First builds of stable versions rather than unstable

  PTR or beta builds

### Multi-Layer Analysis Approach

Each examination tool analyzes formats at multiple levels:

1. **Header Structure**: Magic signatures, version numbers, field counts,

   endianness detection

2. **Content Analysis**: Data patterns, compression types, encoding schemes,

   flag structures

3. **Evolution Tracking**: Changes over time, feature adoption patterns,

   cross-product variations

4. **Efficiency Metrics**: File sizes, compression ratios, bytes-per-entry

   calculations

### Verification Through Real Data

Format understanding is validated against actual CASC files:

- **Direct CDN Access**: Downloads files from cdn.arctium.tools using

  verified hashes

- **Binary Structure Parsing**: Examines actual byte layouts rather than

  theoretical specifications

- **Cross-Reference Validation**: Compares findings across multiple builds to

  identify patterns

- **Edge Case Discovery**: Real-world data reveals format variations not

  covered in documentation

### Intelligent Caching System

Downloaded files are cached with descriptive names to enable offline analysis:

- **Provenance Tracking**: Filenames include product, version, file type, and

  hash prefix

- **Selective Caching**: Only verified, successfully parsed files are retained

- **Development Efficiency**: Subsequent analysis runs use cached data instead

  of re-downloading

- **Storage Management**: Cache cleanup tools manage disk usage while

  preserving important samples

## Integration with Main Project

These tools inform the Rust implementation in several ways:

### Parser Design

- **Version Detection**: Tools identify which format versions exist across WoW

  history

- **Edge Cases**: Real-world data reveals parsing edge cases not documented

  elsewhere

- **Performance Patterns**: Analysis shows which optimizations matter for

  different file sizes

- **Format Evolution**: Timeline of changes guides backwards compatibility

  requirements

### Test Data Generation

- **Known Good Data**: Cached files provide test vectors for parser

  validation

- **Format Examples**: Real builds demonstrate format usage across different

  WoW versions

- **Regression Testing**: Historical builds verify parsers handle format

  evolution correctly

- **Edge Case Coverage**: Real-world files contain variations not present in

  synthetic test data

### Documentation Validation

- **Format Accuracy**: Tools validate documentation claims against actual CASC

  files

- **Evolution Timeline**: Precise transition points for format changes with

  exact build numbers

- **Implementation Requirements**: Real-world constraints and patterns

  discovered through analysis

- **Cross-Product Verification**: Confirms format consistency across wow,

  wow_classic, and wow_classic_era

### Format Discovery Process

The examination methodology follows a systematic discovery process:

1. **Initial Survey**: `cascette builds sync` fetches the build database from
   Wago.tools

2. **Strategic Sampling**: Builds are selected across WoW version transitions
   to identify format changes

3. **Detailed Analysis**: CLI inspection commands (`cascette inspect`)
   validate format assumptions against real files

4. **Verification**: Format parsers are tested against multiple builds to
   confirm consistency

5. **Documentation**: Findings are documented with exact build references and
   transition points

## Further Reading

- [Battle.net Installation Process Analysis](docs/battlenet-install-process.md)
- [Full Installation POC Plan](docs/full-install-poc-plan.md)
- [Full Installation Execution Plan](docs/full-installation-execution-plan.md)

## Support the Project

If you find this project useful, please consider
[sponsoring the project](https://github.com/sponsors/danielsreichenbach).

This is currently a nights-and-weekends effort by one person. Funding goals:

- **20 hours/week** - Sustained funding to dedicate real development time
  instead of squeezing it into spare hours
- **Public CDN mirror** - Host a community mirror for World of Warcraft builds,
  ensuring long-term availability of historical game data

## Contributing

See [AGENTS.md](AGENTS.md) for development setup and contribution guidelines.

## License

This project is dual-licensed under either:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

You may choose to use either license at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

---

**Note**: This project is not affiliated with Blizzard Entertainment. It is
an independent implementation based on reverse engineering by the World of
Warcraft emulation community.

# Cascette Tools

<div align="center">

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![Discord](https://img.shields.io/discord/1394228766414471219?logo=discord&style=flat-square)](https://discord.gg/Q44pPMvGEd)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE-MIT)

</div>

Python tools for NGDP/CASC format analysis.

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
- **Test Coverage**: Comprehensive test suite with 905 tests (74% coverage)

## Installation

### Development Installation

```bash
# Clone the repository
git clone https://github.com/wowemulation-dev/cascette-py.git
cd cascette-py

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# or
.venv\Scripts\activate  # Windows

# Install in development mode with all dependencies
pip install --upgrade pip setuptools wheel
pip install -e ".[dev]"
```

### Production Installation

```bash
pip install cascette-tools
```

## Quick Start

### Command Line Usage

```bash
# Show help
cascette --help

# Check version
cascette version

# Examine various CASC formats
cascette examine encoding <hash>         # Examine encoding files
cascette examine blte <file>             # Examine BLTE files
cascette examine config <file>           # Examine config files
cascette examine archive <file>          # Examine archive index files

# Fetch data from CDN
cascette fetch config <hash>             # Fetch configuration files
cascette fetch encoding <hash>           # Fetch encoding files
cascette fetch data <hash>               # Fetch data archives
cascette fetch patch <hash>              # Fetch patch files
cascette fetch build <product> <version> # Fetch complete build data
cascette fetch manifests <product>       # Fetch TACT manifests (versions/cdns)
cascette fetch batch <file>              # Batch fetch from hash list

# Analyze formats
cascette analyze stats <file>            # Show file statistics
cascette analyze compression <file>      # Analyze BLTE compression
cascette analyze coverage <files...>     # Analyze content coverage
cascette analyze dependencies <file>     # Trace file dependencies

# Validate formats
cascette validate format <file>          # Validate individual files
cascette validate integrity <file>       # Check checksums
cascette validate relationships <files>  # Validate cross-references
cascette validate roundtrip <file>       # Test parse/build cycle
cascette validate batch <directory>      # Batch validate files

# Manage TACT keys
cascette tact list                       # List known TACT keys
cascette tact search <key_id>           # Search for a specific key
cascette tact sync                      # Sync with wowdev/TACTKeys repository
cascette tact export <file>             # Export keys to JSON file
cascette tact stats                     # Show key database statistics

# Manage listfiles
cascette listfile search <pattern>      # Search for file paths
cascette listfile lookup <fdid|path>    # Lookup by FDID or path
cascette listfile sync                  # Sync with wowdev/wow-listfile
cascette listfile export <file>         # Export listfile to file
cascette listfile stats                 # Show listfile statistics
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
├── core/                # Shared functionality
│   ├── __init__.py     # Core module exports
│   ├── types.py        # Type definitions and Pydantic models
│   ├── config.py       # Configuration management
│   ├── cdn.py          # CDN client implementations
│   ├── cache.py        # Caching mechanisms
│   └── utils.py        # Utility functions
├── formats/            # Format parsers and builders
│   ├── __init__.py     # Format module exports
│   ├── base.py         # Base parser/builder classes
│   ├── blte.py         # BLTE format handling
│   ├── encoding.py     # Encoding format handling
│   ├── root.py         # Root format handling
│   └── ...             # Additional format modules
├── commands/           # CLI command implementations
│   ├── __init__.py     # Command module exports
│   ├── examine.py      # File examination commands
│   ├── analyze.py      # Analysis commands
│   ├── fetch.py        # Download commands
│   └── ...             # Additional command modules
├── database/           # Data management
│   ├── __init__.py     # Database module exports
│   ├── tact_keys.py    # TACT key management
│   ├── listfile.py     # Listfile management
│   ├── wago.py         # Wago.tools integration
│   └── storage.py      # Local storage management
└── __main__.py         # Main CLI entry point

tests/                  # Test suite
├── conftest.py         # Pytest configuration and fixtures
├── test_core/          # Core module tests
├── test_formats/       # Format parser tests
├── test_commands/      # CLI command tests
├── test_database/      # Database tests
└── fixtures/           # Test data files
```

## Development

### Prerequisites

- Python 3.12 or higher
- pip and setuptools

### Development Setup

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with coverage
pytest --cov=cascette_tools --cov-report=html

# Type checking
pyright cascette_tools

# Code formatting
black cascette_tools tests

# Linting
ruff check cascette_tools tests
```

## Code Quality and Validation

### Python Code Validation

All Python code in the cascette-tools package must pass these validation steps:

```bash
# Linting and code quality checks
ruff check cascette_tools tests        # Fast, comprehensive linting

# Type checking and static analysis
pyright cascette_tools                 # Strict type checking enabled

# Code formatting (auto-fix)
black cascette_tools tests              # Consistent formatting

# Test coverage requirements
pytest --cov=cascette_tools --cov-fail-under=80  # Minimum 80% coverage
```

### Pre-commit Workflow

Before committing changes:

```bash
# Run all quality checks
ruff check cascette_tools tests && \
pyright cascette_tools && \
pytest --cov=cascette_tools --cov-fail-under=80

# Auto-fix formatting issues
black cascette_tools tests
ruff check --fix cascette_tools tests
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
pytest -m unit

# Integration tests (may require network)
pytest -m integration

# Exclude slow tests for quick feedback
pytest -m "not slow"

# Run specific test files
pytest tests/test_formats/test_blte.py

# Run with verbose output
pytest -v

# Generate HTML coverage report
pytest --cov=cascette_tools --cov-report=html
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
cascette fetch manifests wow

# Or fetch specific build data
cascette fetch build wow 11.0.2.56461

# This downloads build metadata and manifest files for analysis
# Products include: wow, wow_classic, wow_classic_era, wowt, wow_beta
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
cascette analyze stats <file>

# Check compression effectiveness
cascette analyze compression <blte_file>
```

## Command Categories

### Essential Foundation Commands

**Start here - these provide the data for all other analysis:**

| Command | Purpose | Usage |
|---------|---------|--------|
| **`cascette builds sync`** | **Fetch WoW build database from Wago.tools** | **`cascette builds sync`** |

### Core Examination Commands

These commands examine individual files and builds:

| Command | Purpose | Usage |
|---------|---------|--------|
| `cascette examine blte` | BLTE decompression and analysis | `cascette examine blte <input.blte> -o <output.dat>` |
| `cascette examine encoding` | Encoding file analysis and content key lookup | `cascette examine encoding <encoding_hash>` |
| `cascette examine root` | Root file structure validation | `cascette examine root <root_hash>` |
| `cascette examine install` | Install manifest analysis and tag systems | `cascette examine install --product wow` |
| `cascette examine download` | Download manifest priority and platform tags | `cascette examine download --product wow` |
| `cascette examine config` | Product and patch configuration analysis | `cascette examine config --config-type patch` |
| `cascette examine tvfs` | TVFS (virtual file system) manifest analysis | `cascette examine tvfs <tvfs_files>` |
| `cascette examine build` | Comprehensive build analysis | `cascette examine build wow 11.2.0.62706 <build_config>` |
| `cascette examine patch` | Patch archive (PA) format examination | `cascette examine patch --limit 5` |
| `cascette analyze cdn-configs` | CDN configuration and archive analysis | `cascette analyze cdn-configs wow_classic --limit 5` |

### Format Analysis Commands

These commands analyze format characteristics:

| Command | Purpose | Usage |
|---------|---------|--------|
| `cascette analyze stats` | Show file statistics and metadata | `cascette analyze stats <file>` |
| `cascette analyze compression` | Analyze BLTE compression effectiveness | `cascette analyze compression <blte_file>` |
| `cascette analyze coverage` | Analyze content coverage across files | `cascette analyze coverage <files...>` |
| `cascette analyze dependencies` | Trace file dependencies and references | `cascette analyze dependencies <file>` |

### Verification Suite

These commands validate format files:

| Command | Purpose | Usage |
|---------|---------|--------|
| `cascette validate format` | Validate individual format files | `cascette validate format <file>` |
| `cascette validate integrity` | Check file checksums and integrity | `cascette validate integrity <file>` |
| `cascette validate relationships` | Validate cross-file references | `cascette validate relationships <files>` |
| `cascette validate roundtrip` | Test parse/build cycle correctness | `cascette validate roundtrip <file>` |
| `cascette validate batch` | Batch validate multiple files | `cascette validate batch <directory>` |

### Patch Commands

Commands for working with NGDP patches:

| Command | Purpose | Usage |
|---------|---------|--------|
| `cascette fetch patch` | Fetch patch files from CDN | `cascette fetch patch <hash>` |
| `cascette fetch patch --index` | Fetch patch index files | `cascette fetch patch <hash> --index` |

### Utility Commands

| Command | Purpose | Usage |
|---------|---------|--------|
| `cascette examine archive` | Archive index file analysis | `cascette examine archive <file>` |
| `cascette tact list` | List known TACT encryption keys | `cascette tact list` |
| `cascette tact sync` | Sync TACT keys from repository | `cascette tact sync` |
| `cascette listfile search` | Search FileDataID to path mappings | `cascette listfile search <pattern>` |
| `cascette listfile sync` | Sync listfile from repository | `cascette listfile sync` |
| `cascette version` | Show version information | `cascette version` |

## Output Directory Structure

All analysis results are saved to the `results/` directory:

```text
tools/
├── results/              # All generated output files
│   ├── *.json           # Analysis results
│   └── *.txt            # Evolution reports
├── test_data/           # Downloaded CASC files (gitignored)
│   ├── wago-builds-*.json
│   └── wow_*_*.dat/txt  # Cached CASC files
└── cache/               # Temporary download cache
```

## Recommended Usage Workflow

### Complete End-to-End Example

Here's the recommended sequence for a complete download, examination, and
verification process:

```bash
# Step 1: Fetch build database (one-time setup)
cascette builds sync

# Step 2: Test all tools are working
cascette validate tools

# Step 3: Validate downloaded files
cascette validate batch test_data/

# Step 4: Analyze file statistics
cascette analyze stats <file>

# Step 5: Check compression effectiveness
cascette analyze compression <blte_file>

# Step 6: Validate file integrity
cascette validate integrity <file>

# Step 7: Check results
ls -la results/

# Step 8: Review cache usage
cascette analyze cache --list --detailed
```

### 0. Essential First Step - Get Build Database

**REQUIRED** before any analysis:

```bash
# Fetch comprehensive WoW build database (1,900+ builds)
cascette builds sync

# This creates local database with all build metadata
# All other commands automatically detect and use this data
```

Without this step, format evolution analysis is impossible.

### 1. Initial Setup and Verification

Verify the tools are working correctly:

```bash
# Fetch Wago build database
cascette builds sync

# Test fetching a config file
cascette fetch config <hash>

# Validate a downloaded file
cascette validate format <file>
```

This validates our format documentation against real WoW builds and caches
files for future analysis. The test suite ensures all tools are functioning
properly with appropriate timeouts for network operations.

### 2. Individual Build Analysis

To examine a specific build:

```bash
# Analyze a complete build (downloads ~50MB of data)
cascette examine build wow_classic_era 1.13.7.38704 \
  ae66faee0ac786fdd7d8b4cf90a8d5b9

# Examine specific files from that build
cascette examine root b98595f5  # Root file hash from build output
cascette examine encoding bbf06e74  # Encoding file hash from build output
```

### 3. Format Analysis

To analyze format characteristics:

```bash
# Analyze file statistics
cascette analyze stats <file>

# Analyze BLTE compression effectiveness
cascette analyze compression <blte_file>

# Analyze content coverage across files
cascette analyze coverage <encoding_file> <root_file>

# Trace file dependencies
cascette analyze dependencies <file>
```

These scripts examine builds chronologically to identify when format changes
occurred. The specialized trackers provide detailed analysis of specific format
aspects and generate comprehensive reports in the `results/` directory.

### 4. Patch System Analysis

Examine the NGDP patch system:

```bash
# Fetch patch files
cascette fetch patch <hash>

# Fetch patch index files
cascette fetch patch <hash> --index

# Validate patch file format
cascette validate format <patch_file>
```

These tools examine PA (Patch Archive) format, ZBSDIFF1 patch format, and
the patch-entry structure in patch configurations.

### 5. Individual File Analysis

For detailed examination of specific file formats:

```bash
# Decompress BLTE files
cascette examine blte compressed_file.blte -o decompressed.dat

# Search for content keys in encoding files
cascette examine encoding <encoding_hash> --search <content_key>

# Analyze root file structure
cascette examine root <root_hash> --verbose
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

- **Products**: wow, wow_classic, wow_classic_era, wowt, wow_beta, and more

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

Tools connect to `cdn.arctium.tools` by default for actual file retrieval:

- Better availability than official Blizzard CDNs

- Comprehensive archive of builds back to 6.0.x

- Cloudflare-backed for reliability

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
| BLTE | `blte.py` | Complete | All compression types (N, Z, E, F) |
| Encoding | `examine_encoding.py` | Complete | Content key lookup, ESpec support |
| Root | `examine_root.py` | Complete | Versions 1-4, TSFM/MFST magic detection |
| TVFS | `examine_tvfs.py` | Complete | Header parsing, table analysis, version 1 format |
| Build Config | `examine_build.py` | Complete | All field types, space-separated values |
| Install | `examine_build.py` | Basic | Magic detection, header parsing |
| Download | `examine_build.py` | Basic | Magic detection, header parsing |

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
pip install cascette-tools
```

#### Development Installation

```bash
# Install in editable mode with development dependencies
pip install -e ".[dev]"
```

#### Core Dependencies

The package requires:

- `click` - CLI framework
- `pydantic` - Data validation
- `httpx` - Async HTTP client
- `rich` - Terminal formatting
- `structlog` - Structured logging
- `lz4` - LZ4 compression
- `cryptography` - Encryption support
- `aiofiles` - Async file I/O
- `diskcache` - Persistent caching

### System Requirements

- Python 3.12+ (uses type hints and match statements)

- Internet connection for initial downloads

- ~200MB disk space for full cache

### Development Dependencies

For development and testing:

- `pytest` - Testing framework
- `pytest-cov` - Coverage reporting
- `pytest-asyncio` - Async test support
- `pyright` - Type checking
- `ruff` - Fast Python linter
- `black` - Code formatting

## Error Handling and Troubleshooting

### Common Issues

**CDN Connection Timeouts**:

```bash
# Use longer timeouts for slow connections
cascette examine build --timeout 60 wow 11.2.0.62706 <config>
```

**Cache Corruption**:

```bash
# Clean and retry
cascette analyze cache --clean --execute
cascette validate root-transitions
```

**Missing Build Data**:

- Ensure you've run `cascette builds sync` first

- Verify build configuration hashes are correct

- Some older builds may not be available on CDN

### Debugging Options

Most commands support verbose output:

```bash
cascette examine build --verbose wow 11.2.0.62706 <config>
cascette examine root <hash> --debug
cascette --debug <command>  # Enable debug mode globally
```

## Development Workflow

### Adding New Analysis

1. Create new command module in `cascette_tools/commands/`
2. Use existing format parsers from `cascette_tools/formats/`
3. Register command in `__main__.py`
4. Add tests to `tests/` directory
5. Update this README

### Testing Changes

```bash
# Run test suite
pytest

# Run with coverage
pytest --cov=cascette_tools

# Type checking
pyright cascette_tools

# Linting
ruff check cascette_tools tests

# Quick verification of changes
cascette validate all

# Full format analysis
cascette analyze format-evolution wow
```

### Cache Management During Development

```bash
# Clean cache between major changes
cascette analyze cache --clean --execute

# Monitor cache growth
cascette analyze cache --list
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

1. **Initial Survey**: `fetch_wago_builds.py` establishes the complete build

   database foundation

2. **Strategic Sampling**: Selection algorithms identify builds most likely to

   contain format transitions

3. **Detailed Analysis**: Individual examination tools (`examine_*.py`)

   validate format assumptions

4. **Evolution Tracking**: Specialized trackers (`track_*_evolution.py`)

   identify changes over time

5. **Verification**: Automated scripts (`verify_*.py`) confirm discovered

   patterns across build ranges

6. **Documentation**: Findings are documented with exact build references and

   transition points

This process ensures that the Rust implementation handles the complete
spectrum of NGDP/CASC format variations encountered in production WoW builds
from 2014 through present.

## Further Reading

- [Format Evolution Documentation](../docs/format-transitions.md)

- [Root File Format Specification](../docs/root.md)

- [BLTE Format Documentation](../docs/blte.md)

- [Build Configuration Formats](../docs/config-formats.md)

- [NGDP System Overview](../docs/README.md)

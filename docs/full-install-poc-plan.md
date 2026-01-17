# Full Installation POC Plan

This document outlines the implementation plan for full product installation
support in cascette-py and the findings from our proof-of-concept.

## POC Status: WORKING

The POC demonstrates the complete NGDP resolution chain:

```
BuildConfig → Encoding File → Install/Download Manifests
```

### Key Findings

1. **Encoding file IS a loose CDN file**
   - Can be downloaded directly using the encoding key from BuildConfig
   - URL: `/data/{hash[:2]}/{hash[2:4]}/{hash}`
   - No need to search archive indices

2. **Archive-groups are locally generated**
   - Battle.net downloads individual archive indices from CDN
   - Generates mega-index locally by merging indices
   - The `archive-group` hash in CDN config references the local file
   - NOT available from CDN

3. **Resolution chain works correctly**
   - BuildConfig provides encoding key for encoding file
   - Encoding file maps content keys to encoding keys
   - Install/download manifests resolved via encoding file

### WoW Classic Era Statistics (1.15.8.65300)

| Metric | Value |
|--------|-------|
| Encoding file size | 14 MB (BLTE compressed) |
| CKey pages | 2,052 |
| EKey pages | 1,347 |
| Install manifest entries | 265 |
| Install manifest size | ~1 GB |
| Download manifest entries | 219,246 |
| Download manifest size | 7.81 GB |
| Priority levels | 3 (0, 1, 2) |

### Priority Distribution

| Priority | Files | Size | Purpose |
|----------|-------|------|---------|
| 0 | 1,839 | 1.09 GB | Critical (launch required) |
| 1 | 177,588 | 4.62 GB | Core game data |
| 2 | 39,819 | 2.29 GB | Secondary content |

### Available Tags

**Platform**: Windows, OSX, Android, iOS, PS5, Web, XBSX
**Architecture**: x86_32, x86_64, arm64
**Locale**: enUS, deDE, esES, esMX, frFR, koKR, ptBR, ruRU, zhCN, zhTW
**Region**: US, EU, KR, TW, CN
**Content**: speech, text, HighRes, Alternate

## Current Implementation

### Working Components

1. **Install POC Command** (`cascette_tools/commands/install_poc.py`)
   - `discover-latest`: Query versions endpoint and resolve manifests
   - `resolve-manifests`: Resolve manifests from a known BuildConfig hash

2. **Format Parsers**
   - Encoding file parser with content key lookup
   - Install manifest parser
   - Download manifest parser with priority support
   - BLTE decompression

3. **CDN Client**
   - Multi-mirror support (Blizzard + community)
   - Config and data fetching

### Usage Example

```bash
# Discover latest build and resolve all manifests
python -m cascette_tools install-poc discover-latest --product wow_classic_era

# Resolve manifests for a specific build config
python -m cascette_tools install-poc resolve-manifests e2dc540a98cccb45d764025ab28b703a
```

## Next Steps

### Phase 1: Archive Resolution (Current Gap)

While manifests can be resolved, actual file content requires:

1. **Download archive indices from CDN**
   - Each archive has an `.index` file
   - CDN config lists all archive hashes

2. **Build local index map**
   - Map encoding key → (archive_hash, offset, size)
   - This replaces the need for archive-groups

3. **Fetch content via range requests**
   - Use HTTP Range header to fetch specific bytes
   - Extract BLTE-encoded data from archives

### Phase 2: Local Storage

1. **Create local CASC structure**
   - `Data/data/` - CASC archives (buckets 0x00-0x0f)
   - `Data/indices/` - Local index files

2. **Write downloaded content**
   - Write to appropriate bucket based on key hash
   - Update local index files

### Phase 3: Full Installation

1. **Priority-based download**
   - Download priority 0 files first
   - Enable play-while-downloading

2. **Tag filtering**
   - Only download files matching selected tags
   - Platform: Windows
   - Locale: enUS
   - Architecture: x86_64

3. **Progress tracking**
   - Track downloaded vs total bytes
   - Report per-priority completion

## File Locations

| File | Purpose |
|------|---------|
| `cascette_tools/commands/install_poc.py` | POC CLI commands |
| `cascette_tools/formats/encoding.py` | Encoding file parser |
| `cascette_tools/formats/install.py` | Install manifest parser |
| `cascette_tools/formats/download.py` | Download manifest parser |
| `cascette_tools/formats/blte.py` | BLTE decompression |

## References

- `docs/battlenet-install-process.md` - 7-phase installation sequence
- Rust implementation in `cascette-installation` crate

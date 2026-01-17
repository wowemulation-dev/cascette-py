# Battle.net Installation Process Analysis

This document describes the Battle.net product installation process based on
forensic analysis of file timestamps from a WoW Classic Era installation.

## Installation Phases

Based on timestamp analysis, Battle.net follows a precise 7-phase installation
sequence.

### Phase 1: Configuration Download (T+0.0s)

First files written:
```
06:00:27.242 - Data/config/.../e2dc540a98cccb45d764025ab28b703a  (Build Config)
06:00:27.653 - Data/config/.../de01e5d341c7381fbb93e12c514c81c3  (CDN Config)
```

**Purpose**: Establish what version to install and where content is located.

- **Build Config**: Contains hashes for encoding, install, download, root
  manifests
- **CDN Config**: Lists all archive hashes and their index sizes

### Phase 2: Archive Index Download (T+1s - T+3min)

```
06:00:28.475 - Data/indices/0128ec2c42df9e7ac7b58a54ad902147.index
06:00:28.612 - Data/indices/0017a402f556fbece46c38dc431a2c9b.index
... (600+ archive index files)
```

**Purpose**: Download all archive metadata for content resolution.

- Each `.index` file maps encoding keys to (offset, size) within an archive
- Without indices, the client cannot locate any game content
- Total ~300KB of index metadata for WoW Classic

### Phase 3: Local Storage Initialization (T+3min)

```
06:03:02+ - Data/data/0000000001.idx through 0f00000006.idx (empty, 65KB each)
```

**Purpose**: Pre-allocate local CASC storage buckets.

- 16 buckets (0x00-0x0f) based on encoding key hash
- Multiple generations per bucket (001, 002, etc.) for incremental updates
- Initially empty, populated as content downloads

### Phase 4: Encoding Cache Setup (T+3min+33s)

```
06:03:33.713 - Data/ecache/0000000001.idx through 0f00000001.idx
06:03:33.715 - Data/ecache/data.000
```

**Purpose**: Store encoding file entries locally for fast content key resolution.

- Maps content keys (what the game wants) to encoding keys (what CDN has)
- Critical for file extraction without re-downloading encoding file

### Phase 5: Agent Bootstrapper (T+3min+33s)

```
06:03:33.805 - .battle.net/config/0f/6c/0f6ccf1dd9b9c2db99de99535c5a51ae
06:03:33.806 - .battle.net/data/shmem
06:03:33.808 - .battle.net/data/*.idx (16 buckets)
06:03:34.140 - .battle.net/config/41/36/413678ddc8eb0957567321782faa532d
06:03:34.642 - .battle.net/indices/*.index
```

**Purpose**: Install the Battle.net Agent ("bts" product) for managing the main product.

- The `.battle.net/` folder contains a mini CASC installation for the Agent
- Agent handles ongoing updates, repairs, and background downloads

### Phase 6: Critical File Extraction (T+3min+34s)

```
06:03:34.683 - _classic_era_/UTILS/WowWindowsExceptionHandler.dll
06:03:35.243 - _classic_era_/UTILS/WindowsExceptionHandler.dll
06:03:35.427 - _classic_era_/UTILS/WowVoiceProxy.exe
06:03:35.566 - _classic_era_/dxilconv7.dll
06:03:35.569 - _classic_era_/BlizzardError.exe
06:03:35.977 - _classic_era_/llvm_7_0_1.dll
```

**Purpose**: Extract launch-critical files from archives.

- These files have low priority numbers in the download manifest
- Required for the game to start (even if content is incomplete)
- Extracted from CDN archives using encoding file resolution

### Phase 7: Product State Finalization (T+3min+37s)

```
06:03:36.999 - .product.db
06:03:37.000 - Launcher.db
06:03:37.001 - .patch.result
```

**Purpose**: Record installation state.

- `.product.db`: Protobuf database with product info (code, region, build hash)
- `Launcher.db`: Launcher state (4 bytes)
- `.patch.result`: Patch operation result code

## Basic vs Full Installation

### Basic Installation (what we observed)

- **Size**: ~347 MB
- **Content**: Archive indices, empty storage buckets, critical executables
- **Can launch**: Possibly (depends on what critical files were extracted)
- **Gameplay**: Not possible - no game data

### Full Installation

- **Size**: 30-80 GB depending on version
- **Content**: All of basic + complete game data in `Data/data/data.*` files
- **Can launch**: Yes
- **Gameplay**: Full access

## Key Data Structures

### Local Storage (.idx files in Data/data/)

Format: Page-based with 16-byte header
```
0x00: Header size (4 bytes LE)
0x04: TOC hash (4 bytes)
0x08: Unknown (4 bytes)
0x0C: Field sizes (4 bytes)
0x10+: Entries (9-byte key + 4-byte size + 4-byte offset + extra)
```

### CDN Archive Index (.index files)

Format: Entries + 28-byte footer
```
Entries: [ekey (16 bytes)] [offset (4 bytes)] [size (4 bytes)]
Footer: toc_hash(8) version(1) reserved(2) page_kb(1) offset_bytes(1)
        size_bytes(1) key_bytes(1) hash_bytes(1) entry_count(4LE) hash(8)
```

### Product Database (.product.db)

Format: Protobuf with fields:
- Product code (e.g., "wow_classic_era")
- Install path
- Region/locale
- Build hash
- Various timestamps and state flags

## Download Priority System

The download manifest defines download order via priority (0-255):
- **0-50**: Critical files (executables, shaders, UI)
- **51-100**: Core game data
- **100+**: Optional content (cinematics, high-res textures)

Files with lower priority download first, enabling:
1. Faster time to playable state
2. Play-while-downloading functionality
3. Selective quality installation

## Implications for cascette-agent

To replicate this behavior, cascette-agent should:

1. **Phase 1-2**: Download configs and all archive indices first
2. **Phase 3-4**: Initialize empty local storage structures
3. **Phase 5**: Handle nested "bts" installation if needed
4. **Phase 6**: Extract files in priority order from download manifest
5. **Phase 7**: Update product state databases

The current cascette-agent implementation handles basic installation but needs:
- Priority-based download ordering
- Proper local storage initialization
- Product database updates
- Progress tracking per priority level

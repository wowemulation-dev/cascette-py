# Utility Scripts

Helper scripts for data collection and analysis.

## Scripts

### scrape_wiki_builds.py

Scrapes build information from Warcraft Wiki to find builds not in the
Wago.tools database.

Usage:

```bash
uv run python scripts/scrape_wiki_builds.py
```

Creates `missing_builds.json` with build IDs found on the wiki but not
in the local database.

### import_missing_builds.py

Searches Wago.tools for missing builds identified by scrape_wiki_builds.py
and imports them to the local database.

Usage:

```bash
# Run scrape_wiki_builds.py first to create missing_builds.json
uv run python scripts/import_missing_builds.py
```

### fetch_all_builds.py

Fetches all builds from Wago.tools API.

Usage:

```bash
uv run python scripts/fetch_all_builds.py
```

## Note

These scripts are development utilities and not part of the main
cascette-tools package. They require dev dependencies (`uv sync --all-extras`).

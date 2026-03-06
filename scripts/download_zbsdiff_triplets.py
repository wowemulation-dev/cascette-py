#!/usr/bin/env python3
"""Download ZBSDIFF patch triplets (old file, new file, patch) for Rust verification.

Downloads real patch data from Blizzard's CDN and saves triplets:
  - {hash}.old   - old version of the file (source)
  - {hash}.new   - new version of the file (target)
  - {hash}.zbsdiff - the patch itself

The old file is looked up by source_ekey in data archives.
The new file is looked up by target_ckey via the encoding manifest.
The patch is looked up by patch_ekey in patch archives.

Usage:
    uv run python scripts/download_zbsdiff_triplets.py \
        --product wow_classic --limit 5 --output-dir /tmp/zbsdiff-triplets/
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import structlog

from cascette_tools.core.cdn import CDNClient
from cascette_tools.core.cdn_archive_fetcher import (
    CdnArchiveFetcher,
    create_patch_archive_fetcher,
)
from cascette_tools.core.config import CDNConfig
from cascette_tools.core.tact import TACTClient
from cascette_tools.core.types import Product
from cascette_tools.formats.blte import decompress_blte, is_blte
from cascette_tools.formats.config import BuildConfigParser, CDNConfigParser
from cascette_tools.formats.encoding import EncodingParser
from cascette_tools.formats.patch_archive import PatchArchiveParser

logger = structlog.get_logger()


def _get_cdn_mirrors_for_product(product: str) -> list[str]:
    wow_products = [
        "wow", "wow_classic", "wow_classic_era",
        "wow_classic_titan", "wow_anniversary",
    ]
    if product in wow_products:
        return [
            "https://casc.wago.tools",
            "https://cdn.arctium.tools",
            "https://archive.wow.tools",
        ]
    return [
        "http://blzddist1-a.akamaihd.net",
        "http://level3.blizzard.com",
        "http://cdn.blizzard.com",
    ]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Download ZBSDIFF triplets for Rust verification"
    )
    parser.add_argument("--product", "-p", default="wow_classic")
    parser.add_argument("--region", "-r", default="us")
    parser.add_argument("--limit", "-l", type=int, default=5)
    parser.add_argument("--output-dir", "-o", default="/tmp/zbsdiff-triplets")
    parser.add_argument(
        "--max-old-size", type=int, default=512 * 1024,
        help="Maximum old file size in bytes (skip larger files)",
    )
    parser.add_argument(
        "--max-new-size", type=int, default=512 * 1024,
        help="Maximum new file size in bytes (skip larger files)",
    )
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    product_enum = Product(args.product)
    cdn_config = CDNConfig(
        fallback_mirrors=_get_cdn_mirrors_for_product(args.product),
        timeout=30.0,
        max_retries=3,
    )

    # Step 1: Get build config + CDN config hashes from versions manifest
    print(f"Fetching versions manifest for {args.product}...")
    tact_client = TACTClient(region=args.region)
    versions_data = tact_client.fetch_versions(product_enum)
    versions = tact_client.parse_versions(versions_data)

    version_entry = None
    for v in versions:
        r = v.get("Region", v.get("region", ""))
        if r == args.region:
            version_entry = v
            break
    if version_entry is None:
        for v in versions:
            if v.get("BuildConfig", v.get("buildconfig", "")):
                version_entry = v
                break
    if not version_entry:
        print("ERROR: No version entry found")
        sys.exit(1)

    build_config_hash: str | None = version_entry.get(
        "BuildConfig", version_entry.get("buildconfig")
    )
    cdn_config_hash: str | None = version_entry.get(
        "CDNConfig", version_entry.get("cdnconfig")
    )
    print(f"  Build config: {build_config_hash}")
    print(f"  CDN config:   {cdn_config_hash}")

    if not build_config_hash or not cdn_config_hash:
        print("ERROR: Missing build or CDN config hash in version entry")
        sys.exit(1)

    with CDNClient(product_enum, args.region, cdn_config) as cdn_client:
        # Step 2: Parse build config for patch manifest EKey
        print("Fetching build config...")
        build_data = cdn_client.fetch_config(build_config_hash, "build")
        build_config = BuildConfigParser().parse(build_data)

        patch_info = build_config.get_patch_info()
        if patch_info is None:
            print("No patch field in build config")
            sys.exit(0)

        patch_ekey = patch_info.encoding_key or patch_info.content_key
        print(f"  Patch manifest EKey: {patch_ekey}")

        # Step 3: Parse CDN config for archive lists
        print("Fetching CDN config...")
        cdn_data = cdn_client.fetch_config(cdn_config_hash, "cdn")
        parsed_cdn = CDNConfigParser().parse(cdn_data)
        print(f"  Data archives:  {len(parsed_cdn.archives)}")
        print(f"  Patch archives: {len(parsed_cdn.patch_archives)}")

        # Step 4: Download patch manifest
        print("Fetching patch manifest...")
        patch_raw = cdn_client.fetch_patch(patch_ekey)
        if is_blte(patch_raw):
            patch_manifest_data = decompress_blte(patch_raw)
        else:
            patch_manifest_data = patch_raw

        pa_file = PatchArchiveParser().parse(patch_manifest_data)
        print(f"  PA entries: {len(pa_file.entries)}")
        print(f"  File entries: {len(pa_file.file_entries)}")

        # Step 5: Download encoding manifest (to resolve target CKeys to EKeys)
        encoding_info = build_config.get_encoding_info()
        if encoding_info is None:
            print("No encoding field in build config")
            sys.exit(1)

        encoding_ekey = encoding_info.encoding_key or encoding_info.content_key
        print(f"Fetching encoding manifest ({encoding_ekey[:16]}...)...")
        enc_raw = cdn_client.fetch_data(encoding_ekey)
        if is_blte(enc_raw):
            enc_data = decompress_blte(enc_raw)
        else:
            enc_data = enc_raw

        enc_parser = EncodingParser()
        encoding_file = enc_parser.parse(enc_data)
        print(f"  Encoding header: {encoding_file.header.ckey_page_count} CKey pages")

        # Build CKey -> EKey lookup by iterating all encoding pages
        ckey_to_ekey: dict[bytes, bytes] = {}
        for page_idx in range(encoding_file.header.ckey_page_count):
            try:
                page = enc_parser.load_ckey_page_sequential(
                    enc_data, encoding_file, page_idx, max_entries=10000
                )
                for entry in page.entries:
                    if entry.content_key and entry.encoding_keys:
                        ckey_to_ekey[entry.content_key] = entry.encoding_keys[0]
            except Exception as e:
                logger.debug("encoding_page_failed", page=page_idx, error=str(e))

        print(f"  CKey->EKey mappings: {len(ckey_to_ekey)}")

        # Step 6: Download patch archive indexes
        print(f"Downloading {len(parsed_cdn.patch_archives)} patch archive indexes...")
        patch_fetcher = create_patch_archive_fetcher(cdn_client=cdn_client)
        for pa_hash in parsed_cdn.patch_archives:
            try:
                idx_data = cdn_client.fetch_patch(pa_hash, is_index=True)
                patch_fetcher.load_index_from_bytes(pa_hash, idx_data)
            except Exception as e:
                logger.debug("patch_index_failed", hash=pa_hash, error=str(e))
        print(f"  Patch index entries: {patch_fetcher.index_map.total_entries}")

        # Step 7: Download data archive indexes
        print(f"Downloading {len(parsed_cdn.archives)} data archive indexes...")
        data_fetcher = CdnArchiveFetcher(cdn_client=cdn_client, content_type="data")
        for da_hash in parsed_cdn.archives:
            try:
                idx_data = cdn_client.fetch_data(da_hash, is_index=True)
                data_fetcher.load_index_from_bytes(da_hash, idx_data)
            except Exception as e:
                logger.debug("data_index_failed", hash=da_hash, error=str(e))
        print(f"  Data index entries: {data_fetcher.index_map.total_entries}")

        # Step 8: Find file entries with manageable sizes and download triplets
        print(f"\nLooking for patch triplets (max old={args.max_old_size}, "
              f"max new={args.max_new_size})...")

        saved = 0
        skipped = 0
        manifest: list[dict[str, object]] = []

        for fe in pa_file.file_entries:
            if saved >= args.limit:
                break

            for fp in fe.patches:
                if saved >= args.limit:
                    break

                patch_hash = fp.patch_ekey.hex()
                source_hash = fp.source_ekey.hex()
                target_ckey_hex = fe.target_ckey.hex()

                # Check sizes
                if fp.source_decoded_size > args.max_old_size:
                    skipped += 1
                    continue
                if fe.decoded_size > args.max_new_size:
                    skipped += 1
                    continue

                # Resolve target CKey to EKey via encoding manifest
                target_ekey = ckey_to_ekey.get(fe.target_ckey)
                if target_ekey is None:
                    print(f"  SKIP {patch_hash[:16]}: target CKey not in encoding")
                    skipped += 1
                    continue

                target_ekey_hex = target_ekey.hex()

                print(f"\n  [{saved+1}/{args.limit}] Patch {patch_hash[:16]}...")
                print(f"    Source EKey: {source_hash[:16]}... "
                      f"(decoded: {fp.source_decoded_size})")
                print(f"    Target CKey: {target_ckey_hex[:16]}... -> "
                      f"EKey: {target_ekey_hex[:16]}... (decoded: {fe.decoded_size})")

                # Download patch
                try:
                    patch_data_raw = patch_fetcher.fetch_file_via_cdn(
                        cdn_client, fp.patch_ekey, decompress=True, verify=True,
                    )
                    if patch_data_raw is None:
                        # Try loose
                        raw = cdn_client.fetch_patch(patch_hash)
                        patch_data_raw = decompress_blte(raw) if is_blte(raw) else raw

                    if patch_data_raw[:8] != b"ZBSDIFF1":
                        print(f"    SKIP: not ZBSDIFF (magic: {patch_data_raw[:8]!r})")
                        skipped += 1
                        continue

                    print(f"    Patch: {len(patch_data_raw)} bytes")
                except Exception as e:
                    print(f"    SKIP patch download: {e}")
                    skipped += 1
                    continue

                # Download old file (source) from data archives
                try:
                    old_data_raw = data_fetcher.fetch_file_via_cdn(
                        cdn_client, fp.source_ekey, decompress=True, verify=True,
                    )
                    if old_data_raw is None:
                        # Try as loose data file
                        raw = cdn_client.fetch_data(source_hash, quiet=True)
                        old_data_raw = decompress_blte(raw) if is_blte(raw) else raw

                    print(f"    Old file: {len(old_data_raw)} bytes")
                except Exception as e:
                    print(f"    SKIP old file download: {e}")
                    skipped += 1
                    continue

                # Download new file (target) from data archives
                try:
                    new_data_raw = data_fetcher.fetch_file_via_cdn(
                        cdn_client, target_ekey, decompress=True, verify=True,
                    )
                    if new_data_raw is None:
                        raw = cdn_client.fetch_data(target_ekey_hex, quiet=True)
                        new_data_raw = decompress_blte(raw) if is_blte(raw) else raw

                    print(f"    New file: {len(new_data_raw)} bytes")
                except Exception as e:
                    print(f"    SKIP new file download: {e}")
                    skipped += 1
                    continue

                # Verify sizes match PA manifest
                if len(old_data_raw) != fp.source_decoded_size:
                    print(f"    WARN: old size mismatch "
                          f"({len(old_data_raw)} != {fp.source_decoded_size})")
                if len(new_data_raw) != fe.decoded_size:
                    print(f"    WARN: new size mismatch "
                          f"({len(new_data_raw)} != {fe.decoded_size})")

                # Save triplet
                prefix = patch_hash
                (output_dir / f"{prefix}.old").write_bytes(old_data_raw)
                (output_dir / f"{prefix}.new").write_bytes(new_data_raw)
                (output_dir / f"{prefix}.zbsdiff").write_bytes(patch_data_raw)

                manifest.append({
                    "patch_ekey": patch_hash,
                    "source_ekey": source_hash,
                    "target_ckey": target_ckey_hex,
                    "target_ekey": target_ekey_hex,
                    "old_size": len(old_data_raw),
                    "new_size": len(new_data_raw),
                    "patch_size": len(patch_data_raw),
                    "source_decoded_size": fp.source_decoded_size,
                    "target_decoded_size": fe.decoded_size,
                })

                saved += 1
                print(f"    SAVED triplet {saved}/{args.limit}")

        # Write manifest
        manifest_path = output_dir / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2))

        print(f"\n{'='*60}")
        print(f"Saved {saved} triplets to {output_dir}")
        print(f"Skipped {skipped} entries")
        print(f"Manifest: {manifest_path}")


if __name__ == "__main__":
    main()

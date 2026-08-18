"""Detect file-format versions for a build from CDN content.

Given a build config + CDN config, fetches the manifests the client
downloads (root, install, download, size, encoding) and reports their
format versions, plus the CDN archive index footer version and BLTE magic.
This is the CDN-side half of the per-build format registry; the
container-side half (client CAS: idx, local headers, segment headers,
shmem) is detected from a local install.

Format versions are recorded per build so drift across branches
(1.13 / 1.14 / 1.15) can be observed rather than assumed.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cascette_tools.core.cdn import CDNClient
from cascette_tools.core.types import Product
from cascette_tools.formats.archive import ArchiveIndexParser
from cascette_tools.formats.blte import decompress_blte, is_blte
from cascette_tools.formats.config import BuildConfigParser, CDNConfigParser
from cascette_tools.formats.download import DownloadParser
from cascette_tools.formats.encoding import EncodingParser
from cascette_tools.formats.install import InstallParser
from cascette_tools.formats.root import RootParser
from cascette_tools.formats.size import SizeParser


@dataclass
class BuildFormats:
    """Detected format versions for one build."""

    root_version: int | None = None
    install_version: int | None = None
    download_version: int | None = None
    size_version: int | None = None
    encoding_version: int | None = None
    archive_index_version: int | None = None
    blte_magic: str | None = None
    vfs_version: int | None = None
    vfs_manifests: int | None = None

    # Container-side (filled by a local install scan, not CDN)
    idx_version: int | None = None
    local_header_version: int | None = None
    segment_header_bytes: int | None = None
    shmem_version: int | None = None

    # Diagnostics
    warnings: list[str] = field(default_factory=list)

    def to_columns(self) -> dict[str, int | str | None]:
        """Return the CDN-side fields as a column-name → value mapping."""
        return {
            "root_version": self.root_version,
            "install_version": self.install_version,
            "download_version": self.download_version,
            "size_version": self.size_version,
            "encoding_version": self.encoding_version,
            "archive_index_version": self.archive_index_version,
            "blte_magic": self.blte_magic,
            "vfs_version": self.vfs_version,
            "vfs_manifests": self.vfs_manifests,
        }


def detect_cdn_formats(
    build_config_hash: str,
    cdn_config_hash: str,
    *,
    product: Product = Product.WOW_CLASSIC,
    region: str = "us",
) -> BuildFormats:
    """Fetch a build's manifests from CDN and detect their format versions.

    Args:
        build_config_hash: Build config hash from the versions endpoint
        cdn_config_hash: CDN config hash from the versions endpoint
        product: Product enum for the CDN path
        region: CDN region

    Returns:
        BuildFormats with CDN-side versions and any warnings.
    """
    fmts = BuildFormats()
    cdn = CDNClient(product, region=region)
    try:
        # Build config
        bc_raw = cdn.fetch_config(build_config_hash, config_type="build")
        bc_data = decompress_blte(bc_raw) if is_blte(bc_raw) else bc_raw
        bc = BuildConfigParser().parse(bc_data)

        # CDN config (archive index footer version needs one index file)
        cc_raw = cdn.fetch_config(cdn_config_hash, config_type="cdn")
        cc_data = decompress_blte(cc_raw) if is_blte(cc_raw) else cc_raw
        cc = CDNConfigParser().parse(cc_data)

        # Encoding file: version from the header
        enc_info = bc.get_encoding_info()
        if enc_info and enc_info.encoding_key:
            try:
                enc_raw = cdn.fetch_data(enc_info.encoding_key)
                enc_data = decompress_blte(enc_raw) if is_blte(enc_raw) else enc_raw
                enc = EncodingParser().parse(enc_data)
                fmts.encoding_version = enc.header.version
            except Exception as e:  # noqa: BLE001
                fmts.warnings.append(f"encoding: {e}")
        else:
            fmts.warnings.append("encoding: no encoding key in build config")

        # BLTE magic: from the raw encoding file (first 4 bytes)
        if enc_info and enc_info.encoding_key:
            try:
                raw4 = cdn.fetch_data(enc_info.encoding_key)[:4]
                fmts.blte_magic = raw4.hex().upper()
            except Exception:  # noqa: BLE001
                pass

        # Root manifest (TVFS): resolve CKey -> EKey via encoding, then parse
        root_ckey = bc.root
        if root_ckey:
            try:
                root_ekey = _resolve_ekey(cdn, enc_info, bc, root_ckey)
                if root_ekey:
                    root_raw = cdn.fetch_data(root_ekey)
                    root_data = (
                        decompress_blte(root_raw) if is_blte(root_raw) else root_raw
                    )
                    root = RootParser().parse(root_data)
                    fmts.root_version = root.header.version
                else:
                    fmts.warnings.append("root: ekey not resolvable")
            except Exception as e:  # noqa: BLE001
                fmts.warnings.append(f"root: {e}")

        # Install manifest
        inst_info = bc.get_install_info()
        if inst_info and inst_info.encoding_key:
            try:
                inst_raw = cdn.fetch_data(inst_info.encoding_key)
                inst_data = decompress_blte(inst_raw) if is_blte(inst_raw) else inst_raw
                inst = InstallParser().parse(inst_data)
                fmts.install_version = inst.version
            except Exception as e:  # noqa: BLE001
                fmts.warnings.append(f"install: {e}")

        # Download manifest
        dl_info = bc.get_download_info()
        if dl_info and dl_info.encoding_key:
            try:
                dl_raw = cdn.fetch_data(dl_info.encoding_key)
                dl_data = decompress_blte(dl_raw) if is_blte(dl_raw) else dl_raw
                dl = DownloadParser().parse(dl_data)
                fmts.download_version = dl.header.version
            except Exception as e:  # noqa: BLE001
                fmts.warnings.append(f"download: {e}")

        # Size manifest: version from the 15-byte DS header (byte 2).
        size_info = bc.get_size_info()
        if size_info and size_info.encoding_key:
            try:
                sz_raw = cdn.fetch_data(size_info.encoding_key)
                sz_data = decompress_blte(sz_raw) if is_blte(sz_raw) else sz_raw
                # version is header byte 2 after the "DS" magic
                if len(sz_data) >= 3:
                    fmts.size_version = sz_data[2]
                try:
                    sz = SizeParser().parse(sz_data)
                    fmts.size_version = sz.header.version
                except Exception as e:  # noqa: BLE001
                    fmts.warnings.append(f"size (parse): {e}")
            except Exception as e:  # noqa: BLE001
                fmts.warnings.append(f"size: {e}")
        # VFS (TVFS) layer: present in 1.14.4+ build configs as
        # vfs-root + vfs-N. Read the vfs-root manifest header version and
        # count the numbered manifests. Absent on pre-1.14.4 builds.
        vfs_root_info = bc.get_vfs_root_info()
        vfs_entries = bc.get_vfs_entries()
        if vfs_root_info is not None or vfs_entries:
            fmts.vfs_manifests = 1 + len(vfs_entries)  # vfs-root + vfs-N
            root_ekey = (
                vfs_root_info.encoding_key
                if vfs_root_info is not None
                else (vfs_entries[0][1].encoding_key if vfs_entries else None)
            )
            if root_ekey:
                try:
                    vfs_raw = cdn.fetch_data(root_ekey)
                    vfs_data = decompress_blte(vfs_raw) if is_blte(vfs_raw) else vfs_raw
                    if len(vfs_data) >= 5 and vfs_data[:4] == b"TVFS":
                        fmts.vfs_version = vfs_data[4]
                except Exception as e:  # noqa: BLE001
                    fmts.warnings.append(f"vfs: {e}")
        else:
            fmts.vfs_manifests = 0

        # Archive index footer version: parse the first archive's index
        if cc.archives:
            try:
                idx_raw = cdn.fetch_data(cc.archives[0], is_index=True)
                idx = ArchiveIndexParser().parse(idx_raw)
                fmts.archive_index_version = idx.footer.version
            except Exception as e:  # noqa: BLE001
                fmts.warnings.append(f"archive_index: {e}")
        else:
            fmts.warnings.append("archive_index: no archives in CDN config")
    finally:
        cdn.close()
    return fmts


def _resolve_ekey(
    cdn: CDNClient, enc_info: object, bc: object, ckey: str
) -> str | None:
    """Resolve a content key to an encoding key via the encoding file."""
    from cascette_tools.formats.encoding import EncodingParser

    if enc_info is None or not getattr(enc_info, "encoding_key", None):
        return None
    enc_raw = cdn.fetch_data(enc_info.encoding_key)  # type: ignore[attr-defined]
    enc_data = decompress_blte(enc_raw) if is_blte(enc_raw) else enc_raw
    parser = EncodingParser()
    enc_file = parser.parse(enc_data)
    ekeys = parser.find_content_key(enc_data, enc_file, bytes.fromhex(ckey))
    return ekeys[0].hex() if ekeys else None


def detect_container_formats(install_path: str) -> BuildFormats:
    """Detect container-side format versions from a local CAS install.

    Reads ``Data/data``: the idx files (KMT version), the segment header
    (480 bytes, 16 reconstruction headers), the 30-byte LocalHeader
    structure, and the shmem protocol version (if present).

    Args:
        install_path: Root of a local installation (containing ``Data/data``)

    Returns:
        BuildFormats with container-side versions filled in.
    """
    from pathlib import Path

    from cascette_tools.core.local_storage import (
        LOCAL_HEADER_SIZE,
        LocalFileHeader,
        parse_local_idx_file,
    )

    fmts = BuildFormats()
    data_dir = Path(install_path) / "Data" / "data"
    if not data_dir.exists():
        fmts.warnings.append("container: Data/data not found")
        return fmts

    # IDX version: parse the first idx file
    idx_files = sorted(data_dir.glob("*.idx"))
    if idx_files:
        try:
            info = parse_local_idx_file(idx_files[0].read_bytes())
            fmts.idx_version = info.version
        except Exception as e:  # noqa: BLE001
            fmts.warnings.append(f"container idx: {e}")
    else:
        fmts.warnings.append("container: no idx files")

    # Segment header: data.000 first 480 bytes, 16 x 30-byte LocalHeaders
    d0 = data_dir / "data.000"
    if d0.exists():
        head = d0.read_bytes()[:480]
        if len(head) >= 480:
            fmts.segment_header_bytes = 480
            _ = LocalFileHeader.from_bytes(head[:LOCAL_HEADER_SIZE])
            fmts.local_header_version = 30  # fixed 30-byte structure
        else:
            fmts.warnings.append("container: data.000 too small for segment header")
    else:
        fmts.warnings.append("container: no data.000")

    # shmem protocol version: byte 0 of the shmem file (client-written v4)
    shmem_file = data_dir / "shmem"
    if shmem_file.exists():
        fmts.shmem_version = shmem_file.read_bytes()[0]

    return fmts

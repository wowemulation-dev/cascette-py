"""Test that LocalStorage writes the agent-format 30-byte header + segment header."""

from pathlib import Path

from cascette_tools.core.local_storage import (
    LOCAL_HEADER_SIZE,
    SEGMENT_HEADER_SIZE,
    LocalFileHeader,
    LocalStorage,
)


class TestAgentFormatHeaders:
    def test_data_file_starts_with_segment_header(self, tmp_path: Path):
        storage = LocalStorage(tmp_path)
        storage.initialize()
        storage.write_content(b"\xab" * 16, b"hello world")
        data = (storage.data_path / "data.000").read_bytes()
        # 480-byte segment header + 30-byte entry header + payload
        assert len(data) == SEGMENT_HEADER_SIZE + LOCAL_HEADER_SIZE + 11
        # Segment header: 16 reconstruction headers with valid checksums
        seg = data[:SEGMENT_HEADER_SIZE]
        for i in range(16):
            hdr = LocalFileHeader.from_bytes(seg[i * 30 : (i + 1) * 30])
            assert hdr.encoded_size == LOCAL_HEADER_SIZE
            assert hdr.flags == 1  # reconstruction header
            assert hdr.checksum_a != 0
        # Entry header at offset 480
        eh = LocalFileHeader.from_bytes(
            data[SEGMENT_HEADER_SIZE : SEGMENT_HEADER_SIZE + 30]
        )
        assert eh.encoded_size == LOCAL_HEADER_SIZE + 11
        assert eh.flags == 0  # data entry
        assert eh.original_encoding_key()[:9] == b"\xab" * 9

    def test_entry_header_matches_client_format(self, tmp_path: Path):
        """Byte-identical to client: full 16-byte reversed key + checksums."""
        ekey = bytes.fromhex("59cad02d7dc0187413ae485a766f851b")
        total = 30 + 100
        goff = 3 * (1 << 30) + 0x2A40CEFF
        hdr = LocalFileHeader.new(ekey, total, goff)
        # Byte-identical to the client: full 16-byte reversed key
        assert hdr.encoding_key.hex() == "1b856f765a48ae137418c07d2dd0ca59"
        assert hdr.original_encoding_key() == ekey

    def test_resume_appends_after_existing(self, tmp_path: Path):
        storage = LocalStorage(tmp_path)
        storage.initialize()
        e1 = storage.write_content(b"\xab" * 16, b"first")
        e2 = storage.write_content(b"\xcd" * 16, b"second")
        # Second entry starts after first entry's header+payload
        assert e2.archive_offset == e1.archive_offset + LOCAL_HEADER_SIZE + len(
            b"first"
        )

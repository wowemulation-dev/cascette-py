"""Tests for Bob Jenkins lookup3 hash functions."""

from __future__ import annotations

from cascette_tools.crypto.jenkins import (
    _final,  # pyright: ignore[reportPrivateUsage]
    _mix,  # pyright: ignore[reportPrivateUsage]
    _rot,  # pyright: ignore[reportPrivateUsage]
    hashlittle,
    hashlittle2,
)


class TestRot:
    """Tests for 32-bit left rotation."""

    def test_rot_zero(self) -> None:
        assert _rot(0, 0) == 0

    def test_rot_one_bit(self) -> None:
        assert _rot(1, 1) == 2

    def test_rot_wraparound(self) -> None:
        assert _rot(0x80000000, 1) == 1

    def test_rot_full_rotation(self) -> None:
        assert _rot(0xDEADBEEF, 32) == 0xDEADBEEF

    def test_rot_16_bits(self) -> None:
        assert _rot(0x0000FFFF, 16) == 0xFFFF0000

    def test_rot_stays_32_bit(self) -> None:
        result = _rot(0xFFFFFFFF, 7)
        assert result <= 0xFFFFFFFF


class TestMix:
    """Tests for the mix function."""

    def test_mix_zeros(self) -> None:
        a, b, c = _mix(0, 0, 0)
        assert isinstance(a, int)
        assert isinstance(b, int)
        assert isinstance(c, int)

    def test_mix_stays_32_bit(self) -> None:
        a, b, c = _mix(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF)
        assert a <= 0xFFFFFFFF
        assert b <= 0xFFFFFFFF
        assert c <= 0xFFFFFFFF

    def test_mix_deterministic(self) -> None:
        result1 = _mix(1, 2, 3)
        result2 = _mix(1, 2, 3)
        assert result1 == result2

    def test_mix_different_inputs_different_outputs(self) -> None:
        result1 = _mix(1, 2, 3)
        result2 = _mix(4, 5, 6)
        assert result1 != result2


class TestFinal:
    """Tests for the final mixing function."""

    def test_final_zeros(self) -> None:
        a, b, c = _final(0, 0, 0)
        assert isinstance(a, int)
        assert isinstance(b, int)
        assert isinstance(c, int)

    def test_final_stays_32_bit(self) -> None:
        a, b, c = _final(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF)
        assert a <= 0xFFFFFFFF
        assert b <= 0xFFFFFFFF
        assert c <= 0xFFFFFFFF

    def test_final_deterministic(self) -> None:
        result1 = _final(100, 200, 300)
        result2 = _final(100, 200, 300)
        assert result1 == result2


class TestHashlittle:
    """Tests for hashlittle() - single 32-bit hash."""

    def test_known_value(self) -> None:
        assert hashlittle(b"hello", 0) == 885767278

    def test_empty_bytes(self) -> None:
        result = hashlittle(b"", 0)
        assert isinstance(result, int)
        assert result <= 0xFFFFFFFF

    def test_single_byte(self) -> None:
        result = hashlittle(b"a", 0)
        assert isinstance(result, int)
        assert result <= 0xFFFFFFFF

    def test_two_bytes(self) -> None:
        result = hashlittle(b"ab", 0)
        assert isinstance(result, int)

    def test_three_bytes(self) -> None:
        result = hashlittle(b"abc", 0)
        assert isinstance(result, int)

    def test_four_bytes(self) -> None:
        result = hashlittle(b"abcd", 0)
        assert isinstance(result, int)

    def test_five_bytes(self) -> None:
        result = hashlittle(b"abcde", 0)
        assert isinstance(result, int)

    def test_six_bytes(self) -> None:
        result = hashlittle(b"abcdef", 0)
        assert isinstance(result, int)

    def test_seven_bytes(self) -> None:
        result = hashlittle(b"abcdefg", 0)
        assert isinstance(result, int)

    def test_eight_bytes(self) -> None:
        result = hashlittle(b"abcdefgh", 0)
        assert isinstance(result, int)

    def test_nine_bytes(self) -> None:
        result = hashlittle(b"abcdefghi", 0)
        assert isinstance(result, int)

    def test_ten_bytes(self) -> None:
        result = hashlittle(b"abcdefghij", 0)
        assert isinstance(result, int)

    def test_eleven_bytes(self) -> None:
        result = hashlittle(b"abcdefghijk", 0)
        assert isinstance(result, int)

    def test_twelve_bytes(self) -> None:
        result = hashlittle(b"abcdefghijkl", 0)
        assert isinstance(result, int)

    def test_thirteen_bytes_triggers_mix(self) -> None:
        """13-byte input enters the main loop once, then handles 1-byte tail."""
        result = hashlittle(b"abcdefghijklm", 0)
        assert isinstance(result, int)

    def test_twentyfour_bytes_two_blocks(self) -> None:
        """24-byte input: loop once, then full 12-byte tail."""
        result = hashlittle(b"abcdefghijklmnopqrstuvwx", 0)
        assert isinstance(result, int)

    def test_long_input(self) -> None:
        data = b"The quick brown fox jumps over the lazy dog"
        result = hashlittle(data, 0)
        assert isinstance(result, int)
        assert result <= 0xFFFFFFFF

    def test_initval_affects_result(self) -> None:
        h1 = hashlittle(b"test", 0)
        h2 = hashlittle(b"test", 1)
        assert h1 != h2

    def test_deterministic(self) -> None:
        data = b"deterministic test"
        assert hashlittle(data, 42) == hashlittle(data, 42)

    def test_different_data_different_hash(self) -> None:
        assert hashlittle(b"foo", 0) != hashlittle(b"bar", 0)

    def test_all_zeros(self) -> None:
        result = hashlittle(b"\x00\x00\x00\x00", 0)
        assert isinstance(result, int)

    def test_all_ones(self) -> None:
        result = hashlittle(b"\xff\xff\xff\xff", 0)
        assert isinstance(result, int)

    def test_binary_data(self) -> None:
        data = bytes(range(256))
        result = hashlittle(data, 0)
        assert isinstance(result, int)
        assert result <= 0xFFFFFFFF


class TestHashlittle2:
    """Tests for hashlittle2() - dual 32-bit hash."""

    def test_known_value(self) -> None:
        pc, pb = hashlittle2(b"hello", 0, 0)
        assert pc == 885767278
        assert pb == 1543812985

    def test_returns_tuple(self) -> None:
        result = hashlittle2(b"test", 0, 0)
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_empty_bytes(self) -> None:
        pc, pb = hashlittle2(b"", 0, 0)
        assert isinstance(pc, int)
        assert isinstance(pb, int)
        assert pc <= 0xFFFFFFFF
        assert pb <= 0xFFFFFFFF

    def test_single_byte(self) -> None:
        pc, pb = hashlittle2(b"x", 0, 0)
        assert isinstance(pc, int)
        assert isinstance(pb, int)

    def test_all_tail_lengths(self) -> None:
        """Exercise all tail-length branches (1-12 bytes)."""
        for length in range(1, 13):
            data = bytes(range(length))
            pc, pb = hashlittle2(data, 0, 0)
            assert pc <= 0xFFFFFFFF
            assert pb <= 0xFFFFFFFF

    def test_long_input(self) -> None:
        data = b"A" * 100
        pc, pb = hashlittle2(data, 0, 0)
        assert isinstance(pc, int)
        assert isinstance(pb, int)

    def test_pc_seed_affects_result(self) -> None:
        r1 = hashlittle2(b"test", 0, 0)
        r2 = hashlittle2(b"test", 1, 0)
        assert r1 != r2

    def test_pb_seed_affects_result(self) -> None:
        r1 = hashlittle2(b"test", 0, 0)
        r2 = hashlittle2(b"test", 0, 1)
        assert r1 != r2

    def test_deterministic(self) -> None:
        data = b"consistent hashing"
        assert hashlittle2(data, 5, 10) == hashlittle2(data, 5, 10)

    def test_pc_matches_hashlittle(self) -> None:
        """Primary hash from hashlittle2 should match hashlittle with pb=0."""
        data = b"hello"
        h1 = hashlittle(data, 0)
        pc, _ = hashlittle2(data, 0, 0)
        # Note: hashlittle2 with pb=0 may differ from hashlittle since pb affects c
        # but they should match when pb=0 because hashlittle doesn't add pb
        assert h1 == pc

    def test_multiblock_input(self) -> None:
        """25-byte input: 2 full blocks + 1-byte tail."""
        data = b"abcdefghijklmnopqrstuvwxy"
        pc, pb = hashlittle2(data, 0, 0)
        assert pc <= 0xFFFFFFFF
        assert pb <= 0xFFFFFFFF

    def test_binary_data(self) -> None:
        data = bytes(range(256))
        pc, pb = hashlittle2(data, 0, 0)
        assert isinstance(pc, int)
        assert isinstance(pb, int)


class TestCryptoModuleExports:
    """Test that the crypto __init__ exports work."""

    def test_import_from_crypto(self) -> None:
        from cascette_tools.crypto import hashlittle, hashlittle2
        assert callable(hashlittle)
        assert callable(hashlittle2)

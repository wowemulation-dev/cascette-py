"""Pytest configuration and shared fixtures for cascette_tools tests."""

import tempfile
from collections.abc import Generator
from pathlib import Path
from typing import Any
from unittest.mock import Mock, mock_open, patch

import pytest

# Import the main types for fixtures
from cascette_tools.core.config import AppConfig
from cascette_tools.core.types import BuildInfo, Product


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for tests."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        yield Path(tmp_dir)


@pytest.fixture
def sample_build_info() -> BuildInfo:
    """Sample BuildInfo for testing."""
    return BuildInfo(
        build_config="1234567890abcdef1234567890abcdef12345678",
        cdn_config="abcdef1234567890abcdef1234567890abcdef12",
        keyring="fedcba0987654321fedcba0987654321fedcba09",
        build_id=12345,
        version_name="1.15.0.54630",
        product_config="567890abcdef1234567890abcdef1234567890ab"
    )


@pytest.fixture
def sample_product() -> Product:
    """Sample Product for testing."""
    return Product.WOW_CLASSIC


@pytest.fixture
def mock_http_response() -> Mock:
    """Mock HTTP response for testing."""
    response = Mock()
    response.status_code = 200
    response.text = "mock response"
    response.content = b"mock content"
    response.headers = {"content-type": "application/octet-stream"}
    return response


@pytest.fixture
def sample_blte_data() -> bytes:
    """Sample BLTE data for testing."""
    # BLTE header: magic (4) + header size (4) + flags (1) + chunks (3)
    # Simplified BLTE with uncompressed single chunk
    header = b"BLTE"  # Magic
    header += (12).to_bytes(4, 'big')  # Header size
    header += (0).to_bytes(1, 'big')  # Flags
    header += (1).to_bytes(3, 'big')  # Number of chunks

    # Chunk info: compressed size (4) + uncompressed size (4) + checksum (16)
    chunk_data = b"Hello, BLTE!"
    chunk_info = len(chunk_data).to_bytes(4, 'big')  # Compressed size
    chunk_info += len(chunk_data).to_bytes(4, 'big')  # Uncompressed size
    chunk_info += b'\x00' * 16  # MD5 checksum (simplified)

    return header + chunk_info + chunk_data


@pytest.fixture
def sample_encoding_data() -> bytes:
    """Sample encoding file data for testing."""
    # Simplified encoding format
    header = b"EN"  # Magic
    header += (1).to_bytes(1, 'big')  # Version
    header += (16).to_bytes(1, 'big')  # Hash size CKey
    header += (16).to_bytes(1, 'big')  # Hash size EKey
    header += (1000).to_bytes(2, 'big')  # KB to read (simplified)
    header += (1).to_bytes(4, 'big')  # Entry count
    header += b'\x00' * 10  # Reserved

    # Single entry: CKey (16) + EKey (16) + size (5)
    entry = b'\x12' * 16  # Content key
    entry += b'\x34' * 16  # Encoding key
    entry += (1000).to_bytes(5, 'big')  # File size

    return header + entry


@pytest.fixture
def sample_raw_config_data() -> dict[str, Any]:
    """Sample configuration data for testing."""
    return {
        "cache_dir": "/tmp/cascette_cache",
        "cdn_hosts": ["cdn.arctium.tools", "us.patch.battle.net"],
        "user_agent": "cascette-tools/0.1.0",
        "timeout": 30,
        "max_retries": 3,
        "compression_modes": ["zlib", "lz4"],
        "debug": False,
    }


@pytest.fixture(scope="session")
def test_data_dir() -> Path:
    """Directory containing test data files."""
    return Path(__file__).parent / "fixtures"


# Pytest configuration
def pytest_configure(config: pytest.Config) -> None:
    """Configure pytest settings."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )
    config.addinivalue_line(
        "markers", "unit: marks tests as unit tests"
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list) -> None:
    """Modify test collection to add markers automatically."""
    for item in items:
        # Add unit marker to all tests by default
        if not any(marker.name in ['integration', 'slow'] for marker in item.iter_markers()):
            item.add_marker(pytest.mark.unit)

        # Add slow marker to tests that might take longer
        if 'network' in item.nodeid or 'download' in item.nodeid:
            item.add_marker(pytest.mark.slow)


# CLI Testing Fixtures with Enhanced File I/O Support


@pytest.fixture
def disable_coverage():
    """Temporarily disable coverage for faster test execution during development."""
    import os
    old_value = os.environ.get('COVERAGE_PROCESS_START')
    if 'COVERAGE_PROCESS_START' in os.environ:
        del os.environ['COVERAGE_PROCESS_START']
    yield
    if old_value is not None:
        os.environ['COVERAGE_PROCESS_START'] = old_value


@pytest.fixture
def mock_console() -> Mock:
    """Create standardized mock Rich console for CLI testing.

    This fixture provides a consistent console mock that:
    - Properly mocks the status context manager
    - Tracks printed output in printed_lines list for assertions
    - Provides consistent behavior across all CLI tests
    - Captures output that can be used for assertions
    """
    import sys
    from io import StringIO

    console = Mock()

    # Mock the status context manager
    status_cm = Mock()
    status_cm.__enter__ = Mock(return_value=status_cm)
    status_cm.__exit__ = Mock(return_value=None)
    console.status.return_value = status_cm

    # Track printed output for testing
    console.printed_lines = []
    console.captured_output = StringIO()

    def track_print(text, **kwargs):
        # Remove Rich markup for simpler testing
        import re
        clean_text = re.sub(r'\[/?[^\]]*\]', '', str(text))
        console.printed_lines.append(clean_text)
        console.captured_output.write(clean_text + '\n')
        # Also print to actual stdout so Click can capture it
        print(clean_text, file=sys.stdout)

    console.print.side_effect = track_print
    return console


@pytest.fixture
def mock_config() -> Mock:
    """Create standardized mock app config for CLI testing.

    This fixture provides a consistent config mock with commonly
    needed attributes for CLI command testing.
    """
    config = Mock(spec=AppConfig)
    config.output_format = "rich"
    config.data_dir = Path("/test/data")
    config.cache_dir = Path("/test/cache")
    config.cache = Mock()
    config.cdn = Mock()
    config.database = Mock()
    config.cdn_timeout = 30
    config.cdn_max_retries = 3
    return config


@pytest.fixture
def mock_cli_context(mock_config: Mock, mock_console: Mock) -> Mock:
    """Create standardized mock Click context for CLI testing.

    This fixture provides a consistent Click context mock that
    follows the standard pattern used across all CLI commands.
    """
    ctx = Mock()
    ctx.obj = {
        "config": mock_config,
        "console": mock_console,
        "verbose": False,
        "debug": False
    }
    ctx.ensure_object = Mock(return_value={})
    return ctx


@pytest.fixture
def mock_cli_runner_with_context(mock_cli_context):
    """Enhanced CLI runner that properly sets up Click context.

    This fixture provides a CliRunner that automatically includes
    the proper context setup for all cascette-tools commands.
    """
    from click.testing import CliRunner

    class ContextualCliRunner(CliRunner):
        def __init__(self, context_obj=None):
            super().__init__()
            self.context_obj = context_obj or mock_cli_context.obj

        def invoke(self, cli, args=None, **extra):  # type: ignore[override]
            # Ensure the CLI has proper context object
            if 'obj' not in extra:
                extra['obj'] = self.context_obj
            return super().invoke(cli, args, **extra)

    return ContextualCliRunner(mock_cli_context.obj)


@pytest.fixture
def enhanced_cli_test_setup(mock_config, mock_console, mock_file_operations):
    """Complete CLI test setup with context, config, console, and file I/O mocking.

    This fixture provides everything needed for testing CLI commands:
    - Proper Click context setup
    - Mocked app config and console
    - Enhanced file I/O mocking
    - CDN client mocking
    """
    from unittest.mock import patch

    from click.testing import CliRunner

    # Setup CLI context
    context_obj = {
        "config": mock_config,
        "console": mock_console,
        "verbose": False,
        "debug": False
    }

    # Enhanced CLI runner with context
    class ContextualCliRunner(CliRunner):
        def invoke(self, cli, args=None, **extra):  # type: ignore[override]
            if 'obj' not in extra:
                extra['obj'] = context_obj
            # Ensure standalone_mode is False for better error reporting
            if 'standalone_mode' not in extra:
                extra['standalone_mode'] = False
            return super().invoke(cli, args, **extra)

    runner = ContextualCliRunner()

    # Mock CDN clients to prevent network calls
    with patch('cascette_tools.core.cdn.CDNClient') as mock_cdn_class:
        with patch('cascette_tools.core.tact.TACTClient') as mock_tact_class:
            with mock_file_operations.patch_save_file():
                # Setup default CDN client behavior
                mock_cdn = Mock()
                mock_cdn.fetch_config.return_value = b'mock config data'
                mock_cdn.fetch_data.return_value = b'mock data content'
                mock_cdn.fetch_patch.return_value = b'mock patch data'
                mock_cdn.__enter__ = Mock(return_value=mock_cdn)
                mock_cdn.__exit__ = Mock(return_value=None)
                mock_cdn_class.return_value = mock_cdn

                # Setup default TACT client behavior
                mock_tact = Mock()
                mock_tact.fetch_versions.return_value = 'mock versions data'
                mock_tact.fetch_cdns.return_value = 'mock cdns data'
                mock_tact.parse_versions.return_value = []
                mock_tact.parse_cdns.return_value = []
                mock_tact_class.return_value = mock_tact

                yield {
                    'runner': runner,
                    'context': context_obj,
                    'config': mock_config,
                    'console': mock_console,
                    'file_ops': mock_file_operations,
                    'cdn_client': mock_cdn,
                    'tact_client': mock_tact,
                    'cdn_client_class': mock_cdn_class,
                    'tact_client_class': mock_tact_class
                }


# Enhanced File I/O Mocking Fixtures

@pytest.fixture
def mock_file_operations():
    """Enhanced file I/O mocking for cascette-tools commands.

    Provides mocking for specific file operations without interfering
    with pytest's internal operations.
    """
    class FileOperationMocks:
        def __init__(self):
            self.written_files = {}
            self.existing_files = {}
            self.permission_errors = set()

        def setup_file(self, path, content=b'test content'):
            """Add a file to the existing files registry."""
            self.existing_files[str(path)] = content

        def add_permission_error(self, path):
            """Add a path that should raise permission errors."""
            self.permission_errors.add(str(path))

        def get_written_file(self, path):
            """Get content of a written file."""
            return self.written_files.get(str(path))

        def clear(self):
            """Clear all mocked files and errors."""
            self.written_files.clear()
            self.existing_files.clear()
            self.permission_errors.clear()

        def patch_save_file(self):
            """Patch the _save_file function specifically."""
            def mock_save_file(data, output_path, console, verbose):
                path_str = str(output_path)
                if path_str in self.permission_errors:
                    raise PermissionError(f"Permission denied: {path_str}")
                self.written_files[path_str] = data
                if verbose:
                    console.print(f"Saved {len(data)} bytes to {output_path}")

            return patch('cascette_tools.commands.fetch._save_file', side_effect=mock_save_file)

    return FileOperationMocks()


@pytest.fixture
def mock_tempfile_operations():
    """Mock tempfile operations for testing temporary file handling.

    Provides mocking for:
    - tempfile.NamedTemporaryFile
    - tempfile.TemporaryDirectory
    - tempfile.mktemp
    """
    class TempfileMocks:
        def __init__(self):
            self.temp_files = {}
            self.temp_dirs = set()

        def mock_named_temporary_file(self, mode='w+b', delete=True, **kwargs):
            """Mock tempfile.NamedTemporaryFile."""
            temp_name = f"/tmp/mock_temp_{len(self.temp_files)}"
            mock_file = Mock()
            mock_file.name = temp_name
            mock_file.write.side_effect = lambda data: self.temp_files.update({temp_name: data})
            mock_file.read.side_effect = lambda: self.temp_files.get(temp_name, b'')
            mock_file.__enter__ = Mock(return_value=mock_file)
            mock_file.__exit__ = Mock(return_value=None)
            return mock_file

        def mock_temporary_directory(self, **kwargs):
            """Mock tempfile.TemporaryDirectory."""
            temp_dir = f"/tmp/mock_temp_dir_{len(self.temp_dirs)}"
            self.temp_dirs.add(temp_dir)
            mock_dir = Mock()
            mock_dir.name = temp_dir
            mock_dir.__enter__ = Mock(return_value=temp_dir)
            mock_dir.__exit__ = Mock(return_value=None)
            return mock_dir

        def mock_mktemp(self, **kwargs):
            """Mock tempfile.mktemp."""
            return f"/tmp/mock_mktemp_{len(self.temp_files)}"

    mocks = TempfileMocks()

    with patch('tempfile.NamedTemporaryFile', side_effect=mocks.mock_named_temporary_file):
        with patch('tempfile.TemporaryDirectory', side_effect=mocks.mock_temporary_directory):
            with patch('tempfile.mktemp', side_effect=mocks.mock_mktemp):
                yield mocks


@pytest.fixture
def mock_batch_file_operations():
    """Mock batch file operations for testing multiple file scenarios.

    Provides support for:
    - Batch file reading from hash lists
    - Directory traversal for batch validation
    - File pattern matching (glob operations)
    """
    class BatchFileMocks:
        def __init__(self):
            self.file_contents = {}
            self.directories = {}

        def mock_open_file(self, path, mode='r', encoding='utf-8'):
            """Mock file opening for batch operations."""
            path_str = str(path)
            if 'r' in mode:
                if path_str not in self.file_contents:
                    raise FileNotFoundError(f"No such file: {path_str}")
                content = self.file_contents[path_str]
                if 'b' in mode:
                    mock_file = mock_open(read_data=content)()
                else:
                    text_content = content.decode('utf-8') if isinstance(content, bytes) else content
                    mock_file = mock_open(read_data=text_content)()
                return mock_file
            else:
                # Write mode
                mock_file = mock_open()()
                return mock_file

        def mock_glob(self, path, pattern):
            """Mock Path.glob for directory traversal."""
            path_str = str(path)
            if path_str not in self.directories:
                return []
            return [Path(f) for f in self.directories[path_str] if pattern == '*' or pattern in f]

        def mock_rglob(self, path, pattern):
            """Mock Path.rglob for recursive directory traversal."""
            # For simplicity, just return the same as glob
            return self.mock_glob(path, pattern)

        def add_file(self, path, content):
            """Add a file to the batch file registry."""
            self.file_contents[str(path)] = content

        def add_directory(self, path, files):
            """Add a directory with files to the registry."""
            self.directories[str(path)] = [str(f) for f in files]

    mocks = BatchFileMocks()

    with patch('builtins.open', side_effect=mocks.mock_open_file):
        with patch('pathlib.Path.glob', side_effect=mocks.mock_glob):
            with patch('pathlib.Path.rglob', side_effect=mocks.mock_rglob):
                yield mocks


@pytest.fixture
def mock_cdn_and_file_operations(mock_file_operations):
    """Combined mock for CDN client and file operations.

    This fixture combines CDN client mocking with file I/O mocking
    for comprehensive testing of fetch and validate commands.
    """
    class CdnFileMocks:
        def __init__(self, file_ops):
            self.file_ops = file_ops
            self.cdn_responses = {}
            self.cdn_errors = {}

        def mock_cdn_fetch(self, method_name, hash_or_path, **kwargs):
            """Mock CDN fetch operations."""
            key = f"{method_name}:{hash_or_path}"
            if key in self.cdn_errors:
                raise self.cdn_errors[key]
            return self.cdn_responses.get(key, b'mock cdn data')

        def add_cdn_response(self, method_name, hash_or_path, response):
            """Add a CDN response for a specific method and hash."""
            key = f"{method_name}:{hash_or_path}"
            self.cdn_responses[key] = response

        def add_cdn_error(self, method_name, hash_or_path, error):
            """Add a CDN error for a specific method and hash."""
            key = f"{method_name}:{hash_or_path}"
            self.cdn_errors[key] = error

    cdn_mocks = CdnFileMocks(mock_file_operations)

    with patch('cascette_tools.core.cdn.CDNClient') as mock_cdn_class:
        mock_cdn = Mock()
        mock_cdn.fetch_config.side_effect = lambda h: cdn_mocks.mock_cdn_fetch('fetch_config', h)
        mock_cdn.fetch_data.side_effect = lambda h, **kw: cdn_mocks.mock_cdn_fetch('fetch_data', h)
        mock_cdn.fetch_patch.side_effect = lambda h, **kw: cdn_mocks.mock_cdn_fetch('fetch_patch', h)
        mock_cdn_class.return_value.__enter__.return_value = mock_cdn
        mock_cdn_class.return_value.__exit__.return_value = None

        yield cdn_mocks, mock_cdn


@pytest.fixture
def mock_comprehensive_io():
    """Comprehensive I/O mocking combining all file operations.

    This fixture provides a one-stop solution for mocking all I/O operations
    needed by cascette-tools commands including:
    - File reading/writing operations
    - Temporary file operations
    - Directory operations
    - Batch file operations
    """
    with patch('pathlib.Path.write_bytes') as mock_write_bytes:
        with patch('pathlib.Path.write_text') as mock_write_text:
            with patch('pathlib.Path.read_bytes') as mock_read_bytes:
                with patch('pathlib.Path.read_text') as mock_read_text:
                    with patch('pathlib.Path.exists') as mock_exists:
                        with patch('pathlib.Path.mkdir') as mock_mkdir:
                            with patch('pathlib.Path.glob') as mock_glob:
                                with patch('pathlib.Path.rglob') as mock_rglob:
                                    with patch('builtins.open', mock_open()) as mock_open_file:
                                        # Set up default behaviors
                                        mock_exists.return_value = True
                                        mock_read_bytes.return_value = b'mock file content'
                                        mock_read_text.return_value = 'mock file content'
                                        mock_glob.return_value = []
                                        mock_rglob.return_value = []

                                        yield {
                                            'write_bytes': mock_write_bytes,
                                            'write_text': mock_write_text,
                                            'read_bytes': mock_read_bytes,
                                            'read_text': mock_read_text,
                                            'exists': mock_exists,
                                            'mkdir': mock_mkdir,
                                            'glob': mock_glob,
                                            'rglob': mock_rglob,
                                            'open': mock_open_file
                                        }


@pytest.fixture
def mock_hash_validation():
    """Mock hash validation utilities.

    Provides mocking for validate_hash_string and related utilities
    used throughout the commands.
    """
    with patch('cascette_tools.core.utils.validate_hash_string') as mock_validate:
        with patch('cascette_tools.core.utils.compute_md5') as mock_compute_md5:
            # Default behaviors
            mock_validate.return_value = True
            mock_hash_obj = Mock()
            mock_hash_obj.hex.return_value = 'abcdef1234567890abcdef1234567890'
            mock_compute_md5.return_value = mock_hash_obj

            yield {
                'validate_hash': mock_validate,
                'compute_md5': mock_compute_md5,
                'hash_obj': mock_hash_obj
            }

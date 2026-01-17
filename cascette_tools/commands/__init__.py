"""CLI command implementations for cascette_tools.

This module contains all command-line interface implementations:
- examine: Examine NGDP/CASC format files
- analyze: Analyze format data and statistics
- fetch: Download data from CDN sources
- builds: Manage WoW build database from Wago.tools
- tact: TACT key management operations
- validate: Validate format structures
- listfile: Listfile management operations
- install_state: Analyze installation state and progress
"""

from cascette_tools.commands.analyze import analyze
from cascette_tools.commands.builds import builds_group
from cascette_tools.commands.examine import examine
from cascette_tools.commands.fetch import fetch
from cascette_tools.commands.install_analyzer import install_state
from cascette_tools.commands.listfile import listfile_group
from cascette_tools.commands.tact import tact_group
from cascette_tools.commands.validate import validate

__all__ = [
    "analyze",
    "builds_group",
    "examine",
    "fetch",
    "install_state",
    "listfile_group",
    "tact_group",
    "validate",
]

"""CLI command implementations for cascette_tools.

This module contains all command-line interface implementations organized
around the agent.exe workflow: cdn (fetch), install, update, and maintenance.

- cdn: Download data from Blizzard's NGDP CDN infrastructure
- inspect: Examine and analyze NGDP/CASC format files
- validate: Validate format structures
- archive: Work with CDN archive indices and archive-groups
- install: Install and manage game content via the NGDP/CASC pipeline
- builds: Manage WoW build database from Wago.tools
- tact: TACT key management operations
- listfile: Listfile management operations
"""

from cascette_tools.commands.archive import archive
from cascette_tools.commands.builds import builds_group
from cascette_tools.commands.cdn import cdn
from cascette_tools.commands.inspect import inspect
from cascette_tools.commands.install import install
from cascette_tools.commands.listfile import listfile_group
from cascette_tools.commands.tact import tact_group
from cascette_tools.commands.validate import validate

__all__ = [
    "archive",
    "builds_group",
    "cdn",
    "inspect",
    "install",
    "listfile_group",
    "tact_group",
    "validate",
]

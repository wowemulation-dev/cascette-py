"""Main entry point for cascette-tools CLI."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import click
import structlog
from rich.console import Console

from cascette_tools.commands.analyze import analyze
from cascette_tools.commands.archive import archive
from cascette_tools.commands.archive_search import archive_search
from cascette_tools.commands.builds import builds_group
from cascette_tools.commands.examine import examine
from cascette_tools.commands.fetch import fetch
from cascette_tools.commands.install_analyzer import install_state
from cascette_tools.commands.install_poc import install_poc
from cascette_tools.commands.listfile import listfile_group
from cascette_tools.commands.tact import tact_group
from cascette_tools.commands.validate import validate
from cascette_tools.core.config import AppConfig

# Configure structured logging
structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.dev.set_exc_info,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.ConsoleRenderer(),
    ],
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()


@click.group()
@click.version_option(version="0.1.0", prog_name="cascette-tools")
@click.option(
    "--config",
    "-c",
    type=click.Path(exists=True, path_type=Path),
    help="Configuration file path",
)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.option("--debug", "-d", is_flag=True, help="Enable debug output")
@click.option(
    "--output",
    "-o",
    type=click.Choice(["rich", "json", "plain"], case_sensitive=False),
    default="rich",
    help="Output format",
)
@click.pass_context
def main(
    ctx: click.Context,
    config: Path | None,
    verbose: bool,
    debug: bool,
    output: str,
) -> None:
    """Python tools for NGDP/CASC format analysis."""
    ctx.ensure_object(dict)

    # Load configuration
    try:
        app_config = AppConfig.load(config)
    except Exception as e:
        logger.error("Failed to load configuration", error=str(e))
        sys.exit(1)

    # Override config with CLI options
    if verbose or debug:
        app_config.log_level = "DEBUG" if debug else "INFO"
    if output:
        app_config.output_format = output

    # Configure logging level
    if debug:
        structlog.configure(
            processors=[
                structlog.contextvars.merge_contextvars,
                structlog.processors.add_log_level,
                structlog.processors.StackInfoRenderer(),
                structlog.dev.set_exc_info,
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.dev.ConsoleRenderer(colors=True),
            ],
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )

    # Create console for rich output
    console = Console(
        force_terminal=output == "rich",
        no_color=output != "rich",
        width=None if output == "rich" else 120,
    )

    # Store config and console in context for subcommands
    ctx.obj["config"] = app_config
    ctx.obj["console"] = console
    ctx.obj["verbose"] = verbose or debug
    ctx.obj["debug"] = debug

    logger.debug("CLI initialized", config=app_config.model_dump())


@main.command()
@click.pass_context
def version(ctx: click.Context) -> None:
    """Show version information."""
    console: Console = ctx.obj["console"]
    config: AppConfig = ctx.obj["config"]

    if config.output_format == "json":
        import json

        info = {
            "name": "cascette-tools",
            "version": "0.1.0",
            "python_version": sys.version.replace("\n", " "),
            "platform": sys.platform,
        }
        # Use regular print for JSON to avoid Rich formatting
        print(json.dumps(info, indent=2))
    else:
        console.print("cascette-tools 0.1.0")
        if ctx.obj["verbose"]:
            console.print(f"Python {sys.version}")
            console.print(f"Platform: {sys.platform}")


# Register commands
main.add_command(analyze)
main.add_command(archive)
main.add_command(archive_search)
main.add_command(builds_group)
main.add_command(examine)
main.add_command(fetch)
main.add_command(install_state)
main.add_command(install_poc)
main.add_command(listfile_group)
main.add_command(tact_group)
main.add_command(validate)




def handle_exception(exc_type: type[BaseException], exc_value: BaseException, exc_traceback: Any) -> None:
    """Handle uncaught exceptions."""
    if issubclass(exc_type, KeyboardInterrupt):
        logger.info("Operation cancelled by user")
        sys.exit(1)

    logger.error(
        "Uncaught exception",
        exc_info=(exc_type, exc_value, exc_traceback),
    )
    sys.exit(1)


if __name__ == "__main__":
    # Install exception handler
    sys.excepthook = handle_exception

    try:
        main()
    except Exception as e:
        logger.error("CLI execution failed", error=str(e))
        sys.exit(1)

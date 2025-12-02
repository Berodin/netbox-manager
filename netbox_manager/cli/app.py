# SPDX-License-Identifier: Apache-2.0
"""Typer CLI entrypoint for netbox-manager."""

import signal
import sys
from importlib import metadata
from typing import Optional, List
from typing_extensions import Annotated

import typer

from netbox_manager.services import archive, autoconf, purge, resources, validation


def signal_handler_sigint(sig: int, frame: object) -> None:
    """Handle SIGINT signal gracefully."""
    print("SIGINT received. Exit.")
    raise typer.Exit()


def callback_version(value: bool) -> None:
    """Show version and exit if requested."""
    if value:
        print(f"Version {metadata.version('netbox-manager')}")
        raise typer.Exit()


app = typer.Typer()


@app.command(name="run", help="Process NetBox resources, device types, and module types")
def run_command(
    always: Annotated[bool, typer.Option(help="Always run")] = True,
    debug: Annotated[bool, typer.Option(help="Debug")] = False,
    dryrun: Annotated[bool, typer.Option(help="Dry run")] = False,
    limit: Annotated[Optional[str], typer.Option(help="Limit files by prefix")] = None,
    parallel: Annotated[
        Optional[int], typer.Option(help="Process up to n files in parallel")
    ] = 1,
    version: Annotated[
        Optional[bool],
        typer.Option(
            "--version",
            help="Show version and exit",
            callback=callback_version,
            is_eager=True,
        ),
    ] = None,
    skipdtl: Annotated[bool, typer.Option(help="Skip devicetype library")] = False,
    skipmtl: Annotated[bool, typer.Option(help="Skip moduletype library")] = False,
    skipres: Annotated[bool, typer.Option(help="Skip resources")] = False,
    wait: Annotated[bool, typer.Option(help="Wait for NetBox service")] = True,
    filter_task: Annotated[
        Optional[str],
        typer.Option(help="Filter tasks by type (e.g., 'device', 'device_interface')"),
    ] = None,
    include_ignored_files: Annotated[
        bool, typer.Option(help="Include files that are normally ignored")
    ] = False,
    filter_device: Annotated[
        Optional[List[str]],
        typer.Option(help="Filter tasks by device name (can be used multiple times)"),
    ] = None,
    fail_fast: Annotated[
        bool, typer.Option("--fail-fast", help="Exit on first Ansible playbook failure")
    ] = False,
    show_playbooks: Annotated[
        bool,
        typer.Option(
            "--show-playbooks",
            help="Output generated playbooks to stdout without executing them",
        ),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose", help="Run ansible-playbook with -vvv for detailed output"
        ),
    ] = False,
    ignore_errors: Annotated[
        bool,
        typer.Option("--ignore-errors", help="Continue execution even if tasks fail"),
    ] = False,
) -> None:
    """Process NetBox resources, device types, and module types."""
    resources.run(
        always=always,
        debug=debug,
        dryrun=dryrun,
        limit=limit,
        parallel=parallel,
        skipdtl=skipdtl,
        skipmtl=skipmtl,
        skipres=skipres,
        wait=wait,
        filter_task=filter_task,
        include_ignored_files=include_ignored_files,
        filter_device=filter_device,
        fail_fast=fail_fast,
        show_playbooks=show_playbooks,
        verbose=verbose,
        ignore_errors=ignore_errors,
    )


@app.command(
    name="export-archive",
    help="Export devicetypes, moduletypes, and resources to netbox-export.tar.gz",
)
def export_archive_command(
    image: Annotated[
        bool,
        typer.Option(
            "--image", "-i", help="Create an ext4 image file containing the tarball"
        ),
    ] = False,
    image_size: Annotated[
        int, typer.Option("--image-size", help="Size of the ext4 image in MB")
    ] = 100,
) -> None:
    archive.export_archive(image=image, image_size=image_size)


@app.command(
    name="import-archive",
    help="Import and sync content from a netbox-export.tar.gz file",
)
def import_archive_command(
    input_file: Annotated[
        str,
        typer.Option(
            "--input",
            "-i",
            help="Input tarball file to import (default: netbox-export.tar.gz)",
        ),
    ] = "netbox-export.tar.gz",
    destination: Annotated[
        str,
        typer.Option(
            "--destination",
            "-d",
            help="Destination directory for imported content (default: /opt/configuration/netbox)",
        ),
    ] = "/opt/configuration/netbox",
) -> None:
    archive.import_archive(input_file=input_file, destination=destination)


@app.command(name="autoconf", help="Generate automatic configuration based on NetBox data")
def autoconf_command(
    output: Annotated[str, typer.Option(help="Output file path")] = "999-autoconf.yml",
    loopback_output: Annotated[
        str, typer.Option(help="Loopback interfaces output file path")
    ] = "299-autoconf.yml",
    cluster_loopback_output: Annotated[
        str, typer.Option(help="Cluster-based loopback IPs output file path")
    ] = "399-autoconf.yml",
    portchannel_output: Annotated[
        str, typer.Option(help="PortChannel LAG interfaces output file path")
    ] = "999-autoconf-portchannel.yml",
    debug: Annotated[bool, typer.Option(help="Debug")] = False,
    dryrun: Annotated[
        bool, typer.Option(help="Dry run - show tasks but don't write file")
    ] = False,
) -> None:
    autoconf.run_autoconf(
        output=output,
        loopback_output=loopback_output,
        cluster_loopback_output=cluster_loopback_output,
        portchannel_output=portchannel_output,
        debug=debug,
        dryrun=dryrun,
    )


@app.command(name="purge", help="Delete all managed resources from NetBox")
def purge_command(
    debug: Annotated[bool, typer.Option(help="Debug")] = False,
    dryrun: Annotated[
        bool, typer.Option(help="Dry run - show what would be deleted")
    ] = False,
    limit: Annotated[
        Optional[str], typer.Option(help="Limit deletion to specific resource type")
    ] = None,
    exclude_core: Annotated[
        bool, typer.Option(help="Exclude core resources (tenants, sites, locations)")
    ] = False,
    force: Annotated[
        bool, typer.Option(help="Force deletion without confirmation", prompt=False)
    ] = False,
    verbose: Annotated[
        bool, typer.Option(help="Show detailed information about what is being deleted")
    ] = False,
    parallel: Annotated[
        int,
        typer.Option(help="Delete up to n resources of same type in parallel"),
    ] = 1,
) -> None:
    purge.purge(
        debug=debug,
        dryrun=dryrun,
        limit=limit,
        exclude_core=exclude_core,
        force=force,
        verbose=verbose,
        parallel=parallel,
    )


@app.command(name="validate", help="Validate NetBox configuration consistency")
def validate_command(
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Enable verbose output"),
    ] = False,
    check: Annotated[
        Optional[List[str]],
        typer.Option(
            "--check",
            "-c",
            help="Specific check to run (can be used multiple times). Valid: ip-prefixes, vrf-consistency",
        ),
    ] = None,
) -> None:
    validation.run_validation(verbose=verbose, check=check)


@app.command(name="version", help="Show version information")
def version_command() -> None:
    """Display version information for netbox-manager."""
    print(f"netbox-manager {metadata.version('netbox-manager')}")


@app.callback(invoke_without_command=True)
def main_callback(ctx: typer.Context):
    """Handle default behavior when no command is specified."""
    if ctx.invoked_subcommand is None:
        run_command()


def main() -> None:
    signal.signal(signal.SIGINT, signal_handler_sigint)
    app()


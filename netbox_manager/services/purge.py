# SPDX-License-Identifier: Apache-2.0
"""NetBox purge service."""

import concurrent.futures
from typing import Any, Dict, List, Optional, Tuple

from loguru import logger
import pynetbox
import typer

from netbox_manager.config import settings, validate_netbox_connection
from netbox_manager.logging_utils import init_logger
from netbox_manager.netbox.api import create_netbox_api, get_resource_name


def purge(
    debug: bool = False,
    dryrun: bool = False,
    limit: Optional[str] = None,
    exclude_core: bool = False,
    force: bool = False,
    verbose: bool = False,
    parallel: int = 1,
) -> None:
    """Delete all managed resources from NetBox."""
    init_logger(debug)
    validate_netbox_connection()

    if not force and not dryrun:
        confirm = typer.confirm(
            "!!  This will DELETE all managed resources from NetBox. Are you sure?",
            default=False,
        )
        if not confirm:
            logger.info("Purge cancelled by user")
            raise typer.Exit()

    try:
        netbox_api = create_netbox_api()
        logger.info("Starting NetBox purge operation...")

        deletion_order = [
            ("ipam.ip_addresses", "IP addresses"),
            ("ipam.fhrp_group_assignments", "FHRP group assignments"),
            ("dcim.cables", "cables"),
            ("dcim.mac_addresses", "MAC addresses"),
            ("dcim.interfaces", "interfaces"),
            ("dcim.console_server_ports", "console server ports"),
            ("dcim.console_ports", "console ports"),
            ("dcim.power_outlets", "power outlets"),
            ("dcim.power_ports", "power ports"),
            ("dcim.device_bays", "device bays"),
            ("dcim.inventory_items", "inventory items"),
            ("dcim.devices", "devices"),
            ("dcim.virtual_chassis", "virtual chassis"),
            ("dcim.device_types", "device types"),
            ("dcim.module_types", "module types"),
            ("virtualization.clusters", "clusters"),
            ("virtualization.cluster_types", "cluster types"),
            ("ipam.fhrp_groups", "FHRP groups"),
            ("ipam.prefixes", "prefixes"),
            ("ipam.vlans", "VLANs"),
            ("ipam.vlan_groups", "VLAN groups"),
            ("ipam.vrfs", "VRFs"),
            ("dcim.racks", "racks"),
            ("dcim.locations", "locations"),
            ("dcim.sites", "sites"),
            ("organization.tenants", "tenants"),
            ("extras.config_contexts", "config contexts"),
            ("dcim.manufacturers", "manufacturers"),
        ]

        if limit:
            normalized_limit = limit.replace("-", "_").replace(".", "_")
            deletion_order = [
                (api_path, name)
                for api_path, name in deletion_order
                if normalized_limit in api_path.replace(".", "_")
            ]
            if not deletion_order:
                logger.error(f"No resource type matching '{limit}' found")
                raise typer.Exit(1)

        if exclude_core:
            core_resources = ["sites", "locations", "tenants", "racks"]
            deletion_order = [
                (api_path, name)
                for api_path, name in deletion_order
                if not any(core in name for core in core_resources)
            ]

        total_deleted = 0
        errors: List[str] = []

        for api_path, resource_name in deletion_order:
            try:
                api_parts = api_path.split(".")
                endpoint = netbox_api
                for part in api_parts:
                    endpoint = getattr(endpoint, part)

                resources = list(endpoint.all())

                if not resources:
                    if verbose:
                        logger.info(f"No {resource_name} found to delete")
                    else:
                        logger.debug(f"No {resource_name} found to delete")
                    continue

                if dryrun:
                    logger.info(f"Would delete {len(resources)} {resource_name}")
                    if verbose:
                        for resource in resources:
                            name_attr = get_resource_name(resource)
                            logger.info(f"  Would delete {resource_name}: {name_attr}")
                    else:
                        for resource in resources[:5]:
                            name_attr = get_resource_name(resource)
                            logger.debug(f"  - {name_attr}")
                        if len(resources) > 5:
                            logger.debug(f"  ... and {len(resources) - 5} more")
                    continue

                if verbose:
                    logger.info(f"Deleting {len(resources)} {resource_name}...")

                deleted_count = 0

                if api_path in ["users.users", "users.tokens", "auth.tokens"]:
                    continue

                def delete_resource(resource: Any) -> Tuple[bool, Optional[str]]:
                    try:
                        name_attr = get_resource_name(resource)

                        if verbose:
                            logger.info(f"  Deleting {resource_name}: {name_attr}")

                        resource.delete()
                        return True, None
                    except Exception as exc:
                        name_attr = get_resource_name(resource)
                        error_msg = (
                            f"Failed to delete {resource_name} '{name_attr}': {exc}"
                        )
                        if verbose:
                            logger.warning(error_msg)
                        else:
                            logger.debug(error_msg)
                        return False, f"{resource_name} '{name_attr}': {exc}"

                with concurrent.futures.ThreadPoolExecutor(
                    max_workers=parallel
                ) as executor:
                    futures = [
                        executor.submit(delete_resource, resource)
                        for resource in resources
                    ]

                    for future in concurrent.futures.as_completed(futures):
                        success, error = future.result()
                        if success:
                            deleted_count += 1
                        elif error:
                            errors.append(error)

                if deleted_count > 0:
                    logger.info(f"Deleted {deleted_count} {resource_name}")
                    total_deleted += deleted_count

            except AttributeError:
                logger.debug(f"API endpoint {api_path} not found, skipping")
            except Exception as exc:
                logger.error(f"Error processing {resource_name}: {exc}")
                errors.append(f"{resource_name}: {exc}")

        if dryrun:
            logger.info("Dry run complete - no resources were deleted")
        else:
            logger.info(f"Purge complete - deleted {total_deleted} resources")

        if errors:
            logger.warning(f"Encountered {len(errors)} errors during deletion:")
            for error in errors[:10]:
                logger.warning(f"  - {error}")
            if len(errors) > 10:
                logger.warning(f"  ... and {len(errors) - 10} more errors")

    except pynetbox.RequestError as exc:
        logger.error(f"NetBox API error: {exc}")
        raise typer.Exit(1)
    except Exception as exc:  # pragma: no cover - defensive
        logger.error(f"Error during purge: {exc}")
        raise typer.Exit(1)


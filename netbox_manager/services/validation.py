# SPDX-License-Identifier: Apache-2.0
"""Validation checks for NetBox data consistency."""

import ipaddress
from typing import Any, Dict, Iterable, List, Optional, Tuple

from loguru import logger
import pynetbox
import typer

from netbox_manager.config import validate_netbox_connection
from netbox_manager.logging_utils import init_logger
from netbox_manager.netbox.api import create_netbox_api


def validate_ip_addresses_have_prefixes(
    netbox_api: pynetbox.api, verbose: bool = False
) -> Tuple[bool, List[Dict[str, Any]]]:
    """Validate that all IP addresses belong to a prefix in the same VRF."""
    orphaned_ips: List[Dict[str, Any]] = []

    if verbose:
        logger.info("Validating IP addresses have matching prefixes...")

    try:
        all_ips = netbox_api.ipam.ip_addresses.all()
        total_ips = len(all_ips)

        if verbose:
            logger.info(f"Checking {total_ips} IP addresses...")

        for idx, ip_obj in enumerate(all_ips, 1):
            if verbose and idx % 100 == 0:
                logger.debug(f"Progress: {idx}/{total_ips} IP addresses checked")

            orphan_issue = _validate_single_ip(netbox_api, ip_obj)
            if orphan_issue:
                orphaned_ips.append(orphan_issue)

        validation_passed = len(orphaned_ips) == 0

        if verbose:
            if validation_passed:
                logger.info("IP-Prefix check passed")
            else:
                logger.warning(
                    f"Found {len(orphaned_ips)} IP addresses without matching prefixes"
                )

        return validation_passed, orphaned_ips

    except pynetbox.RequestError as exc:
        logger.error(f"NetBox API error during IP-prefix validation: {exc}")
        raise


def _validate_single_ip(netbox_api: pynetbox.api, ip_obj: Any) -> Optional[Dict[str, Any]]:
    """Validate a single IP object's prefix membership."""
    ip_address_str = str(ip_obj.address)
    ip_vrf = ip_obj.vrf
    vrf_id = ip_vrf.id if ip_vrf else None

    device_name = None
    interface_name = None
    if ip_obj.assigned_object:
        assigned_obj = ip_obj.assigned_object
        if hasattr(assigned_obj, "device") and assigned_obj.device:
            device_name = assigned_obj.device.name
        if hasattr(assigned_obj, "name"):
            interface_name = assigned_obj.name

    try:
        ip_network = ipaddress.ip_network(ip_address_str, strict=False)
    except ValueError as exc:
        return _orphan_issue(
            ip_address_str,
            ip_vrf,
            device_name,
            interface_name,
            ip_obj.assigned_object,
            f"Invalid IP address format: {exc}",
        )

    matching_prefixes = (
        netbox_api.ipam.prefixes.filter(contains=str(ip_network.network_address), vrf_id=vrf_id)
        if vrf_id
        else netbox_api.ipam.prefixes.filter(contains=str(ip_network.network_address), vrf_id="null")
    )

    if not matching_prefixes:
        return _orphan_issue(
            ip_address_str,
            ip_vrf,
            device_name,
            interface_name,
            ip_obj.assigned_object,
            "No matching prefix found in same VRF",
        )
    return None


def _orphan_issue(
    address: str,
    vrf: Any,
    device: Optional[str],
    interface: Optional[str],
    assigned_object: Any,
    reason: str,
) -> Dict[str, Any]:
    """Construct orphan IP record."""
    return {
        "address": address,
        "vrf": str(vrf.name) if vrf else "Global",
        "device": device,
        "interface": interface,
        "assigned_object": str(assigned_object) if assigned_object else "Unassigned",
        "reason": reason,
    }


def validate_vrf_consistency(
    netbox_api: pynetbox.api, verbose: bool = False
) -> Tuple[bool, List[Dict[str, Any]]]:
    """Validate VRF consistency between IP addresses and device interfaces."""
    inconsistencies: List[Dict[str, Any]] = []

    if verbose:
        logger.info("Validating VRF consistency between IPs and interfaces...")

    try:
        ips_with_vrf = netbox_api.ipam.ip_addresses.filter(vrf_id__n="null")
        total_ips = len(ips_with_vrf)

        if verbose:
            logger.info(f"Checking {total_ips} IP addresses with VRF assignments...")

        for idx, ip_obj in enumerate(ips_with_vrf, 1):
            if verbose and idx % 100 == 0:
                logger.debug(f"Progress: {idx}/{total_ips} VRF IPs checked")

            inconsistency = _check_ip_vrf_consistency(netbox_api, ip_obj, verbose)
            if inconsistency:
                inconsistencies.append(inconsistency)

        validation_passed = len(inconsistencies) == 0

        if verbose:
            if validation_passed:
                logger.info("VRF consistency check passed")
            else:
                logger.warning(
                    f"Found {len(inconsistencies)} VRF consistency issues"
                )

        return validation_passed, inconsistencies

    except pynetbox.RequestError as exc:
        logger.error(f"NetBox API error during VRF consistency validation: {exc}")
        raise


def _check_ip_vrf_consistency(
    netbox_api: pynetbox.api, ip_obj: Any, verbose: bool
) -> Optional[Dict[str, Any]]:
    """Return inconsistency dict if VRF mismatch is found for a single IP."""
    if not ip_obj.assigned_object:
        return None

    assigned_obj = ip_obj.assigned_object
    if not hasattr(assigned_obj, "device") or not assigned_obj.device:
        return None

    try:
        interface = netbox_api.dcim.interfaces.get(assigned_obj.id)
    except Exception as exc:
        if verbose:
            logger.warning(f"Could not retrieve interface {assigned_obj.id}: {exc}")
        return None

    if not interface:
        return None

    ip_vrf = ip_obj.vrf
    interface_vrf = interface.vrf

    ip_vrf_id = ip_vrf.id if ip_vrf else None
    interface_vrf_id = interface_vrf.id if interface_vrf else None

    if ip_vrf_id == interface_vrf_id:
        return None

    return {
        "ip_address": str(ip_obj.address),
        "ip_vrf": str(ip_vrf.name) if ip_vrf else "None",
        "device": str(interface.device.name),
        "interface": str(interface.name),
        "interface_vrf": str(interface_vrf.name) if interface_vrf else "None",
        "reason": (
            f"VRF mismatch: IP in '{ip_vrf.name if ip_vrf else 'None'}', "
            f"interface in '{interface_vrf.name if interface_vrf else 'None'}'"
        ),
    }


def run_validation(
    verbose: bool = False, check: Optional[List[str]] = None
) -> None:
    """Run validation checks with optional filtering."""
    init_logger(verbose)
    validate_netbox_connection()

    valid_checks = {"ip-prefixes", "vrf-consistency"}

    if check:
        checks_to_run = set(check)
        invalid_checks = checks_to_run - valid_checks
        if invalid_checks:
            logger.error(
                f"Invalid check(s): {', '.join(invalid_checks)}. "
                f"Valid checks: {', '.join(valid_checks)}"
            )
            raise typer.Exit(1)
    else:
        checks_to_run = valid_checks

    logger.info("Starting NetBox validation...")
    if verbose:
        logger.info(f"Running checks: {', '.join(sorted(checks_to_run))}")

    try:
        netbox_api = create_netbox_api()

        all_passed = True
        results: Dict[str, Tuple[bool, List[Dict[str, Any]]]] = {}

        if "ip-prefixes" in checks_to_run:
            logger.info("=== Checking: IP addresses have matching prefixes ===")
            ip_passed, orphaned_ips = validate_ip_addresses_have_prefixes(
                netbox_api, verbose
            )
            results["ip-prefixes"] = (ip_passed, orphaned_ips)
            all_passed = all_passed and ip_passed

            if not ip_passed:
                logger.error(
                    f"IP-prefix check failed: {len(orphaned_ips)} IP(s) without assigned prefix"
                )
                items = orphaned_ips if verbose else orphaned_ips[:20]
                label = "Orphaned IP addresses" if verbose else "Orphaned IP addresses (first 20)"
                logger.info(label + ":")
                for ip_info in items:
                    if ip_info.get("device") and ip_info.get("interface"):
                        location = f"{ip_info['device']}:{ip_info['interface']}"
                    elif ip_info.get("interface"):
                        location = ip_info["interface"]
                    elif ip_info.get("assigned_object"):
                        location = ip_info["assigned_object"]
                    else:
                        location = "Unassigned"

                    logger.info(
                        f"  - {ip_info['address']} (VRF: {ip_info['vrf']}) - "
                        f"{location}: {ip_info['reason']}"
                    )
                if not verbose and len(orphaned_ips) > 20:
                    logger.info(f"  ... and {len(orphaned_ips) - 20} more")
            else:
                logger.info("IP-prefix check passed")

        if "vrf-consistency" in checks_to_run:
            logger.info("=== Checking: VRF consistency between IPs and interfaces ===")
            vrf_passed, inconsistencies = validate_vrf_consistency(
                netbox_api, verbose
            )
            results["vrf-consistency"] = (vrf_passed, inconsistencies)
            all_passed = all_passed and vrf_passed

            if not vrf_passed:
                count = len(inconsistencies)
                plural = "inconsistencies" if count != 1 else "inconsistency"
                logger.error(f"VRF consistency check failed: {count} {plural} found")
                items = inconsistencies if verbose else inconsistencies[:20]
                label = (
                    "VRF inconsistencies"
                    if verbose
                    else "VRF inconsistencies (first 20)"
                )
                logger.info(label + ":")
                for issue in items:
                    logger.info(
                        f"  - {issue['device']}:{issue['interface']} - "
                        f"IP {issue['ip_address']} in VRF '{issue['ip_vrf']}', "
                        f"Interface in VRF '{issue['interface_vrf']}'"
                    )
                if not verbose and len(inconsistencies) > 20:
                    logger.info(f"  ... and {len(inconsistencies) - 20} more")
            else:
                logger.info("VRF consistency check passed")

        logger.info("=" * 50)
        logger.info("VALIDATION SUMMARY")
        logger.info("=" * 50)

        for check_name in sorted(checks_to_run):
            if check_name in results:
                passed, issues = results[check_name]
                status = "PASSED" if passed else f"FAILED ({len(issues)} issues)"
                logger.info(f"{check_name}: {status}")

        logger.info("=" * 50)

        if all_passed:
            logger.info("All validation checks passed")
            raise typer.Exit(0)

        logger.error("Some validation checks failed")
        raise typer.Exit(1)

    except typer.Exit:
        raise
    except pynetbox.RequestError as exc:
        logger.error(f"NetBox API error: {exc}")
        raise typer.Exit(1)
    except Exception as exc:  # pragma: no cover - defensive
        logger.error(f"Error during validation: {exc}")
        if verbose:
            import traceback

            logger.error(traceback.format_exc())
        raise typer.Exit(1)

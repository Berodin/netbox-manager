# SPDX-License-Identifier: Apache-2.0
"""Automatic configuration generation service."""

import ipaddress
import os
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from loguru import logger
import pynetbox
import typer
import yaml

from netbox_manager.config import (
    NETBOX_NODE_ROLES,
    NETBOX_SWITCH_ROLES,
    settings,
    validate_netbox_connection,
)
from netbox_manager.logging_utils import init_logger
from netbox_manager.netbox.api import create_netbox_api, get_device_role_slug
from netbox_manager.utils.yaml_utils import ProperIndentDumper


@dataclass
class ClusterConfig:
    ipv4_network: ipaddress.IPv4Network
    ipv6_network: Optional[ipaddress.IPv6Network]
    offset: int = 0


def has_sonic_hwsku_parameter(device: Any) -> bool:
    """Check if device has sonic_parameters.hwsku custom field."""
    if not (hasattr(device, "custom_fields") and device.custom_fields):
        return False

    sonic_params = device.custom_fields.get("sonic_parameters")
    return bool(
        sonic_params and isinstance(sonic_params, dict) and sonic_params.get("hwsku")
    )


def should_have_loopback_interface(device: Any) -> bool:
    """Determine if a device should have a Loopback0 interface."""
    device_role_slug = get_device_role_slug(device)

    if device_role_slug in NETBOX_NODE_ROLES:
        return True

    is_switch_role = device_role_slug in NETBOX_SWITCH_ROLES
    is_switch_type = (
        device.device_type
        and hasattr(device.device_type, "model")
        and "switch" in device.device_type.model.lower()
    )

    if is_switch_role or is_switch_type:
        if has_sonic_hwsku_parameter(device):
            sonic_params = device.custom_fields.get("sonic_parameters")
            context = (
                f"role: {device_role_slug}"
                if is_switch_role
                else f"type: {device.device_type.model.lower()}"
            )
            logger.debug(
                f"Switch {device.name} ({context}) has sonic_parameters.hwsku: {sonic_params.get('hwsku')}"
            )
            return True

        context = (
            f"role: {device_role_slug}"
            if is_switch_role
            else f"type: {device.device_type.model.lower()}"
        )
        logger.debug(
            f"Switch {device.name} ({context}) does not have sonic_parameters.hwsku, skipping Loopback0"
        )

    return False


def generate_loopback_interfaces(netbox_api: Optional[Any] = None) -> List[Dict[str, Any]]:
    """Generate Loopback0 interfaces for eligible devices that don't have them."""
    api = netbox_api or create_netbox_api()
    tasks = []

    logger.info("Analyzing devices for Loopback0 interface creation...")
    all_devices = api.dcim.devices.all()

    for device in all_devices:
        if should_have_loopback_interface(device):
            tasks.append(
                {
                    "device_interface": {
                        "device": device.name,
                        "name": "Loopback0",
                        "type": "virtual",
                        "enabled": True,
                        "tags": ["managed-by-osism"],
                    }
                }
            )
            logger.info(f"Will create Loopback0 interface for device: {device.name}")

    logger.info(f"Generated {len(tasks)} Loopback0 interface creation tasks")
    return tasks


def _get_cluster_segment_config_context(
    netbox_api: pynetbox.api, cluster_id: int, cluster_name: str = ""
) -> Dict[str, Any]:
    """Retrieve the specific segment config context for a cluster via separate API call."""
    try:
        logger.debug(
            f"Retrieving segment config context for cluster {cluster_name} (ID: {cluster_id}) via separate API call"
        )

        config_contexts = netbox_api.extras.config_contexts.filter(clusters=cluster_id)

        segment_context = None
        for ctx in config_contexts:
            if ctx.name == cluster_name:
                logger.debug(
                    f"Found segment config context: '{ctx.name}' for cluster {cluster_name}"
                )
                segment_context = ctx
                break

        if segment_context and segment_context.data:
            logger.info(
                f"Retrieved segment config context '{segment_context.name}' for cluster {cluster_name}"
            )

            if "_segment_loopback_network_ipv4" in segment_context.data:
                ipv4_net = segment_context.data.get("_segment_loopback_network_ipv4")
                ipv6_net = segment_context.data.get("_segment_loopback_network_ipv6")
                logger.debug(
                    f"Found loopback config in {segment_context.name}: IPv4={ipv4_net}, IPv6={ipv6_net}"
                )

            return segment_context.data
        if segment_context and not segment_context.data:
            logger.warning(
                f"Config context '{segment_context.name}' found for cluster {cluster_name} but contains no data"
            )
            return {}

        logger.warning(
            f"No segment config context found for cluster {cluster_name} (expected config context with name '{cluster_name}')"
        )
        return {}

    except Exception as exc:  # pragma: no cover - network errors
        logger.error(
            f"Error retrieving segment config context for cluster {cluster_name} (ID: {cluster_id}): {exc}"
        )
        return {}


def parse_cluster_config(
    config_context: Dict[str, Any], cluster_name: str
) -> Optional[ClusterConfig]:
    """Return parsed cluster config or None if required data is missing/invalid."""
    loopback_ipv4_network = config_context.get("_segment_loopback_network_ipv4")
    loopback_ipv6_network = config_context.get("_segment_loopback_network_ipv6")
    loopback_offset_ipv4 = config_context.get("_segment_loopback_offset_ipv4", 0)

    if not loopback_ipv4_network:
        logger.info(
            f"Cluster '{cluster_name}' has no _segment_loopback_network_ipv4 in config context, skipping"
        )
        return None

    try:
        ipv4_network = ipaddress.IPv4Network(loopback_ipv4_network, strict=False)
    except ValueError as exc:
        logger.error(
            f"Invalid IPv4 network '{loopback_ipv4_network}' for cluster '{cluster_name}': {exc}"
        )
        return None

    ipv6_network = None
    if loopback_ipv6_network:
        try:
            ipv6_network = ipaddress.IPv6Network(loopback_ipv6_network, strict=False)
        except ValueError as exc:
            logger.error(
                f"Invalid IPv6 network '{loopback_ipv6_network}' for cluster '{cluster_name}': {exc}"
            )

    return ClusterConfig(
        ipv4_network=ipv4_network,
        ipv6_network=ipv6_network,
        offset=int(loopback_offset_ipv4 or 0),
    )


def group_devices_by_cluster(
    devices_with_clusters: List[Any],
) -> Dict[int, Dict[str, Any]]:
    """Group devices by their assigned cluster."""
    clusters_dict = {}
    for device in devices_with_clusters:
        cluster_id = device.cluster.id
        if cluster_id not in clusters_dict:
            clusters_dict[cluster_id] = {"cluster": device.cluster, "devices": []}
        clusters_dict[cluster_id]["devices"].append(device)
    return clusters_dict


def calculate_loopback_ips(
    device: Any, ipv4_network: Any, ipv6_network: Optional[Any], offset: int
) -> Tuple[Optional[str], Optional[str]]:
    """Calculate IPv4 and IPv6 loopback addresses for a device."""
    position = getattr(device, "position", None)
    if position is None:
        logger.warning(
            f"Device '{device.name}' has no rack position, skipping loopback generation"
        )
        return None, None

    if not isinstance(position, int):
        try:
            position = int(position)
            logger.debug(
                f"Device '{device.name}' position converted from {type(getattr(device, 'position', None)).__name__} to int: {position}"
            )
        except (ValueError, TypeError) as exc:
            logger.warning(
                f"Device '{device.name}' has invalid position '{getattr(device, 'position', None)}' (not convertible to int), skipping loopback generation: {exc}"
            )
            return None, None

    byte_4 = position * 2 - 1 + offset

    try:
        network_int = int(ipv4_network.network_address)
        device_ipv4_int = network_int + byte_4
        device_ipv4 = ipaddress.IPv4Address(device_ipv4_int)
        device_ipv4_with_mask = f"{device_ipv4}/32"

        ipv6_addr = None
        if ipv6_network:
            try:
                ipv4_octets = str(device_ipv4).split(".")
                ipv6_suffix = f"{ipv4_octets[0]}:{ipv4_octets[1]}:{ipv4_octets[2]}:{ipv4_octets[3]}"

                network_prefix = str(ipv6_network.network_address).rstrip("::")
                if network_prefix.endswith(":"):
                    network_prefix = network_prefix.rstrip(":")
                ipv6_addr = f"{network_prefix}:0:{ipv6_suffix}/128"
            except Exception as exc:
                logger.error(
                    f"Error generating IPv6 address for device '{device.name}': {exc}"
                )

        return device_ipv4_with_mask, ipv6_addr

    except Exception as exc:  # pragma: no cover - defensive
        logger.error(f"Error generating IPv4 address for device '{device.name}': {exc}")
        return None, None


def generate_cluster_loopback_tasks(
    netbox_api: Optional[Any] = None,
) -> Dict[str, List[Dict[str, Any]]]:
    """Generate loopback IP address assignments for devices with assigned clusters."""
    api = netbox_api or create_netbox_api()
    tasks_by_type: Dict[str, List[Dict[str, Any]]] = {"ip_address": []}

    logger.info("Analyzing devices with clusters for loopback IP generation...")
    all_devices = api.dcim.devices.all()
    devices_with_clusters = [device for device in all_devices if device.cluster]
    logger.info(f"Found {len(devices_with_clusters)} devices with assigned clusters")

    for cluster_id, cluster_data in group_devices_by_cluster(
        devices_with_clusters
    ).items():
        cluster = cluster_data["cluster"]
        devices = cluster_data["devices"]
        logger.info(f"Processing cluster '{cluster.name}' with {len(devices)} devices")
        cluster_tasks = _build_ip_tasks_for_cluster(api, cluster_id, cluster, devices)
        tasks_by_type["ip_address"].extend(cluster_tasks)

    total_tasks = sum(len(tasks) for tasks in tasks_by_type.values())
    logger.info(f"Generated {total_tasks} cluster-based loopback IP assignment tasks")
    return tasks_by_type


def _build_ip_tasks_for_cluster(
    api: Any, cluster_id: int, cluster: Any, devices: List[Any]
) -> List[Dict[str, Any]]:
    """Build IP tasks for a single cluster."""
    config_context = _get_cluster_segment_config_context(api, cluster_id, cluster.name)
    if not config_context:
        logger.warning(
            f"Cluster '{cluster.name}' has no config context assigned, skipping loopback generation for {len(devices)} devices"
        )
        return []

    config = parse_cluster_config(config_context, cluster.name)
    if not config:
        return []

    tasks: List[Dict[str, Any]] = []
    for device in devices:
        if not should_have_loopback_interface(device):
            logger.debug(
                f"Skipping cluster loopback IP generation for {device.name} "
                f"(does not meet Loopback0 interface criteria)"
            )
            continue

        ipv4_addr, ipv6_addr = calculate_loopback_ips(
            device, config.ipv4_network, config.ipv6_network, config.offset
        )

        if ipv4_addr:
            tasks.append(
                {
                    "ip_address": {
                        "address": ipv4_addr,
                        "assigned_object": {"name": "Loopback0", "device": device.name},
                    }
                }
            )
            logger.info(f"Generated IPv4 loopback: {device.name} -> {ipv4_addr}")

        if ipv6_addr:
            tasks.append(
                {
                    "ip_address": {
                        "address": ipv6_addr,
                        "assigned_object": {"name": "Loopback0", "device": device.name},
                    }
                }
            )
            logger.info(f"Generated IPv6 loopback: {device.name} -> {ipv6_addr}")

    return tasks


def generate_device_interface_labels(netbox_api: Optional[Any] = None) -> List[Dict[str, Any]]:
    """Generate device interface label tasks based on switch, router, and firewall custom fields."""
    tasks: List[Dict[str, Any]] = []
    api = netbox_api or create_netbox_api()

    logger.info(
        "Analyzing switch, router, and firewall devices for device interface labeling..."
    )

    all_devices = api.dcim.devices.all()
    devices_with_labels = []

    for device in all_devices:
        device_role_slug = get_device_role_slug(device)
        if device_role_slug in NETBOX_SWITCH_ROLES or device_role_slug in [
            "router",
            "firewall",
        ]:
            if hasattr(device, "custom_fields") and device.custom_fields:
                device_interface_label = device.custom_fields.get(
                    "device_interface_label"
                )
                if device_interface_label:
                    devices_with_labels.append((device, device_interface_label))
                    device_type_name = (
                        "switch"
                        if device_role_slug in NETBOX_SWITCH_ROLES
                        else device_role_slug
                    )
                    logger.debug(
                        f"Found {device_type_name} {device.name} with device_interface_label: {device_interface_label}"
                    )

    logger.info(
        f"Found {len(devices_with_labels)} devices (switches/routers/firewalls) with device_interface_label custom field"
    )

    for source_device, label_value in devices_with_labels:
        source_device_role = get_device_role_slug(source_device)
        device_type_name = (
            "switch"
            if source_device_role in NETBOX_SWITCH_ROLES
            else source_device_role
        )
        logger.debug(
            f"Processing {device_type_name} {source_device.name} with label '{label_value}'"
        )

        frr_local_pref = None
        if hasattr(source_device, "custom_fields") and source_device.custom_fields:
            frr_local_pref = source_device.custom_fields.get("frr_local_pref")
            if frr_local_pref:
                logger.debug(
                    f"{device_type_name} {source_device.name} has frr_local_pref: {frr_local_pref}"
                )

        source_interfaces = api.dcim.interfaces.filter(device_id=source_device.id)

        for interface in source_interfaces:
            if not (
                hasattr(interface, "connected_endpoints")
                and interface.connected_endpoints
            ):
                continue

            for endpoint in interface.connected_endpoints:
                if not (hasattr(endpoint, "device") and endpoint.device):
                    continue

                connected_device = endpoint.device
                connected_role_slug = get_device_role_slug(connected_device)

                if connected_role_slug in NETBOX_NODE_ROLES:
                    interface_name = getattr(endpoint, "name", None)
                    if interface_name:
                        interface_task = {
                            "device": connected_device.name,
                            "name": interface_name,
                            "label": label_value,
                            "tags": ["managed-by-osism"],
                        }

                        if frr_local_pref is not None:
                            interface_task["custom_fields"] = {
                                "frr_local_pref": frr_local_pref
                            }
                            logger.info(
                                f"Will set label on {connected_device.name}:{interface_name} -> '{label_value}' "
                                f"with frr_local_pref={frr_local_pref} "
                                f"(from {device_type_name} {source_device.name}:{interface.name})"
                            )
                        else:
                            logger.info(
                                f"Will set label on {connected_device.name}:{interface_name} -> '{label_value}' (from {device_type_name} {source_device.name}:{interface.name})"
                            )

                        tasks.append({"device_interface": interface_task})
                    else:
                        logger.warning(
                            f"Could not determine interface name for connection to {connected_device.name}"
                        )

    logger.info(f"Generated {len(tasks)} device interface label tasks")
    return tasks


def generate_portchannel_tasks(netbox_api: Optional[Any] = None) -> List[Dict[str, Any]]:
    """Generate PortChannel configuration tasks for switch-to-switch connections."""
    lag_creation_tasks: List[Dict[str, Any]] = []
    member_assignment_tasks: List[Dict[str, Any]] = []

    api = netbox_api or create_netbox_api()

    logger.info("Analyzing switch-to-switch connections for PortChannel generation...")

    all_devices = api.dcim.devices.all()
    switch_devices = []

    for device in all_devices:
        device_role_slug = get_device_role_slug(device)
        if device_role_slug in NETBOX_SWITCH_ROLES:
            switch_devices.append(device)
            logger.debug(f"Found switch: {device.name}")

    logger.info(f"Found {len(switch_devices)} switch devices")

    switch_connections: Dict[Tuple[str, str], List[Tuple[Any, Any]]] = {}

    for switch in switch_devices:
        interfaces = api.dcim.interfaces.filter(device_id=switch.id)

        for interface in interfaces:
            if not (hasattr(interface, "cable") and interface.cable):
                continue

            if not (
                hasattr(interface, "connected_endpoints")
                and interface.connected_endpoints
            ):
                continue

            for endpoint in interface.connected_endpoints:
                if not (hasattr(endpoint, "device") and endpoint.device):
                    continue

                connected_device = endpoint.device
                connected_role_slug = get_device_role_slug(connected_device)

                if connected_role_slug not in NETBOX_SWITCH_ROLES:
                    continue

                switch_pair = tuple(sorted([switch.name, connected_device.name]))

                if switch.name == switch_pair[0]:
                    connection = (interface, endpoint)
                else:
                    connection = (endpoint, interface)

                if switch_pair not in switch_connections:
                    switch_connections[switch_pair] = []

                connection_exists = False
                for existing_conn in switch_connections[switch_pair]:
                    if (
                        existing_conn[0].id == connection[0].id
                        and existing_conn[1].id == connection[1].id
                    ):
                        connection_exists = True
                        break

                if not connection_exists:
                    switch_connections[switch_pair].append(connection)
                    logger.debug(
                        f"Found connection: {switch.name}:{interface.name} <-> "
                        f"{connected_device.name}:{endpoint.name}"
                    )

    for switch_pair in sorted(switch_connections.keys()):
        connections = switch_connections[switch_pair]
        if len(connections) < 2:
            continue

        switch1_name, switch2_name = switch_pair
        logger.info(
            f"Processing {len(connections)} connections between "
            f"{switch1_name} and {switch2_name}"
        )

        switch1_interfaces = []
        switch2_interfaces = []

        for interface1, interface2 in connections:
            switch1_interfaces.append(interface1.name)
            switch2_interfaces.append(interface2.name)

        switch1_interfaces.sort()
        switch2_interfaces.sort()

        def extract_portchannel_number(interface_name: str) -> int:
            numbers = re.findall(r"\d+", interface_name)

            if not numbers:
                return 0

            if "/" in interface_name and len(numbers) >= 2:
                return int(numbers[1])

            return int(numbers[0])

        switch1_port_numbers = [
            extract_portchannel_number(name) for name in switch1_interfaces
        ]
        switch1_portchannel_number = (
            min(switch1_port_numbers) if switch1_port_numbers else 1
        )
        switch1_portchannel_name = f"PortChannel{switch1_portchannel_number}"

        switch2_port_numbers = [
            extract_portchannel_number(name) for name in switch2_interfaces
        ]
        switch2_portchannel_number = (
            min(switch2_port_numbers) if switch2_port_numbers else 1
        )
        switch2_portchannel_name = f"PortChannel{switch2_portchannel_number}"

        logger.info(
            f"Creating {switch1_portchannel_name} on {switch1_name} and {switch2_portchannel_name} on {switch2_name} "
            f"for {len(connections)} connections"
        )

        lag_creation_tasks.append(
            {
                "device_interface": {
                    "device": switch1_name,
                    "name": switch1_portchannel_name,
                    "type": "lag",
                    "tags": ["managed-by-osism"],
                }
            }
        )
        logger.info(
            f"Will create LAG interface: {switch1_name}:{switch1_portchannel_name}"
        )

        lag_creation_tasks.append(
            {
                "device_interface": {
                    "device": switch2_name,
                    "name": switch2_portchannel_name,
                    "type": "lag",
                    "tags": ["managed-by-osism"],
                }
            }
        )
        logger.info(
            f"Will create LAG interface: {switch2_name}:{switch2_portchannel_name}"
        )

        for interface_name in switch1_interfaces:
            member_assignment_tasks.append(
                {
                    "device_interface": {
                        "device": switch1_name,
                        "name": interface_name,
                        "lag": switch1_portchannel_name,
                        "tags": ["managed-by-osism"],
                    }
                }
            )
            logger.info(
                f"Will assign member to LAG: {switch1_name}:{interface_name} -> {switch1_portchannel_name}"
            )

        for interface_name in switch2_interfaces:
            member_assignment_tasks.append(
                {
                    "device_interface": {
                        "device": switch2_name,
                        "name": interface_name,
                        "lag": switch2_portchannel_name,
                        "tags": ["managed-by-osism"],
                    }
                }
            )
            logger.info(
                f"Will assign member to LAG: {switch2_name}:{interface_name} -> {switch2_portchannel_name}"
            )

    def sort_key(task):
        iface = task["device_interface"]
        return (iface["device"], iface["name"])

    lag_creation_tasks.sort(key=sort_key)
    member_assignment_tasks.sort(key=sort_key)

    tasks = lag_creation_tasks + member_assignment_tasks

    logger.info(f"Generated {len(tasks)} PortChannel LAG interface tasks")
    return tasks


def split_tasks_by_type(
    all_tasks: List[Dict[str, Any]]
) -> Dict[str, List[Dict[str, Any]]]:
    """Split a list of tasks into separate lists by resource type."""
    tasks_by_type: Dict[str, List[Dict[str, Any]]] = {}

    for task in all_tasks:
        resource_type = next(iter(task.keys()))
        if resource_type not in tasks_by_type:
            tasks_by_type[resource_type] = []
        tasks_by_type[resource_type].append(task)

    return tasks_by_type


def write_autoconf_files(
    tasks_by_type: Dict[str, List[Dict[str, Any]]],
    file_prefix: str,
    resources_dir: Optional[str] = None,
) -> int:
    """Write autoconf tasks to separate files by resource type."""
    if not resources_dir and settings.RESOURCES:
        resources_dir = settings.RESOURCES

    files_written = 0

    for resource_type, tasks in tasks_by_type.items():
        if not tasks:
            continue

        filename = f"{file_prefix}-{resource_type.replace('_', '-')}.yml"

        if resources_dir:
            filepath = os.path.join(resources_dir, filename)
        else:
            filepath = filename

        os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)

        with open(filepath, "w") as file:
            yaml.dump(
                tasks,
                file,
                Dumper=ProperIndentDumper,
                default_flow_style=False,
                sort_keys=False,
                explicit_start=True,
            )

        logger.info(f"Generated {len(tasks)} {resource_type} tasks in {filepath}")
        files_written += 1

    return files_written


def is_virtual_interface(interface: Any) -> bool:
    """Check if an interface is virtual based on its type."""
    if interface.type:
        if (
            hasattr(interface.type, "value")
            and "virtual" in interface.type.value.lower()
        ):
            return True
        if (
            hasattr(interface.type, "label")
            and "virtual" in interface.type.label.lower()
        ):
            return True
    return False


def collect_interface_assignments(
    netbox_api: pynetbox.api, non_switch_devices: Dict[int, Any]
) -> List[Dict[str, Any]]:
    """Collect MAC address assignments for interfaces."""
    tasks = []
    logger.info("Checking interfaces for MAC address assignments...")

    for device_id in sorted(
        non_switch_devices.keys(), key=lambda d_id: non_switch_devices[d_id].name
    ):
        device = non_switch_devices[device_id]
        device_interfaces = netbox_api.dcim.interfaces.filter(device_id=device_id)

        for interface in device_interfaces:
            if is_virtual_interface(interface):
                continue

            mac_to_assign = None
            if interface.mac_address:
                mac_to_assign = str(interface.mac_address)
            elif interface.mac_addresses and not interface.mac_address:
                mac_to_assign = str(interface.mac_addresses[0].mac_address)

            if mac_to_assign:
                tasks.append(
                    {
                        "device_interface": {
                            "device": device.name,
                            "name": interface.name,
                            "primary_mac_address": mac_to_assign,
                        }
                    }
                )
                logger.info(
                    f"Found MAC assignment: {device.name}:{interface.name} -> {mac_to_assign}"
                )

    return tasks


def collect_ip_assignments_by_interface(
    netbox_api: pynetbox.api,
    non_switch_devices: Dict[int, Any],
    interface_name: str,
    assignment_type: str,
) -> Dict[str, Dict[str, Any]]:
    """Collect IP assignments from a specific interface type."""
    device_assignments: Dict[str, Dict[str, Any]] = {}
    logger.info(
        f"Checking {interface_name} interfaces for {assignment_type} IP assignments..."
    )

    for device_id in sorted(
        non_switch_devices.keys(), key=lambda d_id: non_switch_devices[d_id].name
    ):
        device = non_switch_devices[device_id]
        interfaces = netbox_api.dcim.interfaces.filter(
            device_id=device_id, name=interface_name
        )

        for interface in interfaces:
            ip_addresses = netbox_api.ipam.ip_addresses.filter(
                assigned_object_id=interface.id
            )

            for ip_addr in ip_addresses:
                if device.name not in device_assignments:
                    device_assignments[device.name] = {"name": device.name}

                if assignment_type == "OOB":
                    device_assignments[device.name]["oob_ip"] = ip_addr.address
                    logger.info(
                        f"Found OOB IP assignment: {device.name} -> {ip_addr.address}"
                    )
                else:
                    if ":" not in ip_addr.address:
                        device_assignments[device.name]["primary_ip4"] = ip_addr.address
                        logger.info(
                            f"Found primary IPv4 assignment: {device.name} -> {ip_addr.address}"
                        )
                    else:
                        device_assignments[device.name]["primary_ip6"] = ip_addr.address
                        logger.info(
                            f"Found primary IPv6 assignment: {device.name} -> {ip_addr.address}"
                        )

    return device_assignments


def generate_autoconf_tasks(
    netbox_api: Optional[Any] = None,
) -> Dict[str, List[Dict[str, Any]]]:
    """Generate automatic configuration tasks based on NetBox API data."""
    tasks_by_type: Dict[str, List[Dict[str, Any]]] = {
        "device": [],
        "device_interface": [],
        "ip_address": [],
    }

    api = netbox_api or create_netbox_api()
    logger.info("Analyzing NetBox data for automatic configuration...")

    logger.info("Loading devices from NetBox...")
    all_devices = api.dcim.devices.all()
    all_devices_dict = {}
    non_switch_devices = {}

    for device in all_devices:
        device_role_slug = get_device_role_slug(device)
        all_devices_dict[device.id] = device
        if device_role_slug not in NETBOX_SWITCH_ROLES:
            non_switch_devices[device.id] = device

    logger.info(
        f"Found {len(all_devices_dict)} total devices "
        f"({len(non_switch_devices)} non-switch, {len(all_devices_dict) - len(non_switch_devices)} switches)"
    )

    logger.info("Collecting interface MAC assignments (including switches)...")
    interface_tasks = collect_interface_assignments(api, all_devices_dict)
    tasks_by_type["device_interface"].extend(interface_tasks)

    logger.info("Checking for device IP assignments (including switches)...")

    oob_assignments = collect_ip_assignments_by_interface(
        api, all_devices_dict, "eth0", "OOB"
    )

    primary_assignments = collect_ip_assignments_by_interface(
        api, all_devices_dict, "Loopback0", "Primary"
    )

    all_device_assignments: Dict[str, Dict[str, Any]] = {}
    for assignments_dict in [oob_assignments, primary_assignments]:
        for device_name, assignment in assignments_dict.items():
            if device_name not in all_device_assignments:
                all_device_assignments[device_name] = assignment
            else:
                all_device_assignments[device_name].update(assignment)

    for device_name in sorted(all_device_assignments.keys()):
        device_assignment = all_device_assignments[device_name]
        tasks_by_type["device"].append({"device": device_assignment})

    total_tasks = sum(len(tasks) for tasks in tasks_by_type.values())
    logger.info(f"Generated {total_tasks} automatic configuration tasks")
    return tasks_by_type


def run_autoconf(
    output: str,
    loopback_output: str,
    cluster_loopback_output: str,
    portchannel_output: str,
    debug: bool = False,
    dryrun: bool = False,
) -> None:
    """Generate automatic configuration based on NetBox API data."""
    init_logger(debug)
    validate_netbox_connection()

    try:
        loopback_tasks_list = generate_loopback_interfaces()
        loopback_tasks = split_tasks_by_type(loopback_tasks_list)

        cluster_loopback_tasks = generate_cluster_loopback_tasks()

        portchannel_tasks_list = generate_portchannel_tasks()

        interface_label_tasks_list = generate_device_interface_labels()
        interface_label_tasks = split_tasks_by_type(interface_label_tasks_list)

        other_autoconf_tasks = generate_autoconf_tasks()

        merged_tasks: Dict[str, List[Dict[str, Any]]] = {}
        interface_task_map = {}

        for task in interface_label_tasks.get("device_interface", []):
            if "device_interface" in task:
                device_name = task["device_interface"]["device"]
                interface_name = task["device_interface"]["name"]
                key = f"{device_name}:{interface_name}"
                interface_task_map[key] = task["device_interface"]

        for resource_type in ["device", "device_interface", "ip_address"]:
            merged_tasks[resource_type] = []

        for task in other_autoconf_tasks.get("device_interface", []):
            if "device_interface" in task:
                device_name = task["device_interface"]["device"]
                interface_name = task["device_interface"]["name"]
                key = f"{device_name}:{interface_name}"

                if key in interface_task_map:
                    merged_interface = {
                        **task["device_interface"],
                        **interface_task_map[key],
                    }
                    merged_tasks["device_interface"].append(
                        {"device_interface": merged_interface}
                    )
                    del interface_task_map[key]
                else:
                    merged_tasks["device_interface"].append(task)
            else:
                merged_tasks["device_interface"].append(task)

        for interface_data in interface_task_map.values():
            merged_tasks["device_interface"].append({"device_interface": interface_data})

        for resource_type in ["device", "ip_address"]:
            merged_tasks[resource_type].extend(
                other_autoconf_tasks.get(resource_type, [])
            )

        other_tasks = merged_tasks

        if dryrun:
            if any(tasks for tasks in loopback_tasks.values()):
                logger.info(
                    "Dry run - would generate the following loopback interface tasks:"
                )
                for resource_type, tasks in loopback_tasks.items():
                    if tasks:
                        logger.info(f"  {resource_type}:")
                        for task in tasks:
                            logger.info(
                                f"    {yaml.dump(task, default_flow_style=False).strip()}"
                            )

            if any(tasks for tasks in cluster_loopback_tasks.values()):
                logger.info(
                    "Dry run - would generate the following cluster-based loopback IP tasks:"
                )
                for resource_type, tasks in cluster_loopback_tasks.items():
                    if tasks:
                        logger.info(f"  {resource_type}:")
                        for task in tasks:
                            logger.info(
                                f"    {yaml.dump(task, default_flow_style=False).strip()}"
                            )

            if portchannel_tasks_list:
                logger.info(
                    "Dry run - would generate the following PortChannel LAG interface tasks:"
                )
                for task in portchannel_tasks_list:
                    logger.info(f"    {yaml.dump(task, default_flow_style=False).strip()}")

            if any(tasks for tasks in other_tasks.values()):
                logger.info("Dry run - would generate the following other autoconf tasks:")
                for resource_type, tasks in other_tasks.items():
                    if tasks:
                        logger.info(f"  {resource_type}:")
                        for task in tasks:
                            logger.info(
                                f"    {yaml.dump(task, default_flow_style=False).strip()}"
                            )
            return

        files_written = 0

        if any(tasks for tasks in loopback_tasks.values()):
            loopback_prefix = os.path.splitext(os.path.basename(loopback_output))[0]
            loopback_dir = (
                os.path.dirname(loopback_output)
                if os.path.dirname(loopback_output)
                else settings.RESOURCES
            )
            files_written += write_autoconf_files(
                loopback_tasks, loopback_prefix, loopback_dir
            )

        if any(tasks for tasks in cluster_loopback_tasks.values()):
            cluster_loopback_prefix = os.path.splitext(
                os.path.basename(cluster_loopback_output)
            )[0]
            cluster_loopback_dir = (
                os.path.dirname(cluster_loopback_output)
                if os.path.dirname(cluster_loopback_output)
                else settings.RESOURCES
            )
            files_written += write_autoconf_files(
                cluster_loopback_tasks, cluster_loopback_prefix, cluster_loopback_dir
            )

        if portchannel_tasks_list:
            portchannel_filepath = (
                portchannel_output
                if os.path.dirname(portchannel_output)
                else os.path.join(settings.RESOURCES, portchannel_output)
            )

            portchannel_dir = os.path.dirname(portchannel_filepath)
            if portchannel_dir:
                os.makedirs(portchannel_dir, exist_ok=True)

            with open(portchannel_filepath, "w") as file:
                yaml.dump(
                    portchannel_tasks_list,
                    file,
                    Dumper=ProperIndentDumper,
                    default_flow_style=False,
                    sort_keys=False,
                    explicit_start=True,
                )

            logger.info(
                f"Generated {len(portchannel_tasks_list)} PortChannel tasks in {portchannel_filepath}"
            )
            files_written += 1

        if any(tasks for tasks in other_tasks.values()):
            other_prefix = os.path.splitext(os.path.basename(output))[0]
            other_dir = (
                os.path.dirname(output) if os.path.dirname(output) else settings.RESOURCES
            )
            files_written += write_autoconf_files(other_tasks, other_prefix, other_dir)

        if files_written == 0:
            logger.info("No automatic configuration tasks found")

    except pynetbox.RequestError as exc:
        logger.error(f"NetBox API error: {exc}")
        raise typer.Exit(1)
    except Exception as exc:  # pragma: no cover - defensive
        logger.error(f"Error generating autoconf: {exc}")
        raise typer.Exit(1)

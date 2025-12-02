import ipaddress

from netbox_manager.services.autoconf import calculate_loopback_ips, split_tasks_by_type
from netbox_manager.utils.data import (
    should_skip_task_by_device_filter,
    should_skip_task_by_filter,
)
from netbox_manager.utils.yaml_utils import deep_merge


class DummyDevice:
    def __init__(self, name: str, position: int):
        self.name = name
        self.position = position


def test_deep_merge_merges_nested_dicts_without_mutating_inputs():
    base = {"a": {"b": 1, "shared": {"x": 1}}, "list": [1]}
    override = {"a": {"c": 2, "shared": {"y": 2}}, "extra": True}

    merged = deep_merge(base, override)

    assert merged["a"]["b"] == 1
    assert merged["a"]["c"] == 2
    assert merged["a"]["shared"] == {"x": 1, "y": 2}
    assert merged["extra"] is True
    # original inputs are unchanged
    assert "c" not in base["a"]
    assert base["a"]["shared"] == {"x": 1}


def test_task_filters_normalize_hyphens_and_underscores():
    assert should_skip_task_by_filter("device-interface", "device_interface") is False
    assert should_skip_task_by_filter("ip_address", "device") is True


def test_device_filter_matches_any_device_name_fragment():
    device_names = ["switch01", "server02"]
    assert should_skip_task_by_device_filter(device_names, ["switch"]) is False
    assert should_skip_task_by_device_filter(device_names, ["router"]) is True
    # with no device names present we skip by default
    assert should_skip_task_by_device_filter([], ["any"]) is True


def test_split_tasks_by_type_groups_resource_keys():
    tasks = [
        {"device": {"name": "dev1"}},
        {"device_interface": {"name": "eth0"}},
        {"device": {"name": "dev2"}},
    ]
    grouped = split_tasks_by_type(tasks)
    assert set(grouped.keys()) == {"device", "device_interface"}
    assert len(grouped["device"]) == 2
    assert len(grouped["device_interface"]) == 1


def test_calculate_loopback_ips_from_position_and_offset():
    device = DummyDevice(name="node1", position=10)
    ipv4_network = ipaddress.IPv4Network("10.0.0.0/24")
    ipv6_network = ipaddress.IPv6Network("2001:db8::/64")

    ipv4, ipv6 = calculate_loopback_ips(device, ipv4_network, ipv6_network, offset=0)

    assert ipv4 == "10.0.0.19/32"
    assert ipv6 == "2001:db8:0:10:0:0:19/128"


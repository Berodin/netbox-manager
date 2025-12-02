import ipaddress

from netbox_manager.services.autoconf import ClusterConfig, parse_cluster_config


def test_parse_cluster_config_returns_networks_and_offset():
    context = {
        "_segment_loopback_network_ipv4": "10.10.0.0/24",
        "_segment_loopback_network_ipv6": "fd00:1::/64",
        "_segment_loopback_offset_ipv4": 4,
    }

    cfg = parse_cluster_config(context, "cluster-a")

    assert isinstance(cfg, ClusterConfig)
    assert cfg.ipv4_network == ipaddress.IPv4Network("10.10.0.0/24")
    assert cfg.ipv6_network == ipaddress.IPv6Network("fd00:1::/64")
    assert cfg.offset == 4


def test_parse_cluster_config_requires_ipv4_network():
    context = {
        "_segment_loopback_network_ipv6": "fd00:1::/64",
    }

    cfg = parse_cluster_config(context, "cluster-b")

    assert cfg is None


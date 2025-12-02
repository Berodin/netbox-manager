from netbox_manager.services.autoconf import _portchannel_name_for_interfaces, _extract_port_number


def test_extract_port_number_prefers_second_segment_for_slash_names():
    assert _extract_port_number("Eth1/3/1") == 3
    assert _extract_port_number("GigabitEthernet1/0/1") == 0
    assert _extract_port_number("Ethernet48") == 48
    assert _extract_port_number("no-number") == 0


def test_portchannel_name_for_interfaces_uses_lowest_number():
    assert _portchannel_name_for_interfaces(["Eth1/4/1", "Eth1/3/1"]) == "PortChannel3"
    assert _portchannel_name_for_interfaces(["Ethernet48", "Ethernet49"]) == "PortChannel48"
    assert _portchannel_name_for_interfaces([]) == "PortChannel1"

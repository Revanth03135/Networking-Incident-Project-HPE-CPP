TYPE_MAPPING = {
    "802.1x": "authentication",
    "authentication": "authentication",
    "aaa": "authentication",
    "bgp": "routing",
    "ospf": "routing",
    "rip": "routing",
    "acl": "security",
    "access control": "security",
    "interface": "interface",
    "link": "interface",
    "activate": "system",
    "accounting": "system",
}

SUBTYPE_MAPPING = {
    "802.1x": "802.1x",
    "authentication": "authentication",
    "aaa": "aaa",
    "bgp": "bgp",
    "ospf": "ospf",
    "rip": "rip",
    "acl": "acl",
    "access control": "acl",
    "interface": "link",
    "link": "link",
    "activate": "activate",
    "accounting": "accounting",
}

SEVERITY_MAPPING = {
    "information": "info",
    "informational": "info",
    "info": "info",
    "warning": "warning",
    "error": "error",
    "critical": "critical",
    "fatal": "critical",
    "alert": "critical",
    "emergency": "critical",
}

PLACEHOLDER_TO_SCHEMA = {
    "PORT_NAME": "interface_id",
    "PORT_NUM": "interface_id",
    "LPORT": "interface_id",
    "PORT_ID": "interface_id",
    "RULE_ID": "interface_id",
    "interface_name": "interface_id",
    "VLAN_ID": "vlan",
    "SRC_IP": "ip",
    "IP_ADDRESS": "ip",
    "inside_address": "ip",
    "outside_address": "ip",
    "source_address": "ip",
    "dest_address": "ip",
}
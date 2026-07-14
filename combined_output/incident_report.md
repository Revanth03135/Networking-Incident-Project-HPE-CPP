# Network Incident Investigation Report

Generated: 2026-06-29T15:07:36Z

## Executive Summary
- Total incidents reconstructed: 48
- Total events analyzed: 398
- Total causal links inferred: 322
- Affected devices: 192.168.1.10, 192.168.1.104, Access-6100-02, Access-6100-03, Access-6100-04, Access-6100-05, Core-8325-01, Dist-6300-01, Edge-6300-01, router-1, router-2

## Probable Initiating Triggers
- Incident INC-0007 -> Root Cause: dot1x_failure (device=192.168.1.104, score=54.3)
- Incident INC-0009 -> Root Cause: interface_down (device=192.168.1.10, score=178.6)
- Incident INC-0014 -> Root Cause: stp_topology_change (device=192.168.1.10, score=93.9)
- Incident INC-0017 -> Root Cause: power_failure (device=192.168.1.10, score=220.6)
- Incident INC-0028 -> Root Cause: crc_errors (device=192.168.1.10, score=192.8)
- Incident INC-0030 -> Root Cause: bgp (device=router-2, score=122.2)
- Incident INC-0036 -> Root Cause: transceiver (device=Dist-6300-01, score=188.6)
- Incident INC-0038 -> Root Cause: dot1x_failure (device=Access-6100-02, score=54.3)
- Incident INC-0039 -> Root Cause: power_failure (device=Core-8325-01, score=217.9)
- Incident INC-0044 -> Root Cause: crc_errors (device=192.168.1.10, score=189.2)
- Incident INC-0046 -> Root Cause: dot1x_failure (device=192.168.1.10, score=54.9)
- Incident INC-0051 -> Root Cause: transceiver (device=Dist-6300-01, score=197.8)
- Incident INC-0053 -> Root Cause: dot1x_failure (device=Access-6100-02, score=54.3)
- Incident INC-0054 -> Root Cause: power_failure (device=Core-8325-01, score=217.9)
- Incident INC-0060 -> Root Cause: interface_down (device=router-1, score=196.4)
- Incident INC-0071 -> Root Cause: crc_errors (device=192.168.1.10, score=189.5)
- Incident INC-0076 -> Root Cause: dot1x_failure (device=192.168.1.10, score=55.8)
- Incident INC-0081 -> Root Cause: transceiver (device=192.168.1.104, score=190.1)
- Incident INC-0083 -> Root Cause: transceiver (device=Edge-6300-01, score=189.5)
- Incident INC-0086 -> Root Cause: transceiver (device=Dist-6300-01, score=190.4)
- Incident INC-0087 -> Root Cause: dot1x_failure (device=Access-6100-04, score=54.3)
- Incident INC-0088 -> Root Cause: power_failure (device=Core-8325-01, score=217.9)
- Incident INC-0095 -> Root Cause: transceiver (device=Dist-6300-01, score=192.2)
- Incident INC-0096 -> Root Cause: dot1x_failure (device=Access-6100-03, score=54.3)
- Incident INC-0098 -> Root Cause: power_failure (device=Core-8325-01, score=218.2)
- Incident INC-0099 -> Root Cause: crc_errors (device=Access-6100-05, score=188.9)
- Incident INC-0104 -> Root Cause: transceiver (device=Dist-6300-01, score=192.8)
- Incident INC-0108 -> Root Cause: dot1x_failure (device=Access-6100-02, score=54.3)
- Incident INC-0109 -> Root Cause: power_failure (device=Core-8325-01, score=218.2)
- Incident INC-0110 -> Root Cause: crc_errors (device=Access-6100-03, score=188.9)

## Incident Overview
- INC-0007: events=2, duration=0.0s, primary_issue=dot1x_failure
- INC-0008: events=5, duration=64.0s, primary_issue=ssh_bruteforce
- INC-0009: events=5, duration=145.0s, primary_issue=interface_down
- INC-0014: events=5, duration=471.0s, primary_issue=stp_topology_change
- INC-0017: events=13, duration=195.0s, primary_issue=power_failure
- INC-0028: events=17, duration=360.0s, primary_issue=crc_errors
- INC-0030: events=7, duration=471.0s, primary_issue=bgp
- INC-0033: events=3, duration=40.0s, primary_issue=ssh_bruteforce
- INC-0036: events=4, duration=3.0s, primary_issue=transceiver
- INC-0038: events=2, duration=3.0s, primary_issue=dot1x_failure
- INC-0039: events=4, duration=9.0s, primary_issue=power_failure
- INC-0044: events=5, duration=73.0s, primary_issue=crc_errors
- INC-0046: events=4, duration=28.0s, primary_issue=dot1x_failure
- INC-0051: events=7, duration=241.0s, primary_issue=transceiver
- INC-0052: events=4, duration=15.0s, primary_issue=ssh_bruteforce
- INC-0053: events=2, duration=8.0s, primary_issue=dot1x_failure
- INC-0054: events=4, duration=25.0s, primary_issue=power_failure
- INC-0060: events=12, duration=305.0s, primary_issue=interface_down
- INC-0071: events=6, duration=120.0s, primary_issue=crc_errors
- INC-0076: events=7, duration=48.0s, primary_issue=dot1x_failure
- INC-0079: events=3, duration=40.0s, primary_issue=ssh_bruteforce
- INC-0081: events=9, duration=9.0s, primary_issue=transceiver
- INC-0083: events=7, duration=0.024s, primary_issue=transceiver
- INC-0086: events=10, duration=8.614s, primary_issue=transceiver
- INC-0087: events=2, duration=5.983s, primary_issue=dot1x_failure
- INC-0088: events=4, duration=14.433s, primary_issue=power_failure
- INC-0089: events=2, duration=5.995s, primary_issue=ssh_bruteforce
- INC-0095: events=16, duration=179.892s, primary_issue=transceiver
- INC-0096: events=2, duration=4.102s, primary_issue=dot1x_failure
- INC-0097: events=2, duration=5.14s, primary_issue=ssh_bruteforce
- INC-0098: events=5, duration=12.214s, primary_issue=power_failure
- INC-0099: events=4, duration=12.656s, primary_issue=crc_errors
- INC-0104: events=20, duration=241.0s, primary_issue=transceiver
- INC-0107: events=2, duration=4.0s, primary_issue=ssh_bruteforce
- INC-0108: events=2, duration=6.0s, primary_issue=dot1x_failure
- INC-0109: events=5, duration=12.0s, primary_issue=power_failure
- INC-0110: events=4, duration=10.0s, primary_issue=crc_errors
- INC-0013: events=1, duration=0.0s, primary_issue=admin_auth_failure
- INC-0015: events=1, duration=0.0s, primary_issue=ssh_bruteforce
- INC-0025: events=1, duration=0.0s, primary_issue=standalone_alert
- INC-0031: events=7, duration=320.0s, primary_issue=stp_topology_change
- INC-0034: events=1, duration=0.0s, primary_issue=temperature
- INC-0045: events=1, duration=0.0s, primary_issue=standalone_alert
- INC-0059: events=5, duration=446.0s, primary_issue=stp_topology_change
- INC-0062: events=1, duration=0.0s, primary_issue=fan_failure
- INC-0063: events=1, duration=0.0s, primary_issue=bgp_session_lost
- INC-0064: events=1, duration=0.0s, primary_issue=admin_auth_failure
- INC-0072: events=1, duration=0.0s, primary_issue=standalone_alert

## Detailed Incident Chains
### INC-0007
**Failure Sequence:**
- dot1x_failure ×2 (error)
- dot1x_failure (error)

*Status: Active*
*Duration: 0.0s*

### INC-0008
**Failure Sequence:**
- ssh_bruteforce (warning)
- ssh_bruteforce (warning)
- ssh_bruteforce (warning)
- ssh_bruteforce (warning)
- ssh_bruteforce (critical)

*Status: Active*
*Duration: 64.0s*

### INC-0009
**Failure Sequence:**
- interface_down ×2 (info)
- interface_down (info)
- crc_errors ×2 (warning)
- crc_errors (warning)

**Recovery Sequence:**
- transceiver ×2 (info)

*Status: Recovering*
*Duration: 145.0s*

### INC-0014
**Failure Sequence:**
- stp_topology_change (info)
- stp_topology_change ×2 (info)
- stp_topology_change ×2 (warning)
- ospf_neighbor_down ×2 (warning)

**Recovery Sequence:**
- bgp_session_established ×2 (info)

*Status: Recovering*
*Duration: 471.0s*

### INC-0017
**Failure Sequence:**
- power_failure (critical)
- power_failure ×2 (critical)
- interface_down (critical)
- interface_down (critical)
- stp_topology_change (warning)
- interface_down (error)
- interface_down (info)
- bgp (info)
- fan_failure (warning)
- fan_failure ×2 (warning)
- ospf_neighbor_down (info)
- dot1x_failure (error)
- ospf_neighbor_down (info)

*Status: Active*
*Duration: 195.0s*

### INC-0028
**Failure Sequence:**
- crc_errors (warning)
- crc_errors (warning)
- interface_down (critical)
- stp_topology_change (warning)
- interface_down (critical)
- stp_topology_change (warning)
- bgp (warning)
- ospf_neighbor_down (warning)
- dot1x_failure (error)
- dot1x_failure (error)
- dot1x_failure (error)
- dot1x_failure (error)
- dot1x_failure (error)
- radius_recovered (critical)
- dot1x_failure (error)

**Recovery Sequence:**
- bgp (warning)
- ospf (warning)

*Status: Recovering*
*Duration: 360.0s*

### INC-0030
**Failure Sequence:**
- fan_failure (warning)
- bgp_session_lost (critical)
- bgp (warning)
- power (info)
- stp_topology_change (info)
- radius_recovered (info)
- radius_recovered (info)

*Status: Active*
*Duration: 471.0s*

### INC-0033
**Failure Sequence:**
- ssh_bruteforce (warning)
- ssh_bruteforce (warning)
- ssh_bruteforce (critical)

*Status: Active*
*Duration: 40.0s*

### INC-0036
**Failure Sequence:**
- transceiver (info)
- interface_down (info)
- ospf_neighbor_down (warning)
- bgp_session_lost (warning)

*Status: Active*
*Duration: 3.0s*

### INC-0038
**Failure Sequence:**
- dot1x_failure ×2 (error)
- port_blocked (warning)

*Status: Active*
*Duration: 3.0s*

### INC-0039
**Failure Sequence:**
- power_failure (critical)
- fan_failure (warning)
- thermal (warning)
- linecard_disabled (critical)

*Status: Active*
*Duration: 9.0s*

### INC-0044
**Failure Sequence:**
- crc_errors (warning)
- interface_down (critical)
- stp_topology_change (warning)
- interface_down (critical)
- stp_topology_change (warning)

*Status: Active*
*Duration: 73.0s*

### INC-0046
**Failure Sequence:**
- dot1x_failure (error)
- dot1x_failure (error)
- dot1x_failure (error)
- radius_recovered (critical)

*Status: Active*
*Duration: 28.0s*

### INC-0051
**Failure Sequence:**
- transceiver (warning)
- interface_down (info)
- interface_down (info)
- ospf_neighbor_down (warning)

**Recovery Sequence:**
- transceiver (info)
- interface_up (info)
- ospf_neighbor_up (info)

*Status: Resolved*
*Duration: 241.0s*

### INC-0052
**Failure Sequence:**
- ssh_bruteforce (warning)
- ssh_bruteforce (warning)
- ssh_bruteforce (warning)
- ssh_bruteforce (critical)

*Status: Active*
*Duration: 15.0s*

### INC-0053
**Failure Sequence:**
- dot1x_failure ×2 (error)
- raw (warning)

*Status: Active*
*Duration: 8.0s*

### INC-0054
**Failure Sequence:**
- power_failure (critical)
- fan_failure (warning)
- thermal (warning)
- thermal (critical)

*Status: Active*
*Duration: 25.0s*

### INC-0060
**Failure Sequence:**
- crc_errors (warning)
- crc_errors (warning)
- interface_down (critical)
- interface_down (error)
- interface_down (info)
- stp_topology_change (warning)
- interface_down (critical)
- ospf_neighbor_down (info)
- stp_topology_change (warning)
- bgp (warning)
- ospf_neighbor_down (warning)
- ssh_bruteforce (info)

*Status: Active*
*Duration: 305.0s*

### INC-0071
**Failure Sequence:**
- crc_errors (warning)
- interface_down (critical)
- stp_topology_change (warning)
- interface_down (critical)
- stp_topology_change (warning)
- ospf_neighbor_down (warning)

*Status: Active*
*Duration: 120.0s*

### INC-0076
**Failure Sequence:**
- dot1x_failure (error)
- dot1x_failure (error)
- dot1x_failure (error)
- dot1x_failure (error)
- dot1x_failure (error)
- radius_recovered (critical)
- dot1x_failure (error)

*Status: Active*
*Duration: 48.0s*

### INC-0079
**Failure Sequence:**
- ssh_bruteforce (warning)
- ssh_bruteforce (warning)
- ssh_bruteforce (critical)

*Status: Active*
*Duration: 40.0s*

### INC-0081
**Failure Sequence:**
- transceiver (info)
- interface_down (info)
- interface_down (info)
- ospf_interface_down (info)
- ospf_neighbor_down (warning)
- route_recalculation_started (info)
- route_recalculation_completed (info)
- bgp_session_lost (warning)
- route_withdrawal (info)

*Status: Active*
*Duration: 9.0s*

### INC-0083
**Failure Sequence:**
- transceiver (info)
- interface_down (info)
- interface_down (info)
- ospf_interface_down (info)
- ospf_neighbor_down (warning)
- ospf (info)
- ospf (info)

*Status: Active*
*Duration: 0.024s*

### INC-0086
**Failure Sequence:**
- transceiver (info)
- interface_down (info)
- interface_down (info)
- ospf_interface_down (info)
- ospf_neighbor_down (warning)
- ospf (info)
- ospf (info)
- bgp_session_lost (warning)
- route_withdrawal (info)
- route_withdrawal (info)

*Status: Active*
*Duration: 8.614s*

### INC-0087
**Failure Sequence:**
- dot1x_failure ×3 (error)
- port_blocked (warning)

*Status: Active*
*Duration: 5.983s*

### INC-0088
**Failure Sequence:**
- power_failure (critical)
- fan_failure (warning)
- thermal (warning)
- thermal (warning)

*Status: Active*
*Duration: 14.433s*

### INC-0089
**Failure Sequence:**
- ssh_bruteforce ×3 (warning)
- ssh_source_blocked (critical)

*Status: Active*
*Duration: 5.995s*

### INC-0095
**Failure Sequence:**
- transceiver (info)
- interface_down (info)
- interface_down (info)
- ospf_neighbor_down (warning)
- bgp_session_lost (warning)
- ospf (info)
- ospf (info)
- bgp_session_lost (warning)
- route_recalculation_started (info)
- route_recalculation_completed (info)

**Recovery Sequence:**
- transceiver (info)
- interface_up (info)
- interface_up (info)
- ospf_neighbor_up (info)
- bgp_session_established (info)
- routes_relearned (info)

*Status: Resolved*
*Duration: 179.892s*

### INC-0096
**Failure Sequence:**
- dot1x_failure ×3 (error)
- port_blocked (warning)

*Status: Active*
*Duration: 4.102s*

### INC-0097
**Failure Sequence:**
- ssh_bruteforce ×3 (warning)
- ssh_source_blocked (critical)

*Status: Active*
*Duration: 5.14s*

### INC-0098
**Failure Sequence:**
- power_failure (critical)
- fan_failure (warning)
- thermal (warning)
- thermal (warning)
- linecard_disabled (critical)

*Status: Active*
*Duration: 12.214s*

### INC-0099
**Failure Sequence:**
- crc_errors ×2 (warning)
- interface_down (info)
- interface_down (info)
- lldp (info)

*Status: Active*
*Duration: 12.656s*

### INC-0104
**Failure Sequence:**
- route_withdrawal (info)
- routes_withdrawn (info)
- transceiver ×2 (info)
- interface_down ×2 (info)
- interface_down ×2 (info)
- ospf_interface_down ×2 (info)
- ospf_neighbor_down ×2 (warning)
- route_recalculation_started ×2 (info)
- route_recalculation_completed ×2 (info)
- bgp_session_lost ×2 (warning)
- route_withdrawal (info)
- bgp_session_lost (warning)
- lldp (info)

**Recovery Sequence:**
- transceiver (info)
- interface_up (info)
- interface_up (info)
- ospf_interface_up (info)
- ospf_neighbor_up (info)
- bgp_session_established (info)
- routes_relearned (info)

*Status: Resolved*
*Duration: 241.0s*

### INC-0107
**Failure Sequence:**
- ssh_bruteforce ×3 (warning)
- ssh_source_blocked (critical)

*Status: Active*
*Duration: 4.0s*

### INC-0108
**Failure Sequence:**
- dot1x_failure ×3 (error)
- port_blocked (warning)

*Status: Active*
*Duration: 6.0s*

### INC-0109
**Failure Sequence:**
- power_failure (critical)
- fan_failure (warning)
- thermal (warning)
- thermal (warning)
- linecard_disabled (critical)

*Status: Active*
*Duration: 12.0s*

### INC-0110
**Failure Sequence:**
- crc_errors ×2 (warning)
- interface_down (info)
- interface_down (info)
- lldp (info)

*Status: Active*
*Duration: 10.0s*

### INC-0013
**Failure Sequence:**
- admin_auth_failure ×2 (warning)

*Status: Active*
*Duration: 0.0s*

### INC-0015
**Failure Sequence:**
- ssh_bruteforce ×2 (critical)

*Status: Active*
*Duration: 0.0s*

### INC-0025
**Failure Sequence:**
- raw (warning)

*Status: Active*
*Duration: 0.0s*

### INC-0031
**Failure Sequence:**
- stp_topology_change (info)

**Recovery Sequence:**
- interface_up (info)
- interface_up (info)
- bgp_session_established (info)
- bgp (warning)
- ospf_neighbor_up (info)
- ospf (info)

*Status: Active*
*Duration: 320.0s*

### INC-0034
**Failure Sequence:**
- temperature (warning)

*Status: Active*
*Duration: 0.0s*

### INC-0045
**Failure Sequence:**
- raw (warning)

*Status: Active*
*Duration: 0.0s*

### INC-0059
**Failure Sequence:**
- raw (warning)
- stp_topology_change (info)
- stp_topology_change (info)
- config_change (info)

**Recovery Sequence:**
- bgp (info)

*Status: Active*
*Duration: 446.0s*

### INC-0062
**Failure Sequence:**
- fan_failure (warning)

*Status: Active*
*Duration: 0.0s*

### INC-0063
**Failure Sequence:**
- bgp_session_lost (critical)

*Status: Active*
*Duration: 0.0s*

### INC-0064
**Failure Sequence:**
- admin_auth_failure (error)

*Status: Active*
*Duration: 0.0s*

### INC-0072
**Failure Sequence:**
- raw (critical)

*Status: Active*
*Duration: 0.0s*

## Operational Workflows Detected

### Workflow: WORKFLOW-0001
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - tunnel_activating (info)
  - tunnel_nexthop_delete (info)
  - tunnel_activating (info)
  - tunnel_nexthop_delete (info)
  - tunnel_activating (info)
  - tunnel_nexthop_delete (info)
  - tunnel_activating (info)
  - tunnel_nexthop_delete (info)
  - tunnel_activating (info)
  - tunnel_nexthop_delete (info)
  - tunnel_activating (info)
  - tunnel_nexthop_delete (info)
  - tunnel_activating (info)
  - tunnel_nexthop_delete (info)
  - tunnel_activating (info)
  - vxlan_interface (info)
  - vni_delete (info)
  - tunnel_nexthop_delete (info)
  - tunnel_operational (info)
  - tunnel_nexthop_delete (info)
  - tunnel_operational (info)
  - tunnel_nexthop_delete (info)
  - tunnel_operational (info)
  - tunnel_nexthop_delete (info)
  - tunnel_operational (info)
  - tunnel_nexthop_delete (info)
  - tunnel_operational (info)
  - tunnel_nexthop_delete (info)
  - tunnel_operational (info)
  - tunnel_nexthop_delete (info)
  - tunnel_operational (info)
  - tunnel_nexthop_delete (info)
  - tunnel_operational (info) x9

### Workflow: WORKFLOW-0003
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - config_change (info)

### Workflow: WORKFLOW-0011
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - mac_auth (info)

### Workflow: WORKFLOW-0016
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - bgp_session_established (info)
  - bgp (info)
  - config_change (info)

### Workflow: WORKFLOW-0019
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - interface_up (info) x2
  - stp_topology_change (info)
  - bgp (info)

### Workflow: WORKFLOW-0022
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - lldp (info) x4

### Workflow: WORKFLOW-0026
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - stp_topology_change (info) x2

### Workflow: WORKFLOW-0027
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - authentication (info)
  - config_change (info)

### Workflow: WORKFLOW-0029
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - interface_down (info)

### Workflow: WORKFLOW-0035
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - authentication (info)

### Workflow: WORKFLOW-0041
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - config_change (info)

### Workflow: WORKFLOW-0049
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - power (info)

### Workflow: WORKFLOW-0058
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - config_change (info)

### Workflow: WORKFLOW-0061
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - interface_down (info)

### Workflow: WORKFLOW-0068
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - stp_topology_change (info)
  - bgp_session_established (info)
  - ospf_neighbor_down (info)
  - ospf_neighbor_up (info)

### Workflow: WORKFLOW-0069
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - config_change (info)

### Workflow: WORKFLOW-0075
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - stp_topology_change (info)
  - ospf_neighbor_up (info)

### Workflow: WORKFLOW-0080
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - power (info)

### Workflow: WORKFLOW-0082
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - interface_down (info) x2
  - ospf_neighbor_down (info)
  - ospf_interface_down (info) x2
  - tunnel_nexthop_delete (info)
  - interface_down (info)
  - tunnel_nexthop_delete (info)
  - vtep_deleted (info)
  - tunnel_activating (info) x2
  - vni_delete (info) x2

### Workflow: WORKFLOW-0084
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - raw (info)
  - lldp (info)

### Workflow: WORKFLOW-0090
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - transceiver (info)
  - interface_up (info) x2
  - ospf_interface_up (info)
  - ospf_neighbor_up (info)
  - bgp_session_established (info)
  - routes_relearned (info)

### Workflow: WORKFLOW-0092
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - config_change (info)

### Workflow: WORKFLOW-0094
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - config_change (info)

### Workflow: WORKFLOW-0100
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - raw (info)

### Workflow: WORKFLOW-0101
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - raw (info) x2

### Workflow: WORKFLOW-0103
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - ntp (info)
  - snmp (info)
  - ntp (info)
  - snmp (info)

### Workflow: WORKFLOW-0105
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - config_change (info)
  - raw (info) x2

### Workflow: WORKFLOW-0106
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - mac_auth (info) x2

### Workflow: WORKFLOW-0112
- **Status:** Successful
- **Incident Detected:** No
- **Sequence Summary:**
  - raw (info)

## Standalone Alerts
The following high-severity events were detected but do not appear to be part of a larger cascading incident:

- 192.168.1.104: admin_auth_failure (warning) - Authentication failure for user admin from 192.168.1.99
- 192.168.1.104: ssh_bruteforce (critical) - SSH login failed from IP 203.0.113.5: Maximum attempts exceeded
- 192.168.1.10: raw (warning) - 802.1x: Authentication retry for client 11:22:33:44:55:66 on port 1/1/15
- 192.168.1.10: interface_up (info) - Port 1/1/7 is now on-line
- 192.168.1.10: interface_up (info) - Port 1/1/8 is now on-line
- 192.168.1.10: stp_topology_change (info) - Instance 0: Topology converged, no changes
- 192.168.1.10: bgp_session_established (info) - BGP peer 10.0.0.6 session established
- router-2: bgp (warning) - rpd[1190]: [daemon.info] BGP_NEIGHBOR_STATE_CHANGED: bgp peer 192.168.1.10 state changed from Idle to Established
- 192.168.1.10: ospf_neighbor_up (info) - OSPF neighbor 192.168.3.1 on VLAN 30 changed state from DOWN to FULL
- router-2: ospf (info) - rpd[1190]: [daemon.info] RPD_OSPF_NBRUP: OSPF neighbor 192.168.3.1 on ge-0/0/2.0 state changed from Down to Full
- router-2: temperature (warning) - chassisd[330]: [hw.warn] Temperature sensor 1 reading elevated: 52C (threshold 65C)
- 192.168.1.10: raw (warning) - 802.1x: Authentication retry for client 11:22:33:44:55:66 on port 1/1/15
- 192.168.1.10: raw (warning) - 802.1x: Authentication retry for client 11:22:33:44:55:66 on port 1/1/15
- 192.168.1.10: stp_topology_change (info) - Instance 0: Topology change detected on port 1/1/30, recalculating spanning tree
- 192.168.1.10: stp_topology_change (info) - Instance 0: Topology converged
- router-1: bgp (info) - %BGP-5-ADJCHANGE: neighbor 192.168.1.10 Up
- 192.168.1.10: config_change (info) - Configuration saved by admin via SSH from 192.168.1.200
- 192.168.1.10: fan_failure (warning) - Fan tray 2 speed nominal
- 192.168.1.10: bgp_session_lost (critical) - BGP peer 10.0.0.6 session Down, hold timer expired
- router-1: admin_auth_failure (error) - %SNMP-3-AUTHFAIL: Authentication failure for SNMP req from host 10.0.0.250
- router-1: raw (critical) - %ENVIRONMENT-1-ALERT: Temp: Inlet 1 Temperature reading 41C, threshold 65C - normal

## Routine & Unlinked Noise
The following events were classified as non-actionable noise or routine informational activity:

- 192.168.1.10: ntp (info) - Synchronized to NTP server 10.0.0.1, offset 0.012ms
- 192.168.1.104: snmp (info) - Connection with 192.168.1.50 closed
- 192.168.1.10: snmp (info) - Connection with 192.168.1.50 closed
- 192.168.1.10: interface_up (info) - Port 1/1/9 is now on-line
- 192.168.1.104: interface_up (info) - Port 1/1/1 is now on-line
- 192.168.1.10: lldp (info) - LLDP neighbor discovered on port 1/1/1: remote device router-1 (10.0.0.2)
- 192.168.1.10: lldp (info) - LLDP neighbor discovered on port 1/1/3: remote device switch-2 (10.0.0.4)
- router-1: lldp (info) - %LLDP-5-NEIGHBOR: LLDP neighbor up: switch-1 (192.168.1.10) on GigabitEthernet0/1
- 192.168.1.104: vlan (info) - Vlan 10 is created
- 192.168.1.104: lldp (info) - LLDP neighbor 00:25:B3:11:22:33 discovered on port 1/1/10
- 192.168.1.104: dot1x_logout (info) - 802.1x: Client 00:11:22:33:44:55 logged out from port 1/1/5
- 192.168.1.104: ntp (info) - NTP synchronized to time server 132.163.97.5
- router-1: interface_up (error) - %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to up
- router-1: interface_up (info) - %LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet0/1, changed state to up
- 192.168.1.10: ntp (info) - Synchronized to NTP server 10.0.0.1, offset 0.008ms
- 192.168.1.10: interface_up (info) - Port 1/1/20 is now on-line
- 192.168.1.10: snmp (info) - Connection with 192.168.1.50 closed
- 192.168.1.10: interface_up (info) - Port 1/1/20 is now on-line
- Core-8325-01: ntp (info) - NTP synchronized with server 192.168.1.1
- Core-8325-01: snmp (info) - Connection with 192.168.1.50 closed
- Access-6100-03: lldp (info) - LLDP neighbor discovered on port 1/1/5
- 192.168.1.10: ntp (info) - Synchronized to NTP server 10.0.0.1, offset 0.005ms
- 192.168.1.10: interface_up (info) - Port 1/1/20 is now on-line
- 192.168.1.10: interface_up (info) - Port 1/1/7 is now on-line
- 192.168.1.10: interface_up (info) - Port 1/1/9 is now on-line
- Core-8325-01: ntp (info) - Synchronized to NTP server 10.0.0.1
- Core-8325-01: snmp (info) - Connection with 192.168.1.50 closed
- 192.168.1.10: ntp (info) - Synchronized to NTP server 10.0.0.1, offset 0.006ms
- 192.168.1.10: lldp (info) - LLDP neighbor discovered on port 1/1/1: remote device router-1 (10.0.0.2)
- router-1: lldp (info) - %LLDP-5-NEIGHBOR: LLDP neighbor up: core-switch (192.168.1.10) on GigabitEthernet0/1
- 192.168.1.10: lldp (info) - LLDP neighbor discovered on port 1/1/2: remote device router-2 (10.0.0.6)
- 192.168.1.10: lldp (info) - LLDP neighbor discovered on port 1/1/4: remote device switch-3 (10.0.0.9)
- 192.168.1.10: interface_up (info) - Port 1/1/20 is now on-line
- 192.168.1.10: snmp (info) - Connection with 192.168.1.50 closed
- 192.168.1.10: interface_up (info) - Port 1/1/7 is now on-line
- router-1: interface_up (error) - %LINK-3-UPDOWN: Interface GigabitEthernet0/2, changed state to up
- router-1: interface_up (info) - %LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet0/2, changed state to up
- 192.168.1.10: interface_up (info) - Port 1/1/8 is now on-line
- 192.168.1.10: interface_up (info) - Port 1/1/20 is now on-line
- 192.168.1.10: interface_up (info) - Port 1/1/55 is now on-line
- 192.168.1.10: interface_up (info) - Port 1/1/56 is now on-line
- 192.168.1.10: radius_recovered (info) - 802.1x: Authentication succeeded for client AA:11:BB:22:CC:33 on port 1/1/40 (backup RADIUS)
- 192.168.1.10: radius_recovered (info) - 802.1x: Authentication succeeded for client BB:22:CC:33:DD:44 on port 1/1/41 (backup RADIUS)
- Core-8325-01: vlan (info) - VLAN 100 created
- Core-8325-01: ntp (info) - NTP synchronized with time source 192.168.1.1
- Core-8325-01: ntp (info) - NTP synchronized with server 192.168.10.1
- Core-8325-01: ntp (info) - NTP synchronized with server 192.168.10.1
- Core-8325-01: vlan (info) - VLAN 200 created
- Access-6100-01: lldp (info) - LLDP neighbor discovered on port 1/1/12
- Access-6100-04: interface_up (info) - Port 1/1/20 is now on-line
- Access-6100-04: interface_up (info) - Port 1/1/21 is now on-line

## Confidence and Limitations
- Causality is inferred from temporal and contextual heuristics, not strict proof.
- Confidence increases when links have strong timing, device/interface alignment, and severity progression.

## Recommendations
- Prioritize remediation on root-linked interfaces/devices before downstream symptoms.
- Add monitoring alerts for repeated trigger subtypes and interface recurrence.
- Validate inferred root causes with device-level diagnostics and config audit.
# MAP-T-BR-Verification
Python/Scapy to perform verification of MAP-T Border Relays

These scripts use Scapy to generate packets to be translated by a MAP-T Border Relay, and then receive the packets back
and verify they were translated appropriately via RFC 7599.

There are two current scripts:
  - Functionality Test which tests upstream/downstream traffic, ttl/hop count expiration, TCP MSS clamping, and fragmentation.
  - ICMPv6, which verifies that ICMPv6 packets are translated to ICMP appropriately.
  
These scripts are built for testing a rule with the following parameters:
  - IPv4 Prefix: 198.18.0.0/24
  - IPv6 Prefix: 2001:db8:f0::/48
  - EA Length: 12
  - PSID Offset: 12
  - Default Mapping Rule: 2001:db8:ffff:ff00::/64
  
If you are running this script across a network between the BR, you will need to ensure that the IPv4 and and Default Mapping
Rule are routed to the Border Relay, and the IPv6 Prefix and the IPv4 Source (192.0.2.1) are routed to the host that 
is sending the traffic.

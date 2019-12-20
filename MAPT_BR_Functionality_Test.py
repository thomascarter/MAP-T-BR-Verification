#! /usr/bin/env python

from scapy.all import *
import argparse
import pyswmap
import scapy.contrib.igmp
import ipaddress
from threading import Thread
from Queue import Queue, Empty
from time import sleep
from multiprocessing import Pool, TimeoutError, current_process
import time
import os
import random
import scapy.contrib.igmp
from scapy.utils import PcapWriter
import uuid

# Changing log level to suppress IPv6 error
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# ******************** BR FUNCTIONALITY TEST CLASS - START ******************#
class BRFunctionalityTest:
    def __init__(self,
                 ipv4_internet_address,
                 ipv4_destination_addres,
                 ipv6_cpe_address,
                 ipv6_map_address,
                 ipv4_local_address,
                 ipv6_local_address,
                 ipv4_udp_or_tcp_internet_port,
                 ipv4_udp_or_tcp_map_port,
                 ipv6_udp_or_tcp_map_port,
                 ipv6_udp_or_tcp_internet_port,
                 psid_number,
                 scapy_interface,
                 dir_uuid):
        self.ipv4_internet_address = ipv4_internet_address
        self.ipv4_map_address = ipv4_map_address
        self.ipv6_cpe_address = ipv6_cpe_address
        self.ipv6_map_address = ipv6_map_address
        self.ipv4_local_address = ipv4_local_address
        self.ipv6_local_address = ipv6_local_address
        self.ipv4_udp_or_tcp_internet_port = ipv4_udp_or_tcp_internet_port
        self.ipv4_udp_or_tcp_map_port = ipv4_udp_or_tcp_map_port
        self.ipv6_udp_or_tcp_map_port = ipv6_udp_or_tcp_map_port
        self.ipv6_udp_or_tcp_internet_port = ipv6_udp_or_tcp_internet_port
        self.psid_number = psid_number
        self.scapy_interface = scapy_interface
        self.dir_uuid = dir_uuid
        self.m_finished = False
        self.packet_error = False
        self.comment = ""
        self.write_pcap = False
        self.show_packet = True

    # Upstream refers to IPv6 -> IPv4 direction
    # Downstream refers to IPv4 -> IPv6 direction
    # Check for normal translation of packets of UDP packet in the v4 -> v6 direction
    # Send 128 frame size packet for ipv4/udp. DF=0
    # Received packet should be translated into IPv6 packet and no fragment header
    def downstream_udp_packet_translation(self):
        self.m_finished = False
        self.packet_error = False
        q = Queue()
        fh = open(dir_uuid + "/test_results.txt", "a")
        fh.write("IPv4-> IPv6 UDP Normal Packet:  \n")
        capture_filter = 'udp and src {}'.format(self.ipv6_map_address)
        sniffer = Thread(target=self.sniffer, args=(q, capture_filter, 1))
        sniffer.daemon = True
        sniffer.start()
        capture = Thread(target=self.capsniffer, args=('net 198.18.0.0/24 or net 2001:db8:ffff:ff00::/64', 10, dir_uuid + "/4to6_udp_normal.pcap" ))
        capture.daemon = True
        capture.start()
        while not self.m_finished:
            ip = IP(src=self.ipv4_internet_address, dst=self.ipv4_map_address, tos=0)
            udp = UDP(sport=self.ipv4_udp_or_tcp_internet_port, dport=self.ipv4_udp_or_tcp_map_port)
            payload = "a" * 82
            tx_pkt = ip / udp / payload
            send(tx_pkt, iface=self.scapy_interface, verbose=False)
            sleep(.5)
        sniffer.join()
        capture.join()
        fh.write("Transmitted Packet: " + tx_pkt.show2(dump=True) + "\n")
        try:
            pkt = q.get(timeout=1)
            fh.write("Received Packet: " + pkt.show2(dump=True) + "\n")
            self.v6_address_check(pkt)
            self.v6_port_check(pkt)
            if pkt[0][1].tc != 0:
                self.packet_error = True
                print("IPv6 Traffic Class does not transmitted IPv4 ToS \n")
            if pkt[0][1].nh == 44:
                self.v6_address_check(pkt)
                self.v6_port_check(pkt)
                self.packet_error = True
                fh.write("Fragment Header added\n")
        except Empty:
            fh.write("IPv6 UDP Packet Not Received \n")
            self.packet_error = True
        if self.packet_error:
            fh.write(self.comment)
            print "IPv4 -> IPv6 UDP Normal Packet: FAIL\n"
        if not self.packet_error:
            print "IPv4 -> IPv6 UDP Normal Packet: PASS\n"
        fh.close()

    # Check for normal translation of packets of TCP packet in the v4 -> v6 direction
    # Send 128 frame size packet for ipv4/udp. DF=0
    # Received packet should be translated into IPv6 packet and no fragment header
    def downstream_tcp_packet_translation(self):
        self.m_finished = False
        self.packet_error = False
        q = Queue()
        fh = open(dir_uuid + "/test_results.txt", "a")
        fh.write("IPv4 TC -> IPv6 TCP Normal Packet:  \n")
        capture_filter = 'tcp and src {}'.format(self.ipv6_map_address)
        sniffer = Thread(target=self.sniffer, args=(q, capture_filter, 1))
        sniffer.daemon = True
        sniffer.start()
        capture = Thread(target=self.capsniffer, args=('net 198.18.0.0/24 or net 2001:db8:ffff:ff00::/64', 10, dir_uuid + "/4to6_tcp_normal.pcap" ))
        capture.daemon = True
        capture.start()
        while not self.m_finished:
            ip = IP(src=self.ipv4_internet_address, dst=self.ipv4_map_address, tos=0)
            tcp = TCP(sport=self.ipv4_udp_or_tcp_internet_port, dport=self.ipv4_udp_or_tcp_map_port)
            payload = "a" * 82
            tx_pkt = ip / tcp / payload
            send(tx_pkt, iface=self.scapy_interface, verbose=False)
            sleep(.5)
        sniffer.join()
        capture.join()
        fh.write("Transmitted Packet: " + tx_pkt.show2(dump=True) + "\n")
        try:
            pkt = q.get(timeout=1)
            fh.write("Received Packet: " + pkt.show2(dump=True) + "\n")
            self.v6_address_check(pkt)
            self.v6_port_check(pkt)
            if pkt[0][1].tc != 0:
                self.packet_error = True
                print("IPv6 Traffic Class does not transmitted IPv4 ToS \n")
            if pkt[0][1].nh == 44:
                self.v6_address_check(pkt)
                self.v6_port_check(pkt)
                self.packet_error = True
                fh.write("Fragment Header added")
        except Empty:
            fh.write("IPv6 TCP Packet Not Received \n")
            self.packet_error = True
        if self.packet_error:
            fh.write(self.comment)
            print "IPv4 -> IPv6 TCP Normal Packet: FAIL\n"
        if not self.packet_error:
            print "IPv4 -> IPv6 TCP Normal Packet: PASS\n"
        fh.close()

    # Check for normal translation of packets UDP traffic in v6 -> v4 direction
    # Send 128 frame size packet for ipv6/udp
    # Received packet should be translated into IPv4 packet with DF=1
    def upstream_udp_packet_translation(self):
        self.m_finished = False
        self.packet_error = False
        q = Queue()
        fh = open(dir_uuid + "/test_results.txt", "a")
        fh.write("IPv6 -> IPv4 UDP Normal Packet:  \n")
        capture_filter = 'udp and src {}'.format(self.ipv4_map_address)
        sniffer = Thread(target=self.sniffer, args=(q, capture_filter, 1))
        sniffer.daemon = True
        sniffer.start()
        capture = Thread(target=self.capsniffer, args=('net 198.18.0.0/24 or net 2001:db8:ffff:ff00::/64', 10, dir_uuid + "/6to4_udp_normal.pcap" ))
        capture.daemon = True
        capture.start()
        while not self.m_finished:
            ip = IPv6(src=self.ipv6_cpe_address, dst=self.ipv6_map_address)
            udp = UDP(sport=self.ipv6_udp_or_tcp_map_port, dport=self.ipv6_udp_or_tcp_internet_port)
            payload = "a" * 82
            tx_pkt = ip / udp / payload
            send(tx_pkt, iface=self.scapy_interface, verbose=False)
            sleep(.5)
        sniffer.join()
        capture.join()
        fh.write("Transmitted Packet: " + tx_pkt.show2(dump=True) + "\n")
        try:
            pkt = q.get(timeout=1)
            fh.write("Received Packet: " + pkt.show2(dump=True) + "\n")
            self.v4_address_check(pkt)
            self.v4_port_check(pkt)
            if pkt[0][1].tos != 0:
                self.packet_error = True
                print("IPv4 ToS does not transmitted IPv4 Traffic Class \n")
            if pkt[0][1].proto == 44:
                self.v6_address_check(pkt)
                self.v6_port_check(pkt)
                self.packet_error = True
                fh.write("Fragment Header added\n")
        except Empty:
            fh.write("IPv4 UDP Packet Not Received")
            self.packet_error = True
        if self.packet_error:
            fh.write(self.comment)
            print "IPv6 -> IPv4 UDP Normal Packet: FAIL\n"
        if not self.packet_error:
            print "IPv6 -> IPv4 UDP Normal Packet: PASS\n"
        fh.close()

    # Check for normal translation of packets TCP traffic in v6 -> v4 direction
    # Send 128 frame size packet for ipv6/tcp
    # Received packet should be translated into IPv4 packet with DF=1
    def upstream_tcp_packet_translation(self):
        self.m_finished = False
        self.packet_error = False
        q = Queue()
        fh = open(dir_uuid + "/test_results.txt", "a")
        fh.write("IPv6 -> IPv4 TCP Normal Packet:  \n")
        capture_filter = 'tcp and src {}'.format(self.ipv4_map_address)
        sniffer = Thread(target=self.sniffer, args=(q, capture_filter, 1))
        sniffer.daemon = True
        sniffer.start()
        capture = Thread(target=self.capsniffer, args=('net 198.18.0.0/24 or net 2001:db8:ffff:ff00::/64', 10, dir_uuid + "/6to4_tcp_normal.pcap" ))
        capture.daemon = True
        capture.start()
        while not self.m_finished:
            ip = IPv6(src=self.ipv6_cpe_address, dst=self.ipv6_map_address)
            tcp = TCP(sport=self.ipv6_udp_or_tcp_map_port, dport=self.ipv6_udp_or_tcp_internet_port)
            payload = "a" * 82
            tx_pkt = ip / tcp / payload
            send(tx_pkt, iface=self.scapy_interface, verbose=False)
            sleep(.5)
        sniffer.join()
        capture.join()
        fh.write("Transmitted Packet: " + tx_pkt.show2(dump=True) + "\n")
        try:
            pkt = q.get(timeout=1)
            fh.write("Received Packet: " + pkt.show2(dump=True) + "\n")
            self.v4_address_check(pkt)
            self.v4_port_check(pkt)
            if pkt[0][1].tos != 0:
                self.packet_error = True
                print("IPv4 ToS does not transmitted IPv4 Traffic Class \n")
            if pkt[0][1].proto == 44:
                self.v6_address_check(pkt)
                self.v6_port_check(pkt)
                self.packet_error = True
                fh.write("Fragment Header added\n")
        except Empty:
            fh = open("test_results.txt", "a")
            fh.write("IPv4 UDP Packet Not Received\n")
        if self.packet_error:
            fh.write(self.comment)
            print "IPv6 -> IPv4 TCP Normal Packet: FAIL\n"
        if not self.packet_error:
            print "IPv6 -> IPv4 TCP Normal Packet: PASS\n"
        fh.close()

    # Check for ttl_expired at the BR for a UDP datagram
    # Send 128 frame size packet for ipv4/udp. ttl=2
    # Received packet should be ICMP(Time-to-live exceeded)
    def downstream_br_ttl_expired(self):
        self.m_finished = False
        self.packet_error = False
        q = Queue()
        fh = open(dir_uuid + "/test_results.txt", "a")
        fh.write("IPv4 -> IPv6 TTL Expires at BR Packet:  \n")
        capture_filter = 'dst {}'.format(self.ipv4_internet_address)
        sniffer = Thread(target=self.sniffer, args=(q, capture_filter, 1))
        sniffer.daemon = True
        sniffer.start()
        capture = Thread(target=self.capsniffer, args=('net 198.18.0.0/24 or net 2001:db8:ffff:ff00::/64 or net 192.0.2.0/24', 10, dir_uuid + "/4to6_br_ttl_expired.pcap" ))
        capture.daemon = True
        capture.start()
        while not self.m_finished:
            ip = IP(src=self.ipv4_internet_address, dst=self.ipv4_map_address, tos=0, ttl=2)
            udp = UDP(sport=self.ipv4_udp_or_tcp_internet_port, dport=self.ipv4_udp_or_tcp_map_port)
            payload = "a" * 82
            tx_pkt = ip / udp / payload
            send(tx_pkt, iface=self.scapy_interface, verbose=False)
            sleep(.5)
        sniffer.join()
        capture.join()
        fh.write("Transmitted Packet: " + tx_pkt.show2(dump=True) + "\n")
        try:
            pkt = q.get(timeout=1)
            fh.write("Received Packet: " + pkt.show2(dump=True) + "\n")
            if pkt[0][1].proto != 1:
                fh.write("Packet Type is not ICMP (Proto 1)\n")
                self.packet_error = True
            if pkt[0][2].type != 11:
                fh.write("Incorrect Type Number\n")
                self.packet_error = True
            if pkt[0][2].code != 0:
                fh.write("Incorrect Code Number\n")
                self.packet_error = True
        except Empty:
            fh.write("ICMP Packets Not Received")
            self.packet_error = True
        if self.packet_error:
            print("IPv4 -> IPv6 TTL Expires at BR Packet: FAIL\n")
        if not self.packet_error:
            print("IPv4 -> IPv6 TTL Expires at BR Packet: PASS\n")
        fh.close()

    # Send an ICMP TTL expired packet to the BR
    # The BR should translated to an ICMPv6 Hop Limit Expired Message
    # The BR must perform MAP on both IP headers (packet and packet in error)
    def downstream_ttl_expired(self):
        self.m_finished = False
        self.packet_error = False
        q = Queue()
        fh = open(dir_uuid + "/test_results.txt", "a")
        fh.write("IPv4 -> IPv6 ICMP TTL Expired translated to Hop Limit Expired:  \n")
        capture_filter = 'icmp6 and dst {}'.format(self.ipv6_cpe_address)
        sniffer = Thread(target=self.sniffer, args=(q, capture_filter, 1))
        sniffer.daemon = True
        sniffer.start()
        capture = Thread(target=self.capsniffer, args=('net 198.18.0.0/24 or net 2001:db8:ffff:ff00::/64', 10, dir_uuid + "/4to6_ttl_expired_translated.pcap" ))
        capture.daemon = True
        capture.start()
        while not self.m_finished:
            ip = IP(src=self.ipv4_local_address, dst=self.ipv4_map_address, tos=0)
            icmp = ICMP(type=11, code=0)
            ip2 = IP(dst=self.ipv4_internet_address, src=ipv4_map_address,ttl=1)
            udp = UDP(sport=self.ipv4_udp_or_tcp_map_port, dport=self.ipv4_udp_or_tcp_internet_port)
            payload = "a" * 24
            tx_pkt = ip / icmp / ip2 / udp / payload
            send(tx_pkt, iface=self.scapy_interface, verbose=False)
            sleep(.5)
        sniffer.join()
        capture.join()
        fh.write("Transmitted Packet: " + tx_pkt.show2(dump=True) + "\n")
        try:
            pkt = q.get(timeout=1)
            fh.write("Received Packet: " + pkt.show2(dump=True) + "\n")
            if pkt[0][1].nh != 58:
                fh.write("Packet Type is not ICMP (Proto 58)\n")
                self.packet_error = True
            if pkt[0][2].type != 3 or pkt[0][2].code != 0:
                fh.write("Not an ICMPv6 Hop Limit expired in transit message\n")
                self.packet_error = True
            if pkt[0][3].src != self.ipv6_cpe_address or pkt[0][3].dst != self.ipv6_map_address:
                fh.write("Packet in Error IPv4 not translated correctly to IPv6\n")
                self.packet_error = True
            if pkt[0][4].sport != self.ipv6_udp_or_tcp_map_port or pkt[0][4].dport != self.ipv6_udp_or_tcp_internet_port:
                fh.write("Packet in Error UDP not translated correctly to IPv6\n")
                self.packet_error = True
        except Empty:
            fh.write("ICMPv6 Packets Not Received\n")
            self.packet_error = True
        if self.packet_error:
            print("IPv4 -> IPv6 ICMP TTL Expired translated to Hop Limit Expired: FAIL\n")
        if not self.packet_error:
            print("IPv4 -> IPv6 ICMP TTL Expired translated to Hop Limit Expired: PASS\n")
        fh.close()

    # Check for hop limit expired packets
    # Received packet should be ICMPv6(Time-to-live exceeded)
    def upstream_br_hop_limit_expired(self):
        self.m_finished = False
        self.packet_error = False
        q = Queue()
        fh = open(dir_uuid + "/test_results.txt", "a")
        fh.write("BR Generates ICMPv6 Hop Limit Expired for MAP traffic that expires at BR:  \n")
        capture_filter = 'icmp6 and dst {}'.format(self.ipv6_cpe_address)
        sniffer = Thread(target=self.sniffer, args=(q, capture_filter, 1))
        sniffer.daemon = True
        sniffer.start()
        capture = Thread(target=self.capsniffer, args=('net 198.18.0.0/24 or net 2001:db8:ffff:ff00::/64 or net 2001:db8::/48', 10, dir_uuid + "/6to6_br_hop_limit_expired.pcap" ))
        capture.daemon = True
        capture.start()
        while not self.m_finished:
            ip = IPv6(src=self.ipv6_cpe_address, dst=self.ipv6_map_address, hlim=2)
            udp = UDP(sport=self.ipv6_udp_or_tcp_map_port, dport=self.ipv6_udp_or_tcp_internet_port)
            payload = "a" * 82
            tx_pkt = ip / udp / payload
            send(tx_pkt, iface=self.scapy_interface, verbose=False)
            sleep(.5)
        sniffer.join()
        capture.join()
        fh.write("Transmitted Packet: " + tx_pkt.show2(dump=True) + "\n")
        try:
            pkt = q.get(timeout=1)
            fh.write("Received Packet: " + pkt.show2(dump=True) + "\n")
            if pkt[0][1].nh != 58:
                fh.write("Packet Type is not ICMPv6 (Proto 58)\n")
            self.packet_error = True
            if pkt[0][2].type != 3 or pkt[0][2].code != 0:
                fh.write("ICMP Packet is not Type Number 3, code 0\n")
                self.packet_error = True
        except Empty:
            fh.write("ICMPv6 Hop Limit Expired not received\n")
            self.packet_error = True
        if self.packet_error:
            print("ICMPv6 Hop Limit Expired: PASS\n")
        if not self.packet_error:
            print("ICMPv6 Hop Limit Expired: PASS\n")

    # Checks that the BR translates an ICMPv6 Hop Limit Expired Message to ICMP TTL Expired
    # This includes MAP on the IP header and the IP header of the packet in error
    def upstream_hop_limit_expired(self):
        self.m_finished = False
        self.packet_error = False
        q = Queue()
        fh = open(dir_uuid + "/test_results.txt", "a")
        fh.write("IPv6 -> IPv4 ICMP Hop Limit Expired translated to ICMP TTL Expired:  \n")
        capture_filter = 'icmp and src {}'.format(self.ipv4_map_address )
        sniffer = Thread(target=self.sniffer, args=(q, capture_filter, 1))
        sniffer.daemon = True
        sniffer.start()
        capture = Thread(target=self.capsniffer, args=('net 198.18.0.0/24 or net 2001:db8:ffff:ff00::/64', 10, dir_uuid + "/4to6_ttl_expired_translated.pcap" ))
        capture.daemon = True
        capture.start()
        while not self.m_finished:
            ip = IPv6(src=self.ipv6_local_address, dst=self.ipv6_map_address)
            icmp = ICMPv6TimeExceeded()
            ip2 = IPv6(src=self.ipv6_map_address, dst=self.ipv6_cpe_address, hlim=1)
            udp = UDP(sport=self.ipv6_udp_or_tcp_internet_port, dport=self.ipv6_udp_or_tcp_map_port)
            payload = "a" * 82
            tx_pkt = ip / icmp / ip2 / udp / payload
            send(tx_pkt, iface=self.scapy_interface, verbose=False)
            sleep(.5)
        sniffer.join()
        capture.join()
        fh.write("Transmitted Packet: " + tx_pkt.show2(dump=True) + "\n")
        try:
            pkt = q.get(timeout=1)
            fh.write("Received Packet: " + pkt.show2(dump=True) + "\n")
            if pkt[0][1].proto != 1:
                fh.write("Packet Type is not ICMP (Proto 1)\n")
                self.packet_error = True
            if pkt[0][2].type != 11 or pkt[0][2].code != 0:
                fh.write("Not an ICMP TTL Expired expired in transit message\n")
                self.packet_error = True
            if pkt[0][3].src != self.ipv4_map_address or pkt[0][3].dst != self.ipv4_internet_address:
                fh.write("Packet in Error IPv4 not translated correctly to IPv4\n")
                self.packet_error = True
            if pkt[0][4].sport != self.ipv4_udp_or_tcp_internet_port or pkt[0][4].dport != self.ipv4_udp_or_tcp_internet_port:
                fh.write("Packet in Error UDP not translated correctly to IPv4\n")
                self.packet_error = True
            if self.packet_error:
                print("IPv6 -> IPv4 Hop Limit Expired translated to ICMP TTL Expired: FAIL\n")
            if not self.packet_error:
                print("IPv6 -> IPv4 Hop Limit Expired translated to ICMP TTL Expired: PASS\n")
        except Empty:
            fh.write("ICMP Packets Not Received\n")
            print("IPv6 -> IPv4 Hop Limit Expired translated to ICMP TTL Expired: FAIL\n")
        fh.close()


    # Check for outside domain port number
    # Send 128 frame size packet for ipv4/udp, udp.dstport=1001
    # Received packet should be ICMPv4
    def downstream_outside_port(self):
        self.m_finished = False
        self.packet_error = False
        q = Queue()
        fh = open(dir_uuid + "/test_results.txt", "a")
        fh.write("IPv4 -> IPv6 Outside (Reserved) Port  \n")
        capture_filter = '(net 192.0.2.0/24 and icmp) or dst {}'.format(self.ipv6_cpe_address)
        sniffer = Thread(target=self.sniffer, args=(q, capture_filter, 1))
        sniffer.daemon = True
        sniffer.start()
        capture = Thread(target=self.capsniffer, args=('net 198.18.0.0/24 or net 2001:db8:ffff:ff00::/64', 10, dir_uuid + "/4to6_outside_port.pcap" ))
        capture.daemon = True
        capture.start()
        while not self.m_finished:
            ip = IP(src=self.ipv4_internet_address, dst=self.ipv4_map_address)
            udp = UDP(sport=self.ipv4_udp_or_tcp_internet_port, dport=1001)
            payload = "a" * 82
            tx_pkt = ip / udp / payload
            send(tx_pkt, iface=self.scapy_interface, verbose=False)
            sleep(.5)
        sniffer.join()
        capture.join()
        fh.write("Transmitted Packet: " + tx_pkt.show2(dump=True) + "\n")
        try:
            pkt = q.get(timeout=1)
            if pkt[0][1].proto == 17:
                fh.write("Packet translated normally when it should be dropped\n")
                fh.write("Received Packet: " + pkt.show2(dump=True) + "\n")
                self.packet_error = True
        except Empty:
            fh.write("Packet not received - the packet might have been dropped silently\n")
            print("Downstream Packet to Reserved Port Dropped: CONDITIONAL PASS\n")
            fh.close()
            return
        if self.packet_error:
            print("IPv4 Packet to Dest Reserved Port Dropped: FAIL")
        if not self.packet_error:
            print("IPv4 Packet to Dest Reserved Port Dropped: PASS")
        fh.close()

    # Check for outside port
    # Send 128 frame size packet for ipv6/udp and udp.srcport = 1001
    # Received packet should be ICMPv6(Source address failed ingress/egress policy)
    # Receiving no packets is valid
    def upstream_outside_port(self):
        self.m_finished = False
        self.packet_error = False
        q = Queue()
        fh = open(dir_uuid + "/test_results.txt", "a")
        fh.write("IPv6 -> IPv4 Outside (Reserved) Port  \n")
        capture_filter = '(net 2001:db8::/32 and icmp6) or dst {}'.format(self.ipv4_map_address)
        sniffer = Thread(target=self.sniffer, args=(q, capture_filter, 1))
        sniffer.daemon = True
        sniffer.start()
        capture = Thread(target=self.capsniffer, args=('net 198.18.0.0/24 or net 2001:db8:ffff:ff00::/64', 10, dir_uuid + "/6to4_outside_port.pcap" ))
        capture.daemon = True
        capture.start()
        while not self.m_finished:
            ip = IPv6(src=self.ipv6_cpe_address, dst=self.ipv6_map_address)
            udp = UDP(sport=1001, dport=self.ipv6_udp_or_tcp_internet_port)
            payload = "a" * 82
            tx_pkt = ip / udp / payload
            send(tx_pkt, iface=self.scapy_interface, verbose=False)
            sleep(.5)
        sniffer.join()
        capture.join()
        fh.write("Transmitted Packet: " + tx_pkt.show2(dump=True) + "\n")
        try:
            pkt = q.get(timeout=1)
            if pkt[0][1].proto == 17:
                fh.write("Packet translated normally when it should be dropped\n")
                fh.write("Received Packet: " + pkt.show2(dump=True) + "\n")
                self.packet_error = True
        except Empty:
            fh.write("Packet not received - the packet might have been dropped silently\n")
            print("Downstream Packet to Reserved Port Dropped: CONDITIONAL PASS\n")
            fh.close()
            return
        if self.packet_error:
            print("IPv6 Packet from Src Reserved Port Dropped: FAIL")
        if not self.packet_error:
            print("IPv6 Packet from Src Reserved Port Dropped: PASS")
        fh.close()

    # Check for packet fragmentation by the BR
    # Send 1499 frame size packet for ipv4/udp. DF=0
    # Received packet should be translated into IPv6 packet and fragmented by the BR
    def downstream_br_fragmentation(self):
        self.m_finished = False
        self.packet_error = False
        q = Queue()
        fh = open(dir_uuid + "/test_results.txt", "a")
        fh.write("IPv4 -> IPv6 BR Fragmentation:  \n")
        capture_filter = 'src {}'.format(self.ipv6_map_address)
        sniffer = Thread(target=self.sniffer, args=(q, capture_filter, 2))
        sniffer.daemon = True
        sniffer.start()
        capture = Thread(target=self.capsniffer, args=('net 198.18.0.0/24 or net 2001:db8:ffff:ff00::/64', 10, dir_uuid + "/4to6_br_fragmentation.pcap" ))
        capture.daemon = True
        capture.start()
        while not self.m_finished:
            ip = IP(src=self.ipv4_internet_address, dst=self.ipv4_map_address, tos=0)
            udp = UDP(sport=self.ipv4_udp_or_tcp_internet_port, dport=self.ipv4_udp_or_tcp_map_port)
            payload = "a" * 1460
            tx_pkt = ip / udp / payload
            sleep(.5)
            send(tx_pkt, iface=self.scapy_interface, verbose=False)
        sniffer.join()
        capture.join()
        fh.write("Transmitted Packet: " + tx_pkt.show2(dump=True) + "\n")
        try:
            pkt = q.get(timeout=1)
            fh.write("Received Packet: " + pkt.show2(dump=True) + "\n")
            self.v6_address_check(pkt[0])
            self.v6_port_check(pkt[0])
            if pkt[0][1].nh != 44 and pkt[0][2].nh != 17:
                self.packet_error = True
                print("First packet is not Fragment Header with UDP")
            if pkt[1][1].nh == 44:
                self.packet_error = True
                fh.write("Second Packet is not Fragment Header with UDP")
        except Empty:
            fh.write("IPv6 Fragmented Packets not received\n")
            self.packet_error = True
        if self.packet_error:
            fh.write(self.comment)
            print("IPv4 -> IPv6 BR Fragmentation: FAIL\n")
        if not self.packet_error:
            print("IPv4 -> IPv6 BR Fragmentation: PASS\n")
        fh.close()

    # Check for packet fragmets sent to the BR
    # Send fragments for ipv4/udp. DF=0
    # Received packet should be IPv6 fragments
    def downstream_fragments(self):
        self.m_finished = False
        self.packet_error = False
        q = Queue()
        fh = open(dir_uuid + "/test_results.txt", "a")
        fh.write("IPv4 -> IPv6 Fragments:  \n")
        capture_filter = 'dst {}'.format(self.ipv6_cpe_address)
        sniffer = Thread(target=self.sniffer, args=(q, capture_filter, 4))
        sniffer.daemon = True
        sniffer.start()
        capture = Thread(target=self.capsniffer, args=('net 198.18.0.0/24 or net 2001:db8:ffff:ff00::/64', 10, dir_uuid + "/4to6_fragments.pcap" ))
        capture.daemon = True
        capture.start()
        ip = IP(src=self.ipv4_internet_address, dst=self.ipv4_map_address, flags="MF", frag=0, id=3000)
        udp = UDP(sport=self.ipv4_udp_or_tcp_internet_port, dport=self.ipv4_udp_or_tcp_map_port)
        payload = "a" * 1220
        first_packet = ip / udp / payload
        ip2 = IP(src=self.ipv4_internet_address, dst=self.ipv4_map_address, frag=20, id=3000, proto=17)
        payload2 = "a" * 640
        second_packet = ip2 / payload2
        frags = [first_packet, second_packet]
        sleep(1)
        while not self.m_finished:
            for fragment in frags:
                sleep(.5)
                send(fragment, iface=scapy_interface, verbose=False)
        sniffer.join()
        capture.join()
        try:
            pkt = q.get(timeout=1)
            for packet in frags:
                fh.write("Transmitted Packet: " + packet.show2(dump=True) + "\n")
            for packet in pkt:
                fh.write("Received Packet: " + pkt.show2(dump=True) + "\n")
            if pkt[0][1].nh != 44 and pkt[0][2].nh != 17:
                self.packet_error = True
                print("First packet is not Fragment Header with UDP")
            if pkt[1][1].nh == 44:
                self.packet_error = True
                fh.write("Second Packet is not Fragment Header with UDP")
        except Empty:
            fh.write("IPv6 Fragmented Packets not received\n")
            self.packet_error = True
        if self.packet_error:
            print("IPv4 Fragments forwarded by BR: FAIL\n")
        if not self.packet_error:
            print("IPv4 Fragments forwarded by BR: PASS\n")
        fh.close()

    def upstream_echo_request(self):
        self.m_finished = False
        self.packet_error = False
        fh = open(dir_uuid + "/test_results.txt", "a")
        fh.write("IPv6 -> IPv4 Echo Request:  \n")
        q = Queue()
        capture_filter = 'icmp and dst {}'.format(self.ipv4_internet_address)
        sniffer = Thread(target=self.sniffer, args=(q, capture_filter, 1))
        sniffer.daemon = True
        sniffer.start()
        capture = Thread(target=self.capsniffer, args=('net 198.18.0.0/24 or net 2001:db8:ffff:ff00::/64', 10, dir_uuid + "/6to4_echo_request.pcap" ))
        capture.daemon = True
        capture.start()
        while not self.m_finished:
            ip = IPv6(src=self.ipv6_cpe_address, dst=self.ipv6_map_address)
            icmp = ICMPv6EchoRequest()
            icmp.id = self.ipv6_udp_or_tcp_map_port
            payload = "H" * 10
            tx_pkt = ip / icmp / payload
            send(tx_pkt, iface=self.scapy_interface, verbose=False)
        sniffer.join()
        capture.join()
        fh.write("Transmitted Packet: " + tx_pkt.show2(dump=True) + "\n")
        try:
            pkt = q.get(timeout=1)
            fh.write("Received Packet: " + pkt.show2(dump=True) + "\n")
            if pkt[0][1].proto != 1:
                fh.write("IP Protocol is not ICMP\n")
                self.packet_error = True
            if pkt[0][2].type != 8:
                fh.write("Incorrect Type Number\n")
                self.packet_error = True
            if pkt[0][2].code != 0:
                fh.write("Incorrect Code Number\n")
                self.packet_error = True
            if pkt[0][2].id != ipv6_udp_or_tcp_map_port:
                fh.write("ICMP ID Incorrect\n")
                self.packet_error = True
        except Empty:
            fh.write("ICMP Echo Request Not Received\n")
            self.packet_error = True
        if self.packet_error:
            print("IPv6 -> IPv4 Echo Request: FAIL\n")
        if not self.packet_error:
            print("IPv6 -> IPv4 Echo Request: PASS\n")
        fh.close()

    def upstream_echo_reply(self):
        self.m_finished = False
        self.packet_error = False
        q = Queue()
        fh = open(dir_uuid + "/test_results.txt", "a")
        fh.write("IPv6 -> IPv4 Echo Reply:  \n")
        capture_filter = 'icmp and dst {}'.format(self.ipv4_internet_address)
        sniffer = Thread(target=self.sniffer, args=(q, capture_filter, 1))
        sniffer.daemon = True
        sniffer.start()
        capture = Thread(target=self.capsniffer, args=('net 198.18.0.0/24 or net 2001:db8:ffff:ff00::/64', 10, dir_uuid + "/6to4_echo_reply.pcap" ))
        capture.daemon = True
        capture.start()
        while not self.m_finished:
            ip = IPv6(src=self.ipv6_cpe_address, dst=self.ipv6_map_address)
            icmp = ICMPv6EchoReply()
            icmp.id = self.ipv6_udp_or_tcp_map_port
            payload = "H" * 10
            tx_pkt = ip / icmp / payload
            send(tx_pkt, iface=self.scapy_interface, verbose=False)
        sniffer.join()
        capture.join()
        fh.write("Transmitted Packet: " + tx_pkt.show2(dump=True) + "\n")
        try:
            pkt = q.get(timeout=1)
            fh.write("Received Packet: " + pkt.show2(dump=True) + "\n")
            self.v4_address_check(pkt)
            if pkt[0][1].proto != 1:
                fh.write("Packet is not ICMP\n")
                self.packet_error = True
            if pkt[0][2].type != 0:
                fh.write("Incorrect ICMP Type\n")
                self.packet_error = True
            if pkt[0][2].code != 0:
                fh.write("Incorrect ICMP Code\n")
                self.packet_error = True
            if pkt[0][2].id != ipv6_udp_or_tcp_map_port:
                fh.write("Incorrect ICMP ID\n")
                self.packet_error = True           
        except Empty:
            fh.write("ICMPv4 Packet not received\n")
            self.packet_error = True
        if self.packet_error:
            print("IPv6 -> IPv4 Echo Reply: FAIL\n")
        if not self.packet_error:
            print ("IPv6 -> IPv4 Echo Reply: PASS\n")
        fh.close()

    def downstream_echo_request(self):
        self.m_finished = False
        self.packet_error = False
        q = Queue()
        fh = open(dir_uuid + "/test_results.txt", "a")
        fh.write("IPv4 -> IPv6 Echo Request:  \n")
        capture_filter = 'icmp6 and dst {}'.format(self.ipv6_cpe_address)
        sniffer = Thread(target=self.sniffer, args=(q, capture_filter, 1))
        sniffer.daemon = True
        sniffer.start()
        capture = Thread(target=self.capsniffer, args=('net 198.18.0.0/24 or net 2001:db8:ffff:ff00::/64', 10, dir_uuid + "/4to6_echo_request.pcap" ))
        capture.daemon = True
        capture.start()
        while not self.m_finished:
            ip = IP(src=self.ipv4_internet_address, dst=self.ipv4_map_address)
            icmp = ICMP()
            icmp.type = 8
            icmp.id = self.ipv6_udp_or_tcp_map_port
            payload = "H" * 10
            tx_pkt = ip / icmp / payload
            send(tx_pkt, iface=self.scapy_interface, verbose=False)
        sniffer.join()
        capture.join()
        fh.write("Transmitted Packet: " + tx_pkt.show2(dump=True) + "\n")
        try:
            pkt = q.get(timeout=1)
            fh.write("Received Packet: " + pkt.show2(dump=True) + "\n")
            self.v6_address_check(pkt)
            if pkt[0][1].nh != 58:
                fh.write("Packet is not ICMP\n")
                self.packet_error = True
            if pkt[0][2].type != 128:
                fh.write("Incorrect ICMPv6 Type\n")
                self.packet_error = True
            if pkt[0][2].code != 0:
                fh.write("Incorrect ICMP Code\n")
                self.packet_error = True
            if pkt[0][2].id != ipv6_udp_or_tcp_map_port:
                fh.write("Incorrect ICMP ID\n")
                self.packet_error = True   
        except Empty:
            fh.write("ICMPv4 Echo Request Not Received \n")
            self.packet_error = True
        if self.packet_error:
            print("IPv4 -> IPv6 Echo Request: FAIL\n")
        if not self.packet_error:
            print("IPv4 -> IPv6 Echo Request: PASS\n")
        fh.close()

    def downstream_echo_reply(self):
        self.m_finished = False
        self.packet_error = False
        q = Queue()
        fh = open(dir_uuid + "/test_results.txt", "a")
        fh.write("IPv4 -> IPv6 Echo Reply:  \n")
        capture_filter = 'icmp6 and dst {}'.format(self.ipv6_cpe_address)
        sniffer = Thread(target=self.sniffer, args=(q, capture_filter, 1))
        sniffer.daemon = True
        sniffer.start()
        capture = Thread(target=self.capsniffer, args=('net 198.18.0.0/24 or net 2001:db8:ffff:ff00::/64', 10, dir_uuid + "/4to6_echo_reply.pcap" ))
        capture.daemon = True
        capture.start()
        while not self.m_finished:
            ip = IP(src=self.ipv4_internet_address, dst=self.ipv4_map_address)
            icmp = ICMP()
            icmp.type = 0
            icmp.id = self.ipv6_udp_or_tcp_map_port
            payload = "H" * 10
            tx_pkt = ip / icmp / payload
            send(tx_pkt, iface=self.scapy_interface, verbose=False)
        sniffer.join()
        capture.join()
        fh.write("Transmitted Packet: " + tx_pkt.show2(dump=True) + "\n")
        try:
            pkt = q.get(timeout=1)
            fh.write("Received Packet: " + pkt.show2(dump=True) + "\n")
            self.v6_address_check(pkt)
            if pkt[0][1].nh != 58:
                fh.write("Packet is not ICMP\n")
                self.packet_error = True
            if pkt[0][2].type != 129:
                fh.write("Incorrect ICMPv6 Type\n")
                self.packet_error = True
            if pkt[0][2].code != 0:
                fh.write("Incorrect ICMP Code\n")
                self.packet_error = True
            if pkt[0][2].id != ipv6_udp_or_tcp_map_port:
                fh.write("Incorrect ICMP ID\n")
                self.packet_error = True  
        except Empty:
            fh.write("ICMPv4 Echo Reply Not Received \n")
            self.packet_error = True
        if self.packet_error:
            print("IPv4 -> IPv6 Echo Reply: FAIL\n")
        if not self.packet_error:
            print("IPv4 -> IPv6 Echo Reply: PASS\n")
        fh.close()

    # This simulates an internet side node with a reduced MTU sending Need Frag message back to the MAP CPE
    # The BR should translate
    def downstream_icmp_frag_required(self):
        self.m_finished = False
        self.packet_error = False
        fh = open(dir_uuid + "/test_results.txt", "a")
        fh.write("IPv4 -> IPv6 Translated ICMP Frag Required \n")
        q = Queue()
        capture_filter = 'icmp6 and dst {}'.format(self.ipv6_cpe_address)
        sniffer = Thread(target=self.sniffer, args=(q, capture_filter, 1))
        sniffer.daemon = True
        sniffer.start()
        capture = Thread(target=self.capsniffer, args=('net 198.18.0.0/24 or net 2001:db8:ffff:ff00::/64', 10, dir_uuid + "/4to6_icmp_frag_required.pcap" ))
        capture.daemon = True
        capture.start()
        while not self.m_finished:
            ip = IP(src=self.ipv4_local_address, dst=self.ipv4_map_address)
            icmp = ICMP(type=3, code=4, nexthopmtu = 1300)
            ip2 = IP(src=self.ipv4_map_address, dst=self.ipv4_internet_address)
            udp = UDP(sport=self.ipv4_udp_or_tcp_map_port, dport=self.ipv4_udp_or_tcp_internet_port)
            payload = "a" * 64
            tx_pkt = ip / icmp / ip2 / udp / payload
            send(tx_pkt, iface=self.scapy_interface, verbose=False)
        sniffer.join()
        capture.join()
        fh.write("Transmitted Packet: " + tx_pkt.show2(dump=True) + "\n")
        try:
            pkt = q.get(timeout=1)
            fh.write("Received Packet: " + pkt.show2(dump=True) + "\n")
            if pkt[0][2].type != 2 or pkt[0][2].code != 0:
                self.packet_error = True
                fh.write("ICMPv6 is not Packet too Big \n")
            if pkt[0][2].mtu != 1320:
                self.packet_error = True
                fh.write("Next Hop MTU is not set to 1300\n")
            if self.packet_error:
                print("IPv4 -> IPv6 Translated ICMP Frag Required: FAIL\n")
            if not self.packet_error:
                print("IPv4 -> IPv6 Translated ICMP Frag Required: PASS\n")
            fh.close()
        except Empty:
            print("IPv4 -> IPv6 Translated ICMP Frag Required: FAIL\n")
            fh.write("No ICMPv6 Packet Received\n")
            fh.close()
            return

    # Packet is sent with DF=1 and larger than domain MTU.
    # The BR should respond with an Dest Unreachable, Fraq Needed and DF set
    def downstream_br_udp_frag_required(self):
        self.m_finished = False
        self.packet_error = False
        q = Queue()
        fh = open(dir_uuid + "/test_results.txt", "a")
        fh.write("IPv4 -> IPv6 UDP Frag Required and DF Set   \n")
        capture_filter = 'icmp and dst {}'.format(self.ipv4_internet_address)
        sniffer = Thread(target=self.sniffer, args=(q, capture_filter, 1))
        sniffer.daemon = True
        sniffer.start()
        capture = Thread(target=self.capsniffer, args=('net 198.18.0.0/24 or net 2001:db8:ffff:ff00::/64 or net 192.0.2.0/24', 10, dir_uuid + "/4to4_br_udp_frag_required.pcap" ))
        capture.daemon = True
        capture.start()
        while not self.m_finished:
            ip = IP(src=self.ipv4_internet_address, dst=self.ipv4_map_address, flags='DF')
            udp = UDP(sport=self.ipv4_udp_or_tcp_internet_port, dport=self.ipv4_udp_or_tcp_map_port)
            payload = "a" * 1500
            tx_pkt = ip / udp / payload
            send(tx_pkt, iface=self.scapy_interface, verbose=False)
        sniffer.join()
        capture.join()
        fh.write("Transmitted Packet: " + tx_pkt.show2(dump=True) + "\n")
        try:
            pkt = q.get(timeout=1)
            fh.write("Received Packet: " + pkt.show2(dump=True) + "\n")
            if pkt[0][2].type != 3 or pkt[0][2].code != 4:
                self.packet_error = True
                fh.write("ICMP packet received is not Frag Needed and DF Set\n")
            if pkt[0][2].nexthopmtu != 1480:
                self.packet_error = True
                fh.write("Next Hop MTU is not set to 1480\n")
        except Empty:
            print("Downstream UDP Packet: FAIL\n")
            fh.write("No ICMP Packet Received\n")
        if self.packet_error:
                print("IPv4 -> IPv6 UDP Frag Required and DF Set: FAIL\n")
        if not self.packet_error:
            print("IPv4 -> IPv6 UDP Frag Required and DF Set: PASS\n")
        fh.close()


    # This simulates an IPv6 node beyond the BR having a reduced MTU and signally PMTUD back towards the internet
    # This should never really happen as MTU inside the MAP domain should be "well managed", but we test anyways
    def upstream_packet_too_big(self):
        self.m_finished = False
        self.packet_error = False
        fh = open(dir_uuid + "/test_results.txt", "a")
        fh.write("ICMPv6 packet too big -> ICMP Frag Required \n")
        q = Queue()
        capture_filter = 'icmp and dst {}'.format(self.ipv4_internet_address)
        sniffer = Thread(target=self.sniffer, args=(q, capture_filter, 1))
        sniffer.daemon = True
        sniffer.start()
        capture = Thread(target=self.capsniffer, args=('net 198.18.0.0/24 or net 2001:db8:ffff:ff00::/64 or net 192.0.2.0/24', 10, dir_uuid + "/6to4_icmp6_packet_too_big.pcap" ))
        capture.daemon = True
        capture.start()
        while not self.m_finished:
            ip = IPv6(src=self.ipv6_local_address, dst=self.ipv6_map_address)
            icmp = ICMPv6PacketTooBig()
            icmp.mtu = 1280
            ip2 = IPv6(src=self.ipv6_map_address, dst=self.ipv6_cpe_address)
            udp = UDP(sport=self.ipv6_udp_or_tcp_internet_port, dport=self.ipv6_udp_or_tcp_map_port)
            payload = "H" * 64
            tx_pkt = ip / icmp / ip2 / udp / payload
            send(tx_pkt, iface=self.scapy_interface, verbose=False)
        sniffer.join()
        capture.join()
        fh.write("Transmitted Packet: " + tx_pkt.show2(dump=True) + "\n")
        try:
            pkt = q.get(timeout=1)
            fh.write("Received Packet: " + pkt.show2(dump=True) + "\n")
            if pkt[0][2].type != 3 or pkt[0][2].code != 4:
                self.packet_error = True
                fh.write("ICMPv6 is not Packet too Big \n")
            if pkt[0][2].mtu != 1300:
                self.packet_error = True
                fh.write("Next Hop MTU is not set to 1300\n")
            if self.packet_error:
                print("ICMPv6 packet too big -> ICMP Frag Required: FAIL\n")
            if not self.packet_error:
                print("ICMPv6 packet too big -> ICMP Frag Required: PASS\n")
            fh.close()
        except Empty:
            print("ICMPv6 packet too big -> ICMP Frag Required: FAIL\n")
            fh.write("No ICMPv6 Packet Received\n")
            fh.close()
            return

    def downstream_dest_unreachable(self):
        codes = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]
        for code in codes:
            self.m_finished = False
            self.packet_error = False
            q = Queue()
            fh = open(dir_uuid + "/test_results.txt", "a")
            fh.write("IPv4 -> IPv6 Destination Unreachable  \n")
            capture_filter = 'icmp6 and dst {}'.format(self.ipv6_cpe_address)
            sniffer = Thread(target=self.sniffer, args=(q, capture_filter, 1))
            sniffer.daemon = True
            sniffer.start()
            capture = Thread(target=self.capsniffer, args=('net 198.18.0.0/24 or net 2001:db8:ffff:ff00::/64', 10, dir_uuid + "/4to6_icmp_dest_unreach_code_" + str(code)+ ".pcap" ))
            capture.daemon = True
            capture.start()
            while not self.m_finished:
                ip = IP(src=self.ipv4_local_address, dst=self.ipv4_map_address)
                icmp = ICMP(type=3, code=code)
                ip2 = IP(src=self.ipv4_map_address, dst=self.ipv4_internet_address)
                udp = UDP(sport=self.ipv4_udp_or_tcp_map_port, dport=self.ipv4_udp_or_tcp_internet_port)
                payload = "a" * 82
                tx_pkt = ip / icmp / ip2 / udp / payload
                send(tx_pkt, iface=self.scapy_interface, verbose=False)
                sleep(.5)
            sniffer.join()
            capture.join()
            fh.write("Transmitted Packet: " + tx_pkt.show2(dump=True) + "\n")
            try:
                pkt = q.get(timeout=1)
                fh.write("Received Packet: " + pkt.show2(dump=True) + "\n")
                if code == 0 and pkt[0][2].code == 0:
                    fh.write("ICMP Type 3, Code 0 translated to ICMPv6 Type 1, Code 0\n")
                    print("IPv4 -> IPv6 Dest Unreachable Code 0 Translate: PASS\n")
                if code == 0 and pkt[0][2].code != 0:
                    fh.write("ICMP Type 3, Code 0 NOT translated to ICMPv6 Type 1, Code 0\n")
                    print("IPv4 -> IPv6 Dest Unreachable Code 0 Translate: FAIL\n\n")
                if code == 1 and pkt[0][2].code == 0:
                    fh.write("ICMP Type 3, Code 1 translated to ICMPv6 Type 1, Code 0")
                    print("IPv4 -> IPv6 Dest Unreachable Code 1 Translate: PASS\n")
                if code == 1 and pkt[0][2].code != 0:
                    fh.write("ICMP Type 3, Code 1 NOT translated to ICMPv6 Type 1, Code 0\n")
                    print("IPv4 -> IPv6 Dest Unreachable Code 1 Translate: FAIL\n")
                if code == 3 and pkt[0][2].code == 4:
                    fh.write("ICMP Type 3, Code 3 translated to ICMPv6 Type 4, Code 0\n")
                    print("IPv4 -> IPv6 Dest Unreachable Code 3 Translate: PASS\n")
                if code == 3 and pkt[0][2].code != 4:
                    fh.write("ICMP Type 3, Code 3 NOT translated to ICMPv6 Type 1, Code 0\n")
                    print("IPv4 -> IPv6 Dest Unreachable Code 3 Translate: FAIL\n")
                if code == 5 and pkt[0][2].code == 0:
                    fh.write("ICMP Type 3, Code 5 translated to ICMPv6 Type 1, Code 0\n")
                    print("IPv4 -> IPv6 Dest Unreachable Code 5 Translate: PASS\n")
                if code == 5 and pkt[0][2].code != 0:
                    fh.write("ICMP Type 3, Code 5 NOT translated to ICMPv6 Type 1, Code 0\n")
                    print("IPv4 -> IPv6 Dest Unreachable Code 5 Translate: FAIL")
                if code == 6 and pkt[0][2].code == 0:
                    fh.write("ICMP Type 3, Code 6 translated to ICMPv6 Type 1, Code 0\n")
                    print("IPv4 -> IPv6 Dest Unreachable Code 6 Translate: PASS\n")
                if code == 6 and pkt[0][2].code != 0:
                    fh.write("ICMP Type 3, Code 6 NOT translated to ICMPv6 Type 1, Code 0\n")
                    print("IPv4 -> IPv6 Dest Unreachable Code 6 Translate: FAIL\n")
                if code == 7 and pkt[0][2].code == 0:
                    fh.write("ICMP Type 3, Code 7 translated to ICMPv6 Type 1, Code 0\n")
                    print("IPv4 -> IPv6 Dest Unreachable Code 7 Translate: PASS\n")
                if code == 7 and pkt[0][2].code != 0:
                    fh.write("ICMP Type 7, Code 5 NOT translated to ICMPv6 Type 1, Code 0\n")
                    print("IPv4 -> IPv6 Dest Unreachable Code 7 Translate: FAIL\n")
                if code == 8 and pkt[0][2].code == 0:
                    fh.write("ICMP Type 3, Code 8 translated to ICMPv6 Type 1, Code 0\n")
                    print("IPv4 -> IPv6 Dest Unreachable Code 8 Translate: PASS\n")
                if code == 8 and pkt[0][2].code != 0:
                    fh.write("ICMP Type 3, Code 8 NOT translated to ICMPv6 Type 1, Code 0\n")
                    print("IPv4 -> IPv6 Dest Unreachable Code 8 Translate: FAIL\n")   
                if code == 9 and pkt[0][2].code == 1:
                    fh.write("ICMP Type 3, Code 9 translated to ICMPv6 Type 1, Code 1\n")
                    print("IPv4 -> IPv6 Dest Unreachable Code 9 Translate: PASS\n")
                if code == 9 and pkt[0][2].code != 1:
                    fh.write("ICMP Type 3, Code 9 NOT translated to ICMPv6 Type 1, Code 1\n")
                    print("IPv4 -> IPv6 Dest Unreachable Code 9 Translate: FAIL\n")  
                if code == 10 and pkt[0][2].code == 1:
                    fh.write("ICMP Type 3, Code 10 translated to ICMPv6 Type 1, Code 1\n")
                    print("IPv4 -> IPv6 Dest Unreachable Code 10 Translate: PASS\n")
                if code == 10 and pkt[0][2].code != 1:
                    fh.write("ICMP Type 3, Code 10 NOT translated to ICMPv6 Type 1, Code 1\n")
                    print("IPv4 -> IPv6 Dest Unreachable Code 10 Translate: FAIL\n")
                if code == 11 and pkt[0][2].code == 0:
                    fh.write("ICMP Type 3, Code 11 translated to ICMPv6 Type 1, Code 0\n")
                    print("IPv4 -> IPv6 Dest Unreachable Code 11 Translate: PASS\n")
                if code == 11 and pkt[0][2].code != 0:
                    fh.write("ICMP Type 3, Code 11 NOT translated to ICMPv6 Type 1, Code 0\n")
                    print("IPv4 -> IPv6 Dest Unreachable Code 11 Translate: FAIL\n")
                if code == 12 and pkt[0][2].code == 0:
                    fh.write("ICMP Type 3, Code 12 translated to ICMPv6 Type 1, Code 0\n")
                    print("IPv4 -> IPv6 Dest Unreachable Code 12 Translate: PASS\n")
                if code == 12 and pkt[0][2].code != 0:
                    fh.write("ICMP Type 3, Code 12 NOT translated to ICMPv6 Type 1, Code 0\n")
                    print("IPv4 -> IPv6 Dest Unreachable Code 12 Translate: FAIL\n")
                if code == 13 and pkt[0][2].code == 1:
                    fh.write("ICMP Type 3, Code 13 translated to ICMPv6 Type 1, Code 1\n")
                    print("IPv4 -> IPv6 Dest Unreachable Code 13 Translate: PASS\n")
                if code == 13 and pkt[0][2].code != 1:
                    fh.write("ICMP Type 3, Code 13 NOT translated to ICMPv6 Type 1, Code 1\n")
                    print("IPv4 -> IPv6 Dest Unreachable Code 13 Translate: FAIL\n")
                if code == 15 and pkt[0][2].code == 1:
                    fh.write("ICMP Type 3, Code 15 translated to ICMPv6 Type 1, Code 1\n")
                    print("IPv4 -> IPv6 Dest Unreachable Code 15 Translate: PASS\n")
                if code == 15 and pkt[0][2].code != 1:
                    fh.write("ICMP Type 3, Code 15 NOT translated to ICMPv6 Type 1, Code 1\n")
                    print("IPv4 -> IPv6 Dest Unreachable Code 15 Translate: FAIL\n")
            except Empty:
                if code == 14:
                    fh.write("ICMP Type 3, Code 15 - No packet received\n")
                    print("IPv4 -> IPv6 Dest Unreachable Code 14 Translate: PASS\n")
                else:
                    fh.write("No packet recieved for IPv4 -> IPv6 Dest\n")
                    print("IPv4 -> IPv6 Dest Unreachable Code " + str(code) + " Translate: FAIL\n")
                return
            fh.close() 

    def upsteam_dest_unreachable(self):
        codes = [0,1,2,3,4,5]
        for code in codes:
            self.m_finished = False
            self.packet_error = False
            q = Queue()
            fh = open(dir_uuid + "/test_results.txt", "a")
            fh.write("IPv6 -> IPv4 Destination Unreachable  \n")
            capture_filter = 'icmp and dst {}'.format(self.ipv4_internet_address)
            sniffer = Thread(target=self.sniffer, args=(q, capture_filter, 1))
            sniffer.daemon = True
            sniffer.start()
            capture = Thread(target=self.capsniffer, args=('net 198.18.0.0/24 or net 2001:db8:ffff:ff00::/64', 10, dir_uuid + "/6to4_icmp_dest_unreach_code_" + str(code)+ ".pcap" ))
            capture.daemon = True
            capture.start()
            while not self.m_finished:
                ip = IPv6(src=self.ipv6_local_address, dst=self.ipv6_map_address)
                icmp6 = ICMPv6DestUnreach(type=1, code=code)
                ip2 = IPv6(src=self.ipv6_map_address, dst=self.ipv6_cpe_address)
                udp = UDP(sport=self.ipv6_udp_or_tcp_internet_port, dport=self.ipv6_udp_or_tcp_map_port)
                payload = "a" * 82
                tx_pkt = ip / icmp6 / ip2 / udp / payload
                send(tx_pkt, iface=self.scapy_interface, verbose=False)
                sleep(.5)
            sniffer.join()
            capture.join()
            fh.write("Transmitted Packet: " + tx_pkt.show2(dump=True) + "\n")
            try:
                pkt = q.get(timeout=1)
                fh.write("Received Packet: " + pkt.show2(dump=True) + "\n")
                if code == 0 and pkt[0][2].code == 1:
                    fh.write("ICMPv6 Type 1, Code 0 translated to ICMP Type 3, Code 1\n")
                    print("IPv6 -> IPv4 Dest Unreachable, Code 0 Translate:  PASS\n")
                if code == 0 and pkt[0][2].code != 1:
                    fh.write("ICMP Type 3, Code 0 NOT translated to ICMP Type 3, Code 1\n")
                    print("IPv6 -> IPv4 Dest Unreachable, Code 0 Translate:  FAIL\n\n")
                if code == 1 and pkt[0][2].code == 10:
                    fh.write("ICMP Type 3, Code 1 translated to ICMP Type 3, Code 10")
                    print("IPv6 -> IPv4 Dest Unreachable, Code 1 Translate:  PASS\n")
                if code == 1 and pkt[0][2].code != 10:
                    fh.write("ICMP Type 3, Code 1 NOT translated to ICMP Type 3, Code 10\n")
                    print("IPv6 -> IPv4 Dest Unreachable, Code 1 Translate:  FAIL\n")
                if code == 2 and pkt[0][2].code == 1:
                    fh.write("ICMP Type 3, Code 1 translated to ICMP Type 3, Code 1")
                    print("IPv6 -> IPv4 Dest Unreachable, Code 2 Translate:  PASS\n")
                if code == 2 and pkt[0][2].code != 1:
                    fh.write("ICMP Type 3, Code 1 NOT translated to ICMP Type 3, Code 1\n")
                    print("IPv6 -> IPv4 Dest Unreachable, Code 2 Translate:  FAIL\n")
                if code == 3 and pkt[0][2].code == 1:
                    fh.write("ICMP Type 3, Code 3 translated to ICMP Type 3, Code 1\n")
                    print("IPv6 -> IPv4 Dest Unreachable, Code 3 Translate:  PASS\n")
                if code == 3 and pkt[0][2].code != 1:
                    fh.write("ICMP Type 3, Code 3 NOT translated to ICMP Type 3, Code 1\n")
                    print("IPv6 -> IPv4 Dest Unreachable, Code 3 Translate:  FAIL\n")
                if code == 4 and pkt[0][2].code == 3:
                    fh.write("ICMP Type 3, Code 5 translated to ICMP Type 3, Code 3\n")
                    print("IPv6 -> IPv4 Dest Unreachable, Code 4 Translate: PASS\n")
                if code == 4 and pkt[0][2].code != 3:
                    fh.write("ICMP Type 3, Code 5 NOT translated to ICMP Type 3, Code 3\n")
                    print("IPv6 -> IPv4 Dest Unreachable, Code 4 Translate:  FAIL")
            except Empty:
                if code == 5:
                    fh.write("ICMPv6 Type 1, Code 5 - No packet received\n")
                    print("IPv6 -> IPv4 Dest Unreachable, Code 5 Translate: PASS\n")
                else:
                    fh.write("No packet recieved for IPv4 -> IPv6 Dest\n")
                    print("IPv6 -> IPv4 Dest Unreachable Code " + str(code) + " Translate: FAIL\n")
            fh.close() 


    # This will send an upstream packet with the wrong IPv4 address embedded in bit positions 72-103
    # The BR should either drop the packet, or rewrite the source IPv4 to the prefix that matches the source IPv4 address
    def upstream_spoof_wrong_embedded_ip_host(self):
        self.m_finished = False
        self.packet_error = False
        q = Queue()
        fh = open(dir_uuid + "/test_results.txt", "a")
        fh.write("IPv6 -> IPv4 Spoofed IPv4 Source Address  \n")
        capture_filter = 'udp and src 192.0.2.28'
        sniffer = Thread(target=self.sniffer, args=(q, capture_filter, 1))
        sniffer.daemon = True
        sniffer.start()
        capture = Thread(target=self.capsniffer, args=('net 198.18.0.0/24 or net 2001:db8:ffff:ff00::/64', 10, dir_uuid + "/6to4_spoof_wrong_ip_host.pcap" ))
        capture.daemon = True
        capture.start()
        while not self.m_finished:
            ip = IPv6(src="2001:db8:f0:c30:0:c612:1c:3" , dst=self.ipv6_map_address)
            udp = UDP(sport=self.ipv6_udp_or_tcp_map_port, dport=self.ipv6_udp_or_tcp_internet_port)
            payload = "a" * 82
            tx_pkt = ip / udp / payload
            send(tx_pkt, iface=self.scapy_interface, verbose=False)
            sleep(.5)
        sniffer.join()
        capture.join()
        fh.write("Transmitted Packet: " + tx_pkt.show2(dump=True) + "\n")
        try:
            pkt = q.get(timeout=1)
            if pkt[0][1].src != self.ipv4_map_address:
                fh.write("Packet translated normally when it SHOULD be dropped\n")
                fh.write("Received Packet: " + pkt.show2(dump=True) + "\n")
                self.packet_error = True
        except Empty:
            fh.write("No packet recieved for IPv6 -> IPv4 Spoofed IPv4 Source Address\n")
        if self.packet_error:
            print("IPv6 -> IPv4 Spoofed IPv4 Source Address: FAIL\n")
        if not self.packet_error:
            print("IPv6 -> IPv4 Spoofed IPv4 Source Address: PASS\n")
        fh.close()

    # This will send an upstream packet with the wrong IPv4 prefix embedded in bit positions 72-103
    # The BR should either drop the packet, or rewrite the source IPv4 to the prefix that matches the source IPv4 address
    def upstream_spoof_wrong_embedded_ip_prefix(self):
        self.m_finished = False
        self.packet_error = False
        q = Queue()
        fh = open(dir_uuid + "/test_results.txt", "a")
        fh.write("IPv6 -> IPv4 Spoofed IPv4 Source Prefix  \n")
        capture_filter = 'udp and src net 10.0.0.0/8'
        sniffer = Thread(target=self.sniffer, args=(q, capture_filter, 1))
        sniffer.daemon = True
        sniffer.start()
        capture = Thread(target=self.capsniffer, args=('net 198.18.0.0/24 or net 2001:db8:ffff:ff00::/64', 10, dir_uuid + "/6to4_spoof_wrong_ip_prefix.pcap" ))
        capture.daemon = True
        capture.start()
        while not self.m_finished:
            ip = IPv6(src="2001:db8:f0:c30:0:a00:c:3" , dst=self.ipv6_map_address)
            udp = UDP(sport=self.ipv6_udp_or_tcp_map_port, dport=self.ipv6_udp_or_tcp_internet_port)
            payload = "a" * 82
            tx_pkt = ip / udp / payload
            send(tx_pkt, iface=self.scapy_interface, verbose=False)
            sleep(.5)
        sniffer.join()
        capture.join()
        fh.write("Transmitted Packet: " + tx_pkt.show2(dump=True) + "\n")
        try:
            pkt = q.get(timeout=1)
            if pkt[0][1].src != self.ipv4_map_address:
                fh.write("Packet translated normally when it SHOULD be dropped\n")
                fh.write("Received Packet: " + pkt.show2(dump=True) + "\n")
                self.packet_error = True
        except Empty:
            fh.write("No packet recieved for IPv6 -> IPv4 Spoofed IPv4 Source Prefix")
        if self.packet_error:
            print("IPv6 -> IPv4 Spoofed IPv4 Source Prefix: FAIL\n")
        if not self.packet_error:
            print("IPv6 -> IPv4 Spoofed IPv4 Source Prefix: PASS\n")
        fh.close()

    def upstream_spoof_wrong_ipv6_psid(self):
        self.m_finished = False
        self.packet_error = False
        q = Queue()
        fh = open(dir_uuid + "/test_results.txt", "a")
        fh.write("IPv6 -> IPv4 Spoofed IPv6 PSID field  \n")
        capture_filter = 'udp and dst {}'.format(self.ipv4_internet_address)
        sniffer = Thread(target=self.sniffer, args=(q, capture_filter, 1))
        sniffer.daemon = True
        sniffer.start()
        capture = Thread(target=self.capsniffer, args=('net 198.18.0.0/24 or net 2001:db8:ffff:ff00::/64', 10, dir_uuid + "/6to4_spoof_wrong_ipv6_psid.pcap" ))
        capture.daemon = True
        capture.start()
        while not self.m_finished:
            ip = IPv6(src="2001:db8:f0:c30:0:c612:c:4" , dst=self.ipv6_map_address)
            udp = UDP(sport=self.ipv6_udp_or_tcp_map_port, dport=self.ipv6_udp_or_tcp_internet_port)
            payload = "a" * 82
            tx_pkt = ip / udp / payload
            send(tx_pkt, iface=self.scapy_interface, verbose=False)
            sleep(.5)
        sniffer.join()
        capture.join()
        fh.write("Transmitted Packet: " + tx_pkt.show2(dump=True) + "\n")
        try:
            pkt = q.get(timeout=1)
            if pkt[0][1].src != self.ipv4_map_address:
                fh.write("Packet translated normally when it SHOULD be dropped\n")
                fh.write("Received Packet: " + pkt.show2(dump=True) + "\n")
                self.packet_error = True
        except Empty:
            fh.write("No packet recieved for IPv6 -> IPv4 Spoofed IPv6 PSID field")
            fh.close()
        if self.packet_error:
            print("IPv6 -> IPv4 Spoofed IPv6 PSID field: FAIL\n")
        if not self.packet_error:
            print("IPv6 -> IPv4 Spoofed IPv6 PSID field: PASS\n")
        fh.close()

    def upstream_spoof_wrong_subnet(self):
        self.m_finished = False
        self.packet_error = False
        q = Queue()
        fh = open(dir_uuid + "/test_results.txt", "a")
        fh.write("IPv6 -> IPv4 Spoofed IPv6 PSID field  \n")
        capture_filter = 'udp and dst {}'.format(self.ipv4_internet_address)
        sniffer = Thread(target=self.sniffer, args=(q, capture_filter, 1))
        sniffer.daemon = True
        sniffer.start()
        capture = Thread(target=self.capsniffer, args=('net 198.18.0.0/24 or net 2001:db8:ffff:ff00::/64', 10, dir_uuid + "/6to4_spoof_wrong_ipv6_psid.pcap" ))
        capture.daemon = True
        capture.start()
        while not self.m_finished:
            ip = IPv6(src="2001:db8:f1:c30:0:c612:c:3" , dst=self.ipv6_map_address)
            udp = UDP(sport=self.ipv6_udp_or_tcp_map_port, dport=self.ipv6_udp_or_tcp_internet_port)
            payload = "a" * 82
            tx_pkt = ip / udp / payload
            send(tx_pkt, iface=self.scapy_interface, verbose=False)
            sleep(.5)
        sniffer.join()
        capture.join()
        fh.write("Transmitted Packet: " + tx_pkt.show2(dump=True) + "\n")
        try:
            pkt = q.get(timeout=1)
            if pkt[0][1].src != self.ipv4_map_address:
                fh.write("Packet translated normally when it SHOULD be dropped\n")
                fh.write("Received Packet: " + pkt.show2(dump=True) + "\n")
                self.packet_error = True
        except Empty:
            fh.write("No packet recieved for IPv6 -> IPv4 Spoofed IPv6 PSID field")
        if self.packet_error:
            print("IPv6 -> IPv4 Spoofed IPv6 PSID field: FAIL\n")
        if not self.packet_error:
            print("IPv6 -> IPv4 Spoofed IPv6 PSID field: PASS\n")
        fh.close()

    def upstream_spoof_wrong_port_psid(self):
        self.m_finished = False
        self.packet_error = False
        q = Queue()
        fh = open(dir_uuid + "/test_results.txt", "a")
        fh.write("IPv6 -> IPv4 Spoofed IPv6 PSID in Port  \n")
        capture_filter = 'udp and dst {}'.format(self.ipv4_internet_address)
        sniffer = Thread(target=self.sniffer, args=(q, capture_filter, 1))
        sniffer.daemon = True
        sniffer.start()
        capture = Thread(target=self.capsniffer, args=('net 198.18.0.0/24 or net 2001:db8:ffff:ff00::/64', 10, dir_uuid + "/6to4_spoof_wrong_ipv6_port.pcap" ))
        capture.daemon = True
        capture.start()
        while not self.m_finished:
            ip = IPv6(src=self.ipv6_cpe_address , dst=self.ipv6_map_address)
            udp = UDP(sport=16862, dport=self.ipv6_udp_or_tcp_internet_port)
            payload = "a" * 82
            tx_pkt = ip / udp / payload
            send(tx_pkt, iface=self.scapy_interface, verbose=False)
            sleep(.5)
        sniffer.join()
        capture.join()
        fh.write("Transmitted Packet: " + tx_pkt.show2(dump=True) + "\n")
        try:
            pkt = q.get(timeout=1)
            if pkt[0][1].src != self.ipv4_map_address:
                fh.write("Packet translated normally when it SHOULD be dropped\n")
                fh.write("Received Packet: " + pkt.show2(dump=True) + "\n")
                self.packet_error = True
        except Empty:
            fh.write("No packet recieved for IPv6 -> IPv4 Spoofed IPv6 port PSID")
        if self.packet_error:
            print("IPv6 -> IPv4 Spoofed IPv6 port PSID: FAIL\n")
        if not self.packet_error:
            print("IPv6 -> IPv4 Spoofed IPv6 port PSID: PASS\n")
        fh.close()

    def upstream_map_to_map_same_rule(self):
        self.m_finished = False
        self.packet_error = False
        q = Queue()
        fh = open(dir_uuid + "/test_results.txt", "a")
        fh.write("IPv6 -> IPv6 MAP to MAP - Same Rule, Different Address  \n")
        capture_filter = 'udp and src {}'.format("2001:db8:ffff:ff00:c6:1200:c00:0")
        sniffer = Thread(target=self.sniffer, args=(q, capture_filter, 1))
        sniffer.daemon = True
        sniffer.start()
        capture = Thread(target=self.capsniffer, args=('net 198.18.0.0/24 or net 2001:db8:ffff:ff00::/64', 10, dir_uuid + "/6to6_map2map_same_rule_different_address.pcap" ))
        capture.daemon = True
        capture.start()
        while not self.m_finished:
            ip = IPv6(src=self.ipv6_cpe_address , dst="2001:db8:ffff:ff00:c6:1200:10:0")
            udp = UDP(sport=self.ipv6_udp_or_tcp_map_port, dport=1025)
            payload = "a" * 82
            tx_pkt = ip / udp / payload
            send(tx_pkt, iface=self.scapy_interface, verbose=False)
            sleep(.5)
        sniffer.join()
        capture.join()
        fh.write("Transmitted Packet: " + tx_pkt.show2(dump=True) + "\n")
        try:
            pkt = q.get(timeout=1)
            if pkt[0][1].src != "2001:db8:ffff:ff00:c6:1200:c00:0" or pkt[0][1].dst != "2001:db8:f0::c612:0:0":
                fh.write("Packet not translated correctly\n")
                self.packet_error = True
        except Empty:
            fh.write("No packet recieved for IPv6 -> IPv4 Spoofed IPv6 port PSID\n")
            self.packet_error = True
        if self.packet_error:
            print("IPv6 -> IPv6 MAP to MAP - Same Rule, Same Address: FAIL\n")
        if not self.packet_error:
            print("IPv6 -> IPv6 MAP to MAP - Same Rule, Same Address: PASS\n")
        fh.close()

    def upstream_map_to_map_same_address(self):
        self.m_finished = False
        self.packet_error = False
        q = Queue()
        fh = open(dir_uuid + "/test_results.txt", "a")
        fh.write("IPv6 -> IPv6 MAP to MAP - Same Rule, Same Address  \n")
        capture_filter = 'udp and src {}'.format("2001:db8:ffff:ff00:c6:1200:c00:0")
        sniffer = Thread(target=self.sniffer, args=(q, capture_filter, 1))
        sniffer.daemon = True
        sniffer.start()
        capture = Thread(target=self.capsniffer, args=('net 198.18.0.0/24 or net 2001:db8:ffff:ff00::/64', 10, dir_uuid + "/6to6_map2map_same_rule_same_address.pcap" ))
        capture.daemon = True
        capture.start()
        while not self.m_finished:
            ip = IPv6(src=self.ipv6_cpe_address, dst="2001:db8:ffff:ff00:c6:1200:c00:0")
            udp = UDP(sport=self.ipv6_udp_or_tcp_map_port, dport=1025)
            payload = "a" * 82
            tx_pkt = ip / udp / payload
            send(tx_pkt, iface=self.scapy_interface, verbose=False)
            sleep(.5)
        sniffer.join()
        capture.join()
        fh.write("Transmitted Packet: " + tx_pkt.show2(dump=True) + "\n")
        try:
            pkt = q.get(timeout=1)
            if pkt[0][1].src != "2001:db8:ffff:ff00:c6:1200:c00:0" or pkt[0][1].dst != "2001:db8:f0:c00:0:c612:c:0":
                fh.write("Packet not translated correctly\n")
                self.packet_error = True
        except Empty:
            fh.write("No packet recieved for IPv6 -> IPv4 Spoofed IPv6 port PSID")
            self.packet_error = True
        if self.packet_error:
            print("IPv6 -> IPv6 MAP to MAP - Same Rule, Different Address: FAIL\n")
        if not self.packet_error:
            print("IPv6 -> IPv6 MAP to MAP - Same Rule, Different Address: PASS\n")
        fh.close()

    def v6_address_check(self, pkt):
        if pkt[0][IPv6].src != self.ipv6_map_address:
            self.packet_error = True
            self.comment += "\n  v6 Source Address Error"
        if pkt[0][IPv6].dst != self.ipv6_cpe_address:
            self.packet_error = True
            self.comment += "\n v6 Destination Address Error"

    def v6_port_check(self, pkt):
        if pkt[0][2].sport != self.ipv6_udp_or_tcp_internet_port:
            self.packet_error = True
            self.comment += "\n  v6 UDP Source Port Error"
        if pkt[0][2].dport != self.ipv6_udp_or_tcp_map_port:
            self.packet_error = True
            self.comment += "\n  v6 UDP Destination Port Error"

    def v4_address_check(self, pkt):
        if pkt[0][IP].src != self.ipv4_map_address:
            self.packet_error = True
            self.comment += "\n  v4 Source Address Error"
        if pkt[0][IP].dst != self.ipv4_internet_address:
            self.packet_error = True
            self.comment += "\n  v4 Destination Address Error"

    def v4_port_check(self, pkt):
        if pkt[0][2].sport != self.ipv4_udp_or_tcp_map_port:
            self.packet_error = True
            self.comment += "\n  v4 UDP Source Port Error"
        if pkt[0][2].dport != self.ipv4_udp_or_tcp_internet_port:
            self.packet_error = True
            self.comment += "\n  UDP Destination Port Error"

    def sniffer(self, q, filter, count):
        packet = sniff(count=count, iface=scapy_interface, filter=filter, prn=lambda x: q.put(x), timeout=5)
        self.m_finished = True
        return

    def capsniffer(self, filter, count, file):
        packets = sniff(count=count, iface=scapy_interface, filter=filter, timeout=5)
        wrpcap(file, packets)

# ******************** BR FUNCTIONALITY TEST CLASS - END ******************#
# ******************** MAIN FUNCTION - START ******************#
if __name__ == '__main__':
    # ******************** VARIABLES - START ******************#
    ipv4_internet_address = "192.0.2.1"
    ipv4_map_address = "198.18.0.12"
    ipv6_cpe_address = "2001:db8:f0:c30:0:c612:c:3"
    ipv6_map_address = "2001:db8:ffff:ff00:c0:2:100:0"
    ipv4_local_address = '192.168.1.2'
    ipv6_local_address = '2001:db8:eeee:eeee::6'
    ipv4_udp_or_tcp_internet_port = 65000
    ipv4_udp_or_tcp_map_port = 16606
    ipv6_udp_or_tcp_map_port = 16606
    ipv6_udp_or_tcp_internet_port = 65000
    psid_number = 3
    scapy_interface = "enp6s0"
    # ******************** VARIABLES - END ******************#

    dir_uuid = str(uuid.uuid1())
    try:
        os.mkdir(dir_uuid)
    except OSError:
        print ("Creation of the directory %s failed" % path)

    BR_obj = BRFunctionalityTest(ipv4_internet_address,
                                 ipv4_map_address,
                                 ipv6_cpe_address,
                                 ipv6_map_address,
                                 ipv4_local_address,
                                 ipv6_local_address,
                                 ipv4_udp_or_tcp_internet_port,
                                 ipv4_udp_or_tcp_map_port,
                                 ipv6_udp_or_tcp_map_port,
                                 ipv6_udp_or_tcp_internet_port,
                                 psid_number,
                                 scapy_interface,
                                 dir_uuid)
    
    ############       Normal Translations           ############
    BR_obj.downstream_udp_packet_translation()
    BR_obj.downstream_tcp_packet_translation()
    BR_obj.upstream_udp_packet_translation()
    BR_obj.upstream_tcp_packet_translation()

    ############        Antispoofing checks          ############
    BR_obj.upstream_spoof_wrong_embedded_ip_host()
    BR_obj.upstream_spoof_wrong_embedded_ip_prefix()
    BR_obj.upstream_spoof_wrong_ipv6_psid()
    BR_obj.upstream_spoof_wrong_port_psid()
    BR_obj.upstream_spoof_wrong_subnet()

    ###########     ICMP/ICMPv6 Ping Translations     ############
    BR_obj.downstream_echo_request()
    BR_obj.downstream_echo_reply()
    BR_obj.upstream_echo_request()
    BR_obj.upstream_echo_reply()

    ############ ICMP TTL Expired / Hop Limit Expired ############
    # **********       Generated by BR                ********** #
    BR_obj.downstream_br_ttl_expired()
    BR_obj.upstream_br_hop_limit_expired()
    # **********       Translated by BR               ********** #
    BR_obj.downstream_ttl_expired()
    #BR_obj.upstream_hop_limit_expired()

    ############           Fragmentation              ############
    BR_obj.downstream_br_fragmentation()
    #BR_obj.downstream_fragments()                     # Needs work
    #BR_obj.upstream_fragments()                       # Doesn't exist

    ############              PMTUD                   ############
    # **********        Generated by BR               ********** #
    BR_obj.downstream_br_udp_frag_required()
    # **********        Translated by BR              ********** #
    BR_obj.downstream_icmp_frag_required()
    #BR_obj.upstream_packet_too_big()

    ############           Additional Tests           ############
    BR_obj.downstream_outside_port()
    BR_obj.upstream_outside_port()
    BR_obj.downstream_dest_unreachable()
    #BR_obj.upsteam_dest_unreachable()
    BR_obj.upstream_map_to_map_same_rule()
    BR_obj.upstream_map_to_map_same_address()

    print("Results published to: " + dir_uuid)

# ******************** MAIN FUNCTION - END ******************#

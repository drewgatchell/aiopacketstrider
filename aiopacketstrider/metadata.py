from hashlib import md5
from typing import List, NamedTuple

from pyshark.packet.packet import Packet


class MetaHASSH(NamedTuple):
    stream: int
    protocol_client: str
    hassh: str
    protocol_server: str
    hassh_server: str
    sip: int
    sport: int
    dip: int
    dport: int


class MetaSize(NamedTuple):
    stream: int
    reverse_keystroke_size: int
    size_newkeys_next: int
    size_newkeys_next2: int
    size_newkeys_next3: int
    size_login_prompt: int


async def find_meta_hassh(pcap: List[Packet], num_packets: int, stream: int) -> MetaHASSH:
    """Finds the hassh parameters of each stream"""
    protocol_client = "not contained in pcap"
    protocol_server = "not contained in pcap"
    hassh = "not contained in pcap"
    hassh_server = "not contained in pcap"
    hassh_client_found = hassh_server_found = 0
    sport = dport = sip = dip = 0
    # Step through each packet until we find the hassh components
    for i in range(0, num_packets - 1):
        # If not in the first 50 packets, break
        if i == 50 or (hassh_client_found == 1 and hassh_server_found == 1):
            break
        packet = pcap[i]
        sip = packet.ip.src
        sport = int(packet.tcp.srcport)
        dip = packet.ip.dst
        dport = int(packet.tcp.dstport)

        # Get the Protocol names for client and server
        if "protocol" in packet.ssh.field_names:
            if sport > dport:
                protocol_client = packet.ssh.protocol
            elif dport > sport:
                protocol_server = packet.ssh.protocol
        # Find packets with Message code 20 (kexinit components)
        # but discard spurious packets
        if "message_code" in dir(packet.ssh):
            if int(packet.ssh.message_code) == 20 and "spurious" not in str(
                packet.tcp.field_names
            ):
                # If Client kexinit packet then build hassh
                if sport > dport:
                    ckex = ceacts = cmacts = ccacts = ""
                    if "kex_algorithms" in packet.ssh.field_names:
                        ckex = packet.ssh.kex_algorithms
                    if (
                        "encryption_algorithms_client_to_server"
                        in packet.ssh.field_names
                    ):
                        ceacts = packet.ssh.encryption_algorithms_client_to_server
                    if "mac_algorithms_client_to_server" in packet.ssh.field_names:
                        cmacts = packet.ssh.mac_algorithms_client_to_server
                    if (
                        "compression_algorithms_client_to_server"
                        in packet.ssh.field_names
                    ):
                        ccacts = packet.ssh.compression_algorithms_client_to_server
                    hassh_algos = ";".join([ckex, ceacts, cmacts, ccacts])
                    hassh = md5(hassh_algos.encode()).hexdigest()
                    hassh_client_found = 1

                # If Server kexinit packet then build hassh_server
                if dport > sport:
                    skex = seastc = smastc = scastc = ""
                    if "kex_algorithms" in packet.ssh.field_names:
                        skex = packet.ssh.kex_algorithms
                    if (
                        "encryption_algorithms_server_to_client"
                        in packet.ssh.field_names
                    ):
                        seastc = packet.ssh.encryption_algorithms_server_to_client
                    if "mac_algorithms_server_to_client" in packet.ssh.field_names:
                        smastc = packet.ssh.mac_algorithms_server_to_client
                    if (
                        "compression_algorithms_server_to_client"
                        in packet.ssh.field_names
                    ):
                        scastc = packet.ssh.compression_algorithms_server_to_client
                    hassh_server_algos = ";".join([skex, seastc, smastc, scastc])
                    hassh_server = md5(hassh_server_algos.encode()).hexdigest()
                    hassh_server_found = 1

    # sometimes server and client kex packet arrive out of order, so we must fix this.
    if sport < dport:
        # Store as temp variable
        sip_temp = sip
        sport_temp = sport
        dip_temp = dip
        dport_temp = dport
        # Assign the correct values
        dip = sip_temp
        sip = dip_temp
        sport = dport_temp
        dport = sport_temp

    return MetaHASSH(stream, protocol_client, hassh, protocol_server, hassh_server, sip, sport, dip, dport)


async def find_meta_size(pcap: List[Packet], num_packets: int, stream: int) -> MetaSize:
    """Finds the sizes of "tell" packets which appear just after New keys packet
    These relate the size for reverse and forward keystrokes and login prompt"""
    for i in range(0, num_packets - 4):
        if i == 50:
            break
        if "message_code" in dir(pcap[i].ssh):
            # look for 'New Keys' code packet 21
            if int(pcap[i].ssh.message_code) == 21 and "message_code" not in dir(
                pcap[i + 1].ssh
            ):
                # Session init size_newkeys_next is the packet straight after 'New Keys')
                size_newkeys_next = int(pcap[i + 1].tcp.len)
                if int(pcap[i + 1].tcp.dstport) > int(pcap[i + 1].tcp.srcport):
                    size_newkeys_next = -size_newkeys_next
                # Session init size_newkeys_next2 (should be same size as size_newkeys_next)
                size_newkeys_next2 = int(pcap[i + 2].tcp.len)
                if int(pcap[i + 2].tcp.dstport) > int(pcap[i + 2].tcp.srcport):
                    size_newkeys_next2 = -size_newkeys_next2
                # Session init size_newkeys_next3
                size_newkeys_next3 = int(pcap[i + 3].tcp.len)
                if int(pcap[i + 3].tcp.dstport) > int(pcap[i + 3].tcp.srcport):
                    size_newkeys_next3 = -size_newkeys_next3
                # The Forward password prompt size
                size_login_prompt = int(pcap[i + 4].tcp.len)
                if int(pcap[i + 4].tcp.dstport) > int(pcap[i + 4].tcp.srcport):
                    size_login_prompt = -size_login_prompt
                # Magical observation below
                reverse_keystroke_size = -(size_newkeys_next - 8 + 40)

                break

    return MetaSize(stream, reverse_keystroke_size, size_newkeys_next, size_newkeys_next2, size_newkeys_next3, size_login_prompt)

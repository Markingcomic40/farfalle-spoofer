
import logging
from scapy.layers.l2 import ARP, Ether
from scapy.all import srp

logger = logging.getLogger('NetworkScanner')


class NetworkScanner:
    """Network scanning utility to discover hosts"""

    def __init__(self, interface):
        self.interface = interface

    def scan(self, ip_range):
        logger.info(f"Scanning network range: {ip_range}")

        try:
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)

            responses, _ = srp(arp_request, timeout=3, retry=2,
                               verbose=0, iface=self.interface)

            hosts = []
            for _, received in responses:
                hosts.append({
                    'ip': received.psrc,
                    'mac': received.hwsrc
                })

            logger.info(f"Found {len(hosts)} hosts on the network")
            return hosts

        except Exception as e:
            logger.error(f"Error scanning network: {e}")
            return []

    def get_gateway(self):
        pass

import logging
import threading
from scapy.layers.l2 import Ether, ARP
from scapy.all import srp, sendp, sniff
from scapy.layers.inet import IP, TCP, UDP
import threading
import logging

logger = logging.getLogger('PacketHandler')


class PacketHandler:
    """
    Handles packet interception and forwarding
    """

    def __init__(self, interface, gateway_ip, forward_packets=True):
        self.interface = interface
        self.gateway_ip = gateway_ip
        self.gateway_mac = self._resolve_mac(gateway_ip)
        self.filters = []
        self.running = False
        self.sniffer_thread = None
        self.forward_packets = forward_packets

    def _resolve_mac(self, ip):
        """ARP-ping the gateway to learn its MAC."""
        arp_req = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        resp, _ = srp(arp_req, iface=self.interface,
                      timeout=2, retry=2, verbose=0)
        for _, pkt in resp:
            return pkt[Ether].src
        logging.getLogger('PacketHandler').warning(
            f"Could not resolve MAC for {ip}")
        return None

    def add_filter(self, filter_func):
        """
        Add a packet filter function
        filter_func should take a packet and return True if it wants to process it
        """
        self.filters.append(filter_func)
        return len(self.filters) - 1

    def remove_filter(self, filter_index):
        """Remove a filter by its index"""
        if 0 <= filter_index < len(self.filters):
            self.filters.pop(filter_index)
            return True
        return False

    def _packet_callback(self, packet):
        """Process each sniffed packet"""
        for ff in self.filters:
            if ff(packet):  # Akaa already handled
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
        try:
            filter_str = "ip"

            sniff(
                iface=self.interface,
                prn=self._packet_callback,
                filter=filter_str,
                store=0,
                stop_filter=lambda p: not self.running
            )
        except Exception as e:
            logger.error(f"Error in packet sniffer: {e}")

    def start(self):
        """Start packet handling"""
        if self.running:
            logger.warning("CHILL sh costs 10e the micorgram cmon man")
            return

        self.running = True
        self.sniffer_thread = threading.Thread(target=self._sniffer_loop)
        self.sniffer_thread.daemon = True
        self.sniffer_thread.start()

        logger.info(f"Packet handler started on {self.interface}")

    def stop(self):
        """Stop packet handling"""
        logger.info("Ran outta coke...")
        self.running = False

        if self.sniffer_thread:
            self.sniffer_thread.join(timeout=3)

        logger.info("Dont do drugs!")


logger = logging.getLogger('PacketHandler')

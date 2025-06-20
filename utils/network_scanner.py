import logging
import socket
import concurrent.futures
from collections import defaultdict
from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6ND_NA, ICMPv6NDOptSrcLLAddr, ICMPv6ND_NS
from scapy.layers.dns import DNS, DNSQR
from scapy.all import srp, sr1, sr, sniff, get_if_addr, get_if_hwaddr, send


logger = logging.getLogger('NetworkScanner')


class NetworkScanner:

    def __init__(self, interface):
        self.interface = interface
        self.local_ip = get_if_addr(interface)
        self.local_mac = get_if_hwaddr(interface)

    def scan(self, ip_range, scan_ipv6=True, scan_ports=False, detect_os=False):
        logger.info(f"Starting scan for ipragne: {ip_range}")

        hosts = {}

        # IPv4 ARP scan
        ipv4_hosts = self._scan_ipv4(ip_range)
        for host in ipv4_hosts:
            hosts[host['ip']] = host

        # IPv6 scan
        if scan_ipv6:
            ipv6_hosts = self._scan_ipv6()
            for host in ipv6_hosts:
                # Find matching IPv4 host by MAC or create new entry
                matched = False
                for ip, info in hosts.items():
                    if info['mac'] == host['mac']:
                        info['ipv6'] = host['ipv6']
                        matched = True
                        break
                if not matched:
                    hosts[host['ipv6']] = host

        # Port scanning
        if scan_ports:
            logger.info("Starting port scan...")
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                futures = []
                for ip, info in hosts.items():
                    if ':' not in ip:  # Only doing ipv4 for now lwokey no energy to do more
                        future = executor.submit(self._scan_ports, ip)
                        futures.append((ip, future))

                for ip, future in futures:
                    open_ports = future.result()
                    hosts[ip]['open_ports'] = open_ports

        # OS detection
        if detect_os:
            logger.info("Starting OS detection...")
            for ip, info in hosts.items():
                if ':' not in ip:  # Only for IPv4
                    os_info = self._detect_os(ip)
                    hosts[ip]['os'] = os_info

        # Detect DNS usage
        logger.info("Monitoring DNS usage...")
        dns_usage = self._monitor_dns(duration=5)
        for ip, domains in dns_usage.items():
            if ip in hosts:
                hosts[ip]['dns_queries'] = list(domains)

        return self.prettify(hosts)

    def _scan_ipv4(self, ip_range):
        """ARP scan for IPv4 hosts"""
        logger.info(f"Scanning IPv4 range: {ip_range}")

        try:
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
            responses, _ = srp(arp_request, timeout=3, retry=2,
                               verbose=0, iface=self.interface)

            hosts = []
            for _, received in responses:
                host_info = {
                    'ip': received.psrc,
                    'mac': received.hwsrc,
                    'vendor': self._get_mac_vendor(received.hwsrc),
                    'type': 'Host'
                }

                # Check if its likely a router
                if self._is_router(received.psrc):
                    host_info['type'] = 'Router/Gateway'

                hosts.append(host_info)

            logger.info(f"Found {len(hosts)} IPv4 hosts")
            return hosts

        except Exception as e:
            logger.error(f"Error scanning IPv4: {e}")
            return []

    def _scan_ipv6(self):
        """Scan for IPv6 hosts using multicast ping"""
        logger.info("Scanning for IPv6 hosts...")
        hosts = []

        try:
            # Send IPv6 multicast ping to all nodes via ff02::1 (all nodes addr)
            ping = IPv6(dst="ff02::1") / ICMPv6EchoRequest()
            responses, _ = sr(ping, timeout=3, verbose=0, iface=self.interface)

            for _, received in responses:
                if received.haslayer(IPv6):
                    # Try to get MAC from Ethernet layer
                    mac = None
                    if received.haslayer(Ether):
                        mac = received[Ether].src

                    host_info = {
                        'ipv6': received[IPv6].src,
                        'mac': mac,
                        'vendor': self._get_mac_vendor(mac) if mac else 'Unknown',
                        'type': 'IPv6 Host'
                    }
                    hosts.append(host_info)

            # Neighbor Discovery
            nd_hosts = self._scan_ipv6_nd()
            hosts.extend(nd_hosts)

            logger.info(f"Found {len(hosts)} IPv6 hosts")
            return hosts

        except Exception as e:
            logger.error(f"Error scanning IPv6: {e}")
            return []

    def _scan_ipv6_nd(self):
        hosts = []

        try:
            def is_nd_advertisement(pkt):
                return (pkt.haslayer(IPv6) and
                        pkt.haslayer(ICMPv6ND_NA) and
                        pkt[IPv6].src != '::' and
                        not pkt[IPv6].src.startswith('fe80'))

            def process_na(pkt):
                if is_nd_advertisement(pkt):
                    ipv6 = pkt[IPv6].src
                    mac = None

                    if pkt.haslayer(ICMPv6NDOptSrcLLAddr):
                        mac = pkt[ICMPv6NDOptSrcLLAddr].lladdr
                    elif pkt.haslayer(Ether):
                        mac = pkt[Ether].src

                    if ipv6 and mac:
                        # Check if we already have this host
                        for h in hosts:
                            if h['ipv6'] == ipv6:
                                return

                        hosts.append({
                            'ipv6': ipv6,
                            'mac': mac,
                            'vendor': self._get_mac_vendor(mac),
                            'type': 'IPv6 Host (ND)'
                        })

            # First, send some Neighbor Solicitations to trigger responses
            # Send to all-nodes multicast to discover hosts
            ns_all = IPv6(dst="ff02::1") / ICMPv6ND_NS(tgt="ff02::1")
            send(ns_all, iface=self.interface, verbose=0)

            logger.info("Listening for IPv6 Neighbor Advertisements...")
            sniff(iface=self.interface,
                  prn=process_na,
                  timeout=5,
                  lfilter=is_nd_advertisement,
                  store=0)

            return hosts

        except Exception as e:
            logger.error(f"Error in IPv6 ND scan: {e}")

            try:
                return self._scan_ipv6_active()
            except:
                return []

    def _scan_ipv6_active(self):
        hosts = []
        found_macs = set()

        try:
            logger.info("Using active IPv6 discovery (multicast ping)...")

            # Send IPv6 multicast echo request to all-nodes
            # ff02::1 = all nodes, ff02::2 = all routers
            for target in ["ff02::1", "ff02::2"]:
                ping = IPv6(dst=target, hlim=255) / ICMPv6EchoRequest()

                # Use sr instead of sr1 to get multiple responses
                responses, _ = sr(ping, iface=self.interface,
                                  timeout=3, verbose=0)

                for sent, received in responses:
                    if received.haslayer(IPv6):
                        src_ip = received[IPv6].src

                        # Skip link-local and loopback
                        if src_ip.startswith('fe80') or src_ip == '::1':
                            continue

                        # Get MAC from Ether
                        mac = None
                        if received.haslayer(Ether):
                            mac = received[Ether].src

                        if mac and mac in found_macs:
                            continue

                        if mac:
                            found_macs.add(mac)

                        hosts.append({
                            'ipv6': src_ip,
                            'mac': mac,
                            'vendor': self._get_mac_vendor(mac) if mac else 'Unknown',
                            'type': 'IPv6 Host'
                        })

            # Also try to find hosts by checking the neighbor cache
            neighbor_hosts = self._get_neighbor_cache()
            for host in neighbor_hosts:
                if host['mac'] not in found_macs:
                    hosts.append(host)
                    found_macs.add(host['mac'])

            logger.info(f"Found {len(hosts)} IPv6 hosts via active discovery")
            return hosts

        except Exception as e:
            logger.error(f"Error in active IPv6 scan: {e}")
            return []

    def _get_neighbor_cache(self):
        hosts = []

        try:
            import subprocess
            import platform

            if platform.system() == "Darwin":
                cmd = ["ndp", "-an"]
            elif platform.system() == "Linux":
                cmd = ["ip", "-6", "neigh"]
            else:
                return []

            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')

                for line in lines:
                    if platform.system() == "Darwin":
                        parts = line.split()
                        if len(parts) >= 3 and not parts[0].startswith('Neighbor'):
                            ipv6 = parts[0]
                            mac = parts[1]

                            if not ipv6.startswith('fe80') and mac != '(incomplete)':
                                hosts.append({
                                    'ipv6': ipv6,
                                    'mac': mac,
                                    'vendor': self._get_mac_vendor(mac),
                                    'type': 'IPv6 Host (cache)'
                                })

                    elif platform.system() == "Linux":
                        if 'lladdr' in line and not line.startswith('fe80'):
                            parts = line.split()
                            ipv6 = parts[0]
                            mac_idx = parts.index('lladdr') + 1
                            if mac_idx < len(parts):
                                mac = parts[mac_idx]
                                hosts.append({
                                    'ipv6': ipv6,
                                    'mac': mac,
                                    'vendor': self._get_mac_vendor(mac),
                                    'type': 'IPv6 Host (cache)'
                                })

        except Exception as e:
            logger.debug(f"Could not read neighbor cache: {e}")

        return hosts

    def _scan_ports(self, ip, ports=None):
        """Scans some of the common ports on a host"""
        if ports is None:
            ports = [20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                     993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 8888]

        open_ports = []

        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)

            try:
                result = sock.connect_ex((ip, port))
                if result == 0:
                    service = self._identify_service(port)
                    open_ports.append({
                        'port': port,
                        'service': service,
                        'state': 'open'
                    })
            except:
                pass
            finally:
                sock.close()

        return open_ports

    def _identify_service(self, port):
        """Could also just be stored as a self.services but i think a func looks cleaner"""
        services = {
            20: 'FTP-DATA',
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            111: 'RPC',
            135: 'MSRPC',
            139: 'NetBIOS',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            993: 'IMAPS',
            995: 'POP3S',
            1723: 'PPTP',
            3306: 'MySQL',
            3389: 'RDP',
            5900: 'VNC',
            8080: 'HTTP-Proxy',
            8443: 'HTTPS-Alt',
            8888: 'HTTP-Alt'
        }
        return services.get(port, f'Unknown ({port})')

    def _detect_os(self, ip):
        """Kinda basic OS detection using TTL and other fingerprinting"""
        try:
            # ICMP ping
            response = sr1(IP(dst=ip)/ICMP(), timeout=2, verbose=0)

            if response and response.haslayer(IP):
                ttl = response[IP].ttl

                # Basic TTL fingerprinting
                if ttl <= 64:
                    return "Linux/Unix"
                elif ttl <= 128:
                    return "Windows"
                elif ttl <= 255:
                    return "Network Device"

            # TCP fingerprinting
            tcp_resp = sr1(IP(dst=ip)/TCP(dport=80, flags="S"),
                           timeout=2, verbose=0)
            if tcp_resp and tcp_resp.haslayer(TCP):
                window = tcp_resp[TCP].window

                if window == 8192:
                    return "Windows (older)"
                elif window == 5840:
                    return "Linux"
                elif window == 65535:
                    return "Windows (newer) or BSD perhaps"

        except Exception as e:
            logger.debug(f"OS detection error for {ip}: {e}")

        return "Unknown"

    def _is_router(self, ip):
        """Check if IP is likely a router/gateway in a super super rudimentary way idk if one can do better probs not"""
        ends_in = int(ip.split(
            '.')[-1])  # last octect tends to be 1, well at at least it is on my router and googel says 254 as well lol
        return ends_in in [1, 254]

    def _get_mac_vendor(self, mac):
        """Get vendor name from MAC address"""
        if not mac:
            return "Unknown"

        # Just a few
        mac_vendors = {
            '00:50:56': 'VMware',
            '00:0c:29': 'VMware',
            '00:1c:14': 'VMware',
            '08:00:27': 'VirtualBox',
            '00:15:5d': 'Hyper-V',
            'ac:de:48': 'Apple',
            '00:03:93': 'Apple',
            '00:0a:95': 'Apple',
            '00:16:cb': 'Apple',
            '00:17:f2': 'Apple',
            '00:1b:63': 'Apple',
            '00:1e:c2': 'Apple',
            '00:25:bc': 'Apple',
            '00:26:08': 'Apple',
            '3c:07:54': 'Apple',
            '00:21:70': 'Dell',
            '00:14:22': 'Dell',
            '00:1a:a0': 'Dell',
            '00:06:5b': 'Dell',
            '00:13:72': 'Dell',
            '00:1e:4f': 'Dell',
            '00:23:ae': 'Dell',
            '00:24:e8': 'Dell',
            '00:26:b9': 'Dell',
            'f8:b1:56': 'Dell',
            'bc:30:5b': 'Dell',
            'd0:67:e5': 'Dell',
            'f4:8e:38': 'Dell',
            '00:50:ba': 'Cisco',
            '00:10:07': 'Cisco',
            '00:10:0b': 'Cisco',
            '00:10:11': 'Cisco',
            '00:10:1f': 'Cisco',
            '00:10:2f': 'Cisco',
            '00:10:4b': 'Cisco',
            '00:10:54': 'Cisco',
            '00:10:58': 'Cisco',
            '00:10:5a': 'Cisco',
            '00:1b:21': 'Intel',
            '00:1e:65': 'Intel',
            '00:1f:3a': 'Intel',
            '00:1f:3b': 'Intel',
            '00:1f:3c': 'Intel',
            '00:21:5c': 'Intel',
            '00:21:5d': 'Intel',
            '00:23:14': 'Intel',
            '00:23:15': 'Intel',
            '00:24:d6': 'Intel',
            '00:24:d7': 'Intel',
            '5c:51:4f': 'Intel',
            '5c:e0:c5': 'Intel',
            '5c:f9:dd': 'Intel',
            '60:36:dd': 'Intel',
            '60:57:18': 'Intel',
            '64:80:99': 'Intel',
        }

        mac_prefix = mac[:8].upper()

        for prefix, vendor in mac_vendors.items():
            if mac_prefix.startswith(prefix.upper()):
                return vendor

        return "Unknown"

    def _monitor_dns(self, duration=5):
        """Monitor DNS queries for a short duration"""
        logger.info(f"Monitoring DNS queries for {duration} seconds...")
        dns_queries = defaultdict(set)

        def process_dns(pkt):
            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                # source IP
                src_ip = None
                if pkt.haslayer(IP):
                    src_ip = pkt[IP].src
                elif pkt.haslayer(IPv6):
                    src_ip = pkt[IPv6].src

                if src_ip:
                    query = pkt[DNSQR].qname
                    if isinstance(query, bytes):
                        query = query.decode('utf-8', errors='ignore')
                    dns_queries[src_ip].add(query.rstrip('.'))

        # Sniff DNS traffic
        sniff(iface=self.interface, prn=process_dns, timeout=duration,
              filter="udp port 53", store=0)

        return dns_queries

    def prettify(self, hosts):
        """format results"""
        results = []

        for ip, info in hosts.items():
            result = f"\n{'='*60}\n"
            result += f"Host: {ip}\n"

            if 'mac' in info:
                result += f"MAC: {info['mac']} ({info.get('vendor', 'Unknown')})\n"

            if 'ipv6' in info:
                result += f"IPv6: {info['ipv6']}\n"

            result += f"Type: {info.get('type', 'Unknown')}\n"

            if 'os' in info:
                result += f"OS: {info['os']}\n"

            if 'open_ports' in info and info['open_ports']:
                result += "Open Ports:\n"
                for port_info in info['open_ports']:
                    result += f"  - {port_info['port']}: {port_info['service']}\n"

            if 'dns_queries' in info and info['dns_queries']:
                result += "Recent DNS Queries:\n"
                for domain in info['dns_queries'][:5]:
                    result += f"  - {domain}\n"

            results.append(result)

        return ''.join(results)

    def discover_target_details(self, target_ip):
        logger.info(f"Discovering details for {target_ip}")

        details = {
            'ip': target_ip,
            'alive': False,
            'mac': None,
            'ipv6': None,
            'open_ports': [],
            'os': 'Unknown',
            'dns_server': None,
            'recent_dns': []
        }

        # Check if alive and get MAC
        arp_resp = sr1(ARP(pdst=target_ip), timeout=2, verbose=0)
        if arp_resp:
            details['alive'] = True
            details['mac'] = arp_resp.hwsrc
            details['vendor'] = self._get_mac_vendor(arp_resp.hwsrc)

        if details['alive']:
            # Quick port scan
            details['open_ports'] = self._scan_ports(target_ip,
                                                     ports=[22, 80, 443, 445, 3389])

            # OS detection
            details['os'] = self._detect_os(target_ip)

            # Monitor DNS
            dns_usage = self._monitor_dns(duration=3)
            if target_ip in dns_usage:
                details['recent_dns'] = list(dns_usage[target_ip])

        return details

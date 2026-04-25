"""
Reconnaissance Module - Discovers live hosts and open ports on the network
"""

import logging
import socket
import nmap
import ipaddress
import concurrent.futures
from typing import Dict, List, Tuple, Optional
import threading
import queue
import subprocess
import re
from utils.config import SCAN_CONFIG, IOT_PORTS

logger = logging.getLogger(__name__)


class ReconnaissanceModule:
    """
    Performs network reconnaissance including ARP scanning and port discovery.
    Non-intrusive approach with appropriate timeouts.
    """

    def __init__(self, subnet: str = '192.168.1.0/24', ports: Optional[List[int]] = None):
        """
        Initialize reconnaissance module.
        
        Args:
            subnet: Target subnet for scanning (CIDR format)
            ports: List of ports to scan (default: IOT_PORTS)
        """
        self.subnet = subnet
        self.ports = ports or IOT_PORTS
        self.nm = nmap.PortScanner()
        self.results = {}
        self.timeout = SCAN_CONFIG['timeout']
        self.port_timeout = SCAN_CONFIG['port_timeout']
        
        logger.info(f"Reconnaissance module initialized for subnet: {subnet}")
        self.arp_cache = {}  # Cache for Windows ARP lookups

    def _resolve_hostname(self, host: str, nmap_hostnames: list) -> str:
        """
        Resolve a hostname for a discovered host.
        Uses Nmap-provided hostnames first, then falls back to reverse DNS.
        """
        if nmap_hostnames:
            candidate = nmap_hostnames[0].get('name')
            if candidate:
                return candidate

        try:
            return socket.gethostbyaddr(host)[0]
        except Exception:
            return 'Unknown Host'

    def get_mac_from_arp_cache(self, ip: str) -> str:
        """
        Query Windows ARP cache to get MAC address.
        Essential for mobile hotspot environments where Nmap can't discover MAC.
        
        Args:
            ip: IP address to lookup
            
        Returns:
            MAC address or 'Unknown'
        """
        def parse_arp_output(output: str, target_ip: str) -> str:
            for line in output.splitlines():
                if target_ip in line:
                    match = re.search(r'([0-9a-f]{2}[:-]){5}([0-9a-f]{2})', line, re.IGNORECASE)
                    if match:
                        return match.group(0).replace('-', ':').lower()
            return ''

        try:
            result = subprocess.run(['arp', '-a', ip],
                                    capture_output=True, text=True, timeout=3)
            mac = parse_arp_output(result.stdout, ip)
            if mac:
                logger.debug(f"MAC found in ARP cache for {ip}: {mac}")
                return mac
        except Exception as e:
            logger.debug(f"ARP cache lookup failed for {ip}: {e}")

        # Try the full ARP table if per-IP lookup didn't work
        try:
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=3)
            mac = parse_arp_output(result.stdout, ip)
            if mac:
                logger.debug(f"MAC found in full ARP table for {ip}: {mac}")
                return mac
        except Exception as e:
            logger.debug(f"Full ARP table lookup failed for {ip}: {e}")

        # Ping the host once to populate the ARP cache, then retry
        try:
            subprocess.run(['ping', '-n', '1', '-w', '1000', ip],
                           capture_output=True, text=True, timeout=4)
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=3)
            mac = parse_arp_output(result.stdout, ip)
            if mac:
                logger.debug(f"MAC found after pinging {ip}: {mac}")
                return mac
        except Exception as e:
            logger.debug(f"ARP lookup after ping failed for {ip}: {e}")

        # Fallback to NetBIOS-based MAC discovery if available
        try:
            result = subprocess.run(['nbtstat', '-A', ip], capture_output=True, text=True, timeout=3)
            for line in result.stdout.splitlines():
                if 'MAC Address' in line:
                    match = re.search(r'([0-9a-f]{2}[:-]){5}([0-9a-f]{2})', line, re.IGNORECASE)
                    if match:
                        mac = match.group(0).replace('-', ':').lower()
                        logger.debug(f"MAC found via nbtstat for {ip}: {mac}")
                        return mac
        except Exception as e:
            logger.debug(f"NBTSTAT lookup failed for {ip}: {e}")

        return 'Unknown'

    def discover_hosts_arp(self, stop_event: Optional[threading.Event] = None) -> Dict[str, Dict]:
        """
        Perform fast host discovery (ARP/ICMP sweeps) to identify 'Live' hosts.
        Bypasses full scanning for millions of empty addresses.
        Enhanced with multiple discovery techniques for better coverage.
        
        Returns:
            Dictionary mapping IP addresses to host information
        """
        logger.info(f"Starting enhanced discovery phase on subnet: {self.subnet}")
        
        hosts = {}
        
        try:
            # Phase 1: ARP and ICMP discovery (fastest for local networks)
            logger.info("Phase 1: ARP/ICMP discovery...")
            args = '-PR -PE -sn -T4 -n --min-parallelism 100 --max-retries 1'
            self.nm.scan(hosts=self.subnet, arguments=args)
            
            for host in self.nm.all_hosts():
                if stop_event and stop_event.is_set():
                    break
                    
                if self.nm[host].state() == 'up':
                    mac = self.nm[host]['addresses'].get('mac', 'Unknown')
                    # Fallback to Windows ARP cache if Nmap didn't get MAC (common in hotspots)
                    if mac == 'Unknown':
                        mac = self.get_mac_from_arp_cache(host)
                    hostnames = self.nm[host].hostnames()
                    hostname = self._resolve_hostname(host, hostnames)
                    
                    hosts[host] = {
                        'mac': mac,
                        'hostname': hostname,
                        'discovery_method': 'ARP/ICMP'
                    }
                    logger.info(f"Live host detected: {host} ({mac}) via ARP/ICMP")
            
            # Phase 2: TCP SYN discovery for hosts that might not respond to ICMP
            logger.info("Phase 2: TCP SYN discovery for additional coverage...")
            # Use common ports that are likely to be open on IoT devices
            tcp_args = '-PS21,22,23,80,443,554,8080 -sn -T4 -n --max-retries 1'
            self.nm.scan(hosts=self.subnet, arguments=tcp_args)
            
            for host in self.nm.all_hosts():
                if stop_event and stop_event.is_set():
                    break
                    
                if self.nm[host].state() == 'up' and host not in hosts:
                    mac = self.nm[host]['addresses'].get('mac', 'Unknown')
                    # Fallback to Windows ARP cache if Nmap didn't get MAC
                    if mac == 'Unknown':
                        mac = self.get_mac_from_arp_cache(host)
                    hostnames = self.nm[host].hostnames()
                    hostname = self._resolve_hostname(host, hostnames)
                    
                    hosts[host] = {
                        'mac': mac,
                        'hostname': hostname,
                        'discovery_method': 'TCP SYN'
                    }
                    logger.info(f"Additional host detected: {host} ({mac}) via TCP SYN")
            
            # Phase 3: UDP discovery for devices that only respond to UDP
            logger.info("Phase 3: UDP discovery...")
            udp_args = '-PU53,67,68,123,161 -sn -T4 -n --max-retries 1'
            self.nm.scan(hosts=self.subnet, arguments=udp_args)
            
            for host in self.nm.all_hosts():
                if stop_event and stop_event.is_set():
                    break
                    
                if self.nm[host].state() == 'up' and host not in hosts:
                    mac = self.nm[host]['addresses'].get('mac', 'Unknown')
                    # Fallback to Windows ARP cache if Nmap didn't get MAC
                    if mac == 'Unknown':
                        mac = self.get_mac_from_arp_cache(host)
                    hostnames = self.nm[host].hostnames()
                    hostname = self._resolve_hostname(host, hostnames)
                    
                    hosts[host] = {
                        'mac': mac,
                        'hostname': hostname,
                        'discovery_method': 'UDP'
                    }
                    logger.info(f"Additional host detected: {host} ({mac}) via UDP")
            
            self.results['discovered_hosts'] = hosts
            self.results['discovery'] = hosts
            logger.info(f"Discovery complete. Total live hosts found: {len(hosts)}")
            return hosts
            
        except nmap.PortScannerError as e:
            logger.error(f"Nmap error during discovery: {e}")
            return hosts
        except Exception as e:
            logger.error(f"Unexpected error during discovery: {e}")
            return hosts

    def scan_ports(self, host: str, host_data: Optional[Dict] = None) -> Dict[str, str]:
        """
        Scan common IoT ports on a specific host.
        Uses SYN scan for minimal impact.
        Includes malware-detected ports if specified.
        
        Args:
            host: Target IP address
            host_data: Host information including malware_ports if any
            
        Returns:
            Dictionary with open ports and host info
        """
        logger.info(f"Scanning ports on {host}")
        
        result = {
            'open_ports': {},
            'os_type': 'Unknown'
        }
        
        # Get ports to scan
        ports_to_scan = list(self.ports)  # Copy the default ports
        
        # Add malware-detected ports if any
        if host_data and 'malware_ports' in host_data:
            malware_ports = host_data['malware_ports']
            ports_to_scan.extend(malware_ports)
            logger.info(f"Including malware ports {malware_ports} for {host}")
        
        ports_str = ','.join(map(str, ports_to_scan))
        
        try:
            # -sS: SYN stealth scan, -T3: Normal timing, --max-retries 1: Minimal retries
            # Added -sV for light service/version detection (often includes OS hint)
            self.nm.scan(hosts=host, ports=ports_str, 
                        arguments='-sS -sV --version-light -T3 --max-retries 1 --max-rtt-timeout 1000ms')
            
            if host in self.nm.all_hosts():
                # Extract open ports
                if 'tcp' in self.nm[host]:
                    for port in self.nm[host]['tcp'].keys():
                        state = self.nm[host]['tcp'][port]['state']
                        if state == 'open':
                            result['open_ports'][port] = state
                
                # Try to extract OS/Device type if available from Nmap's OS detection or scripts
                # Since we used -sV, look for service info
                if 'osmatch' in self.nm[host] and self.nm[host]['osmatch']:
                    result['os_type'] = self.nm[host]['osmatch'][0].get('name', 'Unknown')
            
            return result
            
        except nmap.PortScannerError as e:
            logger.error(f"Nmap error during port scan on {host}: {e}")
            return result
        except Exception as e:
            logger.error(f"Error scanning ports on {host}: {e}")
            return result

    def scan_all_hosts_ports(self, hosts: Optional[Dict[str, Dict]] = None, stop_event: Optional[threading.Event] = None) -> Dict:
        """
        Scan all discovered hosts for open ports using multi-threading.
        Includes malware-detected ports that were excluded from regular scanning.
        
        Args:
            hosts: Dictionary of hosts to scan (from discover_hosts_arp)
            stop_event: Optional threading.Event to abort scan
            
        Returns:
            Dictionary with host information and open ports
        """
        if hosts is None:
            hosts = self.results.get('discovered_hosts', {})
        
        if not hosts:
            logger.warning("No hosts to scan")
            return {}
        
        logger.info(f"Scanning {len(hosts)} hosts for open ports (Parallel)")
        
        all_results = {}
        max_workers = SCAN_CONFIG.get('max_threads', 10)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_ip = {executor.submit(self.scan_ports, ip, hosts[ip]): ip for ip in hosts}
            
            for future in concurrent.futures.as_completed(future_to_ip):
                if stop_event and stop_event.is_set():
                    # No easy way to kill running threads, but we stop processing
                    break
                    
                ip = future_to_ip[future]
                try:
                    scan_result = future.result()
                    if scan_result['open_ports']:
                        host_info = hosts[ip]
                        all_results[ip] = {
                            'mac': host_info['mac'],
                            'hostname': host_info['hostname'],
                            'open_ports': scan_result['open_ports'],
                            'os_type': scan_result['os_type'],
                            'status': 'up'
                        }
                except Exception as e:
                    logger.error(f"Error scanning {ip}: {e}")
        
        self.results['port_scan'] = all_results
        logger.info(f"Port scan complete. Found {len(all_results)} hosts with open ports")
        
        return all_results

    def get_service_info(self, port: int) -> str:
        """
        Get standard service information for a port.
        
        Args:
            port: Port number
            
        Returns:
            Service name
        """
        common_services = {
            23: 'Telnet',
            80: 'HTTP',
            443: 'HTTPS',
            554: 'RTSP',
            1883: 'MQTT',
            3306: 'MySQL',
            5900: 'VNC',
            8080: 'HTTP-Proxy',
            8443: 'HTTPS-Alt',
            9200: 'Elasticsearch',
        }
        return common_services.get(port, f'Unknown-{port}')

    def run_full_reconnaissance(self, stop_event: Optional[threading.Event] = None) -> Dict:
        """
        Execute full reconnaissance workflow with host discovery filtering.
        
        Args:
            stop_event: Optional threading.Event to abort scan
            
        Returns:
            Complete reconnaissance results
        """
        logger.info("Starting full reconnaissance scan with Target Filtering")
        
        # Phase 1: Fast Discovery Phase
        hosts = self.discover_hosts_arp(stop_event=stop_event)
        
        if stop_event and stop_event.is_set():
            return self.results
            
        if not hosts:
            logger.warning("No live hosts discovered during Fast Discovery Phase")
            return self.results
        
        # Phase 2: Target Filtering - Only pipe Live IP addresses into port scanner
        self.scan_all_hosts_ports(hosts, stop_event=stop_event)
        
        logger.info(f"Reconnaissance complete. Scanned {len(hosts)} live hosts.")
        return self.results

    def get_results(self) -> Dict:
        """
        Get all reconnaissance results.
        
        Returns:
            Dictionary containing all scan results
        """
        return self.results

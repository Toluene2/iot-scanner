"""
Fingerprinting Module - Identifies device types via MAC OUI, banner grabbing, and UPnP discovery
"""

import logging
import socket
import requests
from typing import Dict, List, Optional
from utils.config import MAC_OUI_DATABASE, SCAN_CONFIG, IOT_DEVICE_SIGNATURES
import struct
import threading

logger = logging.getLogger(__name__)


class FingerprintingModule:
    """
    Performs device fingerprinting through multiple techniques:
    - MAC OUI lookup for manufacturer identification
    - Banner grabbing from open ports
    - UPnP discovery for consumer IoT devices
    """

    def __init__(self):
        """Initialize fingerprinting module"""
        self.timeout = SCAN_CONFIG['timeout']
        self.results = {}
        self.oui_cache = MAC_OUI_DATABASE.copy()
        logger.info("Fingerprinting module initialized")

    def lookup_mac_oui(self, mac_address: str) -> Dict[str, str]:
        """
        Lookup manufacturer from MAC address OUI (Organizationally Unique Identifier).
        
        Args:
            mac_address: MAC address in format XX:XX:XX:XX:XX:XX
            
        Returns:
            Dictionary with OUI and manufacturer information
        """
        logger.debug(f"Looking up MAC OUI for: {mac_address}")
        
        # Handle 'Unknown' MAC addresses
        if mac_address == 'Unknown' or not mac_address:
            return {
                'mac': mac_address,
                'oui': 'Unknown',
                'manufacturer': 'Unknown Manufacturer',
                'source': 'unknown_mac'
            }
        
        try:
            # Normalize MAC and extract OUI (first 3 octets)
            mac_address = mac_address.replace('-', ':').strip()
            oui = mac_address[:8].upper()
            
            # Check local database first
            if oui in self.oui_cache:
                return {
                    'mac': mac_address,
                    'oui': oui,
                    'manufacturer': self.oui_cache[oui],
                    'source': 'local_cache'
                }
            
            # Try online API lookup if configured
            api_key = getattr(__import__('utils.config', fromlist=['MAC_OUI_API_KEY']), 'MAC_OUI_API_KEY')
            if api_key:
                try:
                    response = requests.get(
                        f'https://api.macaddress.io/v1?apiKey={api_key}&output=json&search={mac_address}',
                        timeout=3
                    )
                    if response.status_code == 200:
                        data = response.json()
                        manufacturer = data.get('vendorDetails', {}).get('companyName', 'Unknown')
                        self.oui_cache[oui] = manufacturer
                        return {
                            'mac': mac_address,
                            'oui': oui,
                            'manufacturer': manufacturer,
                            'source': 'macaddress_io'
                        }
                    logger.debug(f"MACAddress.io lookup returned status {response.status_code}")
                except requests.RequestException as e:
                    logger.debug(f"MACAddress.io lookup failed: {e}")
            
            # Try public macvendors.com fallback
            try:
                response = requests.get(f'https://api.macvendors.com/{mac_address}', timeout=3)
                if response.status_code == 200:
                    manufacturer = response.text.strip()
                    if manufacturer and 'error' not in manufacturer.lower():
                        self.oui_cache[oui] = manufacturer
                        return {
                            'mac': mac_address,
                            'oui': oui,
                            'manufacturer': manufacturer,
                            'source': 'macvendors'
                        }
                logger.debug(f"MacVendors lookup returned status {response.status_code}")
            except requests.RequestException as e:
                logger.debug(f"MacVendors lookup failed: {e}")
            
            # Default fallback
            return {
                'mac': mac_address,
                'oui': oui,
                'manufacturer': 'Unknown Manufacturer',
                'source': 'not_found'
            }
            
        except Exception as e:
            logger.error(f"Error looking up MAC OUI for {mac_address}: {e}")
            return {}

    def identify_device_from_banner(self, banner: str) -> Optional[str]:
        """
        Identify device manufacturer/type from service banner.
        Works when MAC-based identification fails (e.g., in hotspots).
        
        Args:
            banner: Service banner text
            
        Returns:
            Probable device manufacturer or None
        """
        banner_lower = banner.lower()
        
        # Common device signatures from banners
        device_signatures = {
            'hikvision': ['hikvision', 'hikvision digital technology'],
            'dahua': ['dahua', 'dhvision'],
            'axis': ['axis', 'axis communications'],
            'ubiquiti': ['ubiquiti', 'ubnt'],
            'cisco': ['cisco', 'ciscosmall business'],
            'mikrotik': ['mikrotik', 'routeros'],
            'tp-link': ['tp-link', 'tplink', 'tp link'],
            'netgear': ['netgear', 'netgear inc'],
            'asus': ['asus', 'asustor'],
            'synology': ['synology', 'dsm'],
            'qnap': ['qnap', 'qts'],
            'apple': ['apple', 'darwin', 'macos'],
            'ubuntu': ['ubuntu', 'linux'],
            'd-link': ['d-link', 'dlink'],
            'belkin': ['belkin', 'wemo'],
        }
        
        for manufacturer, signatures in device_signatures.items():
            for sig in signatures:
                if sig in banner_lower:
                    logger.debug(f"Device identified from banner: {manufacturer}")
                    return manufacturer
        
        return None

    def grab_banner(self, host: str, port: int) -> Dict[str, Optional[str]]:
        """
        Grab service banner from open port to identify service/version.
        Non-intrusive banner grabbing with timeout.
        
        Args:
            host: Target IP address
            port: Target port
            
        Returns:
            Dictionary with banner information
        """
        logger.debug(f"Attempting banner grab on {host}:{port}")
        
        result = {
            'host': host,
            'port': port,
            'banner': None,
            'service': None,
            'version': None,
            'device_from_banner': None,
            'status': 'timeout'
        }
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Connect to service
            sock.connect((host, port))
            
            # Receive banner (many services send it automatically)
            try:
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                
                if banner:
                    result['banner'] = banner.strip()
                    result['status'] = 'success'
                    
                    # Simple service identification from banner
                    if 'HTTP' in banner or 'http' in banner:
                        result['service'] = 'HTTP'
                    elif 'SSH' in banner or 'OpenSSH' in banner:
                        result['service'] = 'SSH'
                    elif 'FTP' in banner:
                        result['service'] = 'FTP'
                    elif 'Telnet' in banner:
                        result['service'] = 'Telnet'
                    
                    # Try to identify device from banner (crucial for hotspots)
                    result['device_from_banner'] = self.identify_device_from_banner(banner)
                    
                    logger.debug(f"Banner grabbed from {host}:{port}: {result['banner'][:50]}")
                
            except socket.timeout:
                result['status'] = 'no_banner'
            
            sock.close()
            
        except socket.timeout:
            logger.debug(f"Socket timeout on {host}:{port}")
            result['status'] = 'timeout'
        except ConnectionRefusedError:
            logger.debug(f"Connection refused on {host}:{port}")
            result['status'] = 'refused'
        except Exception as e:
            logger.error(f"Error grabbing banner from {host}:{port}: {e}")
            result['status'] = 'error'
        
        return result

    def grab_all_banners(self, hosts_with_ports: Dict, stop_event: Optional[threading.Event] = None) -> Dict:
        """
        Grab banners from all open ports on all hosts.
        Critical for mobile hotspot environments where MAC identification fails.
        
        Args:
            hosts_with_ports: Dictionary of hosts and their open ports
            stop_event: Optional threading.Event to abort scan
            
        Returns:
            Dictionary with banner information for all hosts
        """
        logger.info("Starting banner grabbing for all hosts")
        
        banner_results = {}
        
        for host, host_data in hosts_with_ports.items():
            if stop_event and stop_event.is_set():
                logger.info("Banner grabbing aborted by user")
                break
                
            banner_results[host] = {}
            
            for port in host_data.get('open_ports', {}).keys():
                if stop_event and stop_event.is_set():
                    break
                banner = self.grab_banner(host, port)
                banner_results[host][port] = banner
        
        self.results['banners'] = banner_results
        return banner_results
    
    def identify_from_hostname(self, hostname: str) -> Optional[str]:
        """
        Identify device manufacturer from hostname.
        Useful when MAC address is unavailable (e.g., mobile hotspots).
        
        Args:
            hostname: Hostname or reverse DNS name
            
        Returns:
            Probable manufacturer or None
        """
        hostname_lower = hostname.lower()
        
        device_patterns = {
            'hikvision': ['hikvision', 'hik-'],
            'dahua': ['dahua', 'dhivision'],
            'axis': ['axis-'],
            'ubiquiti': ['ubiquiti', 'ubnt-'],
            'cisco': ['cisco-', 'csoc'],
            'mikrotik': ['mikrotik', 'mt-'],
            'tp-link': ['tplink', 'tp-'],
            'netgear': ['netgear', 'ngr-'],
            'asus': ['asus', 'asustor'],
            'synology': ['synology', 'ds-'],
            'qnap': ['qnap', 'ts-'],
            'apple': ['iphone', 'ipad', 'mac', 'macbook'],
            'samsung': ['samsung', 'sm-'],
            'lg': ['lg-', 'lge-'],
        }
        
        for manufacturer, patterns in device_patterns.items():
            for pattern in patterns:
                if pattern in hostname_lower:
                    logger.debug(f"Device identified from hostname: {manufacturer}")
                    return manufacturer
        
        return None

    def identify_device_from_upnp(self, upnp_info: Dict) -> Optional[str]:
        """
        Identify device manufacturer from UPnP response fields.
        Useful when MAC-based identification fails.
        """
        if not upnp_info:
            return None

        keywords = []
        for key in ['server', 'location', 'response']:
            value = upnp_info.get(key, '')
            if value:
                keywords.append(value.lower())

        if not keywords:
            return None

        signature_map = {
            'philips': 'Philips',
            'tplink': 'TP-Link',
            'belkin': 'Belkin',
            'asus': 'Asus',
            'dlink': 'D-Link',
            'sonos': 'Sonos',
            'roku': 'Roku',
            'googlecast': 'Google',
            'netgear': 'Netgear',
            'huawei': 'Huawei',
            'cisco': 'Cisco',
            'ubnt': 'Ubiquiti',
            'ubiquiti': 'Ubiquiti',
            'mikrotik': 'MikroTik',
            'openwrt': 'OpenWrt',
            'dd-wrt': 'DD-WRT',
            'apple': 'Apple',
            'amazon': 'Amazon',
            'samsung': 'Samsung',
        }

        for keyword in keywords:
            for indicator, vendor in signature_map.items():
                if indicator in keyword:
                    logger.debug(f"Device identified from UPnP info: {vendor}")
                    return vendor

        return None

    def upnp_discovery(self) -> List[Dict]:
        """
        Send SSDP M-SEARCH packets to discover UPnP devices.
        Non-intrusive discovery method for consumer IoT devices.
        
        Returns:
            List of discovered UPnP devices
        """
        logger.info("Starting UPnP discovery via SSDP M-SEARCH")
        
        discovered_devices = []
        
        try:
            # SSDP M-SEARCH request (multicast)
            ssdp_request = (
                "M-SEARCH * HTTP/1.1\r\n"
                "HOST: 239.255.255.250:1900\r\n"
                "MAN: \"ssdp:discover\"\r\n"
                "MX: 2\r\n"
                "ST: ssdp:all\r\n"
                "\r\n"
            ).encode('utf-8')
            
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(3)
            
            # Send M-SEARCH request
            sock.sendto(ssdp_request, ('239.255.255.250', 1900))
            
            # Receive responses
            responses_seen = set()
            
            while True:
                try:
                    data, addr = sock.recvfrom(4096)
                    response_str = data.decode('utf-8', errors='ignore')
                    
                    # Avoid duplicates
                    if response_str not in responses_seen:
                        responses_seen.add(response_str)
                        
                        device_info = {
                            'ip': addr[0],
                            'response': response_str[:200]  # First 200 chars
                        }
                        
                        # Extract location from response
                        for line in response_str.split('\r\n'):
                            if 'LOCATION' in line.upper():
                                device_info['location'] = line.split(':', 1)[1].strip()
                            elif 'SERVER' in line.upper():
                                device_info['server'] = line.split(':', 1)[1].strip()
                        
                        discovered_devices.append(device_info)
                        logger.debug(f"UPnP device discovered from {addr[0]}")
                
                except socket.timeout:
                    break
                except Exception as e:
                    logger.debug(f"Error in UPnP discovery: {e}")
                    break
            
            sock.close()
            
            self.results['upnp_devices'] = discovered_devices
            logger.info(f"UPnP discovery complete. Found {len(discovered_devices)} devices")
            
        except Exception as e:
            logger.error(f"Error during UPnP discovery: {e}")
        
        return discovered_devices

    def identify_device_type(self, mac: str, banners: Dict, host_info: Optional[Dict] = None) -> Dict[str, str]:
        """
        Identify device type based on MAC OUI, service banners, and Nmap info.
        
        Args:
            mac: MAC address
            banners: Dictionary of service banners
            host_info: Additional host info from Nmap (OS/Device type/HostName)
            
        Returns:
            Device identification information including display_name
        """
        oui_info = self.lookup_mac_oui(mac)
        manufacturer = oui_info.get('manufacturer', 'Unknown Manufacturer')
        
        # Identity Labeling Logic
        # 1. Use Nmap HostName if available
        # 2. Use Nmap OS/Device Type if available
        # 3. Fallback to Manufacturer Name
        # 4. Final fallback to 'Unknown Device'
        
        display_name = "Unknown Device"
        os_type = "Unknown"
        
        if host_info and host_info.get('hostname') and host_info['hostname'] != 'Unknown Host':
            display_name = host_info.get('hostname')
            
        if host_info and host_info.get('os_type') and host_info['os_type'] != 'Unknown':
            os_type = host_info.get('os_type')
            if display_name == "Unknown Device":
                display_name = os_type
        
        if display_name == "Unknown Device" and manufacturer != "Unknown Manufacturer":
            display_name = manufacturer
            
        device_id_info = {
            'manufacturer': manufacturer,
            'os_type': os_type,
            'display_name': display_name,
            'likely_types': [],
            'confidence': 'Low'
        }
        
        # Check against known signatures
        for device_name, known_ouis in [
            ('Hikvision', ['A0:AB:1B', 'D8:97:BA']),
            ('Espressif', ['48:5F:31', '84:FD:8E']),
            ('TP-Link', ['68:D6:8B', '80:EA:96', 'AC:84:C6']),
            ('Cisco', ['00:15:F2', '00:1A:2B', '00:1F:F3', '08:6D:41', 'C0:25:06']),
            ('Ubiquiti', ['54:AF:97', '78:11:DC']),
        ]:
            if any(mac.upper().startswith(oui) for oui in known_ouis):
                device_id_info['likely_types'].append(device_name)
                device_id_info['confidence'] = 'High'
                if display_name == "Unknown Device":
                    device_id_info['display_name'] = device_name
        
        return device_id_info

    def is_infrastructure(self, ip: str, mac: str, manufacturer: str) -> bool:
        """
        Identify if a device is a 'Switch' or 'Gateway'.
        
        Criteria:
        - IP is .1 or .254
        - Manufacturer is known for networking gear (Cisco, Ubiquiti, etc.)
        - MAC OUI matches networking vendors
        """
        # Check IP (common gateway addresses)
        if ip.endswith('.1') or ip.endswith('.254'):
            return True
            
        # Check networking-focused manufacturers
        infra_manufacturers = ['Cisco', 'Ubiquiti', 'Ruckus', 'MikroTik', 'Juniper', 'Aruba', 'TP-Link']
        if any(vendor.lower() in manufacturer.lower() for vendor in infra_manufacturers):
            # Not all TP-Link devices are infrastructure, but for our filtering logic,
            # we'll flag them as likely infrastructure if they appear on these common IPs
            # or if the user wants to keep the main IoT list clean.
            # However, TP-Link also makes smart bulbs.
            # Let's be more specific:
            if any(vendor.lower() in manufacturer.lower() for vendor in ['Cisco', 'Ubiquiti', 'Ruckus', 'MikroTik']):
                return True
                
        return False

    def run_full_fingerprinting(self, hosts_with_ports: Dict, stop_event: Optional[threading.Event] = None) -> Dict:
        """
        Execute full fingerprinting workflow.
        Uses multiple fallback methods for identification (MAC -> Banner -> Hostname).
        Critical for mobile hotspot environments.
        
        Args:
            hosts_with_ports: Dictionary of hosts and their open ports
            stop_event: Optional threading.Event to abort scan
            
        Returns:
            Complete fingerprinting results
        """
        logger.info("Starting full fingerprinting workflow")
        
        # First pass: MAC OUI lookups and identity labeling
        manufacturer_identified = {}
        for host, host_data in hosts_with_ports.items():
            if stop_event and stop_event.is_set():
                return self.results
                
            mac = host_data.get('mac')
            manufacturer_identified[host] = False
            
            if mac and mac != 'Unknown':
                # OUI Lookup
                oui_info = self.lookup_mac_oui(mac)
                host_data['oui_info'] = oui_info
                
                if oui_info.get('manufacturer') != 'Unknown Manufacturer':
                    manufacturer_identified[host] = True
                    logger.info(f"{host}: Manufacturer identified via MAC: {oui_info.get('manufacturer')}")
                
                # Device Type Identification
                device_info = self.identify_device_type(mac, {}, host_info=host_data)
                host_data['device_info'] = device_info
                
                # Infrastructure check
                host_data['is_infrastructure'] = self.is_infrastructure(
                    host, mac, device_info['manufacturer']
                )
            else:
                # MAC is Unknown - set defaults for later fallback identification
                host_data['oui_info'] = {
                    'mac': mac,
                    'oui': 'Unknown',
                    'manufacturer': 'Unknown (MAC unavailable)',
                    'source': 'unknown_mac'
                }
                host_data['device_info'] = {'manufacturer': 'Unknown'}
                host_data['is_infrastructure'] = False
            
            self.results[host] = host_data
        
        # Banner grabbing - CRITICAL for hotspot environments
        logger.info("Grabbing banners for manufacturer and device identification fallback")
        self.grab_all_banners(hosts_with_ports, stop_event=stop_event)
        
        # Second pass: Use banner and hostname for manufacturer identification
        for host, banners in self.results.get('banners', {}).items():
             if host in self.results:
                 self.results[host]['banners'] = banners
                 
                 # If MAC identification failed, try banner-based identification
                 if not manufacturer_identified.get(host, False) and banners:
                     for port, banner_info in banners.items():
                         device_from_banner = banner_info.get('device_from_banner')
                         if device_from_banner:
                             logger.info(f"{host}: Manufacturer identified via banner on port {port}: {device_from_banner}")
                             self.results[host]['device_info']['manufacturer'] = device_from_banner
                             self.results[host]['device_identification_method'] = 'banner'
                             manufacturer_identified[host] = True
                             break
                 
                 # Third fallback: Try hostname-based identification
                 if not manufacturer_identified.get(host, False):
                     hostname = self.results[host].get('hostname', '')
                     if hostname and hostname != 'Unknown Host':
                         device_from_hostname = self.identify_from_hostname(hostname)
                         if device_from_hostname:
                             logger.info(f"{host}: Manufacturer identified via hostname: {device_from_hostname}")
                             self.results[host]['device_info']['manufacturer'] = device_from_hostname
                             self.results[host]['device_identification_method'] = 'hostname'
                             manufacturer_identified[host] = True

        if stop_event and stop_event.is_set():
            return self.results
            
        # UPnP discovery - another fallback for MAC/hostname unidentified devices
        upnp_devices = self.upnp_discovery()
        for upnp in upnp_devices:
            ip = upnp.get('ip')
            if not ip or ip not in self.results:
                continue

            if self.results[ip].get('device_info', {}).get('manufacturer', 'Unknown') in ['Unknown', 'Unknown Manufacturer']:
                vendor = self.identify_device_from_upnp(upnp)
                if vendor:
                    self.results[ip]['device_info']['manufacturer'] = vendor
                    self.results[ip]['device_identification_method'] = 'upnp'
                    logger.info(f"{ip}: Manufacturer identified via UPnP: {vendor}")

        logger.info("Full fingerprinting complete with fallback identification methods")
        return self.results

    def get_results(self) -> Dict:
        """
        Get all fingerprinting results.
        
        Returns:
            Dictionary containing all fingerprinting results
        """
        return self.results

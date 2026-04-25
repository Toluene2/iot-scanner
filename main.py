"""
Main Scanner Orchestrator - Coordinates all modules and generates reports
"""

import logging
import argparse
import sys
import threading
import subprocess
import re
import ipaddress
import json
from typing import Callable, Optional
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from modules.reconnaissance import ReconnaissanceModule
from modules.fingerprinting import FingerprintingModule
from modules.assessment import VulnerabilityAssessmentModule
from utils.report_generator import ReportGenerator
from utils.config import SCAN_CONFIG, LOG_CONFIG

# Configure logging
logging.basicConfig(
    level=LOG_CONFIG['level'],
    format=LOG_CONFIG['format']
)
logger = logging.getLogger(__name__)


class IoTVulnerabilityScanner:
    """
    Main orchestrator for the IoT vulnerability scanning workflow.
    Coordinates reconnaissance, fingerprinting, and assessment modules.
    """

    def __init__(self, subnet: str = '192.168.1.0/24'):
        """
        Initialize the scanner.
        
        Args:
            subnet: Target subnet for scanning (CIDR format)
        """
        self.subnet = subnet
        self.current_ssid = IoTVulnerabilityScanner.get_current_ssid()

        # If using the default subnet, try to auto-detect the active WiFi/hotspot subnet
        if subnet == '192.168.1.0/24':
            detected_subnet = IoTVulnerabilityScanner.get_wifi_subnet()
            if detected_subnet:
                self.subnet = detected_subnet
                logger.info(f"Detected active WiFi subnet: {detected_subnet}")
            else:
                logger.info("No active WiFi subnet detected; using provided subnet")

        # Initialize modules
        self.recon = ReconnaissanceModule(subnet=self.subnet)
        self.fingerprint = FingerprintingModule()
        self.assessment = VulnerabilityAssessmentModule()
        self.report_gen = ReportGenerator()
        
        logger.info(f"IoT Vulnerability Scanner initialized for subnet: {self.subnet}")

    @staticmethod
    def get_current_ssid() -> Optional[str]:
        """Detect current connected WiFi SSID on Windows."""
        try:
            result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], 
                                 capture_output=True, text=True, check=True)
            match = re.search(r'^\s+SSID\s+:\s+(.+)$', result.stdout, re.MULTILINE)
            if match:
                return match.group(1).strip()
        except Exception as e:
            logger.debug(f"Could not detect SSID: {e}")
        return None

    @staticmethod
    def get_wifi_subnet() -> Optional[str]:
        """Detect current WiFi subnet in CIDR format on Windows."""
        try:
            # 1. Get current SSID and interface name
            result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], 
                                 capture_output=True, text=True, check=True)
            
            # Find the Name of the interface that is connected
            sections = re.split(r'\n\s*\n', result.stdout)
            iface_name = None
            for section in sections:
                if 'State' in section and 'connected' in section.lower():
                    name_match = re.search(r'^\s+Name\s+:\s+(.+)$', section, re.MULTILINE)
                    if name_match:
                        iface_name = name_match.group(1).strip()
                        break
            
            if not iface_name:
                return None
            
            # 2. Get IP and PrefixLength for this interface using PowerShell
            ps_cmd = f'Get-NetIPAddress -InterfaceAlias "{iface_name}" -AddressFamily IPv4 | Select-Object IPAddress, PrefixLength | ConvertTo-Json'
            ps_result = subprocess.run(['powershell', '-Command', ps_cmd], capture_output=True, text=True)
            
            if ps_result.returncode == 0 and ps_result.stdout.strip():
                data = json.loads(ps_result.stdout)
                
                # data can be a list if multiple IPs
                if isinstance(data, list):
                    data = data[0]
                
                ip = data.get('IPAddress')
                prefix = data.get('PrefixLength')
                
                if ip and prefix:
                    interface = ipaddress.IPv4Interface(f"{ip}/{prefix}")
                    return str(interface.network)
                    
        except Exception as e:
            logger.debug(f"Could not detect WiFi subnet: {e}")
            
        return None

    def _apply_target_filters(self, hosts: Dict[str, Dict]) -> Dict[str, Dict]:
        """
        Apply target filtering to discovered hosts.
        Filters out unwanted IP ranges, known infrastructure devices, etc.
        
        Args:
            hosts: Dictionary of discovered hosts from discovery phase
            
        Returns:
            Filtered dictionary of hosts to scan
        """
        filtered = {}
        
        # Common IP ranges to exclude (infrastructure, multicast, etc.)
        exclude_ranges = [
            ipaddress.ip_network('0.0.0.0/8'),      # Current network
            ipaddress.ip_network('127.0.0.0/8'),    # Loopback
            ipaddress.ip_network('169.254.0.0/16'), # Link-local
            ipaddress.ip_network('224.0.0.0/4'),    # Multicast
            ipaddress.ip_network('240.0.0.0/4'),    # Reserved
        ]
        
        # Common infrastructure MAC prefixes to potentially exclude
        # (routers, switches, access points - but keep for IoT scanning)
        infrastructure_macs = [
            # Add specific MAC prefixes if needed for filtering
        ]
        
        for ip, host_info in hosts.items():
            try:
                ip_obj = ipaddress.ip_address(ip)
                
                # Check if IP is in excluded ranges
                excluded = False
                for exclude_range in exclude_ranges:
                    if ip_obj in exclude_range:
                        logger.debug(f"Excluding {ip}: in excluded range {exclude_range}")
                        excluded = True
                        break
                
                if not excluded:
                    filtered[ip] = host_info
                    logger.debug(f"Including {ip} for scanning")
                    
            except ValueError:
                logger.warning(f"Invalid IP address format: {ip}")
                continue
        
        logger.info(f"Target filtering: {len(hosts)} discovered -> {len(filtered)} after filtering")
        return filtered

    def run_scan(self, stop_event: threading.Event = None, progress_callback: Callable[[int, str], None] = None) -> dict:
        """
        Execute complete vulnerability scanning workflow with multi-stage pipeline.
        
        Args:
            stop_event: Optional threading.Event to abort scan
            progress_callback: Optional callback for progress reporting (percentage, message)
            
        Returns:
            Dictionary with complete scan results
        """
        self.results_so_far = {}
        if progress_callback:
            progress_callback(0, "Initializing multi-stage scan pipeline...")
            
        logger.info("=" * 60)
        logger.info("Starting IoT Vulnerability Assessment Scan")
        logger.info("=" * 60)
        
        all_results = {'reconnaissance': {}, 'fingerprinting': {}, 'devices': {}, 'assessment': {}, 'vulnerabilities': []}
        
        # Step 1: Fast Discovery Phase
        if progress_callback:
            progress_callback(5, "Step 1/4: Fast Discovery Phase (ARP/ICMP/TCP/UDP)...")
            
        logger.info("\n[STEP 1/4] Fast Discovery Phase...")
        logger.info("-" * 40)
        # We call discover_hosts_arp directly to separate discovery from port scanning
        live_hosts = self.recon.discover_hosts_arp(stop_event=stop_event)
        
        if stop_event and stop_event.is_set():
            return all_results
            
        logger.info(f"✓ Discovery Phase complete. Found {len(live_hosts)} Live hosts.")
        all_results['reconnaissance']['discovery'] = live_hosts
        
        if not live_hosts:
            logger.warning("No live hosts found during discovery. Scan complete.")
            if progress_callback:
                progress_callback(100, "Scan complete: No live hosts found.")
            return all_results

        # Step 1.5: Target Filtering - Apply filters to discovered hosts
        if progress_callback:
            progress_callback(8, f"Step 1.5/4: Filtering {len(live_hosts)} discovered hosts...")
            
        logger.info("\n[STEP 1.5/4] Target Filtering...")
        logger.info("-" * 40)
        
        filtered_hosts = self._apply_target_filters(live_hosts)
        
        if not filtered_hosts:
            logger.warning("All hosts filtered out. No targets to scan.")
            if progress_callback:
                progress_callback(100, "Scan complete: All hosts filtered out.")
            return all_results
            
        logger.info(f"✓ Filtering complete. {len(filtered_hosts)} hosts remain after filtering.")

        # Batching Logic: Process the IP list in batches of 256
        live_ips = list(filtered_hosts.keys())
        batch_size = SCAN_CONFIG['batch_size']  # Configurable batch size for memory stability
        total_ips = len(live_ips)
        
        all_discovered_hosts_with_ports = {}
        all_fingerprint_results = {}
        all_assessment_results = {}
        
        for i in range(0, total_ips, batch_size):
            if stop_event and stop_event.is_set():
                break
                
            batch_ips = live_ips[i:i + batch_size]
            current_batch_hosts = {ip: filtered_hosts[ip] for ip in batch_ips}
            batch_num = (i // batch_size) + 1
            total_batches = (total_ips + batch_size - 1) // batch_size
            
            msg = f"Processing batch {batch_num}/{total_batches} ({len(batch_ips)} hosts)..."
            logger.info(f"\n--- {msg} ---")
            
            if progress_callback:
                # Progress ranges from 10% to 80% for batch processing
                base_progress = 10 + (i / total_ips) * 70
                progress_callback(int(base_progress), msg)

            # Step 1b: Malware Check on Excluded Ports
            logger.info("Checking excluded ports for malware...")
            malware_hosts = self.assessment.check_excluded_ports_for_malware(batch_ips, stop_event=stop_event)
            
            # Add malware-detected ports to the ports list for affected hosts
            for host_ip, malware_ports in malware_hosts.items():
                if host_ip in current_batch_hosts:
                    # Add the malware ports to be scanned
                    current_batch_hosts[host_ip]['malware_ports'] = malware_ports
                    logger.info(f"Will scan malware ports {malware_ports} on {host_ip}")

            # Step 1c: Target Filtering & Port Scan for this batch
            batch_recon = self.recon.scan_all_hosts_ports(current_batch_hosts, stop_event=stop_event)
            all_discovered_hosts_with_ports.update(batch_recon)
            
            if not batch_recon:
                continue

            # Step 2: Fingerprinting for this batch
            batch_fingerprint = self.fingerprint.run_full_fingerprinting(batch_recon, stop_event=stop_event)
            all_fingerprint_results.update(batch_fingerprint)
            
            # Step 3: Vulnerability Assessment for this batch
            batch_assessment = self.assessment.run_full_assessment(batch_recon, stop_event=stop_event)
            all_assessment_results.update(batch_assessment)

        # Consolidate results
        all_results['reconnaissance']['port_scan'] = all_discovered_hosts_with_ports
        all_results['fingerprinting'] = all_fingerprint_results
        all_results['assessment'] = all_assessment_results
        
        if stop_event and stop_event.is_set():
            return all_results
            
        if not all_discovered_hosts_with_ports:
            logger.warning("No hosts with open ports found after scanning all batches.")
            # Still generate a report even with no open ports - shows discovered devices
            logger.info("Generating report for discovered devices (even with no open ports)...")
            
            # Create device objects from ALL discovered hosts (not just those with open ports)
            device_objects = {}
            for ip in filtered_hosts:
                # Get host info from reconnaissance results
                host_info = all_results['reconnaissance'].get('discovery', {}).get(ip, {})
                mac = host_info.get('mac', 'Unknown')
                hostname = host_info.get('hostname', 'Unknown Host')
                
                if mac == 'Unknown':
                    device_key = f"IP-{ip}"
                else:
                    device_key = mac
                    
                fingerprint_data = all_fingerprint_results.get(ip, {})
                if fingerprint_data:
                    device_info = fingerprint_data.get('device_info', {})
                else:
                    if mac != 'Unknown':
                        oui_info = self.fingerprint.lookup_mac_oui(mac)
                        manufacturer = oui_info.get('manufacturer', 'Unknown')
                    else:
                        manufacturer = self.fingerprint.identify_from_hostname(hostname) or 'Unknown'
                    device_info = {'manufacturer': manufacturer}
                
                device = {
                    'id': device_key,
                    'mac': mac,
                    'ip': ip,
                    'hostname': hostname,
                    'manufacturer': device_info.get('manufacturer', 'Unknown'),
                    'display_name': hostname if hostname != 'Unknown Host' else ip,
                    'open_ports': {},
                    'is_infrastructure': False,
                    'device_type': device_info.get('manufacturer', 'Unknown Device'),
                    'vulnerabilities': []
                }
                device_objects[device_key] = device
            
            all_results['devices'] = device_objects
            
            # Generate report even with no open ports
            vulnerabilities = []
            security_posture = []
            
            html_report = self.report_gen.generate_report(
                all_results['reconnaissance'],
                all_fingerprint_results,
                all_assessment_results,
                vulnerabilities,
                security_posture=security_posture,
                device_objects=device_objects
            )
            
            report_file = self.report_gen.save_report(html_report)
            all_results['report_file'] = report_file
            
            logger.info(f"✓ Report saved to: {report_file}")
            
            if progress_callback:
                progress_callback(100, f"Scan complete: {len(all_discovered_hosts_with_ports)} devices discovered, no open ports found.")
            return all_results

        # TRANSFORMATION: Create Device-Level Objects using MAC as primary key
        if progress_callback:
            progress_callback(85, "Organizing device data...")
            
        logger.info("\nOrganizing discovered entities into Device Objects...")
        device_objects = {}
        
        for ip, host_info in all_discovered_hosts_with_ports.items():
            mac = host_info.get('mac', 'Unknown')
            hostname = host_info.get('hostname', 'Unknown Host')
            
            if mac == 'Unknown':
                device_key = f"IP-{ip}"
            else:
                device_key = mac
                
            fingerprint_data = all_fingerprint_results.get(ip, {})
            device_info = fingerprint_data.get('device_info', {})
            
            device = {
                'id': device_key,
                'mac': mac,
                'ip': ip,
                'hostname': hostname,
                'display_name': hostname if hostname != 'Unknown Host' else device_info.get('display_name', 'Unknown Device'),
                'manufacturer': device_info.get('manufacturer', 'Unknown'),
                'os_type': device_info.get('os_type', 'Unknown'),
                'open_ports': host_info.get('open_ports', {}),
                'banners': fingerprint_data.get('banners', {}),
                'is_infrastructure': fingerprint_data.get('is_infrastructure', False),
                'status': host_info.get('status', 'up')
            }
            device_objects[device_key] = device
            
        all_results['devices'] = device_objects
        
        # Analyze security posture
        if progress_callback:
            progress_callback(90, "Analyzing security posture...")
            
        logger.info("Analyzing security posture...")
        iot_devices = {k: v for k, v in device_objects.items() if not v.get('is_infrastructure')}
        posture_input = {dev['ip']: {'mac': dev['mac'], 'open_ports': dev['open_ports'], 'device_type': dev['display_name']} 
                        for mac, dev in iot_devices.items()}
            
        security_posture = self.assessment.analyze_security_posture(posture_input)
        all_results['security_posture'] = security_posture
        
        vulnerabilities = self.assessment.get_vulnerabilities()
        all_results['vulnerabilities'] = vulnerabilities
        
        # Step 4: Report Generation
        if progress_callback:
            progress_callback(95, "Step 4/4: Generating Report...")
            
        logger.info("\n[STEP 4/4] Generating Report...")
        html_report = self.report_gen.generate_report(
            all_results['reconnaissance'],
            all_fingerprint_results,
            all_assessment_results,
            vulnerabilities,
            security_posture=security_posture,
            device_objects=device_objects
        )
        
        report_file = self.report_gen.save_report(html_report)
        all_results['report_file'] = report_file
        
        logger.info(f"✓ Report saved to: {report_file}")
        
        logger.info("\n" + "=" * 60)
        logger.info("Scan Complete!")
        logger.info("=" * 60)
        
        if progress_callback:
            progress_callback(100, f"Scan complete. {len(device_objects)} devices discovered.")
            
        return all_results
        
        # Print summary
        self._print_summary(vulnerabilities, assessment_results)
        
        if progress_callback:
            progress_callback(100, "Scan Complete! Results ready.")
            
        return all_results

    def _print_summary(self, vulnerabilities: list, assessment_results: dict):
        """
        Print scan summary to console.
        
        Args:
            vulnerabilities: List of identified vulnerabilities
            assessment_results: Assessment module results
        """
        risk_assessment = assessment_results.get('risk_assessment', {})
        
        print("\n" + "=" * 60)
        print("SCAN SUMMARY")
        print("=" * 60)
        print(f"Total Vulnerabilities Found: {len(vulnerabilities)}")
        print(f"Overall Risk Level: {risk_assessment.get('risk_level', 'Unknown')}")
        print(f"Risk Score: {risk_assessment.get('risk_score', 0)}/100")
        print(f"\nSeverity Breakdown:")
        
        severity = risk_assessment.get('severity_breakdown', {})
        for level in ['Critical', 'High', 'Medium', 'Low', 'Info']:
            count = severity.get(level, 0)
            if count > 0:
                print(f"  - {level}: {count}")
        
        print("=" * 60)

    def export_json_results(self, results: dict, filename: str = None) -> str:
        """
        Export scan results as JSON for integration with other tools.
        
        Args:
            results: Complete scan results dictionary
            filename: Output filename (optional)
            
        Returns:
            Path to saved JSON file
        """
        import json
        from datetime import datetime
        
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"reports/iot_scan_results_{timestamp}.json"
        
        try:
            # Make results JSON-serializable
            json_results = {
                'timestamp': datetime.now().isoformat(),
                'subnet': self.subnet,
                'results': results
            }
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(json_results, f, indent=2)
            
            logger.info(f"Results exported to: {filename}")
            return filename
            
        except Exception as e:
            logger.error(f"Error exporting results to JSON: {e}")
            return None


def main():
    """Main entry point for the scanner"""
    
    parser = argparse.ArgumentParser(
        description='Non-Intrusive IoT Vulnerability Scanner for Smart Campus',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan default subnet (192.168.1.0/24)
  python main.py
  
  # Scan custom subnet
  python main.py -s 10.0.0.0/24
  
  # Scan with all exports
  python main.py -s 192.168.1.0/24 --export-json
  
  # Launch Graphical User Interface
  python main.py --gui
        """
    )
    
    parser.add_argument(
        '-s', '--subnet',
        default='192.168.1.0/24',
        help='Target subnet in CIDR format (default: 192.168.1.0/24)'
    )
    
    parser.add_argument(
        '--export-json',
        action='store_true',
        help='Export results to JSON file'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    parser.add_argument(
        '--gui',
        action='store_true',
        help='Launch the Graphical User Interface'
    )
    
    args = parser.parse_args()
    
    # Set log level based on verbose flag or config
    log_level = logging.DEBUG if args.verbose else getattr(logging, LOG_CONFIG.get('level', 'INFO'))
    logging.getLogger().setLevel(log_level)
    
    if args.verbose:
        logger.info("Verbose logging enabled")
    
    # Launch GUI if requested
    if args.gui:
        try:
            from gui import main as gui_main
            return gui_main()
        except ImportError as e:
            print(f"Error: Could not load GUI dependencies. {e}")
            return 1
    
    # Create output directory if needed
    Path('reports').mkdir(exist_ok=True)
    
    # Initialize and run scanner
    scanner = IoTVulnerabilityScanner(subnet=args.subnet)
    results = scanner.run_scan()
    
    # Export JSON if requested
    if args.export_json:
        scanner.export_json_results(results)
    
    return 0


if __name__ == '__main__':
    sys.exit(main())

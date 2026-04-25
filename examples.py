#!/usr/bin/env python3
"""
Example usage scenarios for the IoT Vulnerability Scanner
"""

from main import IoTVulnerabilityScanner
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def example_1_basic_scan():
    """Example 1: Basic scan with default settings"""
    print("\n" + "="*60)
    print("EXAMPLE 1: Basic Scan - Default Subnet")
    print("="*60)
    
    scanner = IoTVulnerabilityScanner(subnet='192.168.1.0/24')
    results = scanner.run_scan()
    
    print("\nResults saved to reports/ directory")


def example_2_custom_subnet():
    """Example 2: Scan custom subnet"""
    print("\n" + "="*60)
    print("EXAMPLE 2: Custom Subnet Scan")
    print("="*60)
    
    scanner = IoTVulnerabilityScanner(subnet='10.0.0.0/24')
    results = scanner.run_scan()
    
    # Export JSON
    scanner.export_json_results(results)


def example_3_small_network():
    """Example 3: Scan specific IP range for small network"""
    print("\n" + "="*60)
    print("EXAMPLE 3: Small Network Scan")
    print("="*60)
    
    # Scan smaller /28 subnet (16 hosts)
    scanner = IoTVulnerabilityScanner(subnet='192.168.1.0/28')
    results = scanner.run_scan()


def example_4_large_campus():
    """Example 4: Scan large campus network with multiple subnets"""
    print("\n" + "="*60)
    print("EXAMPLE 4: Large Campus Network Scan")
    print("="*60)
    
    # Scan larger /20 subnet (4096 hosts) - takes longer
    print("Note: This will take significantly longer due to subnet size")
    print("It's recommended to break into smaller subnets for campus networks")
    
    subnets = [
        '192.168.1.0/24',   # Building A
        '192.168.2.0/24',   # Building B
        '192.168.3.0/24',   # Building C
    ]
    
    for subnet in subnets:
        print(f"\nScanning subnet: {subnet}")
        scanner = IoTVulnerabilityScanner(subnet=subnet)
        results = scanner.run_scan()


def example_5_programmatic_use():
    """Example 5: Use scanner programmatically for custom workflows"""
    print("\n" + "="*60)
    print("EXAMPLE 5: Programmatic Usage")
    print("="*60)
    
    scanner = IoTVulnerabilityScanner(subnet='192.168.1.0/24')
    
    # Access individual results
    logger.info("Running scan...")
    results = scanner.run_scan()
    
    # Extract and process results
    recon = results.get('reconnaissance', {})
    discovered = recon.get('port_scan', {})
    
    logger.info(f"\nDiscovered {len(discovered)} hosts:")
    for host, data in discovered.items():
        mac = data.get('mac', 'Unknown')
        ports = list(data.get('open_ports', {}).keys())
        logger.info(f"  {host} ({mac}): Ports {ports}")
    
    # Get assessment
    assessment = results.get('assessment', {})
    risk = assessment.get('risk_assessment', {})
    logger.info(f"\nRisk Assessment: {risk.get('risk_level')} - {risk.get('total_vulnerabilities')} vulnerabilities")


def example_6_advanced_custom_workflow():
    """Example 6: Advanced custom workflow"""
    print("\n" + "="*60)
    print("EXAMPLE 6: Advanced Custom Workflow")
    print("="*60)
    
    from modules.reconnaissance import ReconnaissanceModule
    from modules.fingerprinting import FingerprintingModule
    from modules.assessment import VulnerabilityAssessmentModule
    
    # Use individual modules
    recon = ReconnaissanceModule(subnet='192.168.1.0/24')
    
    logger.info("Step 1: Host discovery")
    hosts = recon.discover_hosts_arp()
    logger.info(f"Found {len(hosts)} hosts")
    
    logger.info("\nStep 2: Port scanning")
    ports = recon.scan_all_hosts_ports(hosts)
    logger.info(f"Found {len(ports)} hosts with open ports")
    
    logger.info("\nStep 3: Fingerprinting")
    fingerprint = FingerprintingModule()
    fingerprint.run_full_fingerprinting(ports)
    
    logger.info("\nStep 4: Assessment")
    assess = VulnerabilityAssessmentModule()
    assess.run_full_assessment(ports)
    
    vulns = assess.get_vulnerabilities()
    logger.info(f"\nIdentified {len(vulns)} vulnerabilities")


if __name__ == '__main__':
    # Ensure reports directory exists
    Path('reports').mkdir(exist_ok=True)
    
    print("""
╔══════════════════════════════════════════════════════════════╗
║  IoT Vulnerability Scanner - Example Usage Scenarios         ║
║  Adeleke University Smart Campus                             ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    print("""
Select an example to run:
  1. Basic Scan (default subnet: 192.168.1.0/24)
  2. Custom Subnet Scan (10.0.0.0/24)
  3. Small Network Scan (/28)
  4. Large Campus Network (multiple subnets)
  5. Programmatic Usage
  6. Advanced Custom Workflow
  
Or modify this script to run your specific scenario.
    """)
    
    # Uncomment the example you want to run:
    # example_1_basic_scan()
    # example_2_custom_subnet()
    # example_3_small_network()
    # example_4_large_campus()
    # example_5_programmatic_use()
    # example_6_advanced_custom_workflow()
    
    print("\nTo run an example, uncomment it in examples.py and run this file.")
    print("Or use main.py directly from command line:")
    print("  python main.py -s 192.168.1.0/24")

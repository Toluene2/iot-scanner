"""
Vulnerability Assessment Module - Credential spraying and CVE mapping
"""

import logging
import socket
import base64
from typing import Dict, List, Optional
from utils.config import DEFAULT_CREDENTIALS, CVE_DATABASE, SCAN_CONFIG
import threading
import http.client

logger = logging.getLogger(__name__)


class VulnerabilityAssessmentModule:
    """
    Performs vulnerability assessment through:
    - Safe credential spraying (small list, non-blocking)
    - CVE mapping based on device signatures
    - Risk calculation and severity classification
    """

    def __init__(self):
        """Initialize vulnerability assessment module"""
        self.timeout = SCAN_CONFIG['timeout']
        self.results = {}
        self.vulnerabilities = []
        self.risk_summary = {}
        logger.info("Vulnerability Assessment module initialized")

    def safe_credential_test_http(self, host: str, port: int, 
                                  username: str, password: str) -> Dict:
        """
        Safely test HTTP Basic Authentication with default credentials.
        Non-intrusive test that respects timeouts and doesn't crash devices.
        
        Args:
            host: Target IP address
            port: HTTP/HTTPS port
            username: Username to test
            password: Password to test
            
        Returns:
            Dictionary with test result
        """
        result = {
            'host': host,
            'port': port,
            'username': username,
            'password': password,
            'vulnerable': False,
            'status': 'untested'
        }
        
        try:
            # Create HTTP connection with timeout
            if port == 443:
                conn = http.client.HTTPSConnection(host, port, timeout=self.timeout)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=self.timeout)
            
            # Create Basic Auth header
            credentials = f"{username}:{password}"
            encoded = base64.b64encode(credentials.encode()).decode()
            headers = {'Authorization': f'Basic {encoded}'}
            
            # Attempt simple GET request
            conn.request('GET', '/', headers=headers)
            response = conn.getresponse()
            
            # Check response codes
            if response.status in [200, 201, 204]:
                result['vulnerable'] = True
                result['status'] = 'success'
                logger.warning(f"VULNERABLE: {host}:{port} - {username}:{password} accepted")
            elif response.status == 401:
                result['status'] = 'auth_failed'
            elif response.status == 403:
                result['status'] = 'forbidden'
            else:
                result['status'] = f'http_{response.status}'
            
            conn.close()
            
        except socket.timeout:
            result['status'] = 'timeout'
        except ConnectionRefusedError:
            result['status'] = 'connection_refused'
        except Exception as e:
            logger.debug(f"Error testing credentials on {host}:{port}: {e}")
            result['status'] = 'error'
        
        return result

    def safe_credential_test_telnet(self, host: str, port: int,
                                    username: str, password: str) -> Dict:
        """
        Safely test Telnet default credentials.
        Very conservative approach to avoid disrupting devices.
        
        Args:
            host: Target IP address
            port: Telnet port (usually 23)
            username: Username to test
            password: Password to test
            
        Returns:
            Dictionary with test result
        """
        result = {
            'host': host,
            'port': port,
            'username': username,
            'password': password,
            'vulnerable': False,
            'status': 'untested'
        }
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            
            # Send minimal input to test
            try:
                # Wait for initial prompt (short timeout)
                sock.settimeout(1)
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                
                # Send username (non-blocking test)
                sock.send(f"{username}\r\n".encode())
                sock.settimeout(1)
                sock.recv(1024)
                
                # Send password (non-blocking test)
                sock.send(f"{password}\r\n".encode())
                sock.settimeout(1)
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                
                # Check for login success indicators
                if any(indicator in response for indicator in ['#', '>', 'login', 'successful']):
                    result['vulnerable'] = True
                    result['status'] = 'success'
                    logger.warning(f"VULNERABLE: {host}:{port} (Telnet) - {username}:{password} accepted")
                else:
                    result['status'] = 'auth_failed'
                
            except socket.timeout:
                result['status'] = 'no_response'
            finally:
                sock.close()
            
        except socket.timeout:
            result['status'] = 'timeout'
        except ConnectionRefusedError:
            result['status'] = 'connection_refused'
        except Exception as e:
            logger.debug(f"Error testing Telnet credentials on {host}:{port}: {e}")
            result['status'] = 'error'
        
        return result

    def test_default_credentials(self, hosts_with_ports: Dict, stop_event: Optional[threading.Event] = None) -> List[Dict]:
        """
        Test default credentials on all hosts with open HTTP/Telnet ports using multi-threading.
        Uses only TOP 10 default credentials as specified.
        
        Args:
            hosts_with_ports: Dictionary of hosts and their open ports
            stop_event: Optional threading.Event to abort scan
            
        Returns:
            List of vulnerability test results
        """
        import concurrent.futures
        from utils.config import SCAN_CONFIG
        
        logger.info("Starting safe default credential testing (Parallel)")
        
        credential_results = []
        tasks = []
        
        # Collect all tasks to be executed in parallel
        for host, host_data in hosts_with_ports.items():
            open_ports = host_data.get('open_ports', {})
            
            # HTTP ports
            http_ports = [p for p in open_ports.keys() if p in [80, 8080, 443, 8443]]
            for port in http_ports:
                for username, password in DEFAULT_CREDENTIALS:
                    tasks.append(('http', host, port, username, password))
            
            # Telnet port
            if 23 in open_ports:
                for username, password in DEFAULT_CREDENTIALS[:5]:
                    tasks.append(('telnet', host, 23, username, password))
        
        if not tasks:
            return []

        max_workers = SCAN_CONFIG.get('max_threads', 10)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_task = {}
            for t_type, host, port, user, pwd in tasks:
                if t_type == 'http':
                    future = executor.submit(self.safe_credential_test_http, host, port, user, pwd)
                else:
                    future = executor.submit(self.safe_credential_test_telnet, host, port, user, pwd)
                future_to_task[future] = (t_type, host, port, user, pwd)
            
            for future in concurrent.futures.as_completed(future_to_task):
                if stop_event and stop_event.is_set():
                    executor.shutdown(wait=False)
                    logger.info("Credential testing aborted by user")
                    break
                    
                try:
                    result = future.result()
                    credential_results.append(result)
                    
                    if result.get('vulnerable'):
                        t_type, host, port, user, pwd = future_to_task[future]
                        self.vulnerabilities.append({
                            'type': 'weak_credentials',
                            'host': host,
                            'port': port,
                            'severity': 'Critical',
                            'details': f"{t_type.upper()} default credentials accepted: {user}:{pwd}"
                        })
                except Exception as e:
                    logger.error(f"Error testing credentials: {e}")
        
        self.results['credential_tests'] = credential_results
        logger.info(f"Credential testing complete. Found {len([r for r in credential_results if r['vulnerable']])} vulnerable instances")
        
        return credential_results

    def map_cves(self, manufacturers: Dict[str, str]) -> List[Dict]:
        """
        Map identified device signatures to known CVEs.
        Lookup in local CVE database for identified manufacturers.
        
        Args:
            manufacturers: Dictionary of hosts and their manufacturers
            
        Returns:
            List of applicable CVEs
        """
        logger.info("Starting CVE mapping")
        
        cve_results = []
        
        for host, manufacturer in manufacturers.items():
            # Check if manufacturer is in CVE database
            if manufacturer in CVE_DATABASE:
                cves = CVE_DATABASE[manufacturer]
                for cve in cves:
                    cve_result = {
                        'host': host,
                        'manufacturer': manufacturer,
                        'cve': cve['cve'],
                        'severity': cve['severity'],
                        'description': cve['description']
                    }
                    cve_results.append(cve_result)
                    
                    self.vulnerabilities.append({
                        'type': 'known_cve',
                        'host': host,
                        'port': None,
                        'severity': cve['severity'],
                        'details': f"{cve['cve']}: {cve['description']}"
                    })
        
        # Add default CVE for devices with default credentials
        for vuln in self.vulnerabilities:
            if vuln['type'] == 'weak_credentials':
                if vuln not in cve_results:
                    cve_results.append({
                        'host': vuln['host'],
                        'manufacturer': 'Unknown',
                        'cve': 'Default Credentials',
                        'severity': 'High',
                        'description': 'Device uses default or weak credentials'
                    })
        
        self.results['cve_mapping'] = cve_results
        logger.info(f"CVE mapping complete. Found {len(cve_results)} applicable CVEs")
        
        return cve_results

    def calculate_risk_score(self, vulnerabilities: List[Dict]) -> Dict:
        """
        Calculate overall risk score and severity breakdown.
        Uses a percentage-based scoring system (0-150%+).
        
        Args:
            vulnerabilities: List of identified vulnerabilities
            
        Returns:
            Dictionary with risk assessment scores
        """
        severity_levels = {
            'Critical': 25,  # Severity point values
            'High': 15,
            'Medium': 8,
            'Low': 4,
            'Info': 1
        }
        
        severity_counts = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Info': 0
        }
        
        total_score = 0
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Low')
            if severity in severity_levels:
                total_score += severity_levels[severity]
                severity_counts[severity] += 1
        
        # Normalize to 0-100 scale
        # Max expected = 50 points (2 Critical vulnerabilities = 100% risk)
        # This maps severity points linearly to 0-100
        max_expected_points = 50
        risk_score = min((total_score / max_expected_points) * 100, 100)
        
        risk_assessment = {
            'total_vulnerabilities': len(vulnerabilities),
            'risk_score': round(risk_score, 1),
            'severity_breakdown': severity_counts,
            'risk_level': self._determine_risk_level(risk_score)
        }
        
        self.results['risk_assessment'] = risk_assessment
        logger.info(f"Risk assessment: {risk_assessment}")
        
        return risk_assessment

    def _determine_risk_level(self, score: float) -> str:
        """
        Determine overall risk level from score (0-100).
        
        Args:
            score: Risk score (0-100)
            
        Returns:
            Risk level string (Critical, Medium, Low)
        """
        if score >= 70:
            return 'Critical'
        elif score >= 40:
            return 'Medium'
        else:
            return 'Low'

    def analyze_security_posture(self, scan_results: Dict) -> List[Dict]:
        """
        Analyze the security posture of discovered devices.
        Categorizes devices into Risk Levels (CRITICAL, HIGH, MEDIUM, SAFE)
        and provides summary recommendations.
        
        Args:
            scan_results: Dictionary containing all device scan results
            
        Returns:
            List of dictionaries formatted for reporting
        """
        security_posture_report = []
        vulnerabilities = self.get_vulnerabilities()
        
        # Iterate through each discovered host with ports
        for ip, details in scan_results.items():
            mac = details.get('mac', 'Unknown')
            open_ports = details.get('open_ports', {})
            device_type = details.get('device_type', 'Unknown Device')
            
            # Calculate per-device risk score
            device_vulns = [v for v in vulnerabilities if v.get('host') == ip]
            
            # Base risks from open ports if no specific vulnerabilities found yet
            if not device_vulns:
                # Add synthetic vulnerabilities for risk scoring based on open ports
                for port in open_ports:
                    if port in [23, 554]: # Telnet, RTSP
                        device_vulns.append({'severity': 'High'})
                    elif port in [3306, 5900, 9200]: # Database, VNC
                        device_vulns.append({'severity': 'Medium'})
                    elif port in [80, 8080]: # HTTP
                        device_vulns.append({'severity': 'Low'})

            device_risk = self.calculate_risk_score(device_vulns)
            risk_score = device_risk['risk_score']
            risk_level = device_risk['risk_level']
            
            recommendation = "Maintain regular updates and monitor for any unusual network activity."
            risk_factors = []
            
            # Logic for Risk Factors and Recommendations based on risk bands
            if risk_score >= 70:
                recommendation = "CRITICAL: Immediate action required. Change passwords, update firmware, or isolate device."
            elif risk_score >= 40:
                recommendation = "MEDIUM: Monitor device and ensure it's behind a firewall."
            elif risk_score < 40:
                recommendation = "LOW: Maintain regular updates and monitor for any unusual network activity."
            
            for v in device_vulns:
                if v.get('description'):
                    risk_factors.append(v['description'])
                elif v.get('severity'):
                    risk_factors.append(f"Exposed service with {v['severity']} risk")

            # Construct the device summary
            posture_data = {
                'ip': ip,
                'mac': mac,
                'device_type': device_type,
                'risk_level': risk_level,
                'risk_score': risk_score,
                'recommendation': recommendation,
                'risk_factors': risk_factors,
                'open_ports': list(open_ports.keys())
            }
            security_posture_report.append(posture_data)
            
        return security_posture_report

    def detect_malware_on_port_80(self, host: str) -> bool:
        """
        Check for potential malware indicators on port 80.
        Looks for suspicious HTTP responses that might indicate malware.
        
        Args:
            host: Target IP address
            
        Returns:
            True if malware indicators detected
        """
        try:
            conn = http.client.HTTPConnection(host, 80, timeout=self.timeout)
            conn.request('GET', '/')
            response = conn.getresponse()
            
            # Read response body
            body = response.read().decode('utf-8', errors='ignore').lower()
            conn.close()
            
            # Check for malware indicators
            malware_signatures = [
                'malware', 'virus', 'trojan', 'backdoor', 'exploit',
                'shell', 'cmd.exe', 'powershell', 'wget', 'curl',
                'bitcoin', 'ransomware', 'cryptocurrency',
                'mirai', 'botnet', 'ddos'
            ]
            
            for signature in malware_signatures:
                if signature in body:
                    logger.warning(f"Malware signature '{signature}' detected on {host}:80")
                    return True
                    
            # Check for unusual response codes or headers
            if response.status in [301, 302] and 'location' in response.headers:
                location = response.headers['location'].lower()
                if any(sig in location for sig in ['.onion', 'tor', 'darkweb']):
                    logger.warning(f"Suspicious redirect detected on {host}:80")
                    return True
                    
        except Exception as e:
            logger.debug(f"Error checking malware on {host}:80: {e}")
            
        return False

    def detect_malware_on_port_3306(self, host: str) -> bool:
        """
        Check for potential malware indicators on port 3306 (MySQL).
        Looks for unauthorized MySQL access or suspicious configurations.
        
        Args:
            host: Target IP address
            
        Returns:
            True if malware indicators detected
        """
        try:
            import mysql.connector
            # Try to connect without password (common malware behavior)
            conn = mysql.connector.connect(
                host=host,
                user='root',
                password='',
                database='mysql',
                connection_timeout=self.timeout
            )
            
            if conn.is_connected():
                logger.warning(f"Unauthorized MySQL access detected on {host}:3306")
                conn.close()
                return True
                
        except mysql.connector.Error as e:
            # Check for specific error codes that might indicate compromise
            if e.errno in [1045, 1698]:  # Access denied, but might indicate running service
                logger.debug(f"MySQL service detected on {host}:3306")
            else:
                logger.debug(f"MySQL check on {host}:3306: {e}")
        except Exception as e:
            logger.debug(f"Error checking MySQL malware on {host}:3306: {e}")
            
        return False

    def check_excluded_ports_for_malware(self, hosts: List[str], stop_event: Optional[threading.Event] = None) -> Dict[str, List[int]]:
        """
        Check excluded ports (80, 3306) for malware on discovered hosts.
        If malware detected, these ports should be included in scanning.
        
        Args:
            hosts: List of IP addresses to check
            stop_event: Optional threading.Event to abort
            
        Returns:
            Dictionary mapping hosts to ports that should be scanned due to malware
        """
        logger.info("Checking excluded ports for malware indicators")
        
        malware_ports = {}
        import concurrent.futures
        
        def check_host(host):
            if stop_event and stop_event.is_set():
                return host, []
                
            ports_to_scan = []
            
            # Check port 80
            if self.detect_malware_on_port_80(host):
                ports_to_scan.append(80)
                
            # Check port 3306
            if self.detect_malware_on_port_3306(host):
                ports_to_scan.append(3306)
                
            return host, ports_to_scan
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=SCAN_CONFIG['max_threads']) as executor:
            futures = {executor.submit(check_host, host): host for host in hosts}
            
            for future in concurrent.futures.as_completed(futures):
                if stop_event and stop_event.is_set():
                    break
                    
                host, ports = future.result()
                if ports:
                    malware_ports[host] = ports
                    logger.info(f"Malware detected on {host}, will scan ports: {ports}")
        
        return malware_ports

    def run_full_assessment(self, hosts_with_ports: Dict, 
                           host_manufacturers: Optional[Dict] = None,
                           stop_event: Optional[threading.Event] = None) -> Dict:
        """
        Execute full vulnerability assessment workflow.
        
        Args:
            hosts_with_ports: Dictionary of hosts and their open ports
            host_manufacturers: Dictionary of host to manufacturer mapping
            stop_event: Optional threading.Event to abort scan
            
        Returns:
            Complete assessment results
        """
        logger.info("Starting full vulnerability assessment")
        
        # Test default credentials
        self.test_default_credentials(hosts_with_ports, stop_event=stop_event)
        
        if stop_event and stop_event.is_set():
            return self.results
            
        # Map CVEs if manufacturer data available
        if host_manufacturers:
            self.map_cves(host_manufacturers)
        else:
            # Try to extract from fingerprinting results
            manufacturers = {}
            for host, host_data in hosts_with_ports.items():
                oui_info = host_data.get('oui_info', {})
                if oui_info:
                    manufacturers[host] = oui_info.get('manufacturer', 'Unknown')
            
            if manufacturers:
                self.map_cves(manufacturers)
        
        # Calculate overall risk
        self.calculate_risk_score(self.vulnerabilities)
        
        logger.info("Full vulnerability assessment complete")
        return self.results

    def get_results(self) -> Dict:
        """
        Get all vulnerability assessment results.
        
        Returns:
            Dictionary containing all assessment results
        """
        return self.results

    def get_vulnerabilities(self) -> List[Dict]:
        """
        Get list of all identified vulnerabilities.
        
        Returns:
            List of vulnerabilities
        """
        return self.vulnerabilities

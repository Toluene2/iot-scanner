# IoT Vulnerability Scanner - Smart Campus Edition

A **non-intrusive, lightweight IoT vulnerability scanner** designed specifically for fragile IoT environments like Adeleke University's Smart Campus. This tool avoids the aggressive scanning techniques of traditional scanners like Nessus and focuses on safe, device-friendly assessment methods.

## 🎯 Features

### Modular Architecture
- **Reconnaissance Module**: ARP-based host discovery + port scanning
- **Fingerprinting Module**: MAC OUI lookup + banner grabbing + UPnP discovery
- **Vulnerability Assessment Module**: Safe credential testing + CVE mapping
- **Report Generator**: Professional HTML reports with risk categorization
- **Graphical User Interface**: User-friendly desktop interface for non-technical users

### Safety First
- **Configurable Timeouts**: 2-3 second default timeouts to prevent device crashes
- **Non-Intrusive Scanning**: Uses SYN stealth scans and minimal retries
- **Safe Credential Testing**: Only tests top 10 default credentials
- **Agentless**: No software installation required on target devices

### Comprehensive Reporting
- **Risk Categorization**: Critical, High, Medium, Low, Info
- **Executive Summary**: Quick overview of findings
- **Severity Breakdown**: Visual representation of vulnerability distribution
- **Host Details**: MAC address, manufacturer, open ports for each device
- **Actionable Recommendations**: Guidance for remediation

## 📋 Requirements

### System Requirements
- **OS**: Linux/Windows/macOS
- **Python**: 3.7+
- **Nmap**: Must be installed and accessible from PATH

### Dependencies
```
python-nmap==0.7.1
scapy==2.5.0
requests==2.31.0
jinja2==3.1.2
```

## 🚀 Installation

### 1. Clone/Download Project
```bash
cd iot-vulnerability-scanner
```

### 2. Install Nmap
**Ubuntu/Debian:**
```bash
sudo apt-get install nmap
```

**Windows:**
Download from https://nmap.org/download.html

**macOS:**
```bash
brew install nmap
```

### 3. Create Virtual Environment (Recommended)
```bash
python -m venv venv

# Linux/macOS
source venv/bin/activate

# Windows
venv\Scripts\activate
```

### 4. Install Python Dependencies
```bash
pip install -r requirements.txt
```

## 📖 Usage

### Graphical User Interface
```bash
# Launch the GUI application
python main.py --gui

# Or run GUI directly
python gui.py
```

**Default Login Credentials:**
- Username: `admin`
- Password: `admin`
- *Note: You will be required to change the password on first login*

### Password Recovery
If you forget your password, you can reset all user passwords using the provided script:
```bash
python reset_passwords.py
```
This will reset all passwords to `admin` and require users to change them on next login.

### Command Line Interface

#### Basic Scan
```bash
# Scan default subnet (192.168.1.0/24)
python main.py
```

#### Custom Subnet
```bash
python main.py -s 10.0.0.0/24
```

#### Verbose Logging
```bash
python main.py -s 192.168.1.0/24 -v
```

#### Export JSON Results
```bash
python main.py -s 192.168.1.0/24 --export-json
```

### Graphical User Interface (GUI)
```bash
python main.py --gui
```

### Complete Example
```bash
python main.py -s 192.168.50.0/24 --export-json -v
```

## 📁 Project Structure

```
iot-vulnerability-scanner/
├── main.py                          # Main orchestrator & CLI
├── gui.py                           # Graphical User Interface
├── requirements.txt                 # Python dependencies
├── README.md                        # This file
│
├── modules/
│   ├── __init__.py
│   ├── reconnaissance.py            # Host discovery & port scanning
│   ├── fingerprinting.py            # Device identification
│   └── assessment.py                # Vulnerability testing
│
├── utils/
│   ├── __init__.py
│   ├── config.py                    # Configuration & constants
│   └── report_generator.py          # HTML report generation
│
└── reports/                         # Output directory
    ├── iot_vulnerability_report_*.html
    └── iot_scan_results_*.json
```

## 🔧 Configuration

Edit `utils/config.py` to customize:

### Scan Configuration
```python
SCAN_CONFIG = {
    'timeout': 3,              # Socket timeout in seconds
    'port_timeout': 2,         # Individual port timeout
    'retry_count': 1,          # Retries for failed connections
    'max_threads': 5,          # Concurrent scan threads
}
```

### Target Ports
```python
IOT_PORTS = [
    23,    # Telnet
    80,    # HTTP
    443,   # HTTPS
    554,   # RTSP (IP cameras)
    8080,  # HTTP alternative
    # Add more as needed...
]
```

### Default Credentials
```python
DEFAULT_CREDENTIALS = [
    ('admin', 'admin'),
    ('admin', 'password'),
    ('root', 'root'),
    # Top 10 credentials...
]
```

## 📊 Output Examples

### Console Output
```
============================================================
Starting IoT Vulnerability Assessment Scan
============================================================

[STEP 1/4] Running Reconnaissance Module...
----------------------------------------
Reconnaissance module initialized for subnet: 192.168.1.0/24
Starting ARP scan on subnet: 192.168.1.0/24
Discovered host: 192.168.1.100 (a0:ab:1b:00:00:01)
Discovered host: 192.168.1.101 (48:5f:31:00:00:02)
✓ Discovered 2 hosts with open ports

[STEP 2/4] Running Fingerprinting Module...
...
[STEP 3/4] Running Vulnerability Assessment Module...
...
[STEP 4/4] Generating Report...
✓ Report saved to: reports/iot_vulnerability_report_20260126_143022.html

============================================================
SCAN SUMMARY
============================================================
Total Vulnerabilities Found: 3
Overall Risk Level: High

Severity Breakdown:
  - Critical: 1
  - High: 2
============================================================
```

### HTML Report
- Professional styled report with color-coded severity
- Executive summary with key metrics
- Detailed vulnerability listings
- Host discovery information
- Manufacturer identification
- Actionable recommendations

## 🛡️ Safety Mechanisms

### Timeouts
- **Socket Timeout**: 3 seconds (prevents hanging)
- **Port Timeout**: 2 seconds per port
- **Banner Grab Timeout**: 1 second receive timeout

### Non-Intrusive Techniques
- **ARP Scan**: Only Layer 2 discovery, zero network traffic
- **SYN Scan**: Stealth TCP scan without full connection
- **Minimal Retries**: Only 1 retry per port
- **Slow Timing**: T3 timing profile (normal/standard)

### Credential Testing
- **Limited Attempts**: Only 10 default credential pairs
- **Per-Port Testing**: Tests each port independently
- **Timeout Protection**: Respects socket timeouts

## 🔍 Module Details

### Reconnaissance Module (`modules/reconnaissance.py`)
**Purpose**: Discover live hosts and identify open ports

**Key Functions**:
- `discover_hosts_arp()`: ARP scanning for host discovery
- `scan_ports()`: SYN stealth port scanning
- `scan_all_hosts_ports()`: Parallel port scanning
- `get_service_info()`: Map ports to services

**Output**:
```python
{
    'discovered_hosts': {
        '192.168.1.100': 'a0:ab:1b:00:00:01',
        '192.168.1.101': '48:5f:31:00:00:02'
    },
    'port_scan': {
        '192.168.1.100': {
            'mac': 'a0:ab:1b:00:00:01',
            'open_ports': {80: 'open', 443: 'open'},
            'status': 'up'
        }
    }
}
```

### Fingerprinting Module (`modules/fingerprinting.py`)
**Purpose**: Identify device types and services

**Key Functions**:
- `lookup_mac_oui()`: Get manufacturer from MAC address
- `grab_banner()`: Extract service banners
- `upnp_discovery()`: Find UPnP devices via SSDP
- `identify_device_type()`: Classify device based on signatures

**Supported OUI Lookups**:
- Hikvision, Espressif, TP-Link, Cisco, Ubiquiti
- Uses local database + optional online API fallback

### Assessment Module (`modules/assessment.py`)
**Purpose**: Test for vulnerabilities

**Key Functions**:
- `safe_credential_test_http()`: HTTP auth testing
- `safe_credential_test_telnet()`: Telnet credential testing
- `test_default_credentials()`: Batch credential testing
- `map_cves()`: Match to known CVEs
- `calculate_risk_score()`: Generate risk assessment

**CVE Database**: Local mapping of known vulnerabilities by manufacturer

### Report Generator (`utils/report_generator.py`)
**Purpose**: Generate professional HTML reports

**Features**:
- Jinja2 template-based HTML generation
- Color-coded severity levels
- Executive summary
- Detailed vulnerability listings
- Responsive design

## 📈 Risk Scoring

| Severity | Score Range | Color | Examples |
|----------|------------|-------|----------|
| Critical | 9.0+ | Red | Default credentials, Auth bypass |
| High | 7.0-8.9 | Orange | Known CVE, SQL injection |
| Medium | 5.0-6.9 | Yellow | Weak service version |
| Low | 3.0-4.9 | Green | Info disclosure |
| Info | 1.0-2.9 | Blue | Open port, Service banner |

## ⚠️ Important Notes

### Permissions
- **Root/Admin Access**: Not required for scanning
- **Network Access**: Requires network connectivity to target subnet
- **Firewall**: Ensure firewall allows scanning traffic

### Legal Considerations
- **Authorization**: Only scan networks you own or have explicit permission to scan
- **Compliance**: Ensure compliance with local regulations (GDPR, HIPAA, etc.)
- **Documentation**: Maintain records of authorized scans

### Best Practices
1. **Test First**: Scan a test network before production
2. **Schedule Off-Hours**: Run intensive scans during maintenance windows
3. **Monitor Performance**: Watch device behavior during scans
4. **Regular Updates**: Keep vulnerability databases current
5. **Follow Up**: Implement remediation for identified issues

## 🐛 Troubleshooting

### Nmap Not Found
```bash
# Verify nmap installation
which nmap          # Linux/macOS
nmap --version

# If not installed, follow installation steps above
```

### Permission Denied (Linux/macOS)
```bash
# Some nmap features require sudo
sudo python main.py -s 192.168.1.0/24
```

### No Hosts Discovered
- Verify subnet is correct
- Check network connectivity
- Ensure no firewall blocking ARP traffic
- Try with sudo for better ARP support

### Slow Scanning
- Reduce port list in `SCAN_CONFIG`
- Increase timeout if network is slow
- Run during off-peak hours

### UPnP Discovery Not Working
- Ensure UDP port 1900 is not blocked
- Check network supports multicast
- Verify firewall allows SSDP

## 📝 Logging

Logs are printed to console. Enable verbose logging for debugging:

```bash
python main.py -v
```

Log levels:
- **DEBUG**: Detailed diagnostic information
- **INFO**: General informational messages
- **WARNING**: Warning messages for important events
- **ERROR**: Error messages for failures

## 🔄 Future Enhancements

Potential additions:
- [ ] SNMP enumeration module
- [ ] SSL/TLS certificate analysis
- [ ] WiFi network scanning
- [ ] Firmware version detection
- [ ] Database integration for scan history
- [ ] Email report delivery
- [ ] REST API for automation
- [ ] Scheduled scanning
- [ ] Multi-subnet parallel scanning

## 📚 References

- [Nmap Documentation](https://nmap.org/book/)
- [OWASP IoT Security](https://owasp.org/www-project-iot/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework/)
- [MAC Address Lookup API](https://macaddress.io/)

## 📄 License

This project is provided for educational and authorized security testing purposes only.

## ✉️ Support

For issues, questions, or contributions, please refer to project documentation.

---

**Version**: 1.0  
**Last Updated**: January 2026  
**Target**: Adeleke University Smart Campus Security Audit

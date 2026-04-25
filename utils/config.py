"""
Configuration and constants for IoT Vulnerability Scanner
"""

# Network Scanning Configuration
# In utils/config.py

SCAN_CONFIG = {
    'timeout': 3,           # Pure integer for Python sockets
    'port_timeout': "1000ms",  # String with units for Nmap
    'retry_count': 1,
    'max_threads': 10,      # Increased for faster scanning
    'batch_size': 256,      # Number of hosts to process per batch for memory stability
}

# Common IoT Device Ports
IOT_PORTS = [
    23,    # Telnet (legacy IoT devices)
    # 80,    # HTTP - excluded unless malware detected
    443,   # HTTPS
    554,   # RTSP (IP cameras)
    8080,  # HTTP alternative
    8443,  # HTTPS alternative
    # 3306,  # MySQL - excluded unless malware detected
    5900,  # VNC
    9200,  # Elasticsearch
    1883,  # MQTT
]

# Default Credentials for Safe Testing
DEFAULT_CREDENTIALS = [
    ('admin', 'admin'),
    ('admin', 'password'),
    ('admin', '12345'),
    ('root', 'root'),
    ('root', 'password'),
    ('admin', '123456'),
    ('admin', ''),
    ('root', ''),
    ('user', 'user'),
    ('guest', 'guest'),
]

# Known IoT Device Signatures (Device Type: [Port: Service])
IOT_DEVICE_SIGNATURES = {
    'Hikvision': {
        80: 'HTTP',
        443: 'HTTPS',
        554: 'RTSP',
        8000: 'HTTP Management',
    },
    'Espressif': {
        80: 'HTTP',
        443: 'HTTPS',
    },
    'TP-Link': {
        80: 'HTTP',
        443: 'HTTPS',
        1883: 'MQTT',
    },
    'Cisco': {
        22: 'SSH',
        80: 'HTTP',
        443: 'HTTPS',
    },
    'Ubiquiti': {
        22: 'SSH',
        80: 'HTTP',
        443: 'HTTPS',
        8080: 'HTTP Alt',
    },
}

# MAC OUI Database (Comprehensive local cache for common vendors)
MAC_OUI_API_KEY = None

MAC_OUI_DATABASE = {
    # Standard vendors
    '00:00:00': 'Xerox',
    '00:05:85': 'Cabletron',
    '00:0A:95': 'NetAdministrator',
    '00:13:10': 'Linksys',
    '00:15:F2': 'Cisco Systems',
    '00:1A:2B': 'Cisco Systems',
    '00:1F:F3': 'Cisco Systems',
    '08:00:27': 'PCS Systemtechnik',
    '08:6D:41': 'Cisco Systems',
    
    # Networking & Infrastructure
    '44:A7:B1': 'Philips',
    '48:5F:31': 'Espressif Inc.',
    '50:50:F2': 'GIGA-BYTE',
    '54:AF:97': 'Ubiquiti Networks',
    '60:A4:4C': 'Ruckus Wireless',
    '68:D6:8B': 'TP-Link',
    '78:11:DC': 'Ubiquiti Networks',
    '80:EA:96': 'TP-Link',
    '84:FD:8E': 'Espressif Inc.',
    'A0:AB:1B': 'Hikvision Digital Technology',
    'AC:84:C6': 'TP-Link',
    'C0:25:06': 'Cisco Systems',
    'D8:97:BA': 'Hikvision Digital Technology',
    
    # Hotspot & Mobile Vendors (Common in mobile networks)
    '00:1A:6B': 'Intel Corporation',
    '00:1B:21': 'Intel Corporation',
    '00:25:86': 'Apple Inc.',
    '00:26:08': 'Apple Inc.',
    '00:3E:E1': 'Dell Inc.',
    '00:50:F2': 'Microsoft Corporation',
    '00:5A:3E': 'Nokia',
    '00:95:69': 'HTC',
    '00:A4:04': 'Sony Ericsson',
    '00:B3:95': 'Apple Inc.',
    '00:E0:4C': 'Realtek Semiconductor',
    '00:E3:B0': 'Samsung Electronics',
    '00:F4:B9': 'Intel Corporation',
    '04:2A:E4': 'Huawei Technologies',
    '08:35:42': 'Samsung Electronics',
    '08:47:BE': 'Huawei Technologies',
    '0C:47:95': 'Sony Corporation',
    '10:68:FF': 'Samsung Electronics',
    '10:C6:1F': 'Xiaomi Corporation',
    '14:48:F4': 'LG Electronics',
    '14:CC:20': 'Xiaomi Corporation',
    '16:63:EE': 'Wistron Corporation',  # Common hotspot prefix
    '18:60:24': 'NETGEAR',
    '1C:BD:B9': 'Huawei Technologies',
    '1C:E6:2B': 'TP-Link',
    '20:34:FB': 'Apple Inc.',
    '20:F4:6B': 'Samsung Electronics',
    '2C:41:38': 'HTC',
    '2C:54:91': 'Huawei Technologies',
    '34:23:BA': 'Huawei Technologies',
    '34:80:0D': 'ASUS',
    '38:AA:3C': 'Apple Inc.',
    '3C:71:BF': 'Motorola Mobility',
    '40:6C:8F': 'Huawei Technologies',
    '44:48:34': 'OPPO Electronics',
    '44:65:0D': 'Apple Inc.',
    '48:0F:CF': 'Samsung Electronics',
    '48:4B:AA': 'Liteon Technology',
    '50:64:2B': 'Samsung Electronics',
    '50:F5:DA': 'Xiaomi Corporation',
    '52:54:00': 'QEMU',
    '54:26:96': 'Samsung Electronics',
    '54:AB:3A': 'Samsung Electronics',
    '56:E4:6B': 'Broadcom',
    '58:1B:9D': 'Apple Inc.',
    '5C:F3:70': 'HTC',
    '60:D0:F0': 'HTC',
    '64:09:80': 'Motorola Mobility',
    '68:96:0B': 'Broadcom',
    '6C:AD:F8': 'Intel Corporation',
    '70:F1:A1': 'LG Electronics',
    '74:B0:35': 'HTC',
    '78:02:F0': 'Samsung Electronics',
    '78:7E:61': 'Broadcom',
    '7C:D3:0A': 'Microsoft Corporation',
    '80:12:28': 'NETGEAR',
    '80:35:C1': 'D-Link Corporation',
    '84:16:F9': 'Intel Corporation',
    '84:71:27': 'TP-Link',
    '88:41:FC': 'Apple Inc.',
    '8C:89:A5': 'Google Inc.',
    '90:27:E4': 'Huawei Technologies',
    '90:B6:86': 'TP-Link',
    '94:65:2D': 'NETGEAR',
    '94:87:E0': 'Liteon Technology',
    '98:FA:9B': 'Apple Inc.',
    '9C:35:EB': 'Samsung Electronics',
    'A0:36:BC': 'ASUS',
    'A0:CE:C8': 'Huawei Technologies',
    'A4:4E:31': 'Xiaomi Corporation',
    'A8:5E:60': 'Apple Inc.',
    'AC:2B:6E': 'NETGEAR',
    'AC:9B:0A': 'Apple Inc.',
    'AE:AB:BB': 'QEMU',
    'B0:95:75': 'Samsung Electronics',
    'B4:85:34': 'HTC',
    'B8:27:EB': 'Raspberry Pi Foundation',
    'B8:86:BF': 'Samsung Electronics',
    'BC:54:3D': 'Broadcom',
    'C0:9F:42': 'Motorola Mobility',
    'C4:41:1E': 'Samsung Electronics',
    'C8:3A:6B': 'Broadcom',
    'CC:4D:E5': 'Samsung Electronics',
    'D0:3B:F3': 'Broadcom',
    'D4:13:E5': 'NETGEAR',
    'D4:6E:0E': 'Broadcom',
    'D8:80:39': 'Apple Inc.',
    'DC:27:71': 'Apple Inc.',
    'DC:A9:04': 'NETGEAR',
    'DC:EE:06': 'Apple Inc.',
    'E0:55:3D': 'Samsung Electronics',
    'E4:CE:8F': 'NETGEAR',
    'E8:47:3A': 'HTC',
    'E8:8D:28': 'Intel Corporation',
    'E8:99:D0': 'Broadcom',
    'EC:A8:6B': 'Apple Inc.',
    'F0:27:65': 'Samsung Electronics',
    'F0:98:9D': 'TP-Link',
    'F4:43:47': 'Apple Inc.',
    'F4:CA:E5': 'Broadcom',
    'F8:37:B2': 'HTC',
    'F8:FF:C2': 'Sony Corporation',
    'FC:AA:14': 'Apple Inc.',
    'FE:41:C6': 'Broadcom',
}

# CVE Database (Local mapping - device signature to known vulnerabilities)
CVE_DATABASE = {
    'Hikvision': [
        {'cve': 'CVE-2021-36260', 'severity': 'Critical', 'description': 'Authentication bypass in IPv6'},
        {'cve': 'CVE-2019-5250', 'severity': 'High', 'description': 'SQL injection vulnerability'},
    ],
    'Espressif': [
        {'cve': 'CVE-2020-15700', 'severity': 'Medium', 'description': 'WPA2 implementation weakness'},
    ],
    'TP-Link': [
        {'cve': 'CVE-2020-9377', 'severity': 'High', 'description': 'Command injection via HTTP'},
    ],
    'default': [
        {'cve': 'Default Credentials', 'severity': 'High', 'description': 'Device uses default/weak credentials'},
    ],
}

# Risk Severity Levels
RISK_LEVELS = {
    'Extremely High (Critical)': {'color': '#9c27b0', 'score': 12.0},
    'Critical': {'color': '#d32f2f', 'score': 9.0},
    'High': {'color': '#f57c00', 'score': 7.0},
    'Medium': {'color': '#fbc02d', 'score': 5.0},
    'Low': {'color': '#689f38', 'score': 3.0},
    'Safe': {'color': '#388e3c', 'score': 0.0},
    'Info': {'color': '#1976d2', 'score': 1.0},
}

# Log Configuration
LOG_CONFIG = {
    'level': 'INFO',
    'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
}

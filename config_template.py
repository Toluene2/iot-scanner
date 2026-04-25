"""
Advanced Configuration Template
Copy this file as config_custom.py and modify for your specific needs
"""

# ============================================================================
# SCANNING PROFILES - Choose or create your own
# ============================================================================

SCAN_PROFILES = {
    'aggressive': {
        'timeout': "500ms",  # Added "ms" explicitly
        'port_timeout': "500ms",  # Added "ms" explicitly
        'retry_count': 2,
        'max_threads': 10,
        'description': 'Fast scan, may stress devices'
    },

    'balanced': {
        'timeout': "1000ms",  # Added "ms" explicitly
        'port_timeout': "1000ms",  # Added "ms" explicitly
        'retry_count': 1,
        'max_threads': 5,
        'description': 'Default safe scan'
    },

    'conservative': {
        'timeout': "2000ms",
        'port_timeout': "2000ms",
        'retry_count': 1,
        'max_threads': 2,
        'description': 'Slow, safe for fragile devices'
    },

    'stealth': {
        'timeout': "5000ms",
        'port_timeout': "5000ms",
        'retry_count': 0,
        'max_threads': 1,
        'description': 'Ultra-conservative, minimal impact'
    }
}

# ============================================================================
# NETWORK PROFILES - Define subnets for your campus
# ============================================================================

NETWORK_PROFILES = {
    'adeleke_building_a': {
        'subnet': '192.168.100.0/24',
        'description': 'Building A - First Floor IoT',
        'max_hosts': 254,
    },
    
    'adeleke_building_b': {
        'subnet': '192.168.101.0/24',
        'description': 'Building B - Second Floor IoT',
        'max_hosts': 254,
    },
    
    'adeleke_building_c': {
        'subnet': '192.168.102.0/24',
        'description': 'Building C - Third Floor IoT',
        'max_hosts': 254,
    },
    
    'test_network': {
        'subnet': '192.168.1.0/24',
        'description': 'Test/Demo Network',
        'max_hosts': 254,
    }
}

# ============================================================================
# DEVICE PROFILES - Specific IoT device configurations
# ============================================================================

DEVICE_PROFILES = {
    'hikvision_camera': {
        'ports': [80, 443, 554, 8000, 8080, 8443],
        'protocols': ['http', 'https', 'rtsp'],
        'default_creds': [
            ('admin', 'admin'),
            ('admin', '12345'),
            ('admin', 'hikvision'),
        ]
    },
    
    'tp_link_device': {
        'ports': [80, 443, 1883, 8080, 8443],
        'protocols': ['http', 'https', 'mqtt'],
        'default_creds': [
            ('admin', 'admin'),
            ('admin', '1234'),
        ]
    },
    
    'esp32_device': {
        'ports': [80, 443, 8080],
        'protocols': ['http', 'https'],
        'default_creds': [
            ('admin', 'admin'),
            ('admin', 'password'),
        ]
    },
    
    'generic_iot': {
        'ports': [23, 80, 443, 554, 1883, 8080, 8443],
        'protocols': ['telnet', 'http', 'https', 'rtsp', 'mqtt'],
        'default_creds': []  # Will use DEFAULT_CREDENTIALS
    }
}

# ============================================================================
# VULNERABILITY RULES - Custom vulnerability definitions
# ============================================================================

CUSTOM_VULNERABILITIES = [
    {
        'name': 'Weak Default Credentials',
        'severity': 'Critical',
        'description': 'Device accepts well-known default credentials',
        'cves': [],
        'remediation': 'Change all default credentials immediately'
    },
    {
        'name': 'Telnet Service Exposed',
        'severity': 'High',
        'description': 'Unencrypted Telnet service exposed',
        'cves': ['CVE-2019-7314'],
        'remediation': 'Disable Telnet, enable SSH instead'
    },
    {
        'name': 'HTTP without HTTPS',
        'severity': 'Medium',
        'description': 'HTTP traffic not encrypted',
        'cves': [],
        'remediation': 'Enable HTTPS, force HTTP to HTTPS redirect'
    },
    {
        'name': 'Old IoT Device',
        'severity': 'Low',
        'description': 'Device may lack security updates',
        'cves': [],
        'remediation': 'Check manufacturer for firmware updates'
    }
]

# ============================================================================
# REPORTING CONFIGURATION
# ============================================================================

REPORTING_CONFIG = {
    'output_format': 'html',          # html, json, pdf (pdf requires reportlab)
    'include_raw_data': False,        # Include raw scan data in JSON
    'include_recommendations': True,  # Include remediation suggestions
    'theme': 'default',               # default, dark, minimal
    'logo_path': None,                # Path to custom logo image
    'email_reports': False,           # Send via email
    'email_to': [],                   # Email recipients
    'smtp_server': 'smtp.gmail.com',  # SMTP server
    'smtp_port': 587,                 # SMTP port
}

# ============================================================================
# EXPORT FORMATS
# ============================================================================

EXPORT_FORMATS = {
    'html': {
        'enabled': True,
        'directory': 'reports/',
        'filename_format': 'iot_report_{timestamp}.html'
    },
    
    'json': {
        'enabled': False,
        'directory': 'reports/',
        'filename_format': 'iot_results_{timestamp}.json'
    },
    
    'csv': {
        'enabled': False,
        'directory': 'reports/',
        'filename_format': 'iot_vulnerabilities_{timestamp}.csv'
    },
    
    'pdf': {
        'enabled': False,
        'directory': 'reports/',
        'filename_format': 'iot_report_{timestamp}.pdf'
    }
}

# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================

LOGGING_CONFIG = {
    'level': 'INFO',  # DEBUG, INFO, WARNING, ERROR
    'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    'file_logging': True,
    'log_file': 'logs/scanner.log',
    'max_log_size': '10MB',
    'backup_count': 5,
}

# ============================================================================
# INTEGRATION HOOKS - Connect with other tools
# ============================================================================

INTEGRATIONS = {
    'slack': {
        'enabled': False,
        'webhook_url': 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL',
        'send_on_critical': True,
        'send_on_completion': False,
    },
    
    'splunk': {
        'enabled': False,
        'host': 'splunk.example.com',
        'port': 8088,
        'token': 'your-splunk-token',
    },
    
    'elasticsearch': {
        'enabled': False,
        'host': 'elasticsearch.example.com',
        'port': 9200,
        'index': 'iot-vulnerabilities',
    }
}

# ============================================================================
# EXCLUSION LISTS - Devices to skip scanning
# ============================================================================

EXCLUDE_IPS = [
    '192.168.1.1',      # Router
    '192.168.1.2',      # DHCP server
    # Add more IPs to exclude
]

EXCLUDE_MAC_VENDORS = [
    'VMware',           # Virtual machines
    'QEMU',             # QEMU VMs
    # Add vendors to exclude
]

# ============================================================================
# SCHEDULING CONFIGURATION
# ============================================================================

SCHEDULE_CONFIG = {
    'enabled': False,
    'frequency': 'weekly',  # daily, weekly, monthly
    'day_of_week': 'Sunday',  # For weekly
    'time': '02:00',  # UTC time
    'timezone': 'UTC',
    'email_on_completion': True,
    'email_recipients': ['admin@adeleke.edu.ng'],
}

# ============================================================================
# PERFORMANCE TUNING
# ============================================================================

PERFORMANCE = {
    'cache_oui_lookup': True,
    'parallel_scanning': True,
    'max_concurrent_connections': 20,
    'batch_size': 10,
    'use_gpu_acceleration': False,  # If available
}

# ============================================================================
# COMPLIANCE & POLICIES
# ============================================================================

COMPLIANCE = {
    'framework': 'NIST',  # NIST, ISO27001, GDPR
    'retention_days': 90,  # Keep reports for X days
    'audit_logging': True,
    'scan_authorization_required': True,
}

# ============================================================================
# HOW TO USE THIS FILE
# ============================================================================

"""
1. Save this as 'config_custom.py' in the project root
2. Modify the settings for your environment
3. In main.py, import and use:

    from config_custom import SCAN_PROFILES, NETWORK_PROFILES
    
    # Use aggressive profile
    from utils.config import SCAN_CONFIG
    SCAN_CONFIG.update(SCAN_PROFILES['aggressive'])
    
    # Scan using network profile
    network = NETWORK_PROFILES['adeleke_building_a']
    scanner = IoTVulnerabilityScanner(subnet=network['subnet'])
    results = scanner.run_scan()

4. Or pass configuration when creating scanner instances

"""

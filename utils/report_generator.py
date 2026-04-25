"""
Report Generator - Creates HTML reports with Jinja2 templating
"""

import logging
from typing import Dict, List
from jinja2 import Template
from datetime import datetime
from utils.config import RISK_LEVELS

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Generates comprehensive HTML reports from scan results.
    Categorizes findings by risk level and provides executive summary.
    """

    def __init__(self):
        """Initialize report generator"""
        self.report_template = self._get_html_template()
        logger.info("Report Generator initialized")

    def _get_html_template(self) -> Template:
        """
        Get Jinja2 HTML template for vulnerability report.
        
        Returns:
            Jinja2 Template object
        """
        template_str = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IoT Vulnerability Assessment Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.2);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header p {
            font-size: 1.1em;
            opacity: 0.9;
        }
        
        .executive-summary {
            padding: 40px;
            background: #f8f9fa;
            border-bottom: 2px solid #e0e0e0;
        }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        
        .summary-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
        }
        
        .summary-card h3 {
            font-size: 0.9em;
            color: #666;
            margin-bottom: 10px;
            text-transform: uppercase;
        }
        
        .summary-card .value {
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
        }
        
        .risk-level {
            display: inline-block;
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: bold;
            color: white;
            margin-top: 10px;
        }
        
        .severity-breakdown {
            margin-top: 20px;
        }
        
        .severity-bar {
            display: flex;
            gap: 10px;
            margin-top: 10px;
            flex-wrap: wrap;
        }
        
        .severity-item {
            flex: 1;
            min-width: 150px;
            padding: 10px;
            border-radius: 5px;
            color: white;
            font-weight: bold;
            text-align: center;
        }
        
        .critical { background: #d32f2f; }
        .high { background: #f57c00; }
        .medium { background: #fbc02d; color: #333 !important; }
        .low { background: #689f38; }
        .info { background: #1976d2; }
        
        .content {
            padding: 40px;
        }
        
        .section {
            margin-bottom: 40px;
        }
        
        .section h2 {
            font-size: 1.8em;
            color: #333;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid #667eea;
        }
        
        .host-section {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            border-left: 4px solid #667eea;
        }
        
        .host-title {
            font-size: 1.3em;
            font-weight: bold;
            color: #333;
            margin-bottom: 15px;
        }
        
        .host-details {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 15px;
        }
        
        .detail-item {
            font-size: 0.95em;
        }
        
        .detail-label {
            color: #666;
            font-weight: bold;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        
        th {
            background: #667eea;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: bold;
        }
        
        td {
            padding: 12px;
            border-bottom: 1px solid #ddd;
        }
        
        tr:hover {
            background: #f5f5f5;
        }
        
        .vuln-critical {
            background: #ffebee;
            border-left: 4px solid #d32f2f;
        }
        
        .vuln-high {
            background: #fff3e0;
            border-left: 4px solid #f57c00;
        }
        
        .vuln-medium {
            background: #fffde7;
            border-left: 4px solid #fbc02d;
        }
        
        .vuln-low {
            background: #f1f8e9;
            border-left: 4px solid #689f38;
        }
        
        .risk-badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
            color: #fff;
            text-transform: uppercase;
        }
        
        .risk-Extremely-High-Critical { background-color: #9c27b0; }
        .risk-Critical { background-color: #d32f2f; }
        .risk-High { background-color: #f57c00; }
        .risk-Medium { background-color: #fbc02d; color: #000; }
        .risk-Low { background-color: #689f38; }
        .risk-Safe { background-color: #388e3c; }

        .timestamp {
            text-align: center;
            padding: 20px;
            color: #999;
            font-size: 0.9em;
            border-top: 1px solid #e0e0e0;
            margin-top: 40px;
        }
        
        .no-data {
            text-align: center;
            padding: 40px;
            color: #999;
            font-size: 1.1em;
        }
        
        .recommendation {
            background: #e3f2fd;
            border-left: 4px solid #1976d2;
            padding: 15px;
            margin-top: 15px;
            border-radius: 4px;
            font-size: 0.95em;
        }
        
        .recommendation strong {
            color: #1565c0;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 IoT Vulnerability Assessment Report</h1>
            <p>Smart Campus Security Audit - Adeleke University</p>
        </div>
        
        <div class="executive-summary">
            <h2 style="margin: 0 0 20px 0; border: none; font-size: 1.5em;">Executive Summary</h2>
            
            <div class="summary-grid">
                <div class="summary-card">
                    <h3>Total Hosts Scanned</h3>
                    <div class="value">{{ scan_summary.total_hosts }}</div>
                </div>
                <div class="summary-card">
                    <h3>Hosts with Vulnerabilities</h3>
                    <div class="value">{{ scan_summary.vulnerable_hosts }}</div>
                </div>
                <div class="summary-card">
                    <h3>Total Vulnerabilities</h3>
                    <div class="value">{{ scan_summary.total_vulnerabilities }}</div>
                </div>
                <div class="summary-card">
                    <h3>Overall Risk Level</h3>
                    <div style="font-size: 1.5em; margin-top: 10px;">
                        <span class="risk-level" style="background: {{ risk_color }};">
                            {{ scan_summary.risk_level }} ({{ scan_summary.risk_score }}/100)
                        </span>
                    </div>
                </div>
            </div>
            
            {% if scan_summary.severity_breakdown %}
            <div class="severity-breakdown">
                <h3 style="margin: 0 0 15px 0;">Severity Breakdown</h3>
                <div class="severity-bar">
                    {% if scan_summary.severity_breakdown.Critical > 0 %}
                    <div class="severity-item critical">
                        Critical: {{ scan_summary.severity_breakdown.Critical }}
                    </div>
                    {% endif %}
                    {% if scan_summary.severity_breakdown.High > 0 %}
                    <div class="severity-item high">
                        High: {{ scan_summary.severity_breakdown.High }}
                    </div>
                    {% endif %}
                    {% if scan_summary.severity_breakdown.Medium > 0 %}
                    <div class="severity-item medium">
                        Medium: {{ scan_summary.severity_breakdown.Medium }}
                    </div>
                    {% endif %}
                    {% if scan_summary.severity_breakdown.Low > 0 %}
                    <div class="severity-item low">
                        Low: {{ scan_summary.severity_breakdown.Low }}
                    </div>
                    {% endif %}
                </div>
            </div>
            {% endif %}
        </div>
        
        <div class="content">
            {% if security_posture %}
            <div class="section">
                <h2>📊 Device Security Posture Analysis</h2>
                <div class="host-grid">
                    {% for host in security_posture %}
                    <div class="host-card">
                        <div class="host-title">
                            {{ host.ip }} 
                            <span class="risk-badge risk-{{ host.risk_level | replace(' ', '-') | replace('(', '') | replace(')', '') }}">{{ host.risk_level }}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Device:</span> {{ host.device_type }}
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">MAC:</span> {{ host.mac }}
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Ports:</span> {{ host.open_ports | join(', ') }}
                        </div>
                        
                        {% if host.risk_factors %}
                        <div style="margin-top: 10px;">
                            <strong>Risk Factors:</strong>
                            <ul style="margin: 5px 0; padding-left: 20px; color: #d32f2f; font-size: 0.9em;">
                                {% for factor in host.risk_factors %}
                                <li>{{ factor }}</li>
                                {% endfor %}
                            </ul>
                        </div>
                        {% endif %}
                        
                        <div class="recommendation" style="margin-top: 10px; font-style: italic;">
                            <strong>Recommendation:</strong> {{ host.recommendation }}
                        </div>
                    </div>
                    {% endfor %}
                </div>
            </div>
            {% endif %}

            {% if scan_summary.total_vulnerabilities > 0 %}
            
            <!-- Critical Vulnerabilities -->
            {% if critical_vulns %}
            <div class="section">
                <h2 style="color: #d32f2f;">🚨 Critical Vulnerabilities</h2>
                {% for vuln in critical_vulns %}
                <div class="host-section vuln-critical">
                    <div class="host-title">{{ vuln.host }} : {{ vuln.port if vuln.port else 'N/A' }}</div>
                    <div class="detail-item">
                        <span class="detail-label">Type:</span> {{ vuln.type | replace('_', ' ') | title }}
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Details:</span> {{ vuln.details }}
                    </div>
                    <div class="recommendation">
                        <strong>Immediate Action Required:</strong> This vulnerability poses a critical risk and should be remediated immediately. Consider isolating the affected device until patches are applied.
                    </div>
                </div>
                {% endfor %}
            </div>
            {% endif %}
            
            <!-- High Vulnerabilities -->
            {% if high_vulns %}
            <div class="section">
                <h2 style="color: #f57c00;">⚠️ High Severity Vulnerabilities</h2>
                {% for vuln in high_vulns %}
                <div class="host-section vuln-high">
                    <div class="host-title">{{ vuln.host }} : {{ vuln.port if vuln.port else 'N/A' }}</div>
                    <div class="detail-item">
                        <span class="detail-label">Type:</span> {{ vuln.type | replace('_', ' ') | title }}
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Details:</span> {{ vuln.details }}
                    </div>
                </div>
                {% endfor %}
            </div>
            {% endif %}
            
            <!-- Medium Vulnerabilities -->
            {% if medium_vulns %}
            <div class="section">
                <h2 style="color: #fbc02d;">📋 Medium Severity Vulnerabilities</h2>
                {% for vuln in medium_vulns %}
                <div class="host-section vuln-medium">
                    <div class="host-title">{{ vuln.host }} : {{ vuln.port if vuln.port else 'N/A' }}</div>
                    <div class="detail-item">
                        <span class="detail-label">Type:</span> {{ vuln.type | replace('_', ' ') | title }}
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Details:</span> {{ vuln.details }}
                    </div>
                </div>
                {% endfor %}
            </div>
            {% endif %}
            
            <!-- Low Vulnerabilities -->
            {% if low_vulns %}
            <div class="section">
                <h2 style="color: #689f38;">ℹ️ Low Severity Vulnerabilities</h2>
                {% for vuln in low_vulns %}
                <div class="host-section vuln-low">
                    <div class="host-title">{{ vuln.host }} : {{ vuln.port if vuln.port else 'N/A' }}</div>
                    <div class="detail-item">
                        <span class="detail-label">Type:</span> {{ vuln.type | replace('_', ' ') | title }}
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Details:</span> {{ vuln.details }}
                    </div>
                </div>
                {% endfor %}
            </div>
            {% endif %}
            
            {% else %}
            <div class="section">
                <div class="no-data">
                    <p>✅ No critical vulnerabilities detected during this scan.</p>
                    <p style="margin-top: 10px; font-size: 0.9em;">Continue monitoring and maintain regular security updates.</p>
                </div>
            </div>
            {% endif %}
            
            <!-- Discovered Hosts -->
            <div class="section">
                <h2>📡 Discovered Hosts & Services</h2>
                {% for host, details in hosts_summary.items() %}
                <div class="host-section">
                    <div class="host-title">{{ details.display_name }} ({{ host }})</div>
                    <div class="host-details">
                        <div class="detail-item">
                            <span class="detail-label">MAC Address:</span> {{ details.mac }}
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Manufacturer:</span> {{ details.manufacturer }}
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Open Ports:</span> 
                            {% if details.open_ports %}
                                {{ details.open_ports | join(', ') }}
                            {% else %}
                                None detected
                            {% endif %}
                        </div>
                    </div>
                </div>
                {% endfor %}
            </div>
        </div>
        
        <div class="timestamp">
            <p>Report Generated: {{ timestamp }}</p>
            <p>Scan Configuration: Safe, Non-Intrusive Assessment</p>
            <p>Scanner: IoT Vulnerability Scanner v1.0 - Adeleke University Smart Campus</p>
        </div>
    </div>
</body>
</html>
        """
        return Template(template_str)

    def generate_report(self, recon_results: Dict, fingerprint_results: Dict,
                       assessment_results: Dict, vulnerabilities: List,
                       security_posture: List = None, device_objects: Dict = None) -> str:
        """
        Generate comprehensive HTML report from all scan results.
        
        Args:
            recon_results: Results from reconnaissance module
            fingerprint_results: Results from fingerprinting module
            assessment_results: Results from vulnerability assessment module
            vulnerabilities: List of identified vulnerabilities
            security_posture: List of security posture analysis results
            device_objects: Dictionary of Device Objects keyed by MAC
            
        Returns:
            HTML report as string
        """
        logger.info("Generating HTML report")
        
        # Build hosts summary based on Device Objects if available
        hosts_summary = {}
        hosts_with_ports = recon_results.get('port_scan', {})
        
        if device_objects:
            for mac, dev in device_objects.items():
                # Filter out infrastructure if needed, or flag them
                prefix = "[INFRA] " if dev.get('is_infrastructure') else ""
                
                hosts_summary[dev['ip']] = {
                    'mac': dev['mac'],
                    'manufacturer': dev['manufacturer'],
                    'display_name': prefix + dev['display_name'],
                    'open_ports': sorted(list(dev['open_ports'].keys()))
                }
        else:
            # Fallback to old method if device_objects not provided
            hosts_with_ports = recon_results.get('port_scan', {})
            for host, host_data in hosts_with_ports.items():
                oui_info = host_data.get('oui_info', {})
                manufacturer = oui_info.get('manufacturer', 'Unknown')
                
                open_ports_list = list(host_data.get('open_ports', {}).keys())
                
                hosts_summary[host] = {
                    'mac': host_data.get('mac', 'Unknown'),
                    'manufacturer': manufacturer,
                    'display_name': host,
                    'open_ports': sorted(open_ports_list)
                }
        
        # Categorize vulnerabilities by severity
        critical_vulns = [v for v in vulnerabilities if v.get('severity') == 'Critical']
        high_vulns = [v for v in vulnerabilities if v.get('severity') == 'High']
        medium_vulns = [v for v in vulnerabilities if v.get('severity') == 'Medium']
        low_vulns = [v for v in vulnerabilities if v.get('severity') == 'Low']
        
        # Count unique vulnerable hosts
        vulnerable_hosts = set()
        for vuln in vulnerabilities:
            vulnerable_hosts.add(vuln.get('host'))
        
        # Build scan summary
        risk_assessment = assessment_results.get('risk_assessment', {})
        risk_level = risk_assessment.get('risk_level', 'Low')
        
        # Use device_objects count if available, otherwise fall back to hosts_with_ports
        total_hosts = len(device_objects) if device_objects else len(hosts_with_ports)
        
        scan_summary = {
            'total_hosts': total_hosts,
            'vulnerable_hosts': len(vulnerable_hosts),
            'total_vulnerabilities': len(vulnerabilities),
            'risk_level': risk_level,
            'risk_score': risk_assessment.get('risk_score', 0),
            'severity_breakdown': risk_assessment.get('severity_breakdown', {})
        }
        
        # Determine risk color
        risk_color = RISK_LEVELS.get(risk_level, {}).get('color', '#689f38')
        
        # Render template
        html_report = self.report_template.render(
            scan_summary=scan_summary,
            critical_vulns=critical_vulns,
            high_vulns=high_vulns,
            medium_vulns=medium_vulns,
            low_vulns=low_vulns,
            hosts_summary=hosts_summary,
            security_posture=security_posture,
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            risk_color=risk_color
        )
        
        logger.info("HTML report generated successfully")
        return html_report

    def save_report(self, html_content: str, filename: str = None) -> str:
        """
        Save HTML report to file.
        
        Args:
            html_content: HTML content as string
            filename: Output filename (optional)
            
        Returns:
            Path to saved report
        """
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"reports/iot_vulnerability_report_{timestamp}.html"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f"Report saved to: {filename}")
            return filename
            
        except Exception as e:
            logger.error(f"Error saving report: {e}")
            return None

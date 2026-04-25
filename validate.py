#!/usr/bin/env python3
"""
Validation and Testing Script
Verifies scanner installation and components
"""

import sys
import subprocess
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


class ScannerValidator:
    """Validates IoT Vulnerability Scanner installation"""
    
    def __init__(self):
        self.checks_passed = 0
        self.checks_failed = 0
        self.warnings = []
    
    def check_python_version(self):
        """Verify Python 3.7+"""
        logger.info("\n[1/8] Checking Python version...")
        version = sys.version_info
        
        if version.major >= 3 and version.minor >= 7:
            logger.info(f"✓ Python {version.major}.{version.minor}.{version.micro} OK")
            self.checks_passed += 1
            return True
        else:
            logger.error(f"✗ Python {version.major}.{version.minor} is too old (need 3.7+)")
            self.checks_failed += 1
            return False
    
    def check_nmap_installed(self):
        """Verify Nmap is installed"""
        logger.info("\n[2/8] Checking Nmap installation...")
        
        try:
            result = subprocess.run(
                ['nmap', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                version_line = result.stdout.split('\n')[0]
                logger.info(f"✓ {version_line}")
                self.checks_passed += 1
                return True
            else:
                logger.error("✗ Nmap found but failed to run")
                self.checks_failed += 1
                return False
                
        except FileNotFoundError:
            logger.error("✗ Nmap not found in PATH")
            logger.info("  Install with: sudo apt-get install nmap (Linux)")
            logger.info("               brew install nmap (macOS)")
            logger.info("               Download from nmap.org (Windows)")
            self.checks_failed += 1
            return False
        except Exception as e:
            logger.error(f"✗ Error checking Nmap: {e}")
            self.checks_failed += 1
            return False
    
    def check_python_packages(self):
        """Verify required Python packages"""
        logger.info("\n[3/8] Checking Python packages...")
        
        required_packages = {
            'nmap': 'python-nmap',
            'scapy': 'scapy',
            'requests': 'requests',
            'jinja2': 'jinja2',
        }
        
        all_ok = True
        
        for module_name, package_name in required_packages.items():
            try:
                __import__(module_name)
                logger.info(f"✓ {package_name} OK")
                self.checks_passed += 1
            except ImportError:
                logger.error(f"✗ {package_name} not installed")
                logger.info(f"  Install with: pip install {package_name}")
                self.checks_failed += 1
                all_ok = False
        
        return all_ok
    
    def check_project_structure(self):
        """Verify project directory structure"""
        logger.info("\n[4/8] Checking project structure...")
        
        required_files = [
            'main.py',
            'requirements.txt',
            'README.md',
            'utils/config.py',
            'utils/report_generator.py',
            'modules/reconnaissance.py',
            'modules/fingerprinting.py',
            'modules/assessment.py',
        ]
        
        all_ok = True
        root = Path(__file__).parent
        
        for file_path in required_files:
            full_path = root / file_path
            if full_path.exists():
                logger.info(f"✓ {file_path}")
                self.checks_passed += 1
            else:
                logger.error(f"✗ {file_path} missing")
                self.checks_failed += 1
                all_ok = False
        
        return all_ok
    
    def check_reports_directory(self):
        """Verify reports directory exists or can be created"""
        logger.info("\n[5/8] Checking reports directory...")
        
        reports_dir = Path(__file__).parent / 'reports'
        
        if reports_dir.exists():
            logger.info(f"✓ Reports directory exists: {reports_dir}")
            self.checks_passed += 1
            return True
        else:
            try:
                reports_dir.mkdir(exist_ok=True)
                logger.info(f"✓ Reports directory created: {reports_dir}")
                self.checks_passed += 1
                return True
            except Exception as e:
                logger.error(f"✗ Cannot create reports directory: {e}")
                self.checks_failed += 1
                return False
    
    def check_network_connectivity(self):
        """Verify basic network connectivity"""
        logger.info("\n[6/8] Checking network connectivity...")
        
        try:
            # Try to ping Google DNS (non-invasive check)
            result = subprocess.run(
                ['ping', '-c', '1', '8.8.8.8'],
                capture_output=True,
                timeout=3
            )
            
            if result.returncode == 0:
                logger.info("✓ Network connectivity OK")
                self.checks_passed += 1
                return True
            else:
                logger.warning("⚠ Network connectivity check failed (may be expected)")
                self.warnings.append("Network unreachable - some features may not work")
                self.checks_passed += 1
                return True
                
        except FileNotFoundError:
            logger.warning("⚠ ping command not found (expected on some systems)")
            self.warnings.append("Cannot verify network with ping - manual verification needed")
            self.checks_passed += 1
            return True
        except Exception as e:
            logger.warning(f"⚠ Network check skipped: {e}")
            self.warnings.append("Could not verify network connectivity")
            self.checks_passed += 1
            return True
    
    def check_module_imports(self):
        """Verify all modules can be imported"""
        logger.info("\n[7/8] Checking module imports...")
        
        sys.path.insert(0, str(Path(__file__).parent))
        
        modules_to_check = [
            ('modules.reconnaissance', 'ReconnaissanceModule'),
            ('modules.fingerprinting', 'FingerprintingModule'),
            ('modules.assessment', 'VulnerabilityAssessmentModule'),
            ('utils.report_generator', 'ReportGenerator'),
            ('utils.config', 'IOT_PORTS'),
        ]
        
        all_ok = True
        
        for module_name, item_name in modules_to_check:
            try:
                module = __import__(module_name, fromlist=[item_name])
                getattr(module, item_name)
                logger.info(f"✓ {module_name}.{item_name}")
                self.checks_passed += 1
            except Exception as e:
                logger.error(f"✗ {module_name}.{item_name}: {e}")
                self.checks_failed += 1
                all_ok = False
        
        return all_ok
    
    def check_permissions(self):
        """Check necessary permissions"""
        logger.info("\n[8/8] Checking permissions...")
        
        try:
            # Check if we can write to reports directory
            reports_dir = Path(__file__).parent / 'reports'
            test_file = reports_dir / '.permission_test'
            
            with open(test_file, 'w') as f:
                f.write('test')
            test_file.unlink()
            
            logger.info("✓ Write permissions OK")
            self.checks_passed += 1
            return True
            
        except PermissionError:
            logger.error("✗ No write permissions in reports directory")
            logger.info("  Try: sudo chown -R $USER .")
            self.checks_failed += 1
            return False
        except Exception as e:
            logger.warning(f"⚠ Permission check inconclusive: {e}")
            self.warnings.append(f"Permission check: {e}")
            self.checks_passed += 1
            return True
    
    def run_all_checks(self):
        """Run all validation checks"""
        print("""
╔══════════════════════════════════════════════════════════════╗
║  IoT Vulnerability Scanner - Installation Validator          ║
║  Adeleke University Smart Campus                             ║
╚══════════════════════════════════════════════════════════════╝
        """)
        
        self.check_python_version()
        self.check_nmap_installed()
        self.check_python_packages()
        self.check_project_structure()
        self.check_reports_directory()
        self.check_network_connectivity()
        self.check_module_imports()
        self.check_permissions()
        
        self.print_summary()
        
        # Return exit code
        return 0 if self.checks_failed == 0 else 1
    
    def print_summary(self):
        """Print validation summary"""
        total = self.checks_passed + self.checks_failed
        
        print("\n" + "="*60)
        print("VALIDATION SUMMARY")
        print("="*60)
        print(f"Checks Passed: {self.checks_passed}/{total}")
        print(f"Checks Failed: {self.checks_failed}/{total}")
        
        if self.warnings:
            print(f"\nWarnings: {len(self.warnings)}")
            for warning in self.warnings:
                print(f"  ⚠ {warning}")
        
        print("="*60)
        
        if self.checks_failed == 0:
            print("\n✅ All checks passed! Scanner is ready to use.")
            print("\nQuick start:")
            print("  python main.py -s 192.168.1.0/24")
        else:
            print(f"\n❌ {self.checks_failed} check(s) failed. See errors above.")
            print("\nPlease fix these issues before running the scanner.")
        
        print("="*60)


def main():
    """Main entry point"""
    validator = ScannerValidator()
    return validator.run_all_checks()


if __name__ == '__main__':
    sys.exit(main())

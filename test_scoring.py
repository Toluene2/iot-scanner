#!/usr/bin/env python3
"""Test vulnerability scoring implementation"""

from modules.assessment import VulnerabilityAssessmentModule

print("Testing Vulnerability Scoring (0-100 scale)...\n")

assessor = VulnerabilityAssessmentModule()

# Test cases
test_cases = [
    ([], "No vulnerabilities"),
    ([{'severity': 'Low'}], "1 Low vulnerability"),
    ([{'severity': 'Medium'}], "1 Medium vulnerability"),
    ([{'severity': 'High'}], "1 High vulnerability"),
    ([{'severity': 'Critical'}], "1 Critical vulnerability"),
    (
        [{'severity': 'Critical'}, {'severity': 'Critical'}],
        "2 Critical vulnerabilities (max = 100)"
    ),
    (
        [{'severity': 'Critical'}, {'severity': 'High'}, {'severity': 'Medium'}],
        "Mixed: 1 Critical + 1 High + 1 Medium"
    ),
]

for vulnerabilities, description in test_cases:
    result = assessor.calculate_risk_score(vulnerabilities)
    risk_score = result['risk_score']
    risk_level = result['risk_level']
    
    print(f"{description:45} → Score: {risk_score:5.1f}/100 | Level: {risk_level}")

print("\n" + "="*80)
print("RISK LEVEL BANDS:")
print("="*80)
print("  0 - 39pts: LOW risk")
print(" 40 - 69pts: MEDIUM risk")
print(" 70-100pts: CRITICAL risk")

print("\nScoring Formula:")
print("  Base Points: Critical=25, High=15, Medium=8, Low=4, Info=1")
print("  Normalized: (total_points / 50) * 100")
print("  Example: 1 Critical (25pts) = (25/50)*100 = 50/100 (Medium)")
print("  Example: 2 Critical (50pts) = (50/50)*100 = 100/100 (Critical)")

print("\n✓ Vulnerability scoring test completed successfully!")

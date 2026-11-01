
import sys
import os

# Add backend directory to Python path
sys.path.insert(
    0,
    os.path.dirname(os.path.abspath(__file__))
)

from app.services.risk_engine import risk_engine


test_cases = [
    {
        "name": "Clean File",
        "static": {
            "entropy": 5.0,
            "obfuscation_indicators": [],
            "imported_apis": [],
            "suspicious_strings": [],
        },
        "yara": [],
        "ml": {
            "classification": "Benign",
            "is_malicious": False,
            "class_probabilities": {
                "Benign": 0.98,
                "Malicious": 0.02,
            },
            "model_name": "Test Model",
        },
        "vt": None,
    },
    {
        "name": "Suspicious File",
        "static": {
            "entropy": 7.2,
            "obfuscation_indicators": ["packed_section"],
            "imported_apis": [],
            "suspicious_strings": [],
        },
        "yara": [
            {
                "rule_name": "Suspicious_Test_Rule",
                "severity": "Medium",
            }
        ],
        "ml": {
            "classification": "Benign",
            "is_malicious": False,
            "class_probabilities": {
                "Benign": 0.60,
                "Malicious": 0.40,
            },
            "model_name": "Test Model",
        },
        "vt": None,
    },
    {
        "name": "Malicious File",
        "static": {
            "entropy": 7.6,
            "obfuscation_indicators": [
                "packed_section",
                "suspicious_structure",
            ],
            "imported_apis": ["VirtualAlloc", "WriteProcessMemory"],
            "suspicious_strings": ["suspicious_command"],
        },
        "yara": [
            {
                "rule_name": "Test_High_Severity",
                "severity": "High",
            }
        ],
        "ml": {
            "classification": "Malicious",
            "is_malicious": True,
            "class_probabilities": {
                "Benign": 0.05,
                "Malicious": 0.95,
            },
            "model_name": "Test Model",
        },
        "vt": None,
    },
    {
        "name": "Critical Risk File",
        "static": {
            "entropy": 7.9,
            "obfuscation_indicators": [
                "packed_section",
                "suspicious_structure",
            ],
            "imported_apis": [
                "VirtualAlloc",
                "WriteProcessMemory",
                "CreateRemoteThread",
            ],
            "suspicious_strings": [
                "suspicious_command",
                "encoded_payload",
            ],
        },
        "yara": [
            {
                "rule_name": "Test_Critical_Severity",
                "severity": "Critical",
            }
        ],
        "ml": {
            "classification": "Malicious",
            "is_malicious": True,
            "class_probabilities": {
                "Benign": 0.01,
                "Malicious": 0.99,
            },
            "model_name": "Test Model",
        },
        "vt": None,
    },
    {
        "name": "Unknown File",
        "static": {
            "entropy": 5.0,
            "obfuscation_indicators": [],
            "imported_apis": [],
            "suspicious_strings": [],
        },
        "yara": [],
        "ml": None,
        "vt": None,
    },
]


print("\n========== THREATLENS RISK ENGINE TEST ==========\n")

for test in test_cases:
    result = risk_engine.calculate_risk(
        static_analysis=test["static"],
        yara_matches=test["yara"],
        ml_prediction=test["ml"],
        vt_result=test["vt"],
    )

    print("TEST:", test["name"])
    print("Risk Score:", result["risk_score"])
    print("Risk Level:", result["risk_level"])
    print("Reasons:")

    for reason in result["reasons"]:
        print(" -", reason)

    print("Recommendations:")

    for recommendation in result["recommended_actions"]:
        print(" -", recommendation)

    print("-" * 55)

print("\nAll test scenarios executed.")

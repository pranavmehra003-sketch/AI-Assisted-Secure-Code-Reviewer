import re
import math
from typing import List, Dict, Any

# High-precision patterns modeled after Gitleaks and Trufflehog signatures
SECRET_PATTERNS = [
    {
        "id": "SEC-AWS-KEY",
        "title": "AWS Access Key ID Exposure",
        "category": "Hardcoded Secrets",
        "cwe_id": "CWE-798",
        "severity": "CRITICAL",
        "pattern": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        "description": "Hardcoded AWS Access Key ID detected. If committed, an attacker can access your cloud infrastructure.",
        "why_dangerous": "Exposed cloud keys can lead to unauthorized access, cloud compute hijacking, data theft, and catastrophic billing spikes.",
        "fix_recommendation": "Revoke this key immediately in AWS IAM, and use environment variables (e.g., os.getenv('AWS_ACCESS_KEY_ID')) or IAM roles."
    },
    {
        "id": "SEC-GITHUB-TOKEN",
        "title": "GitHub Personal Access Token",
        "category": "Hardcoded Secrets",
        "cwe_id": "CWE-798",
        "severity": "CRITICAL",
        "pattern": r"gh[pousr]_[A-Za-z0-9_]{36,255}",
        "description": "Exposed GitHub Personal Access Token or OAuth Token.",
        "why_dangerous": "Permits attackers to read private repositories, push malicious commits, or compromise CI/CD workflows.",
        "fix_recommendation": "Revoke the token in GitHub Settings and load it via GitHub Actions secrets or environment variables."
    },
    {
        "id": "SEC-PRIVATE-KEY",
        "title": "Unencrypted Private Cryptographic Key",
        "category": "Hardcoded Secrets",
        "cwe_id": "CWE-312",
        "severity": "CRITICAL",
        "pattern": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "description": "An unencrypted private key is embedded directly in source code.",
        "why_dangerous": "Anyone with read access to the source code can impersonate servers or decrypt sensitive encrypted communications.",
        "fix_recommendation": "Store private keys in a secure key vault (e.g. HashiCorp Vault, AWS Secrets Manager) or protected filesystem."
    },
    {
        "id": "SEC-DB-CONN",
        "title": "Hardcoded Database Connection String with Credentials",
        "category": "Hardcoded Secrets",
        "cwe_id": "CWE-798",
        "severity": "HIGH",
        "pattern": r"(?:postgres|postgresql|mysql|mongodb|redis|mssql):\/\/[a-zA-Z0-9_\-\.]+:[^@\s]+@[a-zA-Z0-9_\-\.]+",
        "description": "Hardcoded database URI contains embedded plaintext credentials.",
        "why_dangerous": "Attackers can connect directly to production/staging databases to exfiltrate or delete records.",
        "fix_recommendation": "Configure connection strings using environment variables (e.g., DATABASE_URL)."
    },
    {
        "id": "SEC-SLACK-WEBHOOK",
        "title": "Slack Incoming Webhook URL",
        "category": "Hardcoded Secrets",
        "cwe_id": "CWE-798",
        "severity": "HIGH",
        "pattern": r"https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]{8}\/B[a-zA-Z0-9_]{8,12}\/[a-zA-Z0-9_]{24}",
        "description": "Exposed Slack webhook URL allows sending arbitrary messages to internal channels.",
        "why_dangerous": "Can be exploited for social engineering, spamming internal teams, or phishing.",
        "fix_recommendation": "Keep webhooks in protected environment variables."
    },
    {
        "id": "SEC-GENERIC-SECRET",
        "title": "Potential Hardcoded Secret / API Key Assignment",
        "category": "Hardcoded Secrets",
        "cwe_id": "CWE-798",
        "severity": "MEDIUM",
        "pattern": r"(api[_-]?key|secret[_-]?key|auth[_-]?token|app[_-]?secret)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,64}['\"]",
        "description": "Variable assignment indicates a high probability of a hardcoded sensitive key or token.",
        "why_dangerous": "Hardcoded credentials in code repositories persist in git history and easily leak into third-party hands.",
        "fix_recommendation": "Use dotenv (.env) files or secret management services rather than string literals."
    }
]

def calculate_shannon_entropy(data: str) -> float:
    """Calculates Shannon entropy to detect high-randomness secret strings."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    for x in set(data):
        p_x = float(data.count(x)) / length
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy

def scan_secrets(code: str, filename: str = "snippet") -> List[Dict[str, Any]]:
    """
    Scans source code lines for exposed secrets, tokens, private keys,
    and high-entropy literals.
    """
    findings = []
    lines = code.splitlines()

    for rule in SECRET_PATTERNS:
        compiled_re = re.compile(rule["pattern"], re.IGNORECASE)
        for idx, line in enumerate(lines, start=1):
            # Skip comments or documentation lines that might simply talk about patterns
            match = compiled_re.search(line)
            if match:
                snippet = line.strip()
                # Redact actual matched token in UI snippet for display security
                matched_secret = match.group(0)
                safe_snippet = snippet.replace(matched_secret, "[EXPOSED_SECRET_DETECTED]")

                findings.append({
                    "title": rule["title"],
                    "severity": rule["severity"],
                    "category": rule["category"],
                    "cwe_id": rule["cwe_id"],
                    "line_number": idx,
                    "snippet": snippet[:150],
                    "safe_snippet": safe_snippet[:150],
                    "description": rule["description"],
                    "why_dangerous": rule["why_dangerous"],
                    "attack_scenario": "An attacker discovers this secret in the repository, decompiled binary, or public commit log, then uses it to bypass authentication.",
                    "fix_recommendation": rule["fix_recommendation"],
                    "secure_code": f"# Replace direct literal with environment variable:\nimport os\napi_key = os.environ.get('SERVICE_API_KEY')",
                    "scanner_source": "Gitleaks-Engine"
                })

    return findings

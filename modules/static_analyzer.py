from typing import List, Dict, Any
from scanners.secret_scanner import scan_secrets
from scanners.bandit_scanner import run_bandit_scan
from scanners.custom_rules import scan_custom_rules
from scanners.semgrep_scanner import run_semgrep_scan

def run_all_scanners(code: str, filename: str, language: str) -> List[Dict[str, Any]]:
    """
    Coordinates multi-engine static security analysis:
    1. Secret & Credential Detection
    2. Python AST Static Analysis (Bandit) if applicable
    3. Multi-language OWASP Custom Rules Engine
    4. Semgrep CLI Scan if present
    Then deduplicates and sorts by severity.
    """
    findings: List[Dict[str, Any]] = []

    # 1. Secret Scanning (Language-agnostic)
    secret_findings = scan_secrets(code, filename)
    findings.extend(secret_findings)

    # 2. Language-Specific AST Scanning
    if language.lower() == "python":
        bandit_findings = run_bandit_scan(code, filename)
        findings.extend(bandit_findings)

    # 3. Multi-language Rules Engine
    rule_findings = scan_custom_rules(code, language)
    findings.extend(rule_findings)

    # 4. Semgrep Integration
    semgrep_findings = run_semgrep_scan(code, filename)
    findings.extend(semgrep_findings)

    # Deduplication based on (line_number, cwe_id or title keyword)
    deduped = []
    seen = set()

    for item in findings:
        line = item.get("line_number", 0)
        cwe = item.get("cwe_id", "")
        title_norm = item.get("title", "").split()[0].lower()
        key = (line, cwe, title_norm)

        if key not in seen:
            seen.add(key)
            deduped.append(item)

    # Sort findings by severity priority
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    deduped.sort(key=lambda x: severity_order.get(x.get("severity", "LOW").upper(), 5))

    return deduped

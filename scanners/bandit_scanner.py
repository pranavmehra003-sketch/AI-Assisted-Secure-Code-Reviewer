import subprocess
import json
import tempfile
import os
from pathlib import Path
from typing import List, Dict, Any

def run_bandit_scan(code: str, filename: str = "temp_scan.py") -> List[Dict[str, Any]]:
    """
    Executes Bandit static security analyzer against Python source code.
    Runs Bandit with JSON output and transforms findings into unified schema.
    """
    findings = []
    # Create a temporary file with the code
    temp_file = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as tf:
            tf.write(code)
            temp_file = tf.name

        cmd = ["bandit", "-f", "json", "-q", temp_file]
        # Run bandit with timeout to prevent hang
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=20,
            shell=False
        )

        output = result.stdout.strip()
        if output:
            try:
                data = json.loads(output)
                for item in data.get("results", []):
                    sev = item.get("issue_severity", "LOW").upper()
                    conf = item.get("issue_confidence", "MEDIUM").upper()
                    cwe = item.get("issue_cwe", {})
                    cwe_id = f"CWE-{cwe.get('id')}" if isinstance(cwe, dict) and cwe.get('id') else "CWE-Security"

                    findings.append({
                        "title": item.get("test_name", "Bandit Security Finding"),
                        "severity": sev,
                        "confidence": conf,
                        "category": "Code Quality & Security",
                        "cwe_id": cwe_id,
                        "line_number": item.get("line_number", 0),
                        "snippet": item.get("code", "").strip(),
                        "description": item.get("issue_text", ""),
                        "why_dangerous": f"Bandit flagged this pattern as potentially insecure ({item.get('test_id')}).",
                        "attack_scenario": "Exploitation depends on how untrusted user input interacts with this flagged call.",
                        "fix_recommendation": f"Consult Bandit guidelines for {item.get('test_name')} and replace with safe primitives.",
                        "secure_code": "# Refactor to avoid dangerous function or use safe parameters",
                        "scanner_source": "Bandit-AST"
                    })
            except json.JSONDecodeError:
                pass
    except FileNotFoundError:
        # Bandit not in system path, will rely on our AST/rule analyzer
        pass
    except Exception as e:
        # Ensure unexpected errors are caught gracefully
        pass
    finally:
        if temp_file and os.path.exists(temp_file):
            try:
                os.remove(temp_file)
            except OSError:
                pass

    return findings

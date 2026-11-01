import subprocess
import json
import tempfile
import os
from typing import List, Dict, Any

def run_semgrep_scan(code: str, filename: str = "temp.py") -> List[Dict[str, Any]]:
    """
    Executes Semgrep CLI static analysis if available on system.
    Returns parsed findings or empty list if Semgrep is not installed.
    """
    findings = []
    temp_file = None
    suffix = os.path.splitext(filename)[1] or ".py"

    try:
        with tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False, encoding="utf-8") as tf:
            tf.write(code)
            temp_file = tf.name

        cmd = [
            "semgrep",
            "--config", "auto",
            "--json",
            "--quiet",
            temp_file
        ]

        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=25,
            shell=False
        )

        output = result.stdout.strip()
        if output:
            data = json.loads(output)
            for res in data.get("results", []):
                extra = res.get("extra", {})
                metadata = extra.get("metadata", {})
                sev = extra.get("severity", "WARNING").upper()
                mapped_sev = "HIGH" if sev == "ERROR" else ("MEDIUM" if sev == "WARNING" else "LOW")

                findings.append({
                    "title": res.get("check_id", "Semgrep Finding").split(".")[-1].replace("-", " ").title(),
                    "severity": mapped_sev,
                    "category": metadata.get("category", "Semgrep Security Rule"),
                    "cwe_id": metadata.get("cwe", ["CWE-General"])[0] if isinstance(metadata.get("cwe"), list) else "CWE-General",
                    "line_number": res.get("start", {}).get("line", 0),
                    "snippet": extra.get("lines", "").strip()[:150],
                    "description": extra.get("message", ""),
                    "why_dangerous": metadata.get("impact", "Violates secure coding best practices."),
                    "attack_scenario": "Exploitable if untrusted input reaches this vulnerable code path.",
                    "fix_recommendation": extra.get("fix", "Refactor following safe design pattern."),
                    "secure_code": extra.get("fix", "# See Semgrep security guidelines"),
                    "scanner_source": "Semgrep-CLI"
                })

    except (FileNotFoundError, subprocess.TimeoutExpired):
        # Semgrep is not installed in PATH or timed out; static_analyzer will rely on Bandit + Custom Rules
        pass
    except Exception:
        pass
    finally:
        if temp_file and os.path.exists(temp_file):
            try:
                os.remove(temp_file)
            except OSError:
                pass

    return findings

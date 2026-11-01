import difflib
import ast
from typing import Dict, Any, Tuple
from modules.static_analyzer import run_all_scanners
from modules.severity_classifier import calculate_security_score

def generate_code_diff(original_code: str, fixed_code: str, filename: str = "code") -> str:
    """
    Computes a clean unified diff between the original vulnerable code
    and the proposed secure implementation.
    """
    orig_lines = original_code.splitlines(keepends=True)
    fixed_lines = fixed_code.splitlines(keepends=True)

    diff = difflib.unified_diff(
        orig_lines,
        fixed_lines,
        fromfile=f"a/{filename} (Vulnerable)",
        tofile=f"b/{filename} (Remediated)",
        lineterm=""
    )
    return "".join(diff)

def verify_fix(
    original_code: str,
    fixed_code: str,
    filename: str = "snippet.py",
    language: str = "Python"
) -> Dict[str, Any]:
    """
    Performs automated security regression and syntax validation on proposed fixes:
    1. Checks for syntax validity (Python ast check).
    2. Rescans fixed code using static analyzers.
    3. Quantifies security score delta.
    """
    syntax_valid = True
    syntax_error = ""

    # Python syntax verification
    if language.lower() == "python":
        try:
            ast.parse(fixed_code)
        except SyntaxError as e:
            syntax_valid = False
            syntax_error = f"Syntax error at line {e.lineno}: {e.msg}"

    # Rescan fixed code
    new_findings = run_all_scanners(fixed_code, filename, language)
    new_score, new_grade, new_counts = calculate_security_score(new_findings)

    # Scan original code for baseline
    orig_findings = run_all_scanners(original_code, filename, language)
    orig_score, orig_grade, _ = calculate_security_score(orig_findings)

    resolved_count = max(0, len(orig_findings) - len(new_findings))
    score_delta = round(new_score - orig_score, 1)

    return {
        "syntax_valid": syntax_valid,
        "syntax_error": syntax_error,
        "original_score": orig_score,
        "new_score": new_score,
        "score_delta": score_delta,
        "resolved_vulnerabilities": resolved_count,
        "remaining_vulnerabilities": len(new_findings),
        "is_improved": new_score > orig_score or len(new_findings) < len(orig_findings),
        "new_grade": new_grade
    }

from typing import List, Dict, Any, Tuple
from config import SEVERITY_LEVELS

def calculate_security_score(vulnerabilities: List[Dict[str, Any]]) -> Tuple[float, str, Dict[str, int]]:
    """
    Calculates code security score (0 - 100), security grade (A, B, C, D, F),
    and count of findings by severity.
    """
    counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0
    }

    penalty = 0.0
    for v in vulnerabilities:
        sev = v.get("severity", "LOW").upper()
        if sev not in counts:
            sev = "LOW"
        counts[sev] += 1
        penalty += SEVERITY_LEVELS.get(sev, {}).get("weight", 2)

    # Base score computation
    raw_score = 100.0 - penalty

    # Risk capping: any CRITICAL vulnerability limits the maximum score to 45
    if counts["CRITICAL"] > 0:
        raw_score = min(raw_score, 45.0)
    elif counts["HIGH"] > 0:
        raw_score = min(raw_score, 70.0)

    score = round(max(0.0, min(100.0, raw_score)), 1)

    # Grade assignment
    if score >= 90:
        grade = "A (Secure)"
    elif score >= 75:
        grade = "B (Good)"
    elif score >= 60:
        grade = "C (Moderate Risk)"
    elif score >= 40:
        grade = "D (High Risk)"
    else:
        grade = "F (Critical Risk)"

    return score, grade, counts

def get_owasp_distribution(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
    """Aggregates findings by category or OWASP classification."""
    dist = {}
    for v in vulnerabilities:
        cat = v.get("category", "General")
        dist[cat] = dist.get(cat, 0) + 1
    return dist

import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any
from config import REPORTS_DIR

def sanitize_pdf_text(text: str) -> str:
    """Replaces unprintable unicode characters with ASCII approximations for standard PDF fonts."""
    if not text:
        return ""
    replacements = {
        "–": "-", "—": "-", "“": '"', "”": '"', "‘": "'", "’": "'",
        "•": "*", "…": "...", "→": "->", "←": "<-", "✓": "[OK]", "✗": "[X]"
    }
    res = text
    for k, v in replacements.items():
        res = res.replace(k, v)
    return res.encode("latin-1", "replace").decode("latin-1")

def generate_json_report(
    filename: str,
    language: str,
    security_score: float,
    grade: str,
    vulnerabilities: List[Dict[str, Any]],
    executive_summary: str = ""
) -> str:
    """Generates structured JSON report and saves it to reports directory."""
    report_data = {
        "report_metadata": {
            "title": "AI-Assisted Secure Code Review Report",
            "generated_at": datetime.now().isoformat(),
            "target_file": filename,
            "language": language,
            "audit_engine": "AI Secure Code Reviewer v1.0",
            "security_score": security_score,
            "grade": grade,
            "total_findings": len(vulnerabilities)
        },
        "executive_summary": executive_summary,
        "findings": vulnerabilities
    }

    report_path = REPORTS_DIR / f"report_{Path(filename).stem}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)

    return str(report_path)

def generate_pdf_report(
    filename: str,
    language: str,
    security_score: float,
    grade: str,
    vulnerabilities: List[Dict[str, Any]],
    executive_summary: str = ""
) -> str:
    """
    Generates an industry-standard PDF Security Audit Report using fpdf2.
    """
    try:
        from fpdf import FPDF
    except ImportError:
        # Fallback to json if fpdf is not yet installed
        return generate_json_report(filename, language, security_score, grade, vulnerabilities, executive_summary)

    class SecurityReportPDF(FPDF):
        def header(self):
            # Cyber Banner
            self.set_fill_color(24, 30, 44)
            self.rect(0, 0, 210, 18, "F")
            self.set_font("Helvetica", "B", 10)
            self.set_text_color(0, 230, 180)
            self.set_xy(10, 5)
            self.cell(0, 8, "AI-ASSISTED SECURE CODE REVIEWER | AUDIT REPORT", ln=False)
            self.set_text_color(180, 190, 205)
            self.set_font("Helvetica", "", 8)
            self.set_xy(150, 5)
            self.cell(50, 8, datetime.now().strftime("%Y-%m-%d %H:%M"), align="R", ln=True)
            self.ln(10)

        def footer(self):
            self.set_y(-15)
            self.set_font("Helvetica", "I", 8)
            self.set_text_color(128, 128, 128)
            self.cell(0, 10, f"Page {self.page_no()}/{{nb}} - Confidential Security Assessment", align="C")

    pdf = SecurityReportPDF(orientation="P", unit="mm", format="A4")
    pdf.alias_nb_pages()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=18)

    # Document Title
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(20, 24, 33)
    pdf.cell(0, 10, "Static Application Security Testing Report", ln=True)

    # Meta Subtitle
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(80, 90, 105)
    pdf.cell(0, 6, f"Target File: {sanitize_pdf_text(filename)}  |  Language: {language}", ln=True)
    pdf.ln(4)

    # Score Box
    pdf.set_fill_color(245, 247, 250)
    pdf.set_draw_color(220, 225, 235)
    pdf.rect(10, pdf.get_y(), 190, 24, "DF")

    pdf.set_xy(15, pdf.get_y() + 3)
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(30, 40, 55)
    pdf.cell(50, 6, f"Security Score: {security_score}/100", ln=False)

    pdf.set_font("Helvetica", "B", 12)
    # Color grade
    if security_score >= 80:
        pdf.set_text_color(0, 150, 80)
    elif security_score >= 60:
        pdf.set_text_color(210, 130, 0)
    else:
        pdf.set_text_color(220, 40, 40)
    pdf.cell(50, 6, f"Grade: {grade}", ln=False)

    crit_count = sum(1 for v in vulnerabilities if v.get("severity") == "CRITICAL")
    high_count = sum(1 for v in vulnerabilities if v.get("severity") == "HIGH")
    med_count = sum(1 for v in vulnerabilities if v.get("severity") == "MEDIUM")
    low_count = sum(1 for v in vulnerabilities if v.get("severity") == "LOW")

    pdf.set_text_color(60, 70, 85)
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 6, f"Findings: {len(vulnerabilities)} (Crit: {crit_count}, High: {high_count}, Med: {med_count}, Low: {low_count})", ln=True)
    pdf.ln(12)

    # Executive Summary
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(20, 24, 33)
    pdf.cell(0, 8, "Executive Summary", ln=True)

    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(50, 50, 50)
    summary_text = sanitize_pdf_text(executive_summary or "Security assessment completed. Findings summarized below.")
    pdf.multi_cell(0, 5, summary_text)
    pdf.ln(6)

    # Findings Section
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(20, 24, 33)
    pdf.cell(0, 8, f"Vulnerability Details ({len(vulnerabilities)} Findings)", ln=True)
    pdf.ln(2)

    if not vulnerabilities:
        pdf.set_font("Helvetica", "I", 10)
        pdf.set_text_color(0, 150, 80)
        pdf.cell(0, 8, "[OK] Clean scan. No vulnerabilities or hardcoded secrets detected.", ln=True)
    else:
        for idx, v in enumerate(vulnerabilities, start=1):
            sev = v.get("severity", "LOW").upper()

            # Severity badge bar
            if sev == "CRITICAL":
                pdf.set_fill_color(255, 235, 235)
                pdf.set_draw_color(220, 53, 69)
            elif sev == "HIGH":
                pdf.set_fill_color(255, 243, 230)
                pdf.set_draw_color(253, 126, 20)
            elif sev == "MEDIUM":
                pdf.set_fill_color(255, 250, 230)
                pdf.set_draw_color(255, 193, 7)
            else:
                pdf.set_fill_color(235, 248, 240)
                pdf.set_draw_color(40, 167, 69)

            start_y = pdf.get_y()
            pdf.rect(10, start_y, 190, 8, "DF")

            pdf.set_xy(12, start_y + 1)
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(20, 20, 20)
            title = sanitize_pdf_text(f"#{idx}. [{sev}] {v.get('title')} ({v.get('cwe_id')}) - Line {v.get('line_number', 'N/A')}")
            pdf.cell(0, 6, title, ln=True)
            pdf.ln(2)

            # Details
            pdf.set_font("Helvetica", "B", 8)
            pdf.set_text_color(70, 70, 70)
            pdf.cell(25, 4, "Category:", ln=False)
            pdf.set_font("Helvetica", "", 8)
            pdf.cell(0, 4, sanitize_pdf_text(v.get("category", "General")), ln=True)

            pdf.set_font("Helvetica", "B", 8)
            pdf.cell(25, 4, "Scanner:", ln=False)
            pdf.set_font("Helvetica", "", 8)
            pdf.cell(0, 4, sanitize_pdf_text(v.get("scanner_source", "Static")), ln=True)

            # Code Snippet
            snippet = v.get("snippet", "")
            if snippet:
                pdf.set_fill_color(240, 242, 245)
                pdf.set_font("Courier", "", 8)
                pdf.set_text_color(180, 20, 20)
                clean_snippet = sanitize_pdf_text(snippet.strip())
                pdf.multi_cell(0, 4, f"Vulnerable code: {clean_snippet}", fill=True)
                pdf.ln(1)

            # Explanation & Why Dangerous
            why = v.get("why_dangerous") or v.get("description", "")
            if why:
                pdf.set_font("Helvetica", "B", 8)
                pdf.set_text_color(160, 40, 40)
                pdf.cell(0, 4, "Impact & Risk:", ln=True)
                pdf.set_font("Helvetica", "", 8)
                pdf.set_text_color(40, 40, 40)
                pdf.multi_cell(0, 4, sanitize_pdf_text(why))
                pdf.ln(1)

            # Remediation
            fix = v.get("fix_recommendation") or v.get("secure_code", "")
            if fix:
                pdf.set_font("Helvetica", "B", 8)
                pdf.set_text_color(0, 120, 60)
                pdf.cell(0, 4, "Recommended Fix:", ln=True)
                pdf.set_font("Helvetica", "", 8)
                pdf.set_text_color(40, 40, 40)
                pdf.multi_cell(0, 4, sanitize_pdf_text(fix))
                pdf.ln(4)

    out_file = REPORTS_DIR / f"Security_Report_{Path(filename).stem}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    pdf.output(str(out_file))
    return str(out_file)

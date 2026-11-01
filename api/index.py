import os
import sys
from pathlib import Path

# Add project root to sys.path so modules and scanners can be imported cleanly on Vercel
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from fastapi import FastAPI, HTTPException, Body, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

from modules.input_validator import validate_uploaded_file, detect_language
from modules.static_analyzer import run_all_scanners
from modules.severity_classifier import calculate_security_score, get_owasp_distribution
from modules.ai_reviewer import AIReviewEngine
from modules.fix_recommender import generate_code_diff, verify_fix
from modules.report_generator import generate_pdf_report, generate_json_report
from modules.code_upload import load_sample_file, get_available_samples
from modules.database import (
    init_db, save_review, save_vulnerabilities,
    get_reviews, get_review_by_id, get_vulnerabilities_by_review,
    delete_review, get_security_stats
)

# Initialize database
init_db()

app = FastAPI(
    title="AI-Assisted Secure Code Reviewer API",
    description="Enterprise SAST and AI Remediation API configured for Vercel Serverless deployment",
    version="1.0.0"
)

# Enable CORS for local dev and Vercel domains
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    code: str = Field(..., description="Source code text to audit")
    filename: Optional[str] = "snippet.py"
    language: Optional[str] = "Python"
    ai_provider: Optional[str] = "offline"
    api_key: Optional[str] = None

class VerifyRequest(BaseModel):
    original_code: str
    fixed_code: str
    filename: Optional[str] = "snippet.py"
    language: Optional[str] = "Python"

class DiffRequest(BaseModel):
    original_code: str
    fixed_code: str
    filename: Optional[str] = "snippet.py"

class ChatRequest(BaseModel):
    message: str
    finding: Optional[Dict[str, Any]] = None
    code: Optional[str] = ""
    ai_provider: Optional[str] = "offline"
    api_key: Optional[str] = None

@app.post("/api/chat")
def security_chat_assistant(payload: ChatRequest):
    if payload.api_key:
        if payload.ai_provider == "gemini":
            os.environ["GEMINI_API_KEY"] = payload.api_key
        elif payload.ai_provider == "openai":
            os.environ["OPENAI_API_KEY"] = payload.api_key
        elif payload.ai_provider == "grok":
            os.environ["GROK_API_KEY"] = payload.api_key

    engine = AIReviewEngine(provider=payload.ai_provider or "offline")
    answer = engine.chat_response(payload.message, payload.finding, payload.code or "")
    return {"reply": answer}


@app.get("/api/health")
def health_check():
    stats = get_security_stats()
    return {
        "status": "online",
        "service": "AI-Assisted Secure Code Reviewer",
        "runtime": "Vercel Serverless Python",
        "scanners": ["Bandit AST", "Gitleaks-Engine", "OWASP Rules", "Semgrep"],
        "metrics": stats
    }

@app.get("/api/samples")
def get_sample_codes():
    """Returns available demonstration vulnerable and secure code files."""
    samples = [
        {
            "id": "vulnerable_python.py",
            "name": "Python - SQLi, Command Injection, AWS Key, Pickle",
            "language": "Python",
            "code": load_sample_file("vulnerable_python.py") or ""
        },
        {
            "id": "secure_python.py",
            "name": "Python - Secure Parameterized Implementation",
            "language": "Python",
            "code": load_sample_file("secure_python.py") or ""
        },
        {
            "id": "vulnerable_js.js",
            "name": "JavaScript - XSS, eval(), Command Injection",
            "language": "JavaScript",
            "code": load_sample_file("vulnerable_js.js") or ""
        },
        {
            "id": "vulnerable_java.java",
            "name": "Java - Dynamic SQLi, Hardcoded Credentials, MD5",
            "language": "Java",
            "code": load_sample_file("vulnerable_java.java") or ""
        }
    ]
    return {"samples": samples}

@app.post("/api/scan")
def scan_source_code(payload: ScanRequest):
    code = payload.code
    filename = payload.filename or "snippet.py"
    language = payload.language or detect_language(filename)

    # 1. Validation
    is_valid, err, detected_lang = validate_uploaded_file(filename, code.encode("utf-8"))
    if not is_valid:
        raise HTTPException(status_code=400, detail=err)

    # 2. Run Multi-Engine Static Analysis
    findings = run_all_scanners(code, filename, language)

    # 3. Calculate Security Score & Grade
    score, grade, counts = calculate_security_score(findings)

    # 4. AI Review Engine (supports user-provided API key or fallback)
    if payload.api_key:
        if payload.ai_provider == "gemini":
            os.environ["GEMINI_API_KEY"] = payload.api_key
        elif payload.ai_provider == "openai":
            os.environ["OPENAI_API_KEY"] = payload.api_key
        elif payload.ai_provider == "grok":
            os.environ["GROK_API_KEY"] = payload.api_key

    ai_engine = AIReviewEngine(provider=payload.ai_provider or "offline")

    # 5. Enrich findings with contextual explanations & secure replacements
    enriched_findings = []
    for f in findings:
        ai_exp = ai_engine.generate_explanation(code, f, language)
        item = dict(f)
        item["why_dangerous"] = ai_exp.get("why_dangerous", f.get("why_dangerous", ""))
        item["attack_scenario"] = ai_exp.get("attack_scenario", f.get("attack_scenario", ""))
        item["fix_recommendation"] = ai_exp.get("prevention", f.get("fix_recommendation", ""))
        item["secure_code"] = ai_exp.get("secure_code", f.get("secure_code", ""))
        # Precompute unified diff
        item["diff"] = generate_code_diff(f.get("snippet", ""), item["secure_code"], filename)
        enriched_findings.append(item)

    # 6. Executive Summary
    summary = ai_engine.generate_executive_summary(filename, language, enriched_findings, score)

    # 7. Persist to SQLite (with safe fallback for serverless cold-starts)
    review_id = None
    try:
        review_id = save_review(
            filename=filename,
            file_language=language,
            code_snippet=code,
            security_score=score,
            total_issues=len(enriched_findings),
            critical_count=counts["CRITICAL"],
            high_count=counts["HIGH"],
            medium_count=counts["MEDIUM"],
            low_count=counts["LOW"],
            ai_provider=payload.ai_provider or "offline",
            executive_summary=summary
        )
        if review_id:
            save_vulnerabilities(review_id, enriched_findings)
    except Exception as db_err:
        print(f"Warning: Failed to save review to database: {db_err}")

    return {
        "review_id": review_id,
        "filename": filename,
        "language": language,
        "security_score": score,
        "grade": grade,
        "counts": counts,
        "owasp_distribution": get_owasp_distribution(enriched_findings),
        "executive_summary": summary,
        "findings": enriched_findings
    }

@app.post("/api/verify")
def verify_remediation(payload: VerifyRequest):
    result = verify_fix(
        original_code=payload.original_code,
        fixed_code=payload.fixed_code,
        filename=payload.filename or "snippet.py",
        language=payload.language or "Python"
    )
    return result

@app.post("/api/diff")
def compute_diff(payload: DiffRequest):
    diff = generate_code_diff(payload.original_code, payload.fixed_code, payload.filename or "code")
    return {"diff": diff}

@app.get("/api/history")
def get_audit_history(limit: int = 50):
    reviews = get_reviews(limit=limit)
    return {"reviews": reviews}

@app.get("/api/history/{review_id}")
def get_audit_details(review_id: int):
    rev = get_review_by_id(review_id)
    if not rev:
        raise HTTPException(status_code=404, detail="Review not found")
    vulns = get_vulnerabilities_by_review(review_id)
    return {"review": rev, "vulnerabilities": vulns}

@app.delete("/api/history/{review_id}")
def remove_audit_record(review_id: int):
    deleted = delete_review(review_id)
    return {"deleted": deleted, "review_id": review_id}

@app.post("/api/report/pdf")
def export_pdf_report(payload: Dict[str, Any] = Body(...)):
    filename = payload.get("filename", "audit_file.py")
    language = payload.get("language", "Python")
    score = float(payload.get("security_score", 100.0))
    grade = payload.get("grade", "A")
    findings = payload.get("findings", [])
    summary = payload.get("executive_summary", "")

    pdf_path = generate_pdf_report(filename, language, score, grade, findings, summary)
    if not os.path.exists(pdf_path):
        raise HTTPException(status_code=500, detail="Failed to create PDF report")

    with open(pdf_path, "rb") as f:
        pdf_bytes = f.read()

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="Security_Report_{Path(filename).stem}.pdf"'}
    )

@app.post("/api/report/json")
def export_json_report(payload: Dict[str, Any] = Body(...)):
    filename = payload.get("filename", "audit_file.py")
    language = payload.get("language", "Python")
    score = float(payload.get("security_score", 100.0))
    grade = payload.get("grade", "A")
    findings = payload.get("findings", [])
    summary = payload.get("executive_summary", "")

    json_path = generate_json_report(filename, language, score, grade, findings, summary)
    with open(json_path, "r", encoding="utf-8") as f:
        content = f.read()

    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="Security_Report_{Path(filename).stem}.json"'}
    )

# Mount frontend production build for unified local full-stack server
dist_path = ROOT_DIR / "frontend" / "dist"
if dist_path.exists():
    from fastapi.staticfiles import StaticFiles
    app.mount("/", StaticFiles(directory=str(dist_path), html=True), name="static")


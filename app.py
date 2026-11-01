import streamlit as st
import os
import json
from pathlib import Path
from datetime import datetime
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd

from config import (
    AI_PROVIDER, GEMINI_API_KEY, GEMINI_MODEL,
    OPENAI_API_KEY, OPENAI_MODEL,
    OLLAMA_BASE_URL, OLLAMA_MODEL,
    SEVERITY_LEVELS, OWASP_CATEGORIES
)
from modules.database import (
    init_db, save_review, save_vulnerabilities,
    get_reviews, get_review_by_id, get_vulnerabilities_by_review,
    delete_review, get_security_stats, log_audit_event
)
from modules.input_validator import (
    validate_uploaded_file, detect_language,
    sanitize_prompt_injection, mask_secrets_for_ai
)
from modules.static_analyzer import run_all_scanners
from modules.severity_classifier import calculate_security_score, get_owasp_distribution
from modules.ai_reviewer import AIReviewEngine
from modules.fix_recommender import generate_code_diff, verify_fix
from modules.report_generator import generate_pdf_report, generate_json_report
from modules.code_upload import load_sample_file, get_available_samples, process_uploaded_file

# Initialize SQLite database on load
init_db()

# Page Configuration
st.set_page_config(
    page_title="AI Secure Code Reviewer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Cyber Security Theme Styling
st.markdown("""
<style>
    /* Global Cyber Dark Aesthetic */
    .stApp {
        background: radial-gradient(circle at top right, #111827, #0B0F17);
        color: #E2E8F0;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }
    
    /* Header Branding */
    .cyber-title {
        font-size: 2.2rem;
        font-weight: 800;
        background: linear-gradient(90deg, #00F5A0 0%, #00D9F5 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.2rem;
    }
    
    .cyber-subtitle {
        color: #94A3B8;
        font-size: 1rem;
        margin-bottom: 1.5rem;
    }

    /* Score Card Banner */
    .score-card {
        background: rgba(17, 24, 39, 0.7);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 12px;
        padding: 1.2rem;
        backdrop-filter: blur(10px);
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
        text-align: center;
    }

    /* Severity Badges */
    .badge-critical {
        background-color: #EF4444;
        color: white;
        padding: 3px 10px;
        border-radius: 6px;
        font-weight: bold;
        font-size: 0.8rem;
    }
    .badge-high {
        background-color: #F97316;
        color: white;
        padding: 3px 10px;
        border-radius: 6px;
        font-weight: bold;
        font-size: 0.8rem;
    }
    .badge-medium {
        background-color: #EAB308;
        color: black;
        padding: 3px 10px;
        border-radius: 6px;
        font-weight: bold;
        font-size: 0.8rem;
    }
    .badge-low {
        background-color: #10B981;
        color: white;
        padding: 3px 10px;
        border-radius: 6px;
        font-weight: bold;
        font-size: 0.8rem;
    }

    /* Finding Box */
    .vuln-box {
        background: #1E293B;
        border-left: 4px solid #EF4444;
        border-radius: 8px;
        padding: 1rem;
        margin-bottom: 1rem;
    }

    /* Buttons */
    .stButton>button {
        background: linear-gradient(90deg, #00F5A0 0%, #00D9F5 100%);
        color: #0F172A;
        font-weight: bold;
        border: none;
        border-radius: 8px;
        transition: all 0.3s ease;
    }
    .stButton>button:hover {
        opacity: 0.9;
        transform: translateY(-1px);
        box-shadow: 0 4px 20px rgba(0, 245, 160, 0.4);
    }
</style>
""", unsafe_allow_html=True)

# ----------------- SIDEBAR CONTROLS -----------------
with st.sidebar:
    st.markdown("### 🛡️ Secure Code Reviewer")
    st.caption("AI-Powered SAST & Automated Remediation")
    st.markdown("---")

    # AI Model Engine Configuration
    st.markdown("#### 🤖 AI Engine Settings")
    active_provider = st.selectbox(
        "Active AI Provider",
        options=["Gemini (Cloud)", "OpenAI (Cloud)", "Ollama (Offline/Local)", "Offline Rule-Engine (No Key)"],
        index=0
    )

    provider_map = {
        "Gemini (Cloud)": "gemini",
        "OpenAI (Cloud)": "openai",
        "Ollama (Offline/Local)": "ollama",
        "Offline Rule-Engine (No Key)": "offline"
    }
    selected_provider_key = provider_map[active_provider]

    custom_gemini_key = ""
    custom_openai_key = ""

    if selected_provider_key == "gemini":
        custom_gemini_key = st.text_input("Gemini API Key", value=GEMINI_API_KEY, type="password", help="Free tier API key from Google AI Studio")
        if custom_gemini_key:
            os.environ["GEMINI_API_KEY"] = custom_gemini_key
    elif selected_provider_key == "openai":
        custom_openai_key = st.text_input("OpenAI API Key", value=OPENAI_API_KEY, type="password")
        if custom_openai_key:
            os.environ["OPENAI_API_KEY"] = custom_openai_key
    elif selected_provider_key == "ollama":
        st.info(f"Ollama Endpoint: {OLLAMA_BASE_URL}\nModel: {OLLAMA_MODEL}")

    st.markdown("---")
    st.markdown("#### 🔍 Active Scanners")
    enable_secrets = st.checkbox("Gitleaks Secret Scanner", value=True)
    enable_bandit = st.checkbox("Bandit Python AST Scanner", value=True)
    enable_owasp_rules = st.checkbox("OWASP Multi-Language Rules", value=True)
    enable_semgrep = st.checkbox("Semgrep CLI (if installed)", value=True)

    st.markdown("---")
    stats = get_security_stats()
    st.markdown("#### 📊 System Metrics")
    col_s1, col_s2 = st.columns(2)
    col_s1.metric("Total Reviews", stats["total_reviews"])
    col_s2.metric("Avg Score", f"{stats['avg_security_score']}%")
    st.caption(f"Total Flaws Identified: {stats['total_vulnerabilities']}")

# ----------------- MAIN NAVIGATION TABS -----------------
tab_scan, tab_history, tab_education, tab_audit = st.tabs([
    "🚀 Scan & Code Review",
    "📜 Review History",
    "📚 OWASP & Security Guide",
    "🔒 Security Posture & Logs"
])

# ================= TAB 1: SCAN & CODE REVIEW =================
with tab_scan:
    st.markdown('<div class="cyber-title">AI-Assisted Secure Code Reviewer</div>', unsafe_allow_html=True)
    st.markdown('<div class="cyber-subtitle">Deep static vulnerability analysis, OWASP risk classification, and verified AI remediation suggestions.</div>', unsafe_allow_html=True)

    # Input Method Selection
    input_method = st.radio(
        "Choose Input Method:",
        ["📁 Upload Source File", "✍️ Paste Code Snippet", "🧪 Load Vulnerable Preset Sample"],
        horizontal=True
    )

    source_code = ""
    filename = "snippet.py"
    language = "Python"

    if input_method == "📁 Upload Source File":
        uploaded_file = st.file_uploader(
            "Upload source file (.py, .js, .java, .c, .cpp, .go, .php, .sql, .html, .env)",
            type=["py", "js", "jsx", "ts", "tsx", "java", "c", "cpp", "go", "php", "sql", "html", "env", "json"]
        )
        if uploaded_file:
            res = process_uploaded_file(uploaded_file)
            if res["is_valid"]:
                source_code = res["content"]
                filename = res["filename"]
                language = res["language"]
                st.success(f"Loaded '{filename}' ({language}) - {len(source_code)} characters")
            else:
                st.error(res["error"])

    elif input_method == "✍️ Paste Code Snippet":
        col_l1, col_l2 = st.columns([3, 1])
        with col_l1:
            filename = st.text_input("Filename / Component Name", value="vulnerable_script.py")
        with col_l2:
            language = st.selectbox(
                "Language",
                ["Python", "JavaScript", "Java", "C/C++", "PHP", "Go", "SQL", "HTML"]
            )
        default_paste = """import sqlite3

def get_user(username):
    conn = sqlite3.connect("users.db")
    # Vulnerable SQL query concatenation
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    return conn.execute(query).fetchall()
"""
        source_code = st.text_area("Paste source code here:", value=default_paste, height=220)

    elif input_method == "🧪 Load Vulnerable Preset Sample":
        sample_choice = st.selectbox(
            "Select Preset Vulnerability Demonstration:",
            [
                "vulnerable_python.py (SQLi, Command Injection, Secrets, Pickle)",
                "secure_python.py (Remediated Baseline Sample)",
                "vulnerable_js.js (XSS, Eval, Command Injection)",
                "vulnerable_java.java (SQLi, Hardcoded Creds, Weak MD5)"
            ]
        )
        sample_filename = sample_choice.split(" ")[0]
        sample_content = load_sample_file(sample_filename)
        if sample_content:
            source_code = sample_content
            filename = sample_filename
            language = detect_language(sample_filename)
            st.info(f"Loaded preset: `{filename}`")

    # Code Display / Preview
    if source_code:
        with st.expander("📄 Source Code Inspection", expanded=False):
            st.code(source_code, language=language.lower())

        # Action: Run Review Button
        if st.button("🛡️ Execute AI Security Review", type="primary", use_container_width=True):
            with st.spinner("Analyzing code with Static AST engines & AI Reviewer..."):
                # 1. Validation check
                is_valid, err, detected_lang = validate_uploaded_file(filename, source_code.encode("utf-8"))
                if not is_valid:
                    st.error(err)
                    st.stop()

                # 2. Run Static Analysis Orchestration
                findings = run_all_scanners(source_code, filename, language)

                # 3. Calculate Security Score & Grade
                score, grade, counts = calculate_security_score(findings)

                # 4. Initialize AI Reviewer
                ai_engine = AIReviewEngine(provider=selected_provider_key)

                # 5. Generate AI Deep Explanations for findings
                enhanced_findings = []
                for idx, v in enumerate(findings):
                    ai_res = ai_engine.generate_explanation(source_code, v, language)
                    enhanced = dict(v)
                    enhanced["why_dangerous"] = ai_res.get("why_dangerous", v.get("why_dangerous", ""))
                    enhanced["attack_scenario"] = ai_res.get("attack_scenario", v.get("attack_scenario", ""))
                    enhanced["fix_recommendation"] = ai_res.get("prevention", v.get("fix_recommendation", ""))
                    enhanced["secure_code"] = ai_res.get("secure_code", v.get("secure_code", ""))
                    enhanced_findings.append(enhanced)

                # 6. Executive Summary
                exec_summary = ai_engine.generate_executive_summary(filename, language, enhanced_findings, score)

                # 7. Save to Database
                review_id = save_review(
                    filename=filename,
                    file_language=language,
                    code_snippet=source_code,
                    security_score=score,
                    total_issues=len(enhanced_findings),
                    critical_count=counts["CRITICAL"],
                    high_count=counts["HIGH"],
                    medium_count=counts["MEDIUM"],
                    low_count=counts["LOW"],
                    ai_provider=selected_provider_key,
                    executive_summary=exec_summary
                )
                save_vulnerabilities(review_id, enhanced_findings)

                # Store in session state for UI display
                st.session_state["current_review"] = {
                    "id": review_id,
                    "filename": filename,
                    "language": language,
                    "score": score,
                    "grade": grade,
                    "counts": counts,
                    "findings": enhanced_findings,
                    "summary": exec_summary,
                    "original_code": source_code
                }
                st.success("Security review completed successfully!")

    # ---------------- DISPLAY REVIEW RESULTS ----------------
    if "current_review" in st.session_state:
        rev = st.session_state["current_review"]
        st.markdown("---")
        st.subheader("📊 Security Audit Overview")

        # Top Metric Cards
        col_m1, col_m2, col_m3, col_m4, col_m5 = st.columns(5)
        
        # Color coding for security score
        score_val = rev["score"]
        score_color = "#10B981" if score_val >= 80 else ("#F59E0B" if score_val >= 60 else "#EF4444")
        
        col_m1.metric("Security Score", f"{score_val} / 100", delta=rev["grade"])
        col_m2.metric("Critical Risks", rev["counts"]["CRITICAL"])
        col_m3.metric("High Severity", rev["counts"]["HIGH"])
        col_m4.metric("Medium Severity", rev["counts"]["MEDIUM"])
        col_m5.metric("Low / Info", rev["counts"]["LOW"])

        # Executive Summary Box
        st.markdown(f"**Executive Security Summary:**\n\n{rev['summary']}")

        # Charts Row
        col_chart1, col_chart2 = st.columns([1, 1])

        with col_chart1:
            # Severity distribution chart
            sev_df = pd.DataFrame([
                {"Severity": "Critical", "Count": rev["counts"]["CRITICAL"], "Color": "#EF4444"},
                {"Severity": "High", "Count": rev["counts"]["HIGH"], "Color": "#F97316"},
                {"Severity": "Medium", "Count": rev["counts"]["MEDIUM"], "Color": "#EAB308"},
                {"Severity": "Low", "Count": rev["counts"]["LOW"], "Color": "#10B981"},
            ])
            fig_bar = px.bar(
                sev_df,
                x="Severity",
                y="Count",
                color="Severity",
                color_discrete_map={"Critical": "#EF4444", "High": "#F97316", "Medium": "#EAB308", "Low": "#10B981"},
                title="Vulnerabilities by Severity"
            )
            fig_bar.update_layout(height=280, margin=dict(l=10, r=10, t=30, b=10), template="plotly_dark")
            st.plotly_chart(fig_bar, use_container_width=True)

        with col_chart2:
            # OWASP Distribution Donut Chart
            owasp_dist = get_owasp_distribution(rev["findings"])
            if owasp_dist:
                fig_pie = px.pie(
                    names=list(owasp_dist.keys()),
                    values=list(owasp_dist.values()),
                    title="OWASP Category Breakdown",
                    hole=0.45
                )
                fig_pie.update_layout(height=280, margin=dict(l=10, r=10, t=30, b=10), template="plotly_dark")
                st.plotly_chart(fig_pie, use_container_width=True)
            else:
                st.info("No vulnerabilities detected to display category breakdown.")

        # Detailed Findings Section
        st.markdown("### ⚠️ Detailed Security Findings")
        findings = rev["findings"]

        if not findings:
            st.success("🎉 No security vulnerabilities detected in the uploaded source code!")
        else:
            for i, f in enumerate(findings, start=1):
                sev = f.get("severity", "LOW")
                badge_class = f"badge-{sev.lower()}"
                
                with st.expander(f"#{i}. [{sev}] {f.get('title')} — Line {f.get('line_number', 'N/A')}", expanded=(i == 1)):
                    c1, c2 = st.columns([3, 1])
                    with c1:
                        st.markdown(f"**CWE ID:** `{f.get('cwe_id')}` | **Category:** `{f.get('category')}` | **Engine:** `{f.get('scanner_source')}`")
                    with c2:
                        st.markdown(f"<span class='{badge_class}'>{sev} SEVERITY</span>", unsafe_allow_html=True)

                    st.markdown("#### 🚨 Vulnerable Code Snippet:")
                    snippet = f.get("snippet", "")
                    st.code(snippet, language=rev["language"].lower())

                    st.markdown("#### 💥 Why is this Dangerous?")
                    st.write(f.get("why_dangerous"))

                    st.markdown("#### 🎯 Potential Attack Scenario:")
                    st.info(f.get("attack_scenario"))

                    st.markdown("#### 🛠️ AI Fix Recommendation & Secure Code:")
                    st.write(f.get("fix_recommendation"))
                    
                    secure_code_proposal = f.get("secure_code", "")
                    if secure_code_proposal:
                        st.code(secure_code_proposal, language=rev["language"].lower())

                        # Unified Diff view
                        with st.expander("🔍 View Unified Code Diff", expanded=False):
                            diff_text = generate_code_diff(snippet, secure_code_proposal, rev["filename"])
                            if diff_text:
                                st.code(diff_text, language="diff")
                            else:
                                st.caption("No direct replacement diff available.")

                        # Interactive Fix Verification
                        if st.button(f"✅ Verify AI Fix for Finding #{i}", key=f"verify_btn_{i}"):
                            verification = verify_fix(
                                original_code=snippet,
                                fixed_code=secure_code_proposal,
                                filename=rev["filename"],
                                language=rev["language"]
                            )
                            if verification["syntax_valid"]:
                                st.success(f"✓ Syntax verified. Security Score improved: {verification['original_score']} -> {verification['new_score']} (+{verification['score_delta']} pts)")
                            else:
                                st.warning(f"⚠️ Syntax check warning: {verification['syntax_error']}")

        # Report Export Buttons
        st.markdown("---")
        st.markdown("### 📥 Export Audit Reports")
        col_rep1, col_rep2 = st.columns(2)

        with col_rep1:
            if st.button("📄 Generate Professional PDF Report", use_container_width=True):
                pdf_path = generate_pdf_report(
                    filename=rev["filename"],
                    language=rev["language"],
                    security_score=rev["score"],
                    grade=rev["grade"],
                    vulnerabilities=rev["findings"],
                    executive_summary=rev["summary"]
                )
                if os.path.exists(pdf_path):
                    with open(pdf_path, "rb") as f:
                        st.download_button(
                            label="⬇️ Download PDF Security Report",
                            data=f.read(),
                            file_name=Path(pdf_path).name,
                            mime="application/pdf",
                            use_container_width=True
                        )

        with col_rep2:
            if st.button("💾 Generate JSON Security Report", use_container_width=True):
                json_path = generate_json_report(
                    filename=rev["filename"],
                    language=rev["language"],
                    security_score=rev["score"],
                    grade=rev["grade"],
                    vulnerabilities=rev["findings"],
                    executive_summary=rev["summary"]
                )
                if os.path.exists(json_path):
                    with open(json_path, "r", encoding="utf-8") as f:
                        st.download_button(
                            label="⬇️ Download JSON Machine-Readable Report",
                            data=f.read(),
                            file_name=Path(json_path).name,
                            mime="application/json",
                            use_container_width=True
                        )

# ================= TAB 2: REVIEW HISTORY =================
with tab_history:
    st.markdown("### 📜 Code Review Audit History")
    st.caption("Historical log of static security reviews saved in SQLite database.")

    history_records = get_reviews(limit=50)

    if not history_records:
        st.info("No prior code reviews found. Run a code scan to populate the audit history.")
    else:
        # History table
        df_history = pd.DataFrame(history_records)[
            ["id", "filename", "file_language", "security_score", "total_issues", "critical_count", "high_count", "created_at"]
        ]
        df_history.columns = ["Review ID", "Filename", "Language", "Score", "Total Issues", "Critical", "High", "Audit Date"]
        st.dataframe(df_history, use_container_width=True)

        # Inspect specific review
        st.markdown("#### 🔎 Inspect Historical Finding Details")
        selected_id = st.selectbox(
            "Select Review ID to inspect:",
            options=[r["id"] for r in history_records],
            format_func=lambda x: f"Review #{x} - {next((r['filename'] for r in history_records if r['id'] == x), '')}"
        )

        if selected_id:
            col_h1, col_h2 = st.columns([4, 1])
            with col_h1:
                rev_item = get_review_by_id(selected_id)
                st.markdown(f"**Target:** `{rev_item['filename']}` | **Score:** `{rev_item['security_score']}/100` | **Audited At:** `{rev_item['created_at']}`")
            with col_h2:
                if st.button(f"🗑️ Delete #{selected_id}"):
                    delete_review(selected_id)
                    st.rerun()

            hist_vulns = get_vulnerabilities_by_review(selected_id)
            if hist_vulns:
                for idx, hv in enumerate(hist_vulns, 1):
                    with st.expander(f"#{idx} [{hv['severity']}] {hv['title']} - Line {hv['line_number']}"):
                        st.write(f"**Category:** {hv['category']} ({hv['cwe_id']})")
                        st.code(hv['snippet'])
                        st.write(f"**Risk:** {hv['why_dangerous']}")
                        st.write(f"**Fix:** {hv['fix_recommendation']}")
            else:
                st.success("Clean scan. No vulnerabilities detected in this review.")

# ================= TAB 3: OWASP & SECURITY GUIDE =================
with tab_education:
    st.markdown("### 📚 OWASP Top 10 Security Architecture Reference")
    st.caption("Common software vulnerabilities, attack vectors, and industry remediation standards.")

    for owasp_id, name in OWASP_CATEGORIES.items():
        with st.expander(f"🛡️ {owasp_id}: {name}"):
            if "Injection" in name:
                st.markdown("""
                - **Risk Description:** Untrusted user input is sent to an interpreter as part of a command or query.
                - **Common Examples:** SQL Injection, OS Command Injection, XPath Injection, LDAP Injection.
                - **Mitigation:** Use parameterized queries (Prepared Statements), input validation allowlists, and never use dynamic string concatenation.
                """)
            elif "Cryptographic" in name:
                st.markdown("""
                - **Risk Description:** Inadequate protection of sensitive data in transit or at rest.
                - **Common Examples:** Weak hash functions (MD5, SHA1), hardcoded encryption keys, unencrypted secrets.
                - **Mitigation:** Use modern authenticated encryption (AES-GCM, ChaCha20-Poly1305), secure password hashing (Argon2, PBKDF2), and automated secret scanning.
                """)
            elif "Broken Access" in name:
                st.markdown("""
                - **Risk Description:** Users can act outside of their intended permissions.
                - **Common Examples:** Path traversal (`../../`), IDOR (Insecure Direct Object Reference), privilege escalation.
                - **Mitigation:** Enforce server-side authorization checks, canonicalize file paths, and deny access by default.
                """)
            else:
                st.markdown(f"Adhere to secure development lifecycle (SDLC) best practices and continuous automated SAST analysis to eliminate {name}.")

# ================= TAB 4: AUDIT LOG & SECURITY POLICY =================
with tab_audit:
    st.markdown("### 🔒 Reviewer Security Posture & Guardrails")
    st.markdown("""
    To adhere to enterprise cybersecurity standards, this reviewer enforces the following defense-in-depth principles:
    
    1. **Sandboxed Static Analysis:** Uploaded source files are strictly parsed as plaintext AST and regex tokens—**never executed**.
    2. **Zero-Knowledge AI Redaction:** High-entropy credentials, private keys, and API tokens are automatically redacted via `modules/input_validator.py` before any payload leaves the host machine.
    3. **Prompt Injection Hardening:** Code comments and strings are analyzed and sanitized against jailbreak and delimiter bypass attempts.
    4. **Offline Capability:** Completely functional in offline environments without external cloud API dependencies.
    """)

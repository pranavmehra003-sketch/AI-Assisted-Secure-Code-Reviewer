import json
import re
import requests
from typing import Dict, Any, List, Optional
from config import (
    AI_PROVIDER, GEMINI_API_KEY, GEMINI_MODEL,
    OPENAI_API_KEY, OPENAI_MODEL,
    GROK_API_KEY, GROK_MODEL, GROK_BASE_URL,
    OLLAMA_BASE_URL, OLLAMA_MODEL
)
from modules.input_validator import sanitize_prompt_injection, mask_secrets_for_ai

class AIReviewEngine:
    def __init__(self, provider: Optional[str] = None):
        self.provider = (provider or AI_PROVIDER).lower()

    def generate_explanation(
        self,
        code_context: str,
        vulnerability: Dict[str, Any],
        language: str = "Python"
    ) -> Dict[str, str]:
        """
        Generates deep contextual security review for a detected vulnerability.
        Returns:
            {
                "explanation": str,
                "why_dangerous": str,
                "attack_scenario": str,
                "prevention": str,
                "secure_code": str
            }
        """
        # Step 1: Pre-AI Sanitization & Secret Masking
        safe_code, _ = sanitize_prompt_injection(code_context)
        safe_code = mask_secrets_for_ai(safe_code)

        # Step 2: Route to configured provider
        if self.provider == "gemini" and GEMINI_API_KEY:
            res = self._call_gemini(safe_code, vulnerability, language)
            if res:
                return res

        elif self.provider == "openai" and OPENAI_API_KEY:
            res = self._call_openai(safe_code, vulnerability, language)
            if res:
                return res

        elif self.provider == "grok" and GROK_API_KEY:
            res = self._call_grok(safe_code, vulnerability, language)
            if res:
                return res

        elif self.provider == "ollama":
            res = self._call_ollama(safe_code, vulnerability, language)
            if res:
                return res

        # Step 3: Offline / Built-in High-Fidelity Security Reviewer
        return self._generate_fallback(safe_code, vulnerability, language)

    def generate_executive_summary(
        self,
        filename: str,
        language: str,
        vulnerabilities: List[Dict[str, Any]],
        security_score: float
    ) -> str:
        """Generates an executive-level security review summary."""
        if not vulnerabilities:
            return f"Security audit completed for {filename}. No known static vulnerabilities or credential leaks were detected. The codebase exhibits strong adherence to secure programming best practices."

        crit_count = sum(1 for v in vulnerabilities if v.get("severity") == "CRITICAL")
        high_count = sum(1 for v in vulnerabilities if v.get("severity") == "HIGH")

        summary = (
            f"Security Review for **{filename}** ({language}). "
            f"The analyzed source code obtained an overall Security Score of **{security_score}/100**. "
            f"A total of **{len(vulnerabilities)} vulnerabilities** were identified, including "
            f"**{crit_count} Critical** and **{high_count} High** severity findings. "
        )

        if crit_count > 0:
            summary += "Immediate remediation is recommended prior to production deployment to eliminate dangerous injection vectors or credential exposure."
        else:
            summary += "Remediation of high and medium findings will harden the application against standard OWASP threat models."

        return summary

    def _build_prompt(self, code_snippet: str, vulnerability: Dict[str, Any], language: str) -> str:
        return f"""You are an elite AppSec engineer performing a secure code review.
Analyze the following security finding in {language} code.

Vulnerability Title: {vulnerability.get('title')}
Reported Severity: {vulnerability.get('severity')}
CWE Identifier: {vulnerability.get('cwe_id')}
Vulnerable Snippet / Line:
```
{vulnerability.get('snippet')}
```

Surrounding Code:
```
{code_snippet[:2000]}
```

Provide your analysis in JSON format with exactly these keys:
{{
    "explanation": "Clear explanation of what the vulnerability is in beginner-friendly terms.",
    "why_dangerous": "Detailed explanation of the risk, impact, and blast radius.",
    "attack_scenario": "Concrete step-by-step example of how an attacker could exploit this.",
    "prevention": "Practical developer guidance on how to avoid this class of vulnerability.",
    "secure_code": "The rewritten secure replacement code."
}}
Ensure the response is strictly valid JSON without markdown wrapping.
"""

    def _call_gemini(self, code: str, vuln: Dict[str, Any], language: str) -> Optional[Dict[str, str]]:
        try:
            import google.generativeai as genai
            genai.configure(api_key=GEMINI_API_KEY)
            model = genai.GenerativeModel(GEMINI_MODEL)
            prompt = self._build_prompt(code, vuln, language)
            response = model.generate_content(prompt)
            return self._parse_json_response(response.text)
        except Exception:
            return None

    def _call_openai(self, code: str, vuln: Dict[str, Any], language: str) -> Optional[Dict[str, str]]:
        try:
            from openai import OpenAI
            client = OpenAI(api_key=OPENAI_API_KEY)
            prompt = self._build_prompt(code, vuln, language)
            response = client.chat.completions.create(
                model=OPENAI_MODEL,
                messages=[
                    {"role": "system", "content": "You are a professional Application Security Engineer."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2
            )
            raw = response.choices[0].message.content
            return self._parse_json_response(raw)
        except Exception:
            return None

    def _call_grok(self, code: str, vuln: Dict[str, Any], language: str) -> Optional[Dict[str, str]]:
        try:
            from openai import OpenAI
            client = OpenAI(api_key=GROK_API_KEY, base_url=GROK_BASE_URL)
            prompt = self._build_prompt(code, vuln, language)
            response = client.chat.completions.create(
                model=GROK_MODEL,
                messages=[
                    {"role": "system", "content": "You are a professional Application Security Engineer."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2
            )
            raw = response.choices[0].message.content
            return self._parse_json_response(raw)
        except Exception:
            return None


    def _call_ollama(self, code: str, vuln: Dict[str, Any], language: str) -> Optional[Dict[str, str]]:
        try:
            prompt = self._build_prompt(code, vuln, language)
            payload = {
                "model": OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False,
                "format": "json"
            }
            resp = requests.post(f"{OLLAMA_BASE_URL}/api/generate", json=payload, timeout=15)
            if resp.status_code == 200:
                return json.loads(resp.json().get("response", "{}"))
        except Exception:
            return None
        return None

    def _parse_json_response(self, text: str) -> Optional[Dict[str, str]]:
        try:
            cleaned = text.strip()
            if cleaned.startswith("```json"):
                cleaned = cleaned[7:]
            if cleaned.startswith("```"):
                cleaned = cleaned[3:]
            if cleaned.endswith("```"):
                cleaned = cleaned[:-3]
            data = json.loads(cleaned.strip())
            return {
                "explanation": data.get("explanation", ""),
                "why_dangerous": data.get("why_dangerous", ""),
                "attack_scenario": data.get("attack_scenario", ""),
                "prevention": data.get("prevention", ""),
                "secure_code": data.get("secure_code", "")
            }
        except Exception:
            return None

    def _generate_fallback(self, code: str, vuln: Dict[str, Any], language: str) -> Dict[str, str]:
        """Provides expert-crafted, context-aware cybersecurity analysis even without active cloud API keys."""
        title = vuln.get("title", "Security Finding")
        cwe = vuln.get("cwe_id", "CWE-Security")
        desc = vuln.get("description", "A potential security weakness was detected.")
        why = vuln.get("why_dangerous", "May compromise confidentiality, integrity, or system availability.")
        attack = vuln.get("attack_scenario", "An unauthorized actor could leverage this flaw to manipulate application logic or data.")
        recom = vuln.get("fix_recommendation", "Refactor the flagged pattern following secure coding practices.")
        secure_code = vuln.get("secure_code", "# Consult secure guidelines for replacement")

        return {
            "explanation": f"{title} ({cwe}): {desc}",
            "why_dangerous": why,
            "attack_scenario": attack,
            "prevention": recom,
            "secure_code": secure_code
        }

    def chat_response(self, query: str, finding_context: Optional[Dict[str, Any]] = None, code: str = "") -> str:
        """Provides conversational AppSec answers for developer queries regarding vulnerabilities."""
        safe_query, _ = sanitize_prompt_injection(query)

        if self.provider == "gemini" and GEMINI_API_KEY:
            try:
                import google.generativeai as genai
                genai.configure(api_key=GEMINI_API_KEY)
                model = genai.GenerativeModel(GEMINI_MODEL)
                prompt = f"You are a Principal Cybersecurity Architect. Answer the developer's question directly:\nQuestion: {safe_query}\nVulnerability Context: {json.dumps(finding_context or {})}\nCode: {code[:1500]}"
                resp = model.generate_content(prompt)
                if resp and resp.text:
                    return resp.text.strip()
            except Exception:
                pass

        elif self.provider == "openai" and OPENAI_API_KEY:
            try:
                from openai import OpenAI
                client = OpenAI(api_key=OPENAI_API_KEY)
                prompt = f"You are a Principal Cybersecurity Architect. Answer the developer's question directly:\nQuestion: {safe_query}\nVulnerability Context: {json.dumps(finding_context or {})}\nCode: {code[:1500]}"
                resp = client.chat.completions.create(
                    model=OPENAI_MODEL,
                    messages=[{"role": "system", "content": "You are an elite AppSec Architect."}, {"role": "user", "content": prompt}]
                )
                return resp.choices[0].message.content
            except Exception:
                pass

        elif self.provider == "grok" and GROK_API_KEY:
            try:
                from openai import OpenAI
                client = OpenAI(api_key=GROK_API_KEY, base_url=GROK_BASE_URL)
                prompt = f"You are a Principal Cybersecurity Architect. Answer the developer's question directly:\nQuestion: {safe_query}\nVulnerability Context: {json.dumps(finding_context or {})}\nCode: {code[:1500]}"
                resp = client.chat.completions.create(
                    model=GROK_MODEL,
                    messages=[{"role": "system", "content": "You are an elite AppSec Architect."}, {"role": "user", "content": prompt}]
                )
                return resp.choices[0].message.content
            except Exception:
                pass

        q_lower = safe_query.lower()
        title = finding_context.get("title", "this finding") if finding_context else "this pattern"
        cwe = finding_context.get("cwe_id", "CWE-Security") if finding_context else ""

        if "false positive" in q_lower or "not a bug" in q_lower:
            return f"To evaluate if {title} ({cwe}) is a false positive: verify whether user input is strictly validated by an allowlist schema earlier in the pipeline. If sanitized by design, you can document and mark it as a verified false positive in your compliance audit log."
        elif "exploit" in q_lower or "attacker" in q_lower or "how" in q_lower:
            return f"An attacker exploits {title} by supplying boundary-breaking input (e.g. quote delimiters for SQL injection, traversal sequences '../' for path traversal, or shell separators). This coerces the interpreter to execute arbitrary attacker logic under server privileges."
        elif "fix" in q_lower or "prevent" in q_lower or "orm" in q_lower:
            return f"Best practice remediation for {title}: Replace dynamic concatenation with parameterized interfaces (Prepared Statements, safe subprocess argument arrays, or ORM parameter binding). Never concatenate unvalidated input into execution contexts."
        else:
            return f"Regarding '{safe_query}' on {title} ({cwe}): The key architectural rule is strict separation of code from data. Implement defense-in-depth with input schema validation, least-privilege permissions, and automated regression scanning."


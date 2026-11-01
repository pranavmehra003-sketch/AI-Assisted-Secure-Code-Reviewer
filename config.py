import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
DATABASE_DIR = BASE_DIR / "database"
REPORTS_DIR = BASE_DIR / "reports"
SAMPLE_CODE_DIR = BASE_DIR / "sample_code"

# Ensure runtime directories exist
DATABASE_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
SAMPLE_CODE_DIR.mkdir(parents=True, exist_ok=True)

# Database
DB_PATH = BASE_DIR / os.getenv("DATABASE_PATH", "database/reviews.db")

# AI Settings
AI_PROVIDER = os.getenv("AI_PROVIDER", "gemini").lower()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

# xAI Grok Settings
GROK_API_KEY = os.getenv("GROK_API_KEY", "")
GROK_MODEL = os.getenv("GROK_MODEL", "grok-2-latest")
GROK_BASE_URL = os.getenv("GROK_BASE_URL", "https://api.x.ai/v1")

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "deepseek-coder:6.7b")

# File Upload Constraints
MAX_FILE_SIZE_MB = float(os.getenv("MAX_FILE_SIZE_MB", 5.0))
MAX_FILE_SIZE_BYTES = int(MAX_FILE_SIZE_MB * 1024 * 1024)

SUPPORTED_EXTENSIONS = {
    ".py": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript (React)",
    ".ts": "TypeScript",
    ".tsx": "TypeScript (React)",
    ".java": "Java",
    ".c": "C",
    ".cpp": "C++",
    ".php": "PHP",
    ".go": "Go",
    ".rb": "Ruby",
    ".sql": "SQL",
    ".html": "HTML",
    ".json": "JSON",
    ".yaml": "YAML",
    ".yml": "YAML",
    ".env": "Environment Config"
}

# Severity Colors & Weights for Security Score calculation
SEVERITY_LEVELS = {
    "CRITICAL": {
        "color": "#FF2B2B",
        "badge_color": "danger",
        "weight": 25,
        "cvss_range": "9.0 - 10.0"
    },
    "HIGH": {
        "color": "#FF7A00",
        "badge_color": "warning",
        "weight": 15,
        "cvss_range": "7.0 - 8.9"
    },
    "MEDIUM": {
        "color": "#FFC000",
        "badge_color": "secondary",
        "weight": 7,
        "cvss_range": "4.0 - 6.9"
    },
    "LOW": {
        "color": "#00C853",
        "badge_color": "info",
        "weight": 2,
        "cvss_range": "0.1 - 3.9"
    },
    "INFO": {
        "color": "#29B6F6",
        "badge_color": "light",
        "weight": 0,
        "cvss_range": "0.0"
    }
}

# OWASP Top 10 Mapping Reference
OWASP_CATEGORIES = {
    "A01:2021": "Broken Access Control",
    "A02:2021": "Cryptographic Failures",
    "A03:2021": "Injection",
    "A04:2021": "Insecure Design",
    "A05:2021": "Security Misconfiguration",
    "A06:2021": "Vulnerable and Outdated Components",
    "A07:2021": "Identification and Authentication Failures",
    "A08:2021": "Software and Data Integrity Failures",
    "A09:2021": "Security Logging and Monitoring Failures",
    "A10:2021": "Server-Side Request Forgery (SSRF)"
}

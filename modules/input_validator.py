import re
from pathlib import Path
from typing import Tuple, Dict, Any
from config import MAX_FILE_SIZE_BYTES, MAX_FILE_SIZE_MB, SUPPORTED_EXTENSIONS

# Common binary magic headers to prevent malware/binary ingestion
BINARY_SIGNATURES = [
    b"MZ",            # DOS/Windows PE Executable
    b"\x7fELF",       # Linux ELF Executable
    b"\xca\xfe\xba\xbe", # Java Class File / Mach-O universal
    b"\xfe\xed\xfa\xce", # Mach-O 32-bit
    b"\xfe\xed\xfa\xcf", # Mach-O 64-bit
    b"PK\x03\x04",    # Zip / Jar / Docx archive
]

PROMPT_INJECTION_PATTERNS = [
    r"ignore (all )?previous instructions",
    r"disregard all previous prompts",
    r"system prompt override",
    r"you are now (an unrestricted|in developer mode|DAN)",
    r"reveal (the )?system instructions",
    r"output (your|the) prompt"
]

def detect_language(filename: str) -> str:
    """Infers programming language from file extension."""
    suffix = Path(filename).suffix.lower()
    return SUPPORTED_EXTENSIONS.get(suffix, "Unknown")

def is_binary_content(raw_bytes: bytes) -> bool:
    """Checks if byte stream represents binary or executable content."""
    for sig in BINARY_SIGNATURES:
        if raw_bytes.startswith(sig):
            return True
    # Null byte heuristic: pure source code files rarely have null bytes
    if b"\x00" in raw_bytes[:4096]:
        return True
    return False

def validate_uploaded_file(filename: str, file_bytes: bytes) -> Tuple[bool, str, str]:
    """
    Validates uploaded file against size limits, binary execution hazards,
    and supported extensions.
    Returns: (is_valid, error_msg, language)
    """
    if not filename or len(filename.strip()) == 0:
        return False, "Filename cannot be empty.", ""

    # Size check
    file_size = len(file_bytes)
    if file_size == 0:
        return False, "File is empty (0 bytes). Please upload valid source code.", ""

    if file_size > MAX_FILE_SIZE_BYTES:
        return False, f"File exceeds maximum allowed size ({MAX_FILE_SIZE_MB} MB).", ""

    # Extension check
    suffix = Path(filename).suffix.lower()
    if suffix not in SUPPORTED_EXTENSIONS:
        supported = ", ".join(SUPPORTED_EXTENSIONS.keys())
        return False, f"Unsupported file extension '{suffix}'. Supported formats: {supported}", ""

    # Binary check
    if is_binary_content(file_bytes):
        return False, "Executable or binary payload detected. Only plaintext source files are accepted.", ""

    # Decode text check
    try:
        file_bytes.decode("utf-8")
    except UnicodeDecodeError:
        try:
            file_bytes.decode("latin-1")
        except Exception:
            return False, "File encoding is not recognized. Please upload UTF-8 encoded text.", ""

    language = detect_language(filename)
    return True, "", language

def sanitize_prompt_injection(code: str) -> Tuple[str, bool]:
    """
    Detects and sanitizes potential prompt injection vectors inside source code
    comments or string literals before passing to LLM context.
    """
    detected_injection = False
    sanitized = code

    for pattern in PROMPT_INJECTION_PATTERNS:
        matches = re.findall(pattern, sanitized, re.IGNORECASE)
        if matches:
            detected_injection = True
            sanitized = re.sub(pattern, "[BLOCKED_PROMPT_INJECTION_ATTEMPT]", sanitized, flags=re.IGNORECASE)

    return sanitized, detected_injection

def mask_secrets_for_ai(code: str) -> str:
    """
    Masks high-entropy keys, passwords, and tokens before sending source code
    to external LLMs to ensure zero data leakage.
    """
    patterns = [
        # AWS Access Key
        (r"(AKIA[0-9A-Z]{16})", r"AKIA****************"),
        # Bearer / JWT Tokens
        (r"(Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)", r"Bearer [REDACTED_JWT_TOKEN]"),
        # Generic API Keys / Tokens
        (r"(?i)(api_key|apikey|secret|token|password|auth_token)\s*[:=]\s*['\"][A-Za-z0-9_\-\.+=/]{12,}['\"]",
         r'\1 = "[REDACTED_SECRET_BY_REVIEWER]"'),
        # Private Keys
        (r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[^-]+-----END [A-Z ]+ PRIVATE KEY-----",
         r"-----BEGIN PRIVATE KEY-----\n[REDACTED_PRIVATE_KEY]\n-----END PRIVATE KEY-----")
    ]

    masked = code
    for pat, rep in patterns:
        masked = re.sub(pat, rep, masked, flags=re.DOTALL)
    return masked

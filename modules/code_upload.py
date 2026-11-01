import os
from pathlib import Path
from typing import Dict, Any, List, Optional
from config import SAMPLE_CODE_DIR
from modules.input_validator import validate_uploaded_file, detect_language

def load_sample_file(sample_filename: str) -> Optional[str]:
    """Loads source code from the sample_code repository directory."""
    path = SAMPLE_CODE_DIR / sample_filename
    if path.exists():
        return path.read_text(encoding="utf-8")
    return None

def get_available_samples() -> List[str]:
    """Lists available sample vulnerable code files."""
    if not SAMPLE_CODE_DIR.exists():
        return []
    return [f.name for f in SAMPLE_CODE_DIR.iterdir() if f.is_file()]

def process_uploaded_file(uploaded_file) -> Dict[str, Any]:
    """
    Validates and extracts content from a Streamlit UploadedFile object.
    Returns:
        {
            "is_valid": bool,
            "filename": str,
            "content": str,
            "language": str,
            "error": str
        }
    """
    filename = uploaded_file.name
    raw_bytes = uploaded_file.getvalue()

    is_valid, error_msg, language = validate_uploaded_file(filename, raw_bytes)
    if not is_valid:
        return {
            "is_valid": False,
            "filename": filename,
            "content": "",
            "language": "",
            "error": error_msg
        }

    try:
        content = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        content = raw_bytes.decode("latin-1", errors="replace")

    return {
        "is_valid": True,
        "filename": filename,
        "content": content,
        "language": language,
        "error": ""
    }

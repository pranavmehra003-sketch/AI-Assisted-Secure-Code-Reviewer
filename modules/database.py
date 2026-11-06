import sqlite3
import json
from datetime import datetime
from typing import List, Dict, Any, Optional
from config import DB_PATH, DATABASE_DIR

def get_connection():
    try:
        DATABASE_DIR.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    # Enable cascading deletes (SQLite requires this per-connection)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    """Initializes the database schema if tables do not exist."""
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            file_language TEXT NOT NULL,
            code_snippet TEXT,
            security_score REAL NOT NULL,
            total_issues INTEGER NOT NULL,
            critical_count INTEGER DEFAULT 0,
            high_count INTEGER DEFAULT 0,
            medium_count INTEGER DEFAULT 0,
            low_count INTEGER DEFAULT 0,
            ai_provider TEXT DEFAULT 'none',
            executive_summary TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            review_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            category TEXT,
            cwe_id TEXT,
            line_number INTEGER,
            snippet TEXT,
            description TEXT,
            why_dangerous TEXT,
            attack_scenario TEXT,
            fix_recommendation TEXT,
            secure_code TEXT,
            scanner_source TEXT,
            FOREIGN KEY (review_id) REFERENCES reviews(id) ON DELETE CASCADE
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            details TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Warning: Database initialization skipped or failed: {e}")

def save_review(
    filename: str,
    file_language: str,
    code_snippet: str,
    security_score: float,
    total_issues: int,
    critical_count: int,
    high_count: int,
    medium_count: int,
    low_count: int,
    ai_provider: str,
    executive_summary: str = ""
) -> int:
    """Inserts a new review record and returns its ID."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO reviews (
            filename, file_language, code_snippet, security_score,
            total_issues, critical_count, high_count, medium_count,
            low_count, ai_provider, executive_summary
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        filename, file_language, code_snippet[:5000], security_score,
        total_issues, critical_count, high_count, medium_count,
        low_count, ai_provider, executive_summary
    ))
    review_id = cursor.lastrowid
    conn.commit()
    conn.close()

    log_audit_event("REVIEW_SAVED", f"Review #{review_id} saved for {filename} with score {security_score}")
    return review_id

def save_vulnerabilities(review_id: int, vulnerabilities: List[Dict[str, Any]]):
    """Saves detected vulnerabilities for a given review."""
    conn = get_connection()
    cursor = conn.cursor()
    for v in vulnerabilities:
        cursor.execute("""
            INSERT INTO vulnerabilities (
                review_id, title, severity, category, cwe_id,
                line_number, snippet, description, why_dangerous,
                attack_scenario, fix_recommendation, secure_code, scanner_source
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            review_id,
            v.get("title", "Unknown Finding"),
            v.get("severity", "LOW").upper(),
            v.get("category", "General"),
            v.get("cwe_id", "CWE-Unknown"),
            v.get("line_number", 0),
            v.get("snippet", ""),
            v.get("description", ""),
            v.get("why_dangerous", ""),
            v.get("attack_scenario", ""),
            v.get("fix_recommendation", ""),
            v.get("secure_code", ""),
            v.get("scanner_source", "Static")
        ))
    conn.commit()
    conn.close()

def get_reviews(limit: int = 50) -> List[Dict[str, Any]]:
    """Fetches recent reviews."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM reviews ORDER BY id DESC LIMIT ?
    """, (limit,))
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows

def get_review_by_id(review_id: int) -> Optional[Dict[str, Any]]:
    """Retrieves a single review record."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM reviews WHERE id = ?", (review_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def get_vulnerabilities_by_review(review_id: int) -> List[Dict[str, Any]]:
    """Retrieves all vulnerabilities for a specific review."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM vulnerabilities WHERE review_id = ? ORDER BY
        CASE severity
            WHEN 'CRITICAL' THEN 1
            WHEN 'HIGH' THEN 2
            WHEN 'MEDIUM' THEN 3
            WHEN 'LOW' THEN 4
            ELSE 5
        END ASC
    """, (review_id,))
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows

def delete_review(review_id: int) -> bool:
    """Deletes a review and cascaded findings."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM reviews WHERE id = ?", (review_id,))
    cursor.execute("DELETE FROM vulnerabilities WHERE review_id = ?", (review_id,))
    conn.commit()
    conn.close()
    log_audit_event("REVIEW_DELETED", f"Review #{review_id} deleted")
    return True

def get_security_stats() -> Dict[str, Any]:
    """Computes aggregated metrics for the overview dashboard."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*), AVG(security_score) FROM reviews")
    total_reviews, avg_score = cursor.fetchone()
    total_reviews = total_reviews or 0
    avg_score = round(avg_score or 100.0, 1)

    cursor.execute("""
        SELECT
            SUM(critical_count),
            SUM(high_count),
            SUM(medium_count),
            SUM(low_count),
            SUM(total_issues)
        FROM reviews
    """)
    crit, high, med, low, total_issues = cursor.fetchone()

    conn.close()
    return {
        "total_reviews": total_reviews,
        "avg_security_score": avg_score,
        "critical_issues": crit or 0,
        "high_issues": high or 0,
        "medium_issues": med or 0,
        "low_issues": low or 0,
        "total_vulnerabilities": total_issues or 0
    }

def log_audit_event(event_type: str, details: str):
    """Appends an event to the security audit trail."""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO audit_logs (event_type, details) VALUES (?, ?)", (event_type, details))
        conn.commit()
        conn.close()
    except Exception:
        pass


def get_audit_logs(limit: int = 100) -> List[Dict[str, Any]]:
    """Fetches recent audit log entries."""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,)
        )
        rows = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return rows
    except Exception:
        return []

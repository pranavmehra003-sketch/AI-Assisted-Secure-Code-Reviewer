import React, { useState, useEffect } from 'react';
import confetti from 'canvas-confetti';
import { 
  Shield, AlertTriangle, CheckCircle, Code2, FileText, 
  Download, Terminal, RefreshCw, Trash2, Cpu, ExternalLink,
  ChevronDown, ChevronUp, Check, Play, BookOpen, Clock, Lock
} from 'lucide-react';
import './App.css';

const DEFAULT_CODE = `import sqlite3

def get_user(username):
    conn = sqlite3.connect("users.db")
    # Vulnerable SQL query concatenation
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    return conn.execute(query).fetchall()
`;

export default function App() {
  const [activeTab, setActiveTab] = useState('audit'); // 'audit', 'history', 'owasp'
  const [code, setCode] = useState(DEFAULT_CODE);
  const [filename, setFilename] = useState('vulnerable_script.py');
  const [language, setLanguage] = useState('Python');
  const [aiProvider, setAiProvider] = useState('offline');
  const [apiKey, setApiKey] = useState('');
  
  const [loading, setLoading] = useState(false);
  const [scanStep, setScanStep] = useState('');
  const [reviewResult, setReviewResult] = useState(null);
  const [expandedFindings, setExpandedFindings] = useState({});
  const [verifyStatus, setVerifyStatus] = useState({});
  
  const [samples, setSamples] = useState([]);
  const [history, setHistory] = useState([]);
  const [apiOnline, setApiOnline] = useState(true);

  // Fetch samples and health on mount
  useEffect(() => {
    fetch('/api/samples')
      .then(res => res.json())
      .then(data => {
        if (data.samples) setSamples(data.samples);
      })
      .catch(() => setApiOnline(false));

    loadHistory();
  }, []);

  const loadHistory = () => {
    fetch('/api/history')
      .then(res => res.json())
      .then(data => {
        if (data.reviews) setHistory(data.reviews);
      })
      .catch(() => {});
  };

  const handleSampleSelect = (sampleId) => {
    const s = samples.find(item => item.id === sampleId);
    if (s) {
      setCode(s.code);
      setFilename(s.id);
      setLanguage(s.language);
    }
  };

  const handleFileUpload = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    setFilename(file.name);
    const reader = new FileReader();
    reader.onload = (event) => {
      setCode(event.target.result);
    };
    reader.readAsText(file);
  };

  const runAudit = async () => {
    setLoading(true);
    setReviewResult(null);
    setExpandedFindings({});
    setVerifyStatus({});

    setScanStep('Executing AST Static Analysis (Bandit & Custom Rules)...');
    await new Promise(r => setTimeout(r, 400));

    setScanStep('Inspecting credentials with Gitleaks Secret Scanner...');
    await new Promise(r => setTimeout(r, 400));

    setScanStep('Querying AI Engine for contextual security remediation...');

    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          code,
          filename,
          language,
          ai_provider: aiProvider,
          api_key: apiKey || undefined
        })
      });

      if (!res.ok) {
        const err = await res.json();
        alert(`Scan Error: ${err.detail || 'Validation failed'}`);
        setLoading(false);
        return;
      }

      const data = await res.json();
      setReviewResult(data);
      // Auto-expand first finding
      if (data.findings && data.findings.length > 0) {
        setExpandedFindings({ 0: true });
      }

      if (data.security_score >= 85) {
        confetti({ particleCount: 70, spread: 60 });
      }
      loadHistory();
    } catch (err) {
      alert(`Network error contacting review engine: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleVerify = async (index, originalSnippet, fixedCode) => {
    try {
      const res = await fetch('/api/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          original_code: originalSnippet,
          fixed_code: fixedCode,
          filename,
          language
        })
      });
      const data = await res.json();
      setVerifyStatus(prev => ({ ...prev, [index]: data }));
      if (data.syntax_valid) {
        confetti({ particleCount: 40, spread: 50, origin: { y: 0.8 } });
      }
    } catch (e) {
      alert('Verification request failed');
    }
  };

  const downloadReport = async (type) => {
    if (!reviewResult) return;
    try {
      const res = await fetch(`/api/report/${type}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          filename: reviewResult.filename,
          language: reviewResult.language,
          security_score: reviewResult.security_score,
          grade: reviewResult.grade,
          findings: reviewResult.findings,
          executive_summary: reviewResult.executive_summary
        })
      });
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `Security_Report_${filename.split('.')[0]}.${type}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
    } catch (e) {
      alert(`Failed to download ${type.toUpperCase()} report`);
    }
  };

  const deleteHistoryItem = async (reviewId) => {
    try {
      await fetch(`/api/history/${reviewId}`, { method: 'DELETE' });
      loadHistory();
    } catch (e) {}
  };

  return (
    <div>
      {/* Header */}
      <header className="app-header">
        <div className="logo-area">
          <div className="logo-icon">
            <Shield size={24} />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center' }}>
              <span className="brand-title">AI Secure Code Reviewer</span>
              <span className="brand-badge">Vercel Edition</span>
            </div>
            <p style={{ fontSize: '0.75rem', color: '#64748b' }}>Automated SAST & AI Remediation Platform</p>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="nav-tabs">
          <button 
            className={`tab-btn ${activeTab === 'audit' ? 'active' : ''}`}
            onClick={() => setActiveTab('audit')}
          >
            <Code2 size={16} /> Audit & Fix
          </button>
          <button 
            className={`tab-btn ${activeTab === 'history' ? 'active' : ''}`}
            onClick={() => setActiveTab('history')}
          >
            <Clock size={16} /> History ({history.length})
          </button>
          <button 
            className={`tab-btn ${activeTab === 'owasp' ? 'active' : ''}`}
            onClick={() => setActiveTab('owasp')}
          >
            <BookOpen size={16} /> OWASP Guide
          </button>
        </div>

        {/* Status Pill */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8rem', color: '#94a3b8' }}>
          <span style={{ 
            width: '8px', height: '8px', borderRadius: '50%', 
            background: apiOnline ? '#10b981' : '#ef4444', 
            boxShadow: apiOnline ? '0 0 8px #10b981' : 'none' 
          }} />
          {apiOnline ? 'Vercel API Online' : 'API Connecting...'}
        </div>
      </header>

      {/* Main Container */}
      <div className="app-container">
        {/* Sidebar Controls */}
        <aside className="glass-panel control-sidebar">
          <div className="control-group">
            <label className="control-label">AI Engine Provider</label>
            <select 
              className="custom-select"
              value={aiProvider}
              onChange={(e) => setAiProvider(e.target.value)}
            >
              <option value="offline">Built-in Offline Engine (No Key Needed)</option>
              <option value="grok">xAI Grok (Cloud)</option>
              <option value="gemini">Google Gemini (Cloud)</option>
              <option value="openai">OpenAI GPT-4o (Cloud)</option>
              <option value="ollama">Local Ollama (DeepSeek / Llama)</option>
            </select>
          </div>

          {(aiProvider === 'gemini' || aiProvider === 'openai' || aiProvider === 'grok') && (
            <div className="control-group">
              <label className="control-label">
                {aiProvider === 'gemini' ? 'Gemini API Key' : (aiProvider === 'grok' ? 'xAI Grok API Key' : 'OpenAI API Key')}
              </label>
              <input 
                type="password"
                className="custom-input"
                placeholder={aiProvider === 'grok' ? 'xai-xxxxxxxx...' : 'Paste API Key (Optional if in .env)'}
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
              />
              <span style={{ fontSize: '0.72rem', color: '#64748b' }}>Keys are never stored on external servers.</span>
            </div>
          )}

          <div className="control-group">
            <label className="control-label">Preset Vulnerable Samples</label>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
              <button className="btn-action" onClick={() => handleSampleSelect('vulnerable_python.py')}>
                🐍 Python: SQLi & Command Injection
              </button>
              <button className="btn-action" onClick={() => handleSampleSelect('secure_python.py')}>
                🛡️ Python: Remediated Baseline
              </button>
              <button className="btn-action" onClick={() => handleSampleSelect('vulnerable_js.js')}>
                ⚡ JavaScript: XSS & Eval
              </button>
              <button className="btn-action" onClick={() => handleSampleSelect('vulnerable_java.java')}>
                ☕ Java: SQLi & Broken MD5
              </button>
            </div>
          </div>

          <div className="control-group">
            <label className="control-label">Upload Local File</label>
            <input 
              type="file" 
              className="custom-input" 
              onChange={handleFileUpload} 
              accept=".py,.js,.jsx,.ts,.tsx,.java,.c,.cpp,.go,.php,.sql,.html,.env"
            />
          </div>

          <div style={{ marginTop: 'auto', padding: '1rem', background: '#0b111e', borderRadius: '8px', fontSize: '0.75rem', color: '#64748b' }}>
            <p style={{ fontWeight: '600', color: '#94a3b8', marginBottom: '0.2rem' }}>🔒 Zero-Knowledge Redaction</p>
            Hardcoded credentials and secrets are automatically redacted locally before AI processing.
          </div>
        </aside>

        {/* Main Content Area */}
        <main>
          {activeTab === 'audit' && (
            <div>
              {/* Code Editor Panel */}
              <div className="glass-panel editor-panel" style={{ marginBottom: '1.5rem' }}>
                <div className="editor-header">
                  <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
                    <input 
                      type="text" 
                      className="custom-input" 
                      style={{ width: '220px', padding: '0.4rem 0.6rem', fontSize: '0.85rem' }} 
                      value={filename}
                      onChange={(e) => setFilename(e.target.value)}
                    />
                    <select 
                      className="custom-select" 
                      style={{ padding: '0.4rem 0.6rem', fontSize: '0.85rem' }}
                      value={language}
                      onChange={(e) => setLanguage(e.target.value)}
                    >
                      <option value="Python">Python</option>
                      <option value="JavaScript">JavaScript</option>
                      <option value="Java">Java</option>
                      <option value="C/C++">C/C++</option>
                      <option value="PHP">PHP</option>
                      <option value="Go">Go</option>
                      <option value="SQL">SQL</option>
                    </select>
                  </div>
                  <span style={{ fontSize: '0.78rem', color: '#64748b' }}>{code.length} chars | {code.split('\n').length} lines</span>
                </div>

                <textarea 
                  className="code-textarea"
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                  placeholder="Paste source code to audit..."
                  spellCheck="false"
                />

                <button 
                  className="btn-audit btn-shimmer"
                  onClick={runAudit}
                  disabled={loading}
                >
                  {loading ? (
                    <>
                      <RefreshCw className="spin" size={18} /> {scanStep}
                    </>
                  ) : (
                    <>
                      <Shield size={18} /> Execute AI Security Review
                    </>
                  )}
                </button>
              </div>

              {/* Review Results */}
              {reviewResult && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                  {/* Score Hero Card */}
                  <div className="glass-panel score-hero">
                    <div 
                      className="score-badge-circle"
                      style={{
                        borderColor: reviewResult.security_score >= 80 ? '#10b981' : (reviewResult.security_score >= 60 ? '#f59e0b' : '#ef4444'),
                        color: reviewResult.security_score >= 80 ? '#10b981' : (reviewResult.security_score >= 60 ? '#f59e0b' : '#ef4444')
                      }}
                    >
                      <span style={{ fontSize: '1.8rem', lineHeight: 1 }}>{reviewResult.security_score}</span>
                      <span style={{ fontSize: '0.7rem', color: '#94a3b8' }}>/ 100</span>
                    </div>

                    <div style={{ flex: 1 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.35rem' }}>
                        <h2 style={{ fontSize: '1.4rem', fontWeight: 800 }}>Audit Score: Grade {reviewResult.grade}</h2>
                      </div>
                      <p style={{ fontSize: '0.88rem', color: '#cbd5e1', lineHeight: 1.5 }}>
                        {reviewResult.executive_summary}
                      </p>
                    </div>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                      <button className="btn-action" onClick={() => downloadReport('pdf')}>
                        <Download size={14} /> Download PDF
                      </button>
                      <button className="btn-action" onClick={() => downloadReport('json')}>
                        <FileText size={14} /> Download JSON
                      </button>
                    </div>
                  </div>

                  {/* Metrics Row */}
                  <div className="metrics-grid">
                    <div className="glass-panel metric-card" style={{ borderTop: '3px solid #ef4444' }}>
                      <span className="metric-val" style={{ color: '#ef4444' }}>{reviewResult.counts.CRITICAL}</span>
                      <span className="metric-lbl">Critical</span>
                    </div>
                    <div className="glass-panel metric-card" style={{ borderTop: '3px solid #f97316' }}>
                      <span className="metric-val" style={{ color: '#f97316' }}>{reviewResult.counts.HIGH}</span>
                      <span className="metric-lbl">High</span>
                    </div>
                    <div className="glass-panel metric-card" style={{ borderTop: '3px solid #eab308' }}>
                      <span className="metric-val" style={{ color: '#eab308' }}>{reviewResult.counts.MEDIUM}</span>
                      <span className="metric-lbl">Medium</span>
                    </div>
                    <div className="glass-panel metric-card" style={{ borderTop: '3px solid #10b981' }}>
                      <span className="metric-val" style={{ color: '#10b981' }}>{reviewResult.counts.LOW}</span>
                      <span className="metric-lbl">Low / Info</span>
                    </div>
                  </div>

                  {/* Findings Section */}
                  <div>
                    <h3 style={{ fontSize: '1.2rem', fontWeight: 800, marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <AlertTriangle size={20} color="#00f5a0" />
                      Identified Findings ({reviewResult.findings.length})
                    </h3>

                    {reviewResult.findings.length === 0 ? (
                      <div className="glass-panel" style={{ padding: '2rem', textAlign: 'center' }}>
                        <CheckCircle size={40} color="#10b981" style={{ margin: '0 auto 0.75rem' }} />
                        <h4 style={{ fontSize: '1.1rem', fontWeight: 700 }}>Clean Codebase</h4>
                        <p style={{ fontSize: '0.88rem', color: '#94a3b8' }}>No vulnerabilities or exposed credentials detected.</p>
                      </div>
                    ) : (
                      reviewResult.findings.map((f, idx) => {
                        const isExpanded = !!expandedFindings[idx];
                        const verifyData = verifyStatus[idx];
                        return (
                          <div 
                            key={idx} 
                            className={`glass-panel finding-card ${f.severity.toLowerCase()}`}
                          >
                            <div 
                              style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', cursor: 'pointer' }}
                              onClick={() => setExpandedFindings(p => ({ ...p, [idx]: !p[idx] }))}
                            >
                              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                                <span className={`badge badge-${f.severity.toLowerCase()}`}>{f.severity}</span>
                                <span style={{ fontWeight: 700, fontSize: '0.98rem' }}>#{idx + 1}. {f.title}</span>
                                <span style={{ fontSize: '0.75rem', color: '#64748b' }}>({f.cwe_id}) Line {f.line_number || 'N/A'}</span>
                              </div>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>{f.scanner_source}</span>
                                {isExpanded ? <ChevronUp size={18} /> : <ChevronDown size={18} />}
                              </div>
                            </div>

                            {isExpanded && (
                              <div style={{ marginTop: '1.25rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                                <div>
                                  <label className="control-label">Vulnerable Code Snippet</label>
                                  <div className="snippet-box">{f.snippet}</div>
                                </div>

                                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                                  <div style={{ padding: '0.85rem', background: '#0b111e', borderRadius: '8px' }}>
                                    <p style={{ fontWeight: 700, color: '#f87171', fontSize: '0.8rem', marginBottom: '0.3rem' }}>💥 Why Dangerous?</p>
                                    <p style={{ fontSize: '0.84rem', color: '#cbd5e1', lineHeight: 1.4 }}>{f.why_dangerous}</p>
                                  </div>
                                  <div style={{ padding: '0.85rem', background: '#0b111e', borderRadius: '8px' }}>
                                    <p style={{ fontWeight: 700, color: '#38bdf8', fontSize: '0.8rem', marginBottom: '0.3rem' }}>🎯 Attack Scenario</p>
                                    <p style={{ fontSize: '0.84rem', color: '#cbd5e1', lineHeight: 1.4 }}>{f.attack_scenario}</p>
                                  </div>
                                </div>

                                <div>
                                  <label className="control-label">Recommended Secure Replacement</label>
                                  <div className="secure-box">{f.secure_code}</div>
                                </div>

                                {f.diff && (
                                  <div>
                                    <label className="control-label">Unified Diff</label>
                                    <div className="diff-box">{f.diff}</div>
                                  </div>
                                )}

                                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderTop: '1px solid var(--border-subtle)', paddingTop: '0.85rem' }}>
                                  <button 
                                    className="btn-action btn-verify"
                                    onClick={() => handleVerify(idx, f.snippet, f.secure_code)}
                                  >
                                    <Check size={14} /> Verify Fix & Check Score Delta
                                  </button>

                                  {verifyData && (
                                    <span style={{ fontSize: '0.85rem', color: verifyData.syntax_valid ? '#10b981' : '#f59e0b' }}>
                                      {verifyData.syntax_valid 
                                        ? `✓ Syntax Valid! Score Improved: ${verifyData.original_score} -> ${verifyData.new_score} (+${verifyData.score_delta} pts)`
                                        : `⚠️ ${verifyData.syntax_error}`
                                      }
                                    </span>
                                  )}
                                </div>
                              </div>
                            )}
                          </div>
                        );
                      })
                    )}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* History Tab */}
          {activeTab === 'history' && (
            <div className="glass-panel" style={{ padding: '1.5rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
                <h3 style={{ fontSize: '1.2rem', fontWeight: 800 }}>Audit Review Log</h3>
                <button className="btn-action" onClick={loadHistory}>
                  <RefreshCw size={14} /> Refresh
                </button>
              </div>

              {history.length === 0 ? (
                <p style={{ color: '#94a3b8' }}>No review records found in database.</p>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                  {history.map(item => (
                    <div 
                      key={item.id} 
                      style={{ 
                        display: 'flex', justifyContent: 'space-between', alignItems: 'center', 
                        padding: '1rem', background: '#0b111e', borderRadius: '8px', border: '1px solid var(--border-subtle)' 
                      }}
                    >
                      <div>
                        <div style={{ fontWeight: 700, fontSize: '0.95rem', color: '#f1f5f9' }}>
                          Review #{item.id} — {item.filename} ({item.file_language})
                        </div>
                        <div style={{ fontSize: '0.75rem', color: '#64748b', marginTop: '0.2rem' }}>
                          Audited At: {item.created_at} | Issues: {item.total_issues} (Crit: {item.critical_count}, High: {item.high_count})
                        </div>
                      </div>

                      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                        <span style={{ 
                          fontSize: '1.1rem', fontWeight: 800, 
                          color: item.security_score >= 80 ? '#10b981' : (item.security_score >= 60 ? '#f59e0b' : '#ef4444') 
                        }}>
                          {item.security_score}%
                        </span>
                        <button 
                          className="btn-action" 
                          style={{ padding: '0.35rem 0.6rem', color: '#ef4444' }}
                          onClick={() => deleteHistoryItem(item.id)}
                        >
                          <Trash2 size={14} />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* OWASP Guide Tab */}
          {activeTab === 'owasp' && (
            <div className="glass-panel" style={{ padding: '1.5rem' }}>
              <h3 style={{ fontSize: '1.2rem', fontWeight: 800, marginBottom: '0.5rem' }}>OWASP Top 10 Reference Guide</h3>
              <p style={{ fontSize: '0.85rem', color: '#94a3b8', marginBottom: '1.5rem' }}>
                Key software vulnerabilities, exploitation mechanics, and defense strategies for security engineering interviews and production systems.
              </p>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                {[
                  { id: "A01:2021", name: "Broken Access Control", cwe: "CWE-22, CWE-284", desc: "Failures that allow unauthorized actors to view, edit, or delete unauthorized resources.", fix: "Enforce strict server-side authorization checks, use realpath() checks for path traversal, and deny access by default." },
                  { id: "A02:2021", name: "Cryptographic Failures", cwe: "CWE-327, CWE-328", desc: "Use of outdated hash algorithms (MD5, SHA1) or exposing credentials in code repositories.", fix: "Use salted PBKDF2/Argon2 for passwords, SHA-256 for integrity, and load secrets via protected environment variables." },
                  { id: "A03:2021", name: "Injection", cwe: "CWE-89, CWE-78, CWE-79", desc: "Dynamic concatenation of user inputs into SQL queries, system shells, or HTML outputs.", fix: "Employ parameterized queries (Prepared Statements), disable shell=True, and sanitize DOM insertions." },
                  { id: "A05:2021", name: "Security Misconfiguration", cwe: "CWE-215, CWE-1188", desc: "Leaving debug flags enabled in production, exposing interactive stack traces, or permissive CORS.", fix: "Set DEBUG=False, disable unnecessary web services, and restrict CORS headers." },
                  { id: "A08:2021", name: "Software and Data Integrity Failures", cwe: "CWE-502", desc: "Deserializing untrusted data with formats like pickle or yaml.load without safe loaders.", fix: "Never deserialize untrusted payloads with pickle; prefer JSON or signed HMAC tokens." },
                  { id: "A10:2021", name: "Server-Side Request Forgery (SSRF)", cwe: "CWE-918", desc: "Inducing the server to make unauthorized HTTP requests to internal IP ranges (e.g. AWS metadata 169.254.169.254).", fix: "Validate target URLs against domain allowlists and reject private CIDR/loopback IP blocks." }
                ].map((item, idx) => (
                  <div key={idx} style={{ padding: '1rem', background: '#0b111e', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.4rem' }}>
                      <span style={{ fontWeight: 800, color: '#00f5a0' }}>{item.id}: {item.name}</span>
                      <span style={{ fontSize: '0.75rem', color: '#64748b' }}>{item.cwe}</span>
                    </div>
                    <p style={{ fontSize: '0.85rem', color: '#cbd5e1', marginBottom: '0.4rem' }}>{item.desc}</p>
                    <p style={{ fontSize: '0.8rem', color: '#38bdf8' }}><strong>Remediation:</strong> {item.fix}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}

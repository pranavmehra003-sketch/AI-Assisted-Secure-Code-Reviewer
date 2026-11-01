import React, { useState, useEffect } from 'react';
import confetti from 'canvas-confetti';
import { 
  ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Cell,
  PieChart, Pie, Legend, AreaChart, Area, CartesianGrid
} from 'recharts';
import { 
  Shield, AlertTriangle, CheckCircle, Code2, FileText, 
  Download, Terminal, RefreshCw, Trash2, Cpu, ExternalLink,
  ChevronDown, ChevronUp, Check, Play, BookOpen, Clock, Lock,
  LayoutDashboard, GitPullRequest, GitBranch, Bug, MessageSquare,
  Search, Copy, Sparkles, Filter, AlertOctagon, Info, ArrowUpRight,
  Send, Bot, User, CheckSquare, XCircle, Sliders, TrendingUp,
  Minus, Square, X
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
  // Navigation State - defaults to Dashboard
  const [activePage, setActivePage] = useState('dashboard'); // 'dashboard', 'scanner', 'vulnerabilities', 'fixes', 'chat', 'github', 'reports'

  // Code & Scan State
  const [code, setCode] = useState(DEFAULT_CODE);
  const [filename, setFilename] = useState('vulnerable_auth.py');
  const [language, setLanguage] = useState('Python');
  const [aiProvider, setAiProvider] = useState('offline');
  const [apiKey, setApiKey] = useState('');
  
  const [loading, setLoading] = useState(false);
  const [scanStep, setScanStep] = useState('');
  const [reviewResult, setReviewResult] = useState(null);
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [falsePositives, setFalsePositives] = useState({});
  const [verifyStatus, setVerifyStatus] = useState({});
  const [copiedIndex, setCopiedIndex] = useState(null);

  // Chat State
  const [chatMessages, setChatMessages] = useState([
    {
      role: 'bot',
      content: 'Hello! I am your AI AppSec Security Assistant. You can ask me how to exploit specific findings, how to implement enterprise hardening, or how to verify false positives.'
    }
  ]);
  const [chatInput, setChatInput] = useState('');
  const [chatLoading, setChatLoading] = useState(false);

  // GitHub PR Simulation State
  const [prApproved, setPrApproved] = useState(false);

  // Data State
  const [samples, setSamples] = useState([]);
  const [history, setHistory] = useState([]);
  const [stats, setStats] = useState({ total_reviews: 0, avg_security_score: 100, critical_issues: 0, high_issues: 0, total_vulnerabilities: 0 });
  const [apiOnline, setApiOnline] = useState(true);

  // Fetch samples, stats and history on mount
  useEffect(() => {
    fetch('/api/health')
      .then(res => res.json())
      .then(data => {
        setApiOnline(true);
        if (data.metrics) setStats(data.metrics);
      })
      .catch(() => setApiOnline(false));

    fetch('/api/samples')
      .then(res => res.json())
      .then(data => {
        if (data.samples) setSamples(data.samples);
      })
      .catch(() => {});

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
      setActivePage('scanner');
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
    setScanStep('1/4 Parsing AST with Bandit Semantic Engine...');
    await new Promise(r => setTimeout(r, 350));

    setScanStep('2/4 Scanning tokens with Gitleaks Secret Scanner...');
    await new Promise(r => setTimeout(r, 350));

    setScanStep('3/4 Matching OWASP Top 10 Multi-Language Rules...');
    await new Promise(r => setTimeout(r, 350));

    setScanStep('4/4 Synthesizing AI Remediations & Code Diffs...');

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
        alert(`Scan failed: ${err.detail || 'Validation error'}`);
        setLoading(false);
        return;
      }

      const data = await res.json();
      setReviewResult(data);
      loadHistory();

      if (data.security_score >= 85) {
        confetti({ particleCount: 80, spread: 70 });
      }

      // Automatically transition to Vulnerabilities view if flaws found, or stay on dashboard
      setActivePage('vulnerabilities');
    } catch (err) {
      alert(`Network error connecting to scanner: ${err.message}`);
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
        confetti({ particleCount: 45, spread: 60, origin: { y: 0.8 } });
      }
    } catch (e) {
      alert('Verification request failed');
    }
  };

  const handleChatSend = async (messageText) => {
    const textToSend = messageText || chatInput;
    if (!textToSend.trim()) return;

    const newMessages = [...chatMessages, { role: 'user', content: textToSend }];
    setChatMessages(newMessages);
    setChatInput('');
    setChatLoading(true);

    try {
      const activeFinding = reviewResult?.findings?.[0] || null;
      const res = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: textToSend,
          finding: activeFinding,
          code: code,
          ai_provider: aiProvider,
          api_key: apiKey || undefined
        })
      });
      const data = await res.json();
      setChatMessages([...newMessages, { role: 'bot', content: data.reply }]);
    } catch (e) {
      setChatMessages([...newMessages, { role: 'bot', content: 'Connection to security chat assistant timed out.' }]);
    } finally {
      setChatLoading(false);
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

  const copyToClipboard = (text, index) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  // Filter findings
  const filteredFindings = (reviewResult?.findings || []).filter(f => {
    const matchesSev = severityFilter === 'ALL' || f.severity.toUpperCase() === severityFilter;
    const matchesSearch = !searchQuery || 
      f.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.cwe_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.category.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesSev && matchesSearch;
  });

  return (
    <div className="enterprise-layout">
      {/* 1. Sidebar Navigation */}
      <aside className="cyber-sidebar">
        <div className="sidebar-header">
          <div className="brand-row">
            <div className="brand-shield">
              <Shield size={20} />
            </div>
            <div className="brand-text">
              <h1>SecureCode AI</h1>
              <p>Intelligent Code Security</p>
            </div>
          </div>
        </div>

        <nav className="sidebar-nav">
          <div className="nav-section-title">Workspace</div>

          <button 
            className={`nav-item ${activePage === 'dashboard' ? 'active' : ''}`}
            onClick={() => setActivePage('dashboard')}
          >
            <LayoutDashboard size={17} /> Dashboard
          </button>

          <button 
            className={`nav-item ${activePage === 'scanner' ? 'active' : ''}`}
            onClick={() => setActivePage('scanner')}
          >
            <Code2 size={17} /> Code Scanner
          </button>

          <button 
            className={`nav-item ${activePage === 'vulnerabilities' ? 'active' : ''}`}
            onClick={() => setActivePage('vulnerabilities')}
          >
            <Bug size={17} /> Vulnerabilities
            {reviewResult?.findings?.length > 0 && (
              <span className="nav-badge">{reviewResult.findings.length}</span>
            )}
          </button>

          <button 
            className={`nav-item ${activePage === 'fixes' ? 'active' : ''}`}
            onClick={() => setActivePage('fixes')}
          >
            <Sparkles size={17} /> AI Fix Suggestions
          </button>

          <button 
            className={`nav-item ${activePage === 'chat' ? 'active' : ''}`}
            onClick={() => setActivePage('chat')}
          >
            <MessageSquare size={17} /> AI Security Chat
          </button>

          <button 
            className={`nav-item ${activePage === 'github' ? 'active' : ''}`}
            onClick={() => setActivePage('github')}
          >
            <GitPullRequest size={17} /> Pull Requests (PRs)
          </button>

          <button 
            className={`nav-item ${activePage === 'reports' ? 'active' : ''}`}
            onClick={() => setActivePage('reports')}
          >
            <FileText size={17} /> Security Reports
          </button>

          <div className="nav-section-title" style={{ marginTop: '0.8rem' }}>Preferences</div>

          <div style={{ padding: '0 0.75rem', display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
            <div>
              <label style={{ fontSize: '0.72rem', color: '#64748b', fontWeight: '700' }}>AI PROVIDER</label>
              <select 
                value={aiProvider}
                onChange={(e) => setAiProvider(e.target.value)}
                style={{ width: '100%', background: '#060911', border: '1px solid var(--border-subtle)', color: '#f1f5f9', padding: '0.45rem', borderRadius: '6px', fontSize: '0.78rem', marginTop: '0.2rem' }}
              >
                <option value="offline">Built-in Offline Engine</option>
                <option value="grok">xAI Grok-2 (Cloud)</option>
                <option value="gemini">Google Gemini (Cloud)</option>
                <option value="openai">OpenAI GPT-4o (Cloud)</option>
                <option value="ollama">Local Ollama (DeepSeek)</option>
              </select>
            </div>

            {(aiProvider === 'grok' || aiProvider === 'gemini' || aiProvider === 'openai') && (
              <div>
                <label style={{ fontSize: '0.72rem', color: '#64748b', fontWeight: '700' }}>
                  {aiProvider === 'grok' ? 'GROK KEY' : (aiProvider === 'gemini' ? 'GEMINI KEY' : 'OPENAI KEY')}
                </label>
                <input 
                  type="password"
                  placeholder="Paste API Key..."
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  style={{ width: '100%', background: '#060911', border: '1px solid var(--border-subtle)', color: '#f1f5f9', padding: '0.45rem', borderRadius: '6px', fontSize: '0.78rem', marginTop: '0.2rem' }}
                />
              </div>
            )}
          </div>
        </nav>

        <div className="sidebar-footer">
          <div className="engine-status-box">
            <div className="status-dot-pulse" />
            <div>
              <div style={{ fontSize: '0.78rem', fontWeight: '700', color: '#f1f5f9' }}>AI Security Engine</div>
              <div style={{ fontSize: '0.7rem', color: '#00f5a0' }}>Online & Ready</div>
            </div>
          </div>
        </div>
      </aside>

      {/* 2. Main Viewport */}
      <div className="main-viewport">
        {/* Top Header */}
        <header className="top-nav">
          <div className="page-breadcrumb">
            <span>Workspace</span> / <span className="current">{activePage.toUpperCase()}</span>
          </div>

          <div className="topbar-actions">
            <button className="btn-secondary" onClick={() => handleSampleSelect('vulnerable_python.py')}>
              ⚡ Load Preset Sample
            </button>
            <button className="quick-scan-pill" onClick={runAudit} disabled={loading}>
              <Play size={14} fill="#060911" /> {loading ? 'Auditing...' : 'Run Security Audit'}
            </button>
          </div>
        </header>

        {/* Content Body */}
        <div className="content-body">
          {/* ================= VIEW 1: DASHBOARD ================= */}
          {activePage === 'dashboard' && (() => {
            const severityChartData = [
              { name: 'Critical', count: reviewResult?.counts?.CRITICAL ?? 3, fill: '#ff3366' },
              { name: 'High', count: reviewResult?.counts?.HIGH ?? 5, fill: '#ff7700' },
              { name: 'Medium', count: reviewResult?.counts?.MEDIUM ?? 4, fill: '#ffbb00' },
              { name: 'Low', count: reviewResult?.counts?.LOW ?? 2, fill: '#00e676' }
            ];

            const owaspChartData = (reviewResult?.owasp_distribution && Object.keys(reviewResult.owasp_distribution).length > 0)
              ? Object.entries(reviewResult.owasp_distribution).map(([name, value]) => ({ name, value }))
              : [
                  { name: 'Injection (A03)', value: 45 },
                  { name: 'Cryptographic Failures (A02)', value: 20 },
                  { name: 'Hardcoded Secrets', value: 15 },
                  { name: 'Broken Access Control (A01)', value: 10 },
                  { name: 'Integrity Failures (A08)', value: 10 }
                ];
            const OWASP_COLORS = ['#6366f1', '#00d9f5', '#ff3366', '#ffbb00', '#00f5a0', '#a855f7'];

            const trendData = (history.length >= 2)
              ? history.slice(0, 6).reverse().map(item => ({
                  audit: `Scan #${item.id}`,
                  score: item.security_score,
                  issues: item.total_issues
                }))
              : [
                  { audit: 'Initial Scan', score: 30, issues: 14 },
                  { audit: 'Triage #1', score: 52, issues: 9 },
                  { audit: 'Patch #2', score: 75, issues: 4 },
                  { audit: 'Verified Build', score: 94, issues: 1 }
                ];

            return (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }}>
                {/* Score Hero Card */}
                <div className="score-hero-card">
                  <div className="score-circular-meter">
                    <svg width="110" height="110">
                      <circle cx="55" cy="55" r="45" stroke="#1e293b" strokeWidth="8" fill="none" />
                      <circle 
                        cx="55" cy="55" r="45" 
                        stroke={reviewResult ? (reviewResult.security_score >= 80 ? '#00f5a0' : (reviewResult.security_score >= 60 ? '#f59e0b' : '#ff3366')) : '#00f5a0'} 
                        strokeWidth="8" 
                        fill="none" 
                        strokeDasharray="283" 
                        strokeDashoffset={reviewResult ? 283 - (283 * reviewResult.security_score) / 100 : 0} 
                        strokeLinecap="round" 
                      />
                    </svg>
                    <div className="score-text-inner">
                      <div className="big-num">{reviewResult ? reviewResult.security_score : 94}</div>
                      <div className="grade-lbl">{reviewResult ? reviewResult.grade : 'Grade A'}</div>
                    </div>
                  </div>

                  <div style={{ flex: 1 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.4rem' }}>
                      <h2 style={{ fontSize: '1.45rem', fontWeight: '800' }}>Enterprise Security Posture</h2>
                      <span style={{ fontSize: '0.72rem', padding: '2px 8px', borderRadius: '10px', background: reviewResult?.security_score < 60 ? 'rgba(255, 51, 102, 0.2)' : 'rgba(0, 245, 160, 0.15)', color: reviewResult?.security_score < 60 ? '#ff3366' : '#00f5a0', fontWeight: '700' }}>
                        {reviewResult ? (reviewResult.security_score < 60 ? 'CRITICAL ACTION REQUIRED' : 'COMPLIANCE READY') : 'CONTINUOUS AUDIT ACTIVE'}
                      </span>
                    </div>
                    <p style={{ fontSize: '0.9rem', color: '#cbd5e1', lineHeight: '1.5', maxWidth: '780px' }}>
                      {reviewResult?.executive_summary || 'Your security posture reflects automated AST scanning (Bandit), zero-knowledge secret redaction, and multi-language OWASP threat evaluations. Run a scan to benchmark code risk scores.'}
                    </p>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                    <button className="btn-primary" onClick={() => setActivePage('scanner')}>
                      <Code2 size={15} /> Scan New Code
                    </button>
                    <button className="btn-secondary" onClick={() => setActivePage('reports')}>
                      <FileText size={15} /> Audit Reports
                    </button>
                  </div>
                </div>

                {/* 6 KPI Cards Grid */}
                <div className="kpi-grid">
                  <div className="kpi-card">
                    <div className="kpi-icon-wrapper" style={{ background: 'rgba(99, 102, 241, 0.15)', color: '#818cf8' }}>
                      <Code2 size={24} />
                    </div>
                    <div className="kpi-text">
                      <h3>{history.length > 0 ? history.length : 12}</h3>
                      <p>Total Files Scanned</p>
                    </div>
                  </div>

                  <div className="kpi-card">
                    <div className="kpi-icon-wrapper" style={{ background: 'rgba(255, 51, 102, 0.15)', color: '#ff3366' }}>
                      <AlertOctagon size={24} />
                    </div>
                    <div className="kpi-text">
                      <h3 style={{ color: '#ff3366' }}>{reviewResult?.counts?.CRITICAL ?? 3}</h3>
                      <p>Critical Vulnerabilities</p>
                    </div>
                  </div>

                  <div className="kpi-card">
                    <div className="kpi-icon-wrapper" style={{ background: 'rgba(255, 119, 0, 0.15)', color: '#ff7700' }}>
                      <AlertTriangle size={24} />
                    </div>
                    <div className="kpi-text">
                      <h3 style={{ color: '#ff7700' }}>{reviewResult?.counts?.HIGH ?? 5}</h3>
                      <p>High Severity Flaws</p>
                    </div>
                  </div>

                  <div className="kpi-card">
                    <div className="kpi-icon-wrapper" style={{ background: 'rgba(234, 179, 8, 0.15)', color: '#eab308' }}>
                      <Bug size={24} />
                    </div>
                    <div className="kpi-text">
                      <h3 style={{ color: '#eab308' }}>{(reviewResult?.counts?.MEDIUM ?? 4) + (reviewResult?.counts?.LOW ?? 2)}</h3>
                      <p>Medium / Low Flaws</p>
                    </div>
                  </div>

                  <div className="kpi-card">
                    <div className="kpi-icon-wrapper" style={{ background: 'rgba(0, 245, 160, 0.15)', color: '#00f5a0' }}>
                      <CheckCircle size={24} />
                    </div>
                    <div className="kpi-text">
                      <h3 style={{ color: '#00f5a0' }}>12</h3>
                      <p>Verified Patches</p>
                    </div>
                  </div>

                  <div className="kpi-card">
                    <div className="kpi-icon-wrapper" style={{ background: 'rgba(0, 217, 245, 0.15)', color: '#00d9f5' }}>
                      <GitPullRequest size={24} />
                    </div>
                    <div className="kpi-text">
                      <h3 style={{ color: '#00d9f5' }}>{prApproved ? '43' : '42'}</h3>
                      <p>PRs Audited</p>
                    </div>
                  </div>
                </div>

                {/* Interactive Recharts Analytics Row */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '1.25rem' }}>
                  {/* Chart 1: Severity Bar Chart */}
                  <div className="glass-panel" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                      <h4 style={{ fontSize: '1.05rem', fontWeight: 800 }}>Vulnerabilities by Severity</h4>
                      <span style={{ fontSize: '0.75rem', color: '#64748b' }}>AST & Secret Rules</span>
                    </div>
                    <div style={{ height: '220px', width: '100%' }}>
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={severityChartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                          <XAxis dataKey="name" stroke="#64748b" fontSize={11} tickLine={false} />
                          <YAxis stroke="#64748b" fontSize={11} tickLine={false} />
                          <Tooltip 
                            contentStyle={{ background: '#090e1a', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '8px', color: '#fff' }} 
                            itemStyle={{ color: '#00f5a0' }}
                          />
                          <Bar dataKey="count" radius={[6, 6, 0, 0]}>
                            {severityChartData.map((entry, index) => (
                              <Cell key={`cell-${index}`} fill={entry.fill} />
                            ))}
                          </Bar>
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                  </div>

                  {/* Chart 2: OWASP Threat Distribution Donut */}
                  <div className="glass-panel" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                      <h4 style={{ fontSize: '1.05rem', fontWeight: 800 }}>OWASP Threat Distribution</h4>
                      <span style={{ fontSize: '0.75rem', color: '#64748b' }}>Top 10 Breakdown</span>
                    </div>
                    <div style={{ height: '220px', width: '100%' }}>
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie 
                            data={owaspChartData} 
                            dataKey="value" 
                            nameKey="name" 
                            cx="50%" 
                            cy="50%" 
                            innerRadius={50} 
                            outerRadius={80} 
                            paddingAngle={4}
                          >
                            {owaspChartData.map((entry, index) => (
                              <Cell key={`cell-${index}`} fill={OWASP_COLORS[index % OWASP_COLORS.length]} />
                            ))}
                          </Pie>
                          <Tooltip contentStyle={{ background: '#090e1a', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '8px', color: '#fff' }} />
                        </PieChart>
                      </ResponsiveContainer>
                    </div>
                  </div>

                  {/* Chart 3: Security Score Trajectory Area Chart */}
                  <div className="glass-panel" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                      <h4 style={{ fontSize: '1.05rem', fontWeight: 800 }}>Security Score Trajectory</h4>
                      <span style={{ fontSize: '0.75rem', color: '#00f5a0', fontWeight: '700' }}>+59 pts Improvement</span>
                    </div>
                    <div style={{ height: '220px', width: '100%' }}>
                      <ResponsiveContainer width="100%" height="100%">
                        <AreaChart data={trendData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                          <defs>
                            <linearGradient id="scoreGradient" x1="0" y1="0" x2="0" y2="1">
                              <stop offset="5%" stopColor="#00f5a0" stopOpacity={0.4}/>
                              <stop offset="95%" stopColor="#00f5a0" stopOpacity={0}/>
                            </linearGradient>
                          </defs>
                          <XAxis dataKey="audit" stroke="#64748b" fontSize={11} tickLine={false} />
                          <YAxis stroke="#64748b" fontSize={11} tickLine={false} domain={[0, 100]} />
                          <Tooltip contentStyle={{ background: '#090e1a', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '8px', color: '#fff' }} />
                          <Area type="monotone" dataKey="score" stroke="#00f5a0" strokeWidth={3} fillOpacity={1} fill="url(#scoreGradient)" />
                        </AreaChart>
                      </ResponsiveContainer>
                    </div>
                  </div>
                </div>

                {/* Threat Intelligence CWE Matrix */}
                <div className="glass-panel" style={{ padding: '1.5rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.15rem' }}>
                    <div>
                      <h3 style={{ fontSize: '1.15rem', fontWeight: 800 }}>Threat Intelligence & CWE Matrix</h3>
                      <p style={{ fontSize: '0.8rem', color: '#94a3b8' }}>Real-time signatures monitored across your codebase</p>
                    </div>
                    <button className="btn-secondary" onClick={() => setActivePage('vulnerabilities')}>
                      Explore All Flaws <ArrowUpRight size={14} />
                    </button>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '1rem' }}>
                    {[
                      { cwe: 'CWE-89', name: 'SQL Injection', desc: 'Dynamic query string formatting bypasses authentication', sev: 'CRITICAL', count: 1 },
                      { cwe: 'CWE-78', name: 'OS Command Injection', desc: 'Shell invocation allows remote reverse execution', sev: 'CRITICAL', count: 1 },
                      { cwe: 'CWE-798', name: 'Hardcoded Credentials', desc: 'Exposed AWS tokens & DB credentials in source files', sev: 'CRITICAL', count: 2 },
                      { cwe: 'CWE-79', name: 'Cross-Site Scripting (XSS)', desc: 'Unsanitized innerHTML and DOM injection points', sev: 'HIGH', count: 1 },
                      { cwe: 'CWE-502', name: 'Insecure Deserialization', desc: 'Unpickling untrusted payload executes arbitrary gadgets', sev: 'HIGH', count: 1 },
                      { cwe: 'CWE-328', name: 'Broken Crypto (MD5)', desc: 'Obsolete collision-prone hash algorithm in authentication', sev: 'MEDIUM', count: 1 }
                    ].map((item, idx) => (
                      <div key={idx} style={{ padding: '1rem', background: '#090e1a', borderRadius: '10px', border: '1px solid var(--border-subtle)', display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <span style={{ fontSize: '0.78rem', fontWeight: '800', color: '#818cf8' }}>{item.cwe}</span>
                          <span className={`badge badge-${item.sev.toLowerCase()}`}>{item.sev}</span>
                        </div>
                        <div style={{ fontWeight: '700', fontSize: '0.92rem' }}>{item.name}</div>
                        <p style={{ fontSize: '0.78rem', color: '#94a3b8', lineHeight: '1.4' }}>{item.desc}</p>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Recent Scans Activity Table */}
                <div className="glass-panel" style={{ padding: '1.5rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.15rem' }}>
                    <div>
                      <h3 style={{ fontSize: '1.15rem', fontWeight: 800 }}>Recent Scan Activity</h3>
                      <p style={{ fontSize: '0.8rem', color: '#94a3b8' }}>Audit trails persisted in local SQLite database</p>
                    </div>
                    <button className="btn-secondary" onClick={() => setActivePage('reports')}>
                      Audit History Log <Clock size={14} />
                    </button>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
                    {(history.length > 0 ? history.slice(0, 4) : [
                      { id: 104, filename: 'auth_service.py', file_language: 'Python', total_issues: 4, critical_count: 2, security_score: 45.0, created_at: 'Just now' },
                      { id: 103, filename: 'payment_gateway.js', file_language: 'JavaScript', total_issues: 2, critical_count: 0, security_score: 82.0, created_at: '2 hours ago' },
                      { id: 102, filename: 'user_repository.java', file_language: 'Java', total_issues: 3, critical_count: 1, security_score: 55.0, created_at: 'Yesterday' }
                    ]).map((item, idx) => (
                      <div 
                        key={idx} 
                        style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0.85rem 1.15rem', background: '#090e1a', borderRadius: '8px', border: '1px solid var(--border-subtle)', flexWrap: 'wrap', gap: '0.75rem' }}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
                          <div style={{ width: '32px', height: '32px', borderRadius: '8px', background: 'rgba(99, 102, 241, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#818cf8' }}>
                            <FileText size={16} />
                          </div>
                          <div>
                            <div style={{ fontWeight: '700', fontSize: '0.92rem' }}>{item.filename} <span style={{ fontSize: '0.75rem', color: '#64748b' }}>({item.file_language})</span></div>
                            <div style={{ fontSize: '0.72rem', color: '#64748b' }}>Audit #{item.id} · {item.created_at}</div>
                          </div>
                        </div>

                        <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem' }}>
                          <div style={{ textAlign: 'right' }}>
                            <div style={{ fontSize: '0.82rem', fontWeight: '700', color: '#cbd5e1' }}>{item.total_issues} Findings</div>
                            <div style={{ fontSize: '0.72rem', color: item.critical_count > 0 ? '#ff3366' : '#00f5a0' }}>{item.critical_count} Critical</div>
                          </div>

                          <span style={{ fontSize: '1.15rem', fontWeight: '800', color: item.security_score >= 80 ? '#00f5a0' : (item.security_score >= 60 ? '#f59e0b' : '#ff3366') }}>
                            {item.security_score}%
                          </span>

                          <button className="btn-secondary" style={{ padding: '0.35rem 0.75rem', fontSize: '0.78rem' }} onClick={() => setActivePage('vulnerabilities')}>
                            View Flaws
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            );
          })()}

          {/* ================= VIEW 2: CODE SCANNER ================= */}
          {activePage === 'scanner' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
              {/* Presets & Upload Row */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
                <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                  <button className="btn-secondary" onClick={() => handleSampleSelect('vulnerable_python.py')}>
                    🐍 Python SQLi & Shell
                  </button>
                  <button className="btn-secondary" onClick={() => handleSampleSelect('secure_python.py')}>
                    🛡️ Secure Python Baseline
                  </button>
                  <button className="btn-secondary" onClick={() => handleSampleSelect('vulnerable_js.js')}>
                    ⚡ JS: XSS & Eval
                  </button>
                  <button className="btn-secondary" onClick={() => handleSampleSelect('vulnerable_java.java')}>
                    ☕ Java: SQLi & MD5
                  </button>
                </div>

                <div>
                  <label className="btn-secondary" style={{ cursor: 'pointer' }}>
                    📁 Upload File
                    <input type="file" style={{ display: 'none' }} onChange={handleFileUpload} />
                  </label>
                </div>
              </div>

              {/* Code Window Frame - Windows Style */}
              <div className="code-window-frame">
                <div className="window-titlebar win-titlebar">
                  <div className="win-title-left">
                    <div className="win-active-tab">
                      <Code2 size={13} style={{ color: '#38bdf8' }} />
                      <input 
                        type="text" 
                        value={filename}
                        onChange={(e) => setFilename(e.target.value)}
                        className="win-tab-input"
                        title="File name"
                      />
                    </div>
                  </div>

                  <div className="win-title-right">
                    <div className="win-info-group">
                      <select 
                        value={language}
                        onChange={(e) => setLanguage(e.target.value)}
                        className="win-lang-select"
                      >
                        <option value="Python">Python</option>
                        <option value="JavaScript">JavaScript</option>
                        <option value="Java">Java</option>
                        <option value="C/C++">C/C++</option>
                        <option value="PHP">PHP</option>
                        <option value="Go">Go</option>
                        <option value="SQL">SQL</option>
                      </select>
                      <span className="win-char-count">{code.length} chars</span>
                    </div>

                    <div className="windows-window-controls" aria-label="Windows controls">
                      <button type="button" className="win-ctrl-btn" title="Minimize">
                        <Minus size={13} strokeWidth={2} />
                      </button>
                      <button type="button" className="win-ctrl-btn" title="Maximize">
                        <Square size={11} strokeWidth={1.8} />
                      </button>
                      <button type="button" className="win-ctrl-btn close" title="Close">
                        <X size={14} strokeWidth={2} />
                      </button>
                    </div>
                  </div>
                </div>

                <textarea 
                  className="editor-surface"
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                  placeholder="Paste or edit code here..."
                  spellCheck="false"
                />
              </div>

              {/* Scan Trigger Bar */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '1.25rem', background: 'var(--bg-card)', borderRadius: '12px', border: '1px solid var(--border-subtle)' }}>
                <div>
                  <div style={{ fontWeight: '700', fontSize: '0.95rem' }}>Static AST & AI Review Engine</div>
                  <div style={{ fontSize: '0.78rem', color: '#94a3b8' }}>
                    Runs Bandit AST, Gitleaks secrets regex, and OWASP multi-language pattern checks with zero-knowledge secret redaction.
                  </div>
                </div>

                <button className="btn-primary" onClick={runAudit} disabled={loading} style={{ padding: '0.8rem 1.8rem', fontSize: '0.95rem' }}>
                  {loading ? (
                    <>
                      <RefreshCw className="spin" size={17} /> {scanStep}
                    </>
                  ) : (
                    <>
                      <Play size={16} fill="#060911" /> Run Full Security Audit
                    </>
                  )}
                </button>
              </div>
            </div>
          )}

          {/* ================= VIEW 3: VULNERABILITY EXPLORER ================= */}
          {activePage === 'vulnerabilities' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
              {/* Controls Filter Bar */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
                <div style={{ display: 'flex', gap: '0.4rem' }}>
                  {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => (
                    <button 
                      key={sev}
                      className={`btn-secondary ${severityFilter === sev ? 'active' : ''}`}
                      onClick={() => setSeverityFilter(sev)}
                      style={{ fontSize: '0.78rem', padding: '0.4rem 0.85rem' }}
                    >
                      {sev}
                    </button>
                  ))}
                </div>

                <div style={{ position: 'relative', width: '280px' }}>
                  <Search size={15} style={{ position: 'absolute', left: '10px', top: '10px', color: '#64748b' }} />
                  <input 
                    type="text" 
                    placeholder="Search by CWE, title..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    style={{ width: '100%', background: '#090e1a', border: '1px solid var(--border-subtle)', borderRadius: '8px', padding: '0.5rem 0.8rem 0.5rem 2.2rem', color: '#f1f5f9', fontSize: '0.85rem', outline: 'none' }}
                  />
                </div>
              </div>

              {/* Findings List */}
              {filteredFindings.length === 0 ? (
                <div className="glass-panel" style={{ padding: '3rem', textAlign: 'center' }}>
                  <CheckCircle size={44} color="#00f5a0" style={{ margin: '0 auto 1rem' }} />
                  <h3 style={{ fontSize: '1.2rem', fontWeight: 800 }}>No Vulnerabilities Detected</h3>
                  <p style={{ color: '#94a3b8', fontSize: '0.88rem' }}>The scanned source code adheres to secure development guidelines.</p>
                </div>
              ) : (
                filteredFindings.map((f, idx) => {
                  const isMarkedFP = !!falsePositives[idx];
                  return (
                    <div 
                      key={idx}
                      className={`glass-panel finding-card ${f.severity.toLowerCase()}`}
                      style={{ opacity: isMarkedFP ? 0.45 : 1 }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.85rem' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                          <span className={`badge badge-${f.severity.toLowerCase()}`}>{f.severity}</span>
                          <h4 style={{ fontSize: '1.05rem', fontWeight: '800' }}>#{idx + 1}. {f.title}</h4>
                          <span style={{ fontSize: '0.75rem', color: '#64748b' }}>({f.cwe_id}) · Line {f.line_number || 'N/A'}</span>
                        </div>

                        <div style={{ display: 'flex', gap: '0.5rem' }}>
                          <button 
                            className="btn-secondary" 
                            style={{ fontSize: '0.75rem', padding: '0.35rem 0.65rem' }}
                            onClick={() => setFalsePositives(p => ({ ...p, [idx]: !p[idx] }))}
                          >
                            {isMarkedFP ? 'Unmark False Positive' : 'Mark False Positive'}
                          </button>
                        </div>
                      </div>

                      {/* Code Snippet Box */}
                      <div style={{ marginBottom: '0.85rem' }}>
                        <label style={{ fontSize: '0.72rem', color: '#64748b', fontWeight: '700' }}>VULNERABLE PATTERN</label>
                        <div className="snippet-box">{f.snippet}</div>
                      </div>

                      {/* Impact & Attack Vectors */}
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '0.85rem' }}>
                        <div style={{ padding: '0.85rem', background: '#090e1a', borderRadius: '8px' }}>
                          <div style={{ fontSize: '0.78rem', fontWeight: '700', color: '#ff7777', marginBottom: '0.25rem' }}>💥 Risk & Impact</div>
                          <p style={{ fontSize: '0.84rem', color: '#cbd5e1', lineHeight: '1.4' }}>{f.why_dangerous}</p>
                        </div>
                        <div style={{ padding: '0.85rem', background: '#090e1a', borderRadius: '8px' }}>
                          <div style={{ fontSize: '0.78rem', fontWeight: '700', color: '#38bdf8', marginBottom: '0.25rem' }}>🎯 Attack Scenario</div>
                          <p style={{ fontSize: '0.84rem', color: '#cbd5e1', lineHeight: '1.4' }}>{f.attack_scenario}</p>
                        </div>
                      </div>

                      {/* Remediation Preview */}
                      <div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <label style={{ fontSize: '0.72rem', color: '#00f5a0', fontWeight: '700' }}>AI REMEDIATION PROPOSAL</label>
                          <button 
                            className="btn-secondary"
                            style={{ fontSize: '0.75rem', padding: '0.25rem 0.5rem' }}
                            onClick={() => copyToClipboard(f.secure_code, idx)}
                          >
                            <Copy size={12} /> {copiedIndex === idx ? 'Copied!' : 'Copy Code'}
                          </button>
                        </div>
                        <div className="secure-box">{f.secure_code}</div>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          )}

          {/* ================= VIEW 4: AI FIX SUGGESTIONS (DIFF VIEWER) ================= */}
          {activePage === 'fixes' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <h3 style={{ fontSize: '1.25rem', fontWeight: 800 }}>Side-by-Side Remediation Diffs</h3>
                  <p style={{ fontSize: '0.85rem', color: '#94a3b8' }}>
                    Compare vulnerable code against automated secure patches with real-time AST syntax verification.
                  </p>
                </div>
              </div>

              {!reviewResult || reviewResult.findings.length === 0 ? (
                <div className="glass-panel" style={{ padding: '2.5rem', textAlign: 'center' }}>
                  <p style={{ color: '#94a3b8' }}>No active audit findings. Run a scan from the Code Scanner view to generate diffs.</p>
                </div>
              ) : (
                reviewResult.findings.map((f, idx) => {
                  const verifyData = verifyStatus[idx];
                  return (
                    <div key={idx} className="glass-panel" style={{ padding: '1.5rem' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
                          <span className={`badge badge-${f.severity.toLowerCase()}`}>{f.severity}</span>
                          <h4 style={{ fontSize: '1rem', fontWeight: '800' }}>Finding #{idx + 1}: {f.title}</h4>
                        </div>

                        <button 
                          className="btn-primary"
                          style={{ fontSize: '0.82rem', padding: '0.45rem 0.95rem' }}
                          onClick={() => handleVerify(idx, f.snippet, f.secure_code)}
                        >
                          <Check size={14} /> Verify Fix & Recalculate Score
                        </button>
                      </div>

                      {verifyData && (
                        <div style={{ padding: '0.65rem 0.85rem', borderRadius: '6px', background: verifyData.syntax_valid ? 'rgba(0, 245, 160, 0.1)' : 'rgba(239, 68, 68, 0.1)', border: `1px solid ${verifyData.syntax_valid ? '#00f5a0' : '#ef4444'}`, fontSize: '0.82rem', marginBottom: '0.85rem' }}>
                          {verifyData.syntax_valid ? (
                            <span style={{ color: '#00f5a0' }}>
                              ✓ Syntax Verified! Baseline Score: {verifyData.original_score} ➔ Remediated Score: <strong>{verifyData.new_score}</strong> (+{verifyData.score_delta} pts)
                            </span>
                          ) : (
                            <span style={{ color: '#ef4444' }}>⚠️ Syntax Error: {verifyData.syntax_error}</span>
                          )}
                        </div>
                      )}

                      {/* Side by side diff container */}
                      <div className="diff-container">
                        <div className="diff-pane original">
                          <div className="diff-pane-title">Original (Vulnerable)</div>
                          <div className="diff-content">{f.snippet}</div>
                        </div>

                        <div className="diff-pane remediated">
                          <div className="diff-pane-title">AI Replacement (Secured)</div>
                          <div className="diff-content">{f.secure_code}</div>
                        </div>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          )}

          {/* ================= VIEW 5: AI SECURITY CHAT ================= */}
          {activePage === 'chat' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div>
                <h3 style={{ fontSize: '1.25rem', fontWeight: 800 }}>AI Security Architect Copilot</h3>
                <p style={{ fontSize: '0.85rem', color: '#94a3b8' }}>
                  Ask questions regarding detected flaws, exploit mechanics, false-positive justification, and compliance rules.
                </p>
              </div>

              {/* Preset prompt chips */}
              <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                <button className="btn-secondary" onClick={() => handleChatSend('How could an attacker exploit this vulnerability in production?')}>
                  🎯 How to exploit in production?
                </button>
                <button className="btn-secondary" onClick={() => handleChatSend('Can we resolve this using an ORM or Prepared Statement?')}>
                  🛠️ How to fix with ORM?
                </button>
                <button className="btn-secondary" onClick={() => handleChatSend('Is this considered a false positive if input is validated earlier?')}>
                  ❓ Is this a false positive?
                </button>
                <button className="btn-secondary" onClick={() => handleChatSend('Explain this vulnerability to a junior developer.')}>
                  📖 Explain to junior dev
                </button>
              </div>

              {/* Chat Window */}
              <div className="chat-window">
                <div className="chat-messages">
                  {chatMessages.map((msg, i) => (
                    <div key={i} className={`chat-bubble ${msg.role}`}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.72rem', color: msg.role === 'bot' ? '#818cf8' : '#ffffff', fontWeight: '700', marginBottom: '0.35rem' }}>
                        {msg.role === 'bot' ? <Bot size={14} /> : <User size={14} />}
                        {msg.role === 'bot' ? 'Security Architect' : 'Developer'}
                      </div>
                      <p style={{ whiteSpace: 'pre-wrap' }}>{msg.content}</p>
                    </div>
                  ))}
                  {chatLoading && (
                    <div className="chat-bubble bot" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <RefreshCw size={14} className="spin" /> Analyzing security context...
                    </div>
                  )}
                </div>

                <div className="chat-input-row">
                  <input 
                    type="text" 
                    className="chat-input"
                    placeholder="Ask the security architect anything about your code..."
                    value={chatInput}
                    onChange={(e) => setChatInput(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && handleChatSend()}
                  />
                  <button className="btn-primary" onClick={() => handleChatSend()} disabled={chatLoading}>
                    <Send size={15} /> Send
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* ================= VIEW 6: GITHUB PULL REQUESTS ================= */}
          {activePage === 'github' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
              <div>
                <h3 style={{ fontSize: '1.25rem', fontWeight: 800 }}>GitHub Pull Request Scanner</h3>
                <p style={{ fontSize: '0.85rem', color: '#94a3b8' }}>
                  Simulated DevSecOps bot scanning incoming pull requests and posting automated inline vulnerability comments.
                </p>
              </div>

              <div className="pr-card">
                <div className="pr-header">
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
                    <GitPullRequest size={20} color="#00f5a0" />
                    <div>
                      <h4 style={{ fontSize: '1.05rem', fontWeight: '800' }}>PR #42: feat(auth): add database user login query</h4>
                      <p style={{ fontSize: '0.75rem', color: '#64748b' }}>Opened by developer-jane · target branch: main · 2 files changed</p>
                    </div>
                  </div>

                  <span className={`pr-badge ${prApproved ? 'open' : 'open'}`}>
                    {prApproved ? '✓ APPROVED' : 'SECURITY CHECKS REQUIRED'}
                  </span>
                </div>

                {/* Inline Comment Simulation */}
                <div className="inline-comment-box">
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', color: '#ff3366', fontWeight: '700', fontSize: '0.85rem', marginBottom: '0.35rem' }}>
                    <Bot size={15} /> SecureCode AI Bot (Reviewer) flagged Line 14:
                  </div>
                  <p style={{ color: '#cbd5e1', lineHeight: '1.4' }}>
                    ⚠️ <strong>CRITICAL SQL Injection Vulnerability Detected (CWE-89):</strong>
                    <br />
                    Untrusted input <code>username</code> is concatenated directly into the query string without parameterization. An attacker can bypass authentication with <code>' OR '1'='1</code>.
                  </p>
                  <div style={{ marginTop: '0.5rem', background: '#05080e', padding: '0.65rem', borderRadius: '5px', fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: '#00f5a0' }}>
                    Suggested Fix: cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
                  </div>
                </div>

                <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', marginTop: '0.5rem' }}>
                  <button 
                    className="btn-secondary" 
                    onClick={() => { setPrApproved(false); alert('Security changes requested on PR #42.'); }}
                  >
                    <XCircle size={15} /> Request Changes
                  </button>
                  <button 
                    className="btn-primary" 
                    onClick={() => { setPrApproved(true); confetti({ particleCount: 50, spread: 60 }); }}
                  >
                    <CheckSquare size={15} /> Approve PR (After AI Fix)
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* ================= VIEW 7: SECURITY REPORTS & HISTORY ================= */}
          {activePage === 'reports' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
              {/* Export Panel */}
              <div className="glass-panel" style={{ padding: '1.5rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
                  <div>
                    <h3 style={{ fontSize: '1.25rem', fontWeight: 800 }}>Compliance Audit Reports</h3>
                    <p style={{ fontSize: '0.85rem', color: '#94a3b8' }}>
                      Export branded PDF security audits and machine-readable JSON artifacts.
                    </p>
                  </div>

                  <div style={{ display: 'flex', gap: '0.75rem' }}>
                    <button className="btn-primary" onClick={() => downloadReport('pdf')} disabled={!reviewResult}>
                      <Download size={15} /> Export PDF Report
                    </button>
                    <button className="btn-secondary" onClick={() => downloadReport('json')} disabled={!reviewResult}>
                      <FileText size={15} /> Export JSON Report
                    </button>
                  </div>
                </div>
              </div>

              {/* History Table */}
              <div className="glass-panel" style={{ padding: '1.5rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                  <h4 style={{ fontSize: '1.1rem', fontWeight: '800' }}>Historical Scan Audit Trail</h4>
                  <button className="btn-secondary" onClick={loadHistory}>
                    <RefreshCw size={14} /> Refresh Trail
                  </button>
                </div>

                {history.length === 0 ? (
                  <p style={{ color: '#94a3b8' }}>No scans recorded in SQLite database.</p>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                    {history.map(item => (
                      <div 
                        key={item.id}
                        style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0.95rem 1.25rem', background: '#090e1a', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}
                      >
                        <div>
                          <div style={{ fontWeight: '700', fontSize: '0.95rem' }}>Review #{item.id} — {item.filename} ({item.file_language})</div>
                          <div style={{ fontSize: '0.75rem', color: '#64748b', marginTop: '0.2rem' }}>
                            {item.created_at} · Issues: {item.total_issues} (Crit: {item.critical_count}, High: {item.high_count}) · Engine: {item.ai_provider}
                          </div>
                        </div>

                        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                          <span style={{ fontSize: '1.15rem', fontWeight: '800', color: item.security_score >= 80 ? '#00f5a0' : (item.security_score >= 60 ? '#f59e0b' : '#ff3366') }}>
                            {item.security_score}%
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

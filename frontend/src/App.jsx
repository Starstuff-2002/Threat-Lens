import React, { useState, useEffect, useCallback, useRef } from 'react';
import Editor from '@monaco-editor/react';
import { debounce } from 'lodash';
import AdminDashboard from './AdminDashboard';
import './index.css';

function App() {
  const [currentUser, setCurrentUser] = useState(null); // {username, role}
  const [currentView, setCurrentView] = useState('editor'); // 'editor' | 'admin'
  const [usernameInput, setUsernameInput] = useState('');
  const [passwordInput, setPasswordInput] = useState('');
  const [loginError, setLoginError] = useState('');

  const [code, setCode] = useState('// Write your code here...\n');
  const [findings, setFindings] = useState([]);
  const [iocs, setIocs] = useState([]);
  const [enrichments, setEnrichments] = useState({}); // { [ioc]: { verdict, score, source, detail, loading } }
  const [scanHistory, setScanHistory] = useState([]); // Last 5 unique artifacts
  
  const editorRef = useRef(null);
  const monacoRef = useRef(null);
  const handleEditorDidMount = (editor, monaco) => {
    editorRef.current = editor;
    monacoRef.current = monaco;
  };

  // 1. Analyze Code via FastAPI
  const analyzeCode = useCallback(
    debounce(async (currentCode, userRole) => {
      if (!userRole || userRole === 'guest') {
        setFindings([]);
        setIocs([]);
        return;
      }

      try {
        const response = await fetch('http://localhost:8000/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ code: currentCode }),
        });
        
        if (response.ok) {
          const data = await response.json();
          setFindings(data.findings || []);
          setIocs(data.iocs || []);
          
          // Update History Strip
          const newArtifacts = (data.findings || []).map(f => f.artifact);
          setScanHistory(prev => {
            const combined = [...new Set([...newArtifacts, ...prev])];
            return combined.slice(0, 5);
          });
        }
      } catch (error) {
        console.error('Failed to fetch from backend:', error);
      }
    }, 800),
    []
  );

  const handleEditorChange = (value, event) => {
    setCode(value);
    analyzeCode(value, currentUser?.role);
  };

  // 2. Fetch Enrichments via FastAPI Proxy -> Go Microservice
  useEffect(() => {
    if (iocs.length === 0) return;

    // Filter IOCs that need enrichment (not already enriched/loading)
    const iocsToEnrich = iocs.filter(ioc => !enrichments[ioc.value]);
    if (iocsToEnrich.length === 0) return;

    // Mark as loading immediately
    setEnrichments(prev => {
      const updated = { ...prev };
      iocsToEnrich.forEach(ioc => {
        updated[ioc.value] = { loading: true };
      });
      return updated;
    });

    const fetchEnrichment = async () => {
      try {
        const response = await fetch('http://localhost:8000/enrich', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ iocs: iocsToEnrich }),
        });
        
        if (response.ok) {
          const data = await response.json();
          const results = data.results || [];
          
          setEnrichments(prev => {
            const updated = { ...prev };
            results.forEach(res => {
              updated[res.ioc] = {
                loading: false,
                verdict: res.verdict,
                score: res.score,
                source: res.source,
                detail: res.detail
              };
            });
            return updated;
          });
        }
      } catch (error) {
        console.error('Enrichment failed:', error);
      }
    };

    fetchEnrichment();
  }, [iocs]); // Intentionally omitting enrichments to prevent infinite loops

  // Apply Monaco error markers with dynamic severity (upgrades to critical if malicious)
  useEffect(() => {
    if (!editorRef.current || !monacoRef.current) return;
    const model = editorRef.current.getModel();
    if (!model) return;

    const markers = findings.map((finding) => {
      let currentSeverity = finding.severity;
      
      // Dynamic Upgrade Check
      const intel = enrichments[finding.artifact];
      if (intel && !intel.loading && intel.verdict === 'malicious') {
          currentSeverity = 'critical'; // Upgrade visually
      }

      let monacoSeverity;
      switch (currentSeverity) {
        case 'critical':
        case 'high':
          monacoSeverity = monacoRef.current.MarkerSeverity.Error;
          break;
        case 'medium':
          monacoSeverity = monacoRef.current.MarkerSeverity.Warning;
          break;
        case 'low':
        default:
          monacoSeverity = monacoRef.current.MarkerSeverity.Info;
          break;
      }

      return {
        startLineNumber: finding.line,
        startColumn: finding.startColumn || 1,
        endLineNumber: finding.line,
        endColumn: finding.endColumn || 100,
        message: intel && intel.detail ? `${finding.message}\n\nThreat Intel: ${intel.detail}` : finding.message,
        severity: monacoSeverity,
      };
    });

    monacoRef.current.editor.setModelMarkers(model, 'threatlens', markers);
  }, [findings, enrichments]);

  const handleLogin = async (e) => {
    e.preventDefault();
    try {
      const response = await fetch('http://localhost:8000/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: usernameInput, password: passwordInput })
      });
      if (response.ok) {
        const user = await response.json();
        setCurrentUser(user);
        setLoginError('');
        if (user.role !== 'guest') {
            analyzeCode(code, user.role);
        }
      } else {
        setLoginError('Invalid username or password');
      }
    } catch (err) {
      setLoginError('Failed to connect to authentication server');
    }
  };

  const handleLogout = () => {
    setCurrentUser(null);
    setCurrentView('editor');
    handleClear();
    setUsernameInput('');
    setPasswordInput('');
  };

  const handleClear = () => {
    setCode('// Write your code here...\n');
    setFindings([]);
    setIocs([]);
    setEnrichments({});
    setScanHistory([]);
    if (editorRef.current) {
        monacoRef.current.editor.setModelMarkers(editorRef.current.getModel(), 'threatlens', []);
    }
  };

  if (!currentUser) {
    return (
      <div className="login-container">
        <div className="login-box">
          <h2>ThreatLens IAM</h2>
          <p>Login to access the security scanner</p>
          <form onSubmit={handleLogin}>
            <input type="text" placeholder="Username" value={usernameInput} onChange={e => setUsernameInput(e.target.value)} />
            <input type="password" placeholder="Password" value={passwordInput} onChange={e => setPasswordInput(e.target.value)} />
            {loginError && <div className="error-message">{loginError}</div>}
            <button type="submit" className="login-btn">Login</button>
          </form>
          <div className="login-hint">Hint: admin/admin | dev/password | guest/guest</div>
        </div>
      </div>
    );
  }

  return (
    <div className="app-container">
      {/* Top Navbar */}
      <div className="top-navbar">
        <div className="nav-brand">ThreatLens</div>
        <div className="nav-controls">
          <span className="user-info">
            Logged in as <strong>{currentUser.username}</strong> 
            <span className={`role-badge role-${currentUser.role}`}>{currentUser.role}</span>
          </span>
          <button className="nav-btn" onClick={() => setCurrentView('editor')}>Editor</button>
          {currentUser.role === 'admin' && (
            <button className="nav-btn" onClick={() => setCurrentView('admin')}>Admin</button>
          )}
          <button className="nav-btn logout-btn" onClick={handleLogout}>Logout</button>
        </div>
      </div>

      <div className="main-content">
        {currentView === 'admin' ? (
          <AdminDashboard />
        ) : (
          <>
            <div className="editor-panel">
              <Editor
                height="100%"
                defaultLanguage="python"
                theme="vs-dark"
                value={code}
                onChange={handleEditorChange}
                onMount={handleEditorDidMount}
                options={{
                  minimap: { enabled: false },
                  fontSize: 14,
                  hover: { enabled: true },
                  readOnly: currentUser.role === 'guest'
                }}
              />
            </div>
            <div className="side-panel">
              
              {/* History Strip */}
              <div className="history-strip">
                 <div className="history-title">Recent Scans:</div>
                 <div className="history-items">
                    {scanHistory.map((sh, idx) => (
                        <span key={idx} className="history-badge">{sh}</span>
                    ))}
                    {scanHistory.length === 0 && <span className="history-empty">None</span>}
                 </div>
              </div>

              <div className="panel-header">
                <div>
                  <h2>Security Findings</h2>
                  {currentUser.role === 'guest' ? (
                    <p className="status-disabled">Scanner disabled for Guests</p>
                  ) : (
                    <p className="status-active">Real-time Scanner & Intel Active</p>
                  )}
                </div>
                <button className="clear-btn" onClick={handleClear}>Clear</button>
              </div>
              
              <div className="panel-content">
                {currentUser.role === 'guest' ? (
                  <div className="placeholder-text error-variant">
                    Insufficient privileges. Please log in as a Developer to use the threat scanner.
                  </div>
                ) : findings.length === 0 ? (
                  <div className="placeholder-text">
                    Scanning active... No threats detected.
                  </div>
                ) : (
                  <div className="findings-list">
                    {findings.map((f, i) => {
                      const intel = enrichments[f.artifact];
                      const displaySeverity = (intel && !intel.loading && intel.verdict === 'malicious') ? 'critical' : f.severity;
                      
                      return (
                        <div key={i} className={`threat-card severity-${displaySeverity} ${intel && !intel.loading && intel.verdict==='malicious' ? 'upgraded' : ''}`}>
                          <div className="card-header">
                            <span className="severity-badge">{displaySeverity}</span>
                            <span className="line-ref">Line {f.line}</span>
                          </div>
                          <div className="card-title">{f.message}</div>
                          <div className="card-artifact">{f.artifact}</div>
                          
                          {/* Threat Intel Section */}
                          {(f.type === 'suspicious_ip' || f.type === 'suspicious_url' || f.type === 'suspicious_hash') && (
                            <div className="intel-section">
                              {intel?.loading ? (
                                <div className="intel-loading">
                                  <div className="spinner"></div>
                                  <span>Querying Threat Intel...</span>
                                </div>
                              ) : intel ? (
                                <div className="intel-results">
                                  <div className="intel-verdict">
                                    Verdict: <span className={`verdict-${intel.verdict}`}>{intel.verdict.toUpperCase()}</span>
                                  </div>
                                  <div className="score-container">
                                    <div className="score-label">Threat Score ({intel.score}/100)</div>
                                    <div className="score-bar-bg">
                                      <div className={`score-bar-fill score-${intel.score > 50 ? 'high' : 'low'}`} style={{ width: `${intel.score}%` }}></div>
                                    </div>
                                  </div>
                                  <div className="intel-detail">{intel.detail}</div>
                                  <div className="intel-source">Source: {intel.source}</div>
                                </div>
                              ) : null}
                            </div>
                          )}
                        </div>
                      )
                    })}
                  </div>
                )}
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

export default App;

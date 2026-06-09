import { useState, useEffect, useRef } from "react";

const SAMPLE_LOGS = [
  { id: 1, raw: "2026-06-06T03:42:11Z FAILED LOGIN user=admin src_ip=185.220.101.47 attempts=47 dest=10.0.0.5:22 proto=SSH", severity: null, category: null, analysis: null },
  { id: 2, raw: "2026-06-06T04:15:33Z DNS_QUERY client=10.0.1.88 query=c2-payload.darkweb.xyz type=A resp=NXDOMAIN", severity: null, category: null, analysis: null },
  { id: 3, raw: "2026-06-06T04:17:02Z HTTP_POST url=http://10.0.1.88:4444/beacon size=1248 ua='Mozilla/5.0' interval=30s", severity: null, category: null, analysis: null },
  { id: 4, raw: "2026-06-06T05:01:44Z PROCESS_CREATE parent=winword.exe child=cmd.exe cmdline='cmd /c powershell -enc SGVsbG8gV29ybGQ=' user=jsmith host=WKSTN-042", severity: null, category: null, analysis: null },
  { id: 5, raw: "2026-06-06T05:45:19Z FILE_ACCESS path=C:\\Windows\\System32\\lsass.exe action=READ proc=mimikatz.exe pid=3821 user=SYSTEM", severity: null, category: null, analysis: null },
  { id: 6, raw: "2026-06-06T06:10:05Z OUTBOUND_CONN src=10.0.2.14 dst=93.184.216.34:443 bytes_out=4200000 bytes_in=1200 duration=3600s", severity: null, category: null, analysis: null },
];

const SEVERITY_CONFIG = {
  CRITICAL: { color: "#ff2d55", bg: "rgba(255,45,85,0.12)", glow: "0 0 12px rgba(255,45,85,0.4)" },
  HIGH:     { color: "#ff6b00", bg: "rgba(255,107,0,0.12)", glow: "0 0 12px rgba(255,107,0,0.4)" },
  MEDIUM:   { color: "#ffd60a", bg: "rgba(255,214,10,0.10)", glow: "0 0 12px rgba(255,214,10,0.3)" },
  LOW:      { color: "#30d158", bg: "rgba(48,209,88,0.10)", glow: "0 0 12px rgba(48,209,88,0.3)" },
  INFO:     { color: "#64d2ff", bg: "rgba(100,210,255,0.10)", glow: "0 0 12px rgba(100,210,255,0.3)" },
};

const MITRE_MAP = {
  "Brute Force": "T1110",
  "C2 Communication": "T1071",
  "Suspicious DNS": "T1071.004",
  "Lateral Movement": "T1021",
  "Credential Dumping": "T1003",
  "Data Exfiltration": "T1048",
  "Process Injection": "T1055",
  "Phishing": "T1566",
};

function SeverityBadge({ level }) {
  const cfg = SEVERITY_CONFIG[level] || SEVERITY_CONFIG.INFO;
  return (
    <span style={{
      display: "inline-block",
      padding: "2px 10px",
      borderRadius: "4px",
      background: cfg.bg,
      color: cfg.color,
      border: `1px solid ${cfg.color}`,
      fontSize: "11px",
      fontFamily: "'JetBrains Mono', monospace",
      fontWeight: 700,
      letterSpacing: "0.08em",
      boxShadow: cfg.glow,
    }}>{level}</span>
  );
}

function PulseRing({ active }) {
  return active ? (
    <span style={{ position: "relative", display: "inline-block", width: 10, height: 10 }}>
      <span style={{
        display: "block", width: 10, height: 10, borderRadius: "50%",
        background: "#ff2d55", animation: "pulse 1.2s infinite",
      }} />
    </span>
  ) : null;
}

function StatCard({ label, value, color }) {
  return (
    <div style={{
      background: "rgba(255,255,255,0.03)",
      border: "1px solid rgba(255,255,255,0.08)",
      borderRadius: 8,
      padding: "14px 18px",
      minWidth: 100,
      textAlign: "center",
    }}>
      <div style={{ fontSize: 26, fontWeight: 800, color: color || "#fff", fontFamily: "'JetBrains Mono', monospace" }}>{value}</div>
      <div style={{ fontSize: 11, color: "#8888a0", marginTop: 2, letterSpacing: "0.06em" }}>{label}</div>
    </div>
  );
}

function ThreatMatrix({ logs }) {
  const analyzed = logs.filter(l => l.severity);
  const counts = {};
  analyzed.forEach(l => { counts[l.severity] = (counts[l.severity] || 0) + 1; });
  const total = analyzed.length;

  return (
    <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
      {["CRITICAL","HIGH","MEDIUM","LOW","INFO"].map(s => {
        const c = counts[s] || 0;
        const pct = total ? Math.round((c / total) * 100) : 0;
        const cfg = SEVERITY_CONFIG[s];
        return (
          <div key={s} style={{ flex: 1, minWidth: 80, background: cfg.bg, border: `1px solid ${cfg.color}33`, borderRadius: 8, padding: "10px 12px" }}>
            <div style={{ color: cfg.color, fontFamily: "'JetBrains Mono', monospace", fontSize: 11, fontWeight: 700 }}>{s}</div>
            <div style={{ color: "#fff", fontSize: 22, fontWeight: 800, marginTop: 2 }}>{c}</div>
            <div style={{ color: cfg.color, fontSize: 10, opacity: 0.7 }}>{pct}%</div>
          </div>
        );
      })}
    </div>
  );
}

export default function SOCDashboard() {
  const [logs, setLogs] = useState(SAMPLE_LOGS);
  const [analyzing, setAnalyzing] = useState(null);
  const [selected, setSelected] = useState(null);
  const [customLog, setCustomLog] = useState("");
  const [activeTab, setActiveTab] = useState("logs");
  const [scanAll, setScanAll] = useState(false);
  const [tick, setTick] = useState(0);
  const scanAllRef = useRef(false);

  useEffect(() => {
    const t = setInterval(() => setTick(x => x + 1), 1000);
    return () => clearInterval(t);
  }, []);

  const analyzeLog = async (log) => {
    setAnalyzing(log.id);
    try {
      const response = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "claude-sonnet-4-20250514",
          max_tokens: 1000,
          system: `You are a senior SOC analyst AI assistant. Analyze security log entries and return ONLY valid JSON (no markdown, no preamble) with this exact structure:
{
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "category": "short threat category name",
  "mitre_technique": "T1XXX.XXX or T1XXX",
  "mitre_name": "MITRE ATT&CK technique name",
  "summary": "1-2 sentence analyst summary of what this log event indicates",
  "indicators": ["list", "of", "key", "IOCs", "or", "suspicious", "elements"],
  "recommended_action": "Specific immediate action a SOC analyst should take",
  "false_positive_likelihood": "Low|Medium|High",
  "tlp": "RED|AMBER|GREEN|WHITE"
}
Severity guide: CRITICAL=active breach/RCE/cred dump, HIGH=likely malicious/C2/exfil, MEDIUM=suspicious/needs investigation, LOW=policy violation/recon, INFO=benign/informational.`,
          messages: [{ role: "user", content: `Analyze this security log entry:\n\n${log.raw}` }]
        })
      });
      const data = await response.json();
      const text = data.content?.map(b => b.text || "").join("") || "";
      const clean = text.replace(/```json|```/g, "").trim();
      const parsed = JSON.parse(clean);
      setLogs(prev => prev.map(l => l.id === log.id ? { ...l, ...parsed, analyzed: true } : l));
    } catch (e) {
      setLogs(prev => prev.map(l => l.id === log.id ? {
        ...l, severity: "INFO", category: "Parse Error",
        summary: "Could not parse AI response. Check API connectivity.",
        indicators: [], recommended_action: "Retry analysis.", false_positive_likelihood: "Unknown", tlp: "WHITE", analyzed: true
      } : l));
    }
    setAnalyzing(null);
  };

  const analyzeAll = async () => {
    scanAllRef.current = true;
    setScanAll(true);
    const pending = logs.filter(l => !l.analyzed);
    for (const log of pending) {
      if (!scanAllRef.current) break;
      await analyzeLog(log);
    }
    setScanAll(false);
    scanAllRef.current = false;
  };

  const addCustomLog = () => {
    if (!customLog.trim()) return;
    const newLog = { id: Date.now(), raw: customLog.trim(), severity: null, category: null, analysis: null };
    setLogs(prev => [newLog, ...prev]);
    setCustomLog("");
    setActiveTab("logs");
    setTimeout(() => analyzeLog(newLog), 200);
  };

  const analyzedCount = logs.filter(l => l.analyzed).length;
  const criticalCount = logs.filter(l => l.severity === "CRITICAL").length;
  const highCount = logs.filter(l => l.severity === "HIGH").length;

  const timeStr = new Date().toLocaleTimeString("en-US", { hour12: false });

  return (
    <div style={{
      minHeight: "100vh",
      background: "#070b14",
      color: "#e2e8f0",
      fontFamily: "'IBM Plex Sans', 'Segoe UI', sans-serif",
    }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@300;400;500;600&family=JetBrains+Mono:wght@400;700&display=swap');
        * { box-sizing: border-box; margin: 0; padding: 0; }
        ::-webkit-scrollbar { width: 4px; } ::-webkit-scrollbar-track { background: #0d1220; } ::-webkit-scrollbar-thumb { background: #2a3550; border-radius: 4px; }
        @keyframes pulse { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:0.5;transform:scale(1.4)} }
        @keyframes scanline { 0%{transform:translateY(-100%)} 100%{transform:translateY(100vh)} }
        @keyframes fadeIn { from{opacity:0;transform:translateY(8px)} to{opacity:1;transform:translateY(0)} }
        @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0} }
        .log-row:hover { background: rgba(100,210,255,0.04) !important; cursor:pointer; }
        .tab-btn { cursor:pointer; border:none; background:none; font-family:inherit; }
        .analyze-btn:hover { opacity:0.85; }
        .analyze-btn:active { transform:scale(0.97); }
      `}</style>

      {/* Scanline overlay */}
      <div style={{ position:"fixed", top:0, left:0, right:0, bottom:0, pointerEvents:"none", zIndex:999, background:"repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.03) 2px, rgba(0,0,0,0.03) 4px)" }} />

      {/* Header */}
      <div style={{ borderBottom: "1px solid rgba(100,210,255,0.15)", padding: "0 24px", display:"flex", alignItems:"center", justifyContent:"space-between", height: 56, background:"rgba(7,11,20,0.95)", backdropFilter:"blur(12px)", position:"sticky", top:0, zIndex:100 }}>
        <div style={{ display:"flex", alignItems:"center", gap: 14 }}>
          <div style={{ width:28, height:28, background:"linear-gradient(135deg,#64d2ff,#0070f3)", borderRadius:6, display:"flex", alignItems:"center", justifyContent:"center", fontSize:14, fontWeight:800 }}>⬡</div>
          <div>
            <div style={{ fontFamily:"'JetBrains Mono', monospace", fontWeight:700, fontSize:13, letterSpacing:"0.1em", color:"#64d2ff" }}>SENTINEL<span style={{ color:"#ffffff99" }}>::</span>AI</div>
            <div style={{ fontSize:10, color:"#ffffff44", letterSpacing:"0.15em" }}>SOC THREAT INTELLIGENCE PLATFORM</div>
          </div>
        </div>
        <div style={{ display:"flex", alignItems:"center", gap:20 }}>
          {criticalCount > 0 && (
            <div style={{ display:"flex", alignItems:"center", gap:6, background:"rgba(255,45,85,0.1)", border:"1px solid rgba(255,45,85,0.3)", borderRadius:6, padding:"4px 10px" }}>
              <PulseRing active />
              <span style={{ fontSize:11, color:"#ff2d55", fontWeight:600, fontFamily:"'JetBrains Mono', monospace" }}>{criticalCount} CRITICAL</span>
            </div>
          )}
          <div style={{ fontFamily:"'JetBrains Mono', monospace", fontSize:12, color:"#ffffff44" }}>{timeStr} UTC</div>
        </div>
      </div>

      <div style={{ maxWidth: 1100, margin:"0 auto", padding:"24px 20px" }}>

        {/* Stats Row */}
        <div style={{ display:"flex", gap:12, marginBottom:24, flexWrap:"wrap" }}>
          <StatCard label="TOTAL EVENTS" value={logs.length} color="#64d2ff" />
          <StatCard label="ANALYZED" value={analyzedCount} color="#30d158" />
          <StatCard label="CRITICAL" value={criticalCount} color="#ff2d55" />
          <StatCard label="HIGH" value={highCount} color="#ff6b00" />
          <div style={{ flex:1, minWidth:200 }}>
            <ThreatMatrix logs={logs} />
          </div>
        </div>

        {/* Tabs */}
        <div style={{ display:"flex", gap:0, marginBottom:20, borderBottom:"1px solid rgba(255,255,255,0.08)" }}>
          {["logs","add-log","about"].map(tab => (
            <button key={tab} className="tab-btn" onClick={() => setActiveTab(tab)} style={{
              padding:"10px 20px", fontSize:12, fontWeight:600, letterSpacing:"0.08em",
              color: activeTab === tab ? "#64d2ff" : "#ffffff55",
              borderBottom: activeTab === tab ? "2px solid #64d2ff" : "2px solid transparent",
              transition:"all 0.2s",
            }}>
              {tab === "logs" ? "🛡  LOG EVENTS" : tab === "add-log" ? "＋  INJECT LOG" : "ℹ  ABOUT"}
            </button>
          ))}
          <div style={{ flex:1 }} />
          <button className="analyze-btn" onClick={analyzeAll} disabled={scanAll || analyzedCount === logs.length} style={{
            margin:"4px 0", padding:"6px 16px", borderRadius:6, border:"1px solid rgba(100,210,255,0.3)",
            background: scanAll ? "rgba(100,210,255,0.05)" : "rgba(100,210,255,0.1)", color:"#64d2ff",
            fontSize:11, fontWeight:700, fontFamily:"'JetBrains Mono', monospace", cursor:"pointer", letterSpacing:"0.08em", transition:"all 0.2s",
          }}>
            {scanAll ? "⟳ SCANNING..." : "⚡ ANALYZE ALL"}
          </button>
        </div>

        {/* LOG EVENTS TAB */}
        {activeTab === "logs" && (
          <div style={{ display:"flex", gap:20 }}>
            {/* Log list */}
            <div style={{ flex:1 }}>
              {logs.map((log, i) => (
                <div key={log.id} className="log-row" onClick={() => setSelected(selected?.id === log.id ? null : log)}
                  style={{
                    background: selected?.id === log.id ? "rgba(100,210,255,0.07)" : "rgba(255,255,255,0.02)",
                    border: selected?.id === log.id ? "1px solid rgba(100,210,255,0.3)" : "1px solid rgba(255,255,255,0.06)",
                    borderRadius:8, padding:"12px 14px", marginBottom:8,
                    animation: `fadeIn 0.3s ease ${i * 0.05}s both`, transition:"all 0.2s",
                  }}>
                  <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:6 }}>
                    <div style={{ fontFamily:"'JetBrains Mono', monospace", fontSize:10, color:"#ffffff33", minWidth:24 }}>
                      {String(i+1).padStart(2,"0")}
                    </div>
                    {log.severity ? <SeverityBadge level={log.severity} /> : (
                      <span style={{ fontSize:11, color:"#ffffff33", fontFamily:"'JetBrains Mono', monospace" }}>UNANALYZED</span>
                    )}
                    {log.category && (
                      <span style={{ fontSize:11, color:"#ffffff66", background:"rgba(255,255,255,0.06)", borderRadius:4, padding:"2px 8px" }}>
                        {log.category}
                      </span>
                    )}
                    {log.mitre_technique && (
                      <span style={{ fontSize:10, color:"#0070f3", background:"rgba(0,112,243,0.1)", borderRadius:4, padding:"2px 8px", fontFamily:"'JetBrains Mono', monospace" }}>
                        {log.mitre_technique}
                      </span>
                    )}
                    <div style={{ flex:1 }} />
                    {analyzing === log.id ? (
                      <span style={{ fontSize:10, color:"#64d2ff", fontFamily:"'JetBrains Mono', monospace", animation:"blink 1s infinite" }}>ANALYZING...</span>
                    ) : !log.analyzed ? (
                      <button className="analyze-btn" onClick={e => { e.stopPropagation(); analyzeLog(log); }} style={{
                        padding:"3px 10px", borderRadius:5, border:"1px solid rgba(100,210,255,0.3)",
                        background:"rgba(100,210,255,0.08)", color:"#64d2ff", fontSize:10,
                        fontWeight:700, cursor:"pointer", fontFamily:"'JetBrains Mono', monospace",
                      }}>ANALYZE</button>
                    ) : (
                      <span style={{ fontSize:10, color:"#30d158", fontFamily:"'JetBrains Mono', monospace" }}>✓ DONE</span>
                    )}
                  </div>
                  <div style={{ fontFamily:"'JetBrains Mono', monospace", fontSize:11, color:"#a0aec0", lineHeight:1.5, wordBreak:"break-all" }}>
                    {log.raw}
                  </div>
                </div>
              ))}
            </div>

            {/* Detail panel */}
            {selected && selected.analyzed && (
              <div style={{ width:320, flexShrink:0, animation:"fadeIn 0.25s ease" }}>
                <div style={{
                  background:"rgba(255,255,255,0.02)", border:"1px solid rgba(255,255,255,0.08)",
                  borderRadius:10, padding:18, position:"sticky", top:80,
                }}>
                  <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:14 }}>
                    <SeverityBadge level={selected.severity} />
                    <span style={{ fontSize:12, color:"#ffffff88", fontWeight:600 }}>{selected.category}</span>
                  </div>

                  <div style={{ marginBottom:14 }}>
                    <div style={{ fontSize:10, color:"#ffffff44", letterSpacing:"0.1em", marginBottom:4 }}>AI ANALYSIS</div>
                    <div style={{ fontSize:12, color:"#c8d8e8", lineHeight:1.6 }}>{selected.summary}</div>
                  </div>

                  {selected.indicators?.length > 0 && (
                    <div style={{ marginBottom:14 }}>
                      <div style={{ fontSize:10, color:"#ffffff44", letterSpacing:"0.1em", marginBottom:6 }}>KEY INDICATORS</div>
                      {selected.indicators.map((ind, i) => (
                        <div key={i} style={{ display:"flex", alignItems:"center", gap:6, marginBottom:4 }}>
                          <div style={{ width:4, height:4, borderRadius:"50%", background:"#ff6b00", flexShrink:0 }} />
                          <span style={{ fontSize:11, color:"#a0aec0", fontFamily:"'JetBrains Mono', monospace" }}>{ind}</span>
                        </div>
                      ))}
                    </div>
                  )}

                  {selected.mitre_technique && (
                    <div style={{ marginBottom:14, background:"rgba(0,112,243,0.08)", border:"1px solid rgba(0,112,243,0.2)", borderRadius:6, padding:"10px 12px" }}>
                      <div style={{ fontSize:10, color:"#0070f3", letterSpacing:"0.1em", marginBottom:4 }}>MITRE ATT&CK</div>
                      <div style={{ fontFamily:"'JetBrains Mono', monospace", fontSize:13, color:"#64d2ff", fontWeight:700 }}>{selected.mitre_technique}</div>
                      <div style={{ fontSize:11, color:"#a0aec0", marginTop:2 }}>{selected.mitre_name}</div>
                    </div>
                  )}

                  <div style={{ marginBottom:14, background:"rgba(255,214,10,0.06)", border:"1px solid rgba(255,214,10,0.15)", borderRadius:6, padding:"10px 12px" }}>
                    <div style={{ fontSize:10, color:"#ffd60a", letterSpacing:"0.1em", marginBottom:4 }}>RECOMMENDED ACTION</div>
                    <div style={{ fontSize:11, color:"#e2e8f0", lineHeight:1.5 }}>{selected.recommended_action}</div>
                  </div>

                  <div style={{ display:"flex", gap:8 }}>
                    <div style={{ flex:1, background:"rgba(255,255,255,0.04)", borderRadius:6, padding:"8px 10px" }}>
                      <div style={{ fontSize:9, color:"#ffffff33", marginBottom:2 }}>FALSE POS.</div>
                      <div style={{ fontSize:12, fontWeight:600, color: selected.false_positive_likelihood === "Low" ? "#30d158" : selected.false_positive_likelihood === "High" ? "#ff6b00" : "#ffd60a" }}>
                        {selected.false_positive_likelihood}
                      </div>
                    </div>
                    <div style={{ flex:1, background:"rgba(255,255,255,0.04)", borderRadius:6, padding:"8px 10px" }}>
                      <div style={{ fontSize:9, color:"#ffffff33", marginBottom:2 }}>TLP</div>
                      <div style={{ fontSize:12, fontWeight:700, color: selected.tlp === "RED" ? "#ff2d55" : selected.tlp === "AMBER" ? "#ff6b00" : selected.tlp === "GREEN" ? "#30d158" : "#ffffff88" }}>
                        TLP:{selected.tlp}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* ADD LOG TAB */}
        {activeTab === "add-log" && (
          <div style={{ maxWidth:700, animation:"fadeIn 0.3s ease" }}>
            <div style={{ marginBottom:12 }}>
              <div style={{ fontSize:11, color:"#ffffff55", letterSpacing:"0.08em", marginBottom:8 }}>PASTE A RAW LOG ENTRY FOR AI ANALYSIS</div>
              <textarea value={customLog} onChange={e => setCustomLog(e.target.value)}
                placeholder={`Example:\n2026-06-06T08:00:00Z FAILED_LOGIN user=root src_ip=192.168.1.50 attempts=150 proto=SSH`}
                style={{
                  width:"100%", height:140, background:"rgba(255,255,255,0.04)",
                  border:"1px solid rgba(255,255,255,0.1)", borderRadius:8, padding:"12px 14px",
                  color:"#c8d8e8", fontFamily:"'JetBrains Mono', monospace", fontSize:12,
                  resize:"vertical", outline:"none", lineHeight:1.6,
                }} />
            </div>
            <button className="analyze-btn" onClick={addCustomLog} disabled={!customLog.trim()} style={{
              padding:"10px 24px", borderRadius:8, border:"1px solid rgba(100,210,255,0.3)",
              background:"rgba(100,210,255,0.1)", color:"#64d2ff", fontSize:13,
              fontWeight:700, cursor:"pointer", fontFamily:"'JetBrains Mono', monospace", letterSpacing:"0.08em",
            }}>
              ⚡ INJECT &amp; ANALYZE
            </button>
            <div style={{ marginTop:24 }}>
              <div style={{ fontSize:11, color:"#ffffff33", marginBottom:12, letterSpacing:"0.08em" }}>EXAMPLE LOG FORMATS TO TRY</div>
              {[
                "2026-06-06T09:00:00Z REGISTRY_MOD key=HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run value=svchost32.exe proc=unknown.exe",
                "2026-06-06T10:15:00Z NETWORK_SCAN src=10.0.5.22 target=10.0.0.0/24 ports=1-65535 proto=TCP rate=5000pps",
                "2026-06-06T11:30:00Z EMAIL_ATTACHMENT file=invoice.pdf.exe sha256=a3f2...d9e1 sender=billing@supp1ier.com",
              ].map((ex, i) => (
                <div key={i} onClick={() => setCustomLog(ex)} style={{
                  fontFamily:"'JetBrains Mono', monospace", fontSize:10, color:"#64d2ff77",
                  background:"rgba(100,210,255,0.04)", border:"1px solid rgba(100,210,255,0.1)",
                  borderRadius:6, padding:"8px 12px", marginBottom:8, cursor:"pointer",
                  transition:"all 0.2s", wordBreak:"break-all", lineHeight:1.5,
                }} onMouseEnter={e => e.target.style.color="#64d2ff"} onMouseLeave={e => e.target.style.color="#64d2ff77"}>
                  {ex}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ABOUT TAB */}
        {activeTab === "about" && (
          <div style={{ maxWidth:680, animation:"fadeIn 0.3s ease" }}>
            <div style={{ background:"rgba(255,255,255,0.02)", border:"1px solid rgba(255,255,255,0.08)", borderRadius:10, padding:24 }}>
              <div style={{ fontSize:16, fontWeight:600, color:"#64d2ff", marginBottom:16 }}>About This Project</div>
              <div style={{ fontSize:13, color:"#a0aec0", lineHeight:1.8, marginBottom:20 }}>
                <strong style={{ color:"#e2e8f0" }}>SENTINEL::AI</strong> is a SOC Threat Intelligence Dashboard built as a portfolio project demonstrating AI-augmented security operations. It uses the <strong style={{ color:"#e2e8f0" }}>Claude API</strong> (Anthropic) to perform real-time analysis of raw security log entries — classifying threats, mapping them to <strong style={{ color:"#e2e8f0" }}>MITRE ATT&CK techniques</strong>, and generating actionable analyst recommendations.
              </div>
              <div style={{ marginBottom:20 }}>
                <div style={{ fontSize:11, color:"#ffffff44", letterSpacing:"0.1em", marginBottom:10 }}>TECHNICAL STACK</div>
                {["React (functional components, hooks)", "Anthropic Claude API (claude-sonnet-4)", "MITRE ATT&CK Framework mapping", "TLP traffic light protocol classification", "Real-time streaming log ingestion (simulated)", "Severity triage: CRITICAL → INFO"].map((item, i) => (
                  <div key={i} style={{ display:"flex", alignItems:"center", gap:8, marginBottom:6 }}>
                    <div style={{ width:4, height:4, background:"#64d2ff", borderRadius:"50%" }} />
                    <span style={{ fontSize:12, color:"#c8d8e8", fontFamily:"'JetBrains Mono', monospace" }}>{item}</span>
                  </div>
                ))}
              </div>
              <div style={{ background:"rgba(0,112,243,0.08)", border:"1px solid rgba(0,112,243,0.2)", borderRadius:8, padding:"14px 16px" }}>
                <div style={{ fontSize:11, color:"#0070f3", letterSpacing:"0.1em", marginBottom:6 }}>PORTFOLIO NOTE</div>
                <div style={{ fontSize:12, color:"#a0aec0", lineHeight:1.7 }}>
                  This tool demonstrates practical application of AI in a SOC context — relevant to threat detection, triage automation, and analyst workflow acceleration. The AI classifies events against real-world attack patterns (credential dumping, C2 beaconing, lateral movement) that align with CompTIA Security+ and SOC Analyst core competencies.
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

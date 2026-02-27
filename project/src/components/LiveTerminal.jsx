import { useEffect, useRef, useState } from 'react';
import { Terminal, Activity, Download } from 'lucide-react';

// Agent colour scheme
const AGENT_COLORS = {
  1: { label: 'Agent 1 — Static Analyst',    text: 'text-cyan-400',    border: 'border-cyan-400/40',    bg: 'bg-cyan-400/5',  dot: 'bg-cyan-400' },
  2: { label: 'Agent 2 — Threat OSINT',      text: 'text-amber-400',   border: 'border-amber-400/40',   bg: 'bg-amber-400/5', dot: 'bg-amber-400' },
  3: { label: 'Agent 3 — Lead Investigator',  text: 'text-emerald-400', border: 'border-emerald-400/40', bg: 'bg-emerald-400/5', dot: 'bg-emerald-400' },
};

const LiveTerminal = ({ isActive, fileId, analysisMode }) => {
  // Each segment: { agentId, agentName, text }
  const [segments, setSegments] = useState([]);
  const [currentAgent, setCurrentAgent] = useState(null);
  const [reportDownloadUrl, setReportDownloadUrl] = useState(null);
  const terminalRef = useRef(null);

  // Clear terminal when a new analysis starts
  useEffect(() => {
    if (isActive) {
      setSegments([]);
      setCurrentAgent(null);
      setReportDownloadUrl(null);
    }
  }, [isActive]);

  useEffect(() => {
    const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:5000';
    const eventSource = new EventSource(`${apiUrl}/api/swarm-stream`);

    // Default message handler — streaming text tokens
    eventSource.onmessage = (event) => {
      const data = event.data;
      if (!data || data === '[DONE]') return;

      setSegments((prev) => {
        const updated = [...prev];
        if (updated.length === 0) {
          // No agent header yet (v1 mode) — create a default segment
          updated.push({ agentId: null, agentName: null, text: data });
        } else {
          // Append to the latest segment
          const last = updated[updated.length - 1];
          updated[updated.length - 1] = { ...last, text: last.text + data };
        }
        return updated;
      });
    };

    // Agent lifecycle events (v2 mode)
    eventSource.addEventListener('agentStart', (event) => {
      try {
        const payload = JSON.parse(event.data);
        setCurrentAgent(payload);
        setSegments((prev) => [
          ...prev,
          { agentId: payload.id, agentName: payload.name, text: '' },
        ]);
      } catch (_) {}
    });

    eventSource.addEventListener('agentDone', (event) => {
      try {
        const payload = JSON.parse(event.data);
        // If the finished agent is the current one, clear active state
        setCurrentAgent((cur) => (cur?.id === payload.id ? null : cur));
      } catch (_) {}
    });

    // Report download event
    eventSource.addEventListener('fileReady', (event) => {
      try {
        const payload = JSON.parse(event.data);
        const url = payload?.url || event.data;
        if (url) setReportDownloadUrl(url);
      } catch {
        if (event.data) setReportDownloadUrl(event.data);
      }
    });

    eventSource.onerror = (error) => {
      console.error('SSE connection error:', error);
    };

    return () => eventSource.close();
  }, []);

  // Auto-scroll
  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [segments]);

  const hasContent = segments.some((s) => s.text.length > 0);

  return (
    <div className="bg-slate-900 border border-zinc-800 rounded-lg flex flex-col h-full">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-zinc-800 bg-slate-950">
        <div className="flex items-center space-x-2">
          <Terminal className="w-4 h-4 text-cyber-green" />
          <span className="text-sm font-semibold text-slate-200">
            {analysisMode === 'v2' ? 'Deep Swarm Terminal' : 'Live Swarm Terminal'}
          </span>
        </div>
        <div className="flex items-center space-x-2">
          {currentAgent ? (
            <>
              <div className={`w-2 h-2 rounded-full animate-pulse ${AGENT_COLORS[currentAgent.id]?.dot || 'bg-cyber-green'}`} />
              <span className={`text-xs ${AGENT_COLORS[currentAgent.id]?.text || 'text-cyber-green'}`}>
                {currentAgent.name}
              </span>
            </>
          ) : isActive ? (
            <>
              <Activity className="w-4 h-4 text-cyber-green animate-pulse" />
              <span className="text-xs text-cyber-green">Active</span>
            </>
          ) : (
            <span className="text-xs text-slate-500">Idle</span>
          )}
        </div>
      </div>

      {/* Terminal body */}
      <div
        ref={terminalRef}
        className="flex-1 p-4 overflow-y-auto scrollbar-custom bg-slate-950/50 font-mono"
      >
        {!hasContent && !isActive && (
          <div className="flex flex-col items-center justify-center h-full text-slate-600">
            <Terminal className="w-12 h-12 mb-3 opacity-50" />
            <p className="text-sm">Awaiting file upload...</p>
            <p className="text-xs mt-1">
              {analysisMode === 'v2'
                ? '3 AI agents will activate upon analysis'
                : 'AI agent will activate upon analysis'}
            </p>
          </div>
        )}

        {segments.map((seg, idx) => {
          const colors = AGENT_COLORS[seg.agentId];
          if (!seg.text && !colors) return null;

          return (
            <div key={idx} className="mb-4">
              {/* Agent header badge (v2 mode) */}
              {colors && (
                <div className={`flex items-center gap-2 mb-2 px-3 py-1.5 rounded border ${colors.border} ${colors.bg}`}>
                  <div className={`w-2 h-2 rounded-full ${colors.dot}`} />
                  <span className={`text-xs font-bold tracking-wide uppercase ${colors.text}`}>
                    {colors.label}
                  </span>
                </div>
              )}
              {/* Agent text */}
              <pre className={`text-sm whitespace-pre-wrap font-sans break-words m-0 pl-1 ${
                colors ? colors.text.replace('text-', 'text-').replace('-400', '-200') : 'text-slate-300'
              }`}
                style={{ color: undefined }}
              >
                <span className={colors ? '' : 'text-slate-300'}>
                  {seg.text}
                </span>
              </pre>
            </div>
          );
        })}
      </div>

      {/* Report download */}
      {reportDownloadUrl && (
        <div className="px-4 py-3 border-t border-zinc-800 bg-cyber-green/10">
          <a
            href={reportDownloadUrl}
            download
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center justify-center gap-2 w-full py-3 px-4 rounded-lg bg-cyber-green text-slate-900 font-semibold text-sm shadow-lg shadow-cyber-green/20 hover:bg-cyber-green/90 transition-all hover:scale-[1.02] active:scale-[0.98]"
          >
            <Download className="w-5 h-5" />
            Download Official Forensic Report (.html)
          </a>
        </div>
      )}

      {/* Status bar */}
      <div className="px-4 py-2 border-t border-zinc-800 bg-slate-950">
        <div className="flex items-center space-x-2 text-xs text-slate-600">
          <div className="w-2 h-2 rounded-full bg-zinc-700"></div>
          <span>
            {currentAgent
              ? `${currentAgent.name} streaming...`
              : hasContent
                ? 'Analysis complete'
                : 'System ready'}
          </span>
        </div>
      </div>
    </div>
  );
};

export default LiveTerminal;

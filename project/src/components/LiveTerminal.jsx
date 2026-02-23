import { useEffect, useRef, useState } from 'react';
import { Terminal, Activity, Download } from 'lucide-react';

const LiveTerminal = ({ isActive, fileId }) => {
  const [streamText, setStreamText] = useState('');
  const [reportDownloadUrl, setReportDownloadUrl] = useState(null);
  const terminalRef = useRef(null);

  // Clear stream and report when a new analysis starts
  useEffect(() => {
    if (isActive) {
      setStreamText('');
      setReportDownloadUrl(null);
    }
  }, [isActive]);

  useEffect(() => {
    const eventSource = new EventSource('http://localhost:5000/api/swarm-stream');

    eventSource.onmessage = (event) => {
      const data = event.data.trim();
      if (data === '[DONE]') return;
      if (data) setStreamText((prev) => prev + data);
    };

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

  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [streamText]);

  return (
    <div className="bg-slate-900 border border-zinc-800 rounded-lg flex flex-col h-full">
      <div className="flex items-center justify-between px-4 py-3 border-b border-zinc-800 bg-slate-950">
        <div className="flex items-center space-x-2">
          <Terminal className="w-4 h-4 text-cyber-green" />
          <span className="text-sm font-semibold text-slate-200">Live Swarm Terminal</span>
        </div>
        <div className="flex items-center space-x-2">
          {isActive && (
            <>
              <Activity className="w-4 h-4 text-cyber-green animate-pulse" />
              <span className="text-xs text-cyber-green">Active</span>
            </>
          )}
          {!isActive && (
            <span className="text-xs text-slate-500">Idle</span>
          )}
        </div>
      </div>

      <div
        ref={terminalRef}
        className="flex-1 p-4 overflow-y-auto scrollbar-custom bg-slate-950/50 font-mono"
      >
        {streamText === '' && !isActive && (
          <div className="flex flex-col items-center justify-center h-full text-slate-600">
            <Terminal className="w-12 h-12 mb-3 opacity-50" />
            <p className="text-sm">Awaiting file upload...</p>
            <p className="text-xs mt-1">AI agents will activate upon analysis</p>
          </div>
        )}

        {streamText !== '' && (
          <pre className="text-slate-300 text-sm whitespace-pre-wrap font-sans break-words m-0">
            {streamText}
          </pre>
        )}
      </div>

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
            📄 Download Official Forensic Report (.html)
          </a>
        </div>
      )}

      <div className="px-4 py-2 border-t border-zinc-800 bg-slate-950">
        <div className="flex items-center space-x-2 text-xs text-slate-600">
          <div className="w-2 h-2 rounded-full bg-zinc-700"></div>
          <span>
            {streamText ? 'Streaming analysis...' : 'System ready'}
          </span>
        </div>
      </div>
    </div>
  );
};

export default LiveTerminal;

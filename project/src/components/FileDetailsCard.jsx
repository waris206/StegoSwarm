import { FileIcon, Hash, Weight, CheckCircle, Copy, BarChart3, ShieldAlert } from 'lucide-react';
import { useState } from 'react';

const FileDetailsCard = ({ file }) => {
  const [copied, setCopied] = useState(false);

  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(file.sha256);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="bg-slate-900/50 border border-zinc-800 rounded-lg p-6 space-y-6">
      <div className="flex items-start justify-between">
        <div className="flex items-start space-x-4">
          <div className="p-3 bg-slate-800 rounded-lg border border-zinc-700">
            <FileIcon className="w-8 h-8 text-cyber-blue" />
          </div>
          <div className="flex-1">
            <h3 className="text-lg font-semibold text-slate-200 mb-1">
              {file.name}
            </h3>
            <div className="flex items-center space-x-4 text-sm text-slate-400">
              <div className="flex items-center space-x-1">
                <Weight className="w-4 h-4" />
                <span>{formatFileSize(file.size)}</span>
              </div>
              {file.entropy && (
                <div className="flex items-center space-x-1">
                  <BarChart3 className="w-4 h-4" />
                  <span>Entropy: {file.entropy}</span>
                </div>
              )}
            </div>
          </div>
        </div>
        <div className="flex items-center space-x-2 text-xs text-cyber-green">
          <CheckCircle className="w-4 h-4" />
          <span>Verified</span>
        </div>
      </div>

      <div className="border-t border-zinc-800 pt-4 space-y-4">
        <div>
          <div className="flex items-start justify-between mb-2">
            <div className="flex items-center space-x-2">
              <Hash className="w-4 h-4 text-slate-400" />
              <span className="text-sm font-medium text-slate-300">SHA-256 Hash</span>
            </div>
            <button
              onClick={copyToClipboard}
              className="flex items-center space-x-1 text-xs text-slate-400 hover:text-cyber-green transition-colors"
            >
              <Copy className="w-3 h-3" />
              <span>{copied ? 'Copied!' : 'Copy'}</span>
            </button>
          </div>
          <div className="bg-slate-950 border border-zinc-800 rounded p-3 overflow-x-auto">
            <code className="text-xs text-cyber-green font-mono break-all">
              {file.sha256}
            </code>
          </div>
        </div>
        
        {file.entropy && (
          <div>
            <div className="flex items-center space-x-2 mb-2">
              <BarChart3 className="w-4 h-4 text-slate-400" />
              <span className="text-sm font-medium text-slate-300">Shannon Entropy</span>
            </div>
            <div className="bg-slate-950 border border-zinc-800 rounded p-3 mb-3">
              <code className="text-xs text-cyber-blue font-mono">
                {file.entropy} bits/byte
              </code>
            </div>
            {file.magicBytes && (
              <div>
                <div className="flex items-center space-x-2 mb-2">
                  <Hash className="w-4 h-4 text-slate-400" />
                  <span className="text-sm font-medium text-slate-300">Magic Bytes (Hex Signature)</span>
                </div>
                <div className="bg-slate-950 border border-zinc-800 rounded p-3">
                  <code className="text-xs text-cyber-blue font-mono">
                    {file.magicBytes}
                  </code>
                </div>
              </div>
            )}
          </div>
        )}
        
        {file.virusTotal && (
          <div>
            <div className="flex items-center space-x-2 mb-2">
              <ShieldAlert className="w-4 h-4 text-slate-400" />
              <span className="text-sm font-medium text-slate-300">Threat Intelligence (VirusTotal)</span>
            </div>
            <div className="bg-slate-950 border border-zinc-800 rounded p-3">
              <code
                className={`text-xs font-mono ${
                  file.virusTotal.malicious > 0 ? 'text-red-400' : 'text-cyber-green'
                }`}
              >
                Malicious: {file.virusTotal.malicious ?? 0} / Clean: {file.virusTotal.undetected ?? 0}
              </code>
            </div>
          </div>
        )}
      </div>

      <div className="flex items-center justify-between text-xs">
        <span className="text-slate-500">Forensic integrity preserved</span>
        <span className="text-cyber-blue">Ready for analysis</span>
      </div>
    </div>
  );
};

export default FileDetailsCard;

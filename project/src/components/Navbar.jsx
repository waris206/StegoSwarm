import { Shield, Bug } from 'lucide-react';

const Navbar = () => {
  return (
    <nav className="bg-slate-900 border-b border-zinc-800 px-6 py-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="relative">
            <Shield className="w-8 h-8 text-cyber-green" strokeWidth={2} />
            <Bug className="w-4 h-4 text-cyber-blue absolute -bottom-1 -right-1" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-cyber-green cyber-glow tracking-wider">
              ThreatLens
            </h1>
            <p className="text-xs text-slate-400 tracking-wide">
              AI-Driven Malware Triage & Deep Swarm Inspection
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-6">
          <div className="flex items-center space-x-2">
            <div className="w-2 h-2 bg-cyber-green rounded-full animate-pulse"></div>
            <span className="text-xs text-slate-400">Swarm Active</span>
          </div>
          <div className="text-xs text-slate-500">
            v2.0.0
          </div>
        </div>
      </div>
    </nav>
  );
};

export default Navbar;

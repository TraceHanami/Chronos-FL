import React, { useEffect, useState } from 'react';

export const App: React.FC = () => {
  const [status, setStatus] = useState<any>(null);

  useEffect(() => {
    fetch('/api/status')
      .then(res => res.json())
      .then(data => setStatus(data))
      .catch(console.error);
  }, []);

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 p-8 font-sans">
      <header className="flex items-center justify-between border-b border-slate-800 pb-4 mb-6">
        <div>
          <h1 className="text-2xl font-bold text-sky-400">CHRONOS-FL</h1>
          <p className="text-xs text-slate-400 uppercase tracking-widest">Cyber Forensic Flight Recorder Platform</p>
        </div>
        <div className="px-3 py-1 bg-emerald-500/10 border border-emerald-500 text-emerald-400 rounded text-xs font-mono">
          {status ? status.system : 'Connecting...'}
        </div>
      </header>

      <main className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="bg-slate-800 border border-slate-700 p-4 rounded-lg">
          <h2 className="text-xs font-semibold text-slate-400 uppercase">Events Collected</h2>
          <div className="text-3xl font-bold font-mono text-sky-400 mt-2">{status?.total_events_collected ?? 0}</div>
        </div>
        <div className="bg-slate-800 border border-slate-700 p-4 rounded-lg">
          <h2 className="text-xs font-semibold text-slate-400 uppercase">Anti-Forensic Alerts</h2>
          <div className="text-3xl font-bold font-mono text-rose-500 mt-2">{status?.anti_forensic_alerts ?? 0}</div>
        </div>
        <div className="bg-slate-800 border border-slate-700 p-4 rounded-lg">
          <h2 className="text-xs font-semibold text-slate-400 uppercase">Evidence Gaps</h2>
          <div className="text-3xl font-bold font-mono text-purple-400 mt-2">{status?.evidence_gaps_detected ?? 0}</div>
        </div>
        <div className="bg-slate-800 border border-slate-700 p-4 rounded-lg">
          <h2 className="text-xs font-semibold text-slate-400 uppercase">Ledger Integrity</h2>
          <div className="mt-2 font-semibold">
            <span className={`px-2 py-1 rounded text-xs uppercase ${status?.ledger_integrity === 'INTACT' ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500' : 'bg-rose-500/20 text-rose-400 border border-rose-500'}`}>
              {status?.ledger_integrity ?? 'UNKNOWN'}
            </span>
          </div>
        </div>
      </main>
    </div>
  );
};

export default App;

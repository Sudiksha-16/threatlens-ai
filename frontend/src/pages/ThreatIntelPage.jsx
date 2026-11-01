import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { 
  Binary, ShieldAlert, Bug, Activity, Terminal, 
  ExternalLink, ArrowUpRight, Flame, Layers 
} from 'lucide-react';
import { analyticsAPI, scanAPI } from '../services/api';

export const ThreatIntelPage = () => {
  const [intel, setIntel] = useState(null);
  const [highRiskScans, setHighRiskScans] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchIntel = async () => {
      try {
        const [analyticsRes, scansRes] = await Promise.all([
          analyticsAPI.getAnalytics({ time_range: '90d' }),
          scanAPI.getHistory({ risk_level: 'Critical', limit: 5 }),
        ]);
        setIntel(analyticsRes.data);
        setHighRiskScans(scansRes.data.scans || []);
      } catch (err) {
        console.error('Failed to load threat intel:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchIntel();
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="w-10 h-10 border-4 border-[#38D6C5] border-t-transparent rounded-full animate-spin"></div>
      </div>
    );
  }

  const yaraFreq = intel?.yara_rule_frequency || [];
  const commonInd = intel?.common_indicators || [];
  const families = intel?.family_distribution || [];

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-[#25354B]">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Threat Intelligence Feeds</h1>
          <p className="text-xs text-[#9AA9BC] mt-1 font-mono">
            AGGREGATED IOCS &bull; YARA SIGNATURE CORPUS &bull; LOCAL TELEMETRY
          </p>
        </div>

        <div className="px-3 py-1 bg-[#111C2E] border border-[#25354B] rounded-full text-xs font-mono text-[#38D6C5] flex items-center space-x-2">
          <span className="w-2 h-2 rounded-full bg-[#35C98A] animate-pulse"></span>
          <span>Feed Status: Synchronized</span>
        </div>
      </div>

      {/* Info Callout */}
      <div className="p-4 bg-[#111C2E] border border-[#25354B] rounded-2xl flex items-start space-x-3 text-xs text-[#9AA9BC]">
        <Binary className="w-5 h-5 text-[#668CFF] shrink-0 mt-0.5" />
        <div>
          <p className="text-white font-semibold">Distinction of Intelligence Sources</p>
          <p className="mt-0.5">
            ThreatLens AI strictly distinguishes between internal SOC scan intelligence (derived from uploaded files, local ML, and compiled YARA rules) and external threat intelligence (VirusTotal hash verification).
          </p>
        </div>
      </div>

      {/* Top Threat Indicators Grid */}
      <div className="grid md:grid-cols-2 gap-6">
        {/* Frequently Matched YARA Signatures */}
        <div className="p-6 bg-[#111C2E] border border-[#25354B] rounded-2xl space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-base font-bold text-white flex items-center space-x-2">
              <Flame className="w-4 h-4 text-[#D94C63]" />
              <span>Top Matched YARA Signatures</span>
            </h3>
            <span className="text-xs font-mono text-[#9AA9BC]">Compiled Rules</span>
          </div>

          <div className="space-y-3">
            {yaraFreq.length > 0 ? (
              yaraFreq.map((item, idx) => (
                <div key={idx} className="p-3 bg-[#0C1423] border border-[#25354B] rounded-xl flex items-center justify-between">
                  <div>
                    <p className="text-xs font-mono font-bold text-[#38D6C5]">{item.rule}</p>
                    <p className="text-[10px] text-[#9AA9BC] mt-0.5">Category: {item.category || 'General'}</p>
                  </div>
                  <span className="px-2.5 py-1 bg-[#162338] text-white font-mono font-bold text-xs rounded-lg border border-[#25354B]">
                    {item.count} hits
                  </span>
                </div>
              ))
            ) : (
              <p className="text-xs text-[#9AA9BC] italic py-4">No recurring YARA hits in current telemetry period.</p>
            )}
          </div>
        </div>

        {/* High-Frequency Suspicious Indicators */}
        <div className="p-6 bg-[#111C2E] border border-[#25354B] rounded-2xl space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-base font-bold text-white flex items-center space-x-2">
              <Activity className="w-4 h-4 text-[#F5B84B]" />
              <span>Recurring Suspicious Indicators</span>
            </h3>
            <span className="text-xs font-mono text-[#9AA9BC]">Heuristic Triggers</span>
          </div>

          <div className="space-y-3">
            {commonInd.length > 0 ? (
              commonInd.map((item, idx) => (
                <div key={idx} className="p-3 bg-[#0C1423] border border-[#25354B] rounded-xl flex items-center justify-between">
                  <p className="text-xs text-white max-w-[280px] truncate">{item.indicator}</p>
                  <span className="px-2.5 py-1 bg-[#162338] text-[#F5B84B] font-mono font-bold text-xs rounded-lg border border-[#25354B] shrink-0">
                    {item.count} files
                  </span>
                </div>
              ))
            ) : (
              <p className="text-xs text-[#9AA9BC] italic py-4">No recurring indicator anomalies identified.</p>
            )}
          </div>
        </div>
      </div>

      {/* Critical Threats / IOC Watchlist */}
      <div className="p-6 bg-[#111C2E] border border-[#25354B] rounded-2xl space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-base font-bold text-white">Critical Severity Threat Watchlist</h3>
            <p className="text-xs text-[#9AA9BC]">High-risk samples detected by the local detection pipeline</p>
          </div>
          <Link to="/history?risk_level=Critical" className="text-xs text-[#38D6C5] hover:underline flex items-center space-x-1">
            <span>Filter Critical Only</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </Link>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-[#25354B] text-[#9AA9BC] uppercase bg-[#0C1423]/50">
                <th className="py-3 px-4">Sample Name</th>
                <th className="py-3 px-4">SHA-256 Hash</th>
                <th className="py-3 px-4">Family</th>
                <th className="py-3 px-4">Risk Score</th>
                <th className="py-3 px-4">Detected</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#25354B]">
              {highRiskScans.length > 0 ? (
                highRiskScans.map((s) => (
                  <tr key={s.scan_id} className="hover:bg-[#162338]/40">
                    <td className="py-3 px-4 text-white font-medium">{s.file_name}</td>
                    <td className="py-3 px-4 text-[#9AA9BC]">{s.file_hash?.substring(0, 16)}...</td>
                    <td className="py-3 px-4 text-[#D94C63] font-semibold">{s.malware_family || 'Generic'}</td>
                    <td className="py-3 px-4 text-[#D94C63] font-bold">{s.risk_score}/100</td>
                    <td className="py-3 px-4 text-[#9AA9BC]">{new Date(s.created_at).toLocaleDateString()}</td>
                    <td className="py-3 px-4 text-right">
                      <Link
                        to={`/scan/results/${s.scan_id}`}
                        className="px-2.5 py-1 bg-[#162338] text-[#38D6C5] hover:bg-[#38D6C5] hover:text-[#080D18] rounded-md transition"
                      >
                        Inspect IOC
                      </Link>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="6" className="py-6 text-center text-[#9AA9BC] italic">
                    No critical risk threat samples recorded yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

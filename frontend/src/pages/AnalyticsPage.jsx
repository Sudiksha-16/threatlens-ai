import React, { useState, useEffect } from 'react';
import { 
  BarChart3, PieChart as PieIcon, TrendingUp, ShieldAlert, 
  RefreshCw, Filter, Layers 
} from 'lucide-react';
import { 
  ResponsiveContainer, BarChart, Bar, XAxis, YAxis, 
  Tooltip, PieChart, Pie, Cell, AreaChart, Area, Legend 
} from 'recharts';
import { analyticsAPI } from '../services/api';

const COLORS = ['#38D6C5', '#668CFF', '#F5B84B', '#D94C63', '#35C98A', '#F16B75', '#A78BFA'];

export const AnalyticsPage = () => {
  const [timeRange, setTimeRange] = useState('30d');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [classFilter, setClassFilter] = useState('ALL');
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchAnalytics = async () => {
    try {
      const res = await analyticsAPI.getAnalytics({
        time_range: timeRange,
        severity: severityFilter !== 'ALL' ? severityFilter : undefined,
        classification: classFilter !== 'ALL' ? classFilter : undefined,
      });
      setData(res.data);
    } catch (err) {
      console.error('Analytics load error:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    setLoading(true);
    fetchAnalytics();
  }, [timeRange, severityFilter, classFilter]);

  if (loading && !data) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="w-10 h-10 border-4 border-[#38D6C5] border-t-transparent rounded-full animate-spin"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Page Header with Multi-filters */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-[#25354B]">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Malware &amp; Threat Analytics</h1>
          <p className="text-xs text-[#9AA9BC] mt-1 font-mono">
            AGGREGATED MULTI-CHART THREAT VISUALIZATIONS &bull; {data?.total_scans || 0} TOTAL SAMPLES
          </p>
        </div>

        {/* Filter Controls */}
        <div className="flex flex-wrap items-center gap-3">
          {/* Time range */}
          <div className="flex items-center bg-[#111C2E] border border-[#25354B] rounded-xl p-1 text-xs">
            {['24h', '7d', '30d', '90d', 'all'].map((r) => (
              <button
                key={r}
                onClick={() => setTimeRange(r)}
                className={`px-3 py-1 rounded-lg font-medium uppercase transition ${
                  timeRange === r
                    ? 'bg-[#38D6C5] text-[#080D18] font-bold'
                    : 'text-[#9AA9BC] hover:text-white'
                }`}
              >
                {r}
              </button>
            ))}
          </div>

          {/* Severity */}
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-[#111C2E] border border-[#25354B] text-white rounded-xl px-3 py-1.5 text-xs focus:outline-none focus:border-[#38D6C5]"
          >
            <option value="ALL">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>

          {/* Classification */}
          <select
            value={classFilter}
            onChange={(e) => setClassFilter(e.target.value)}
            className="bg-[#111C2E] border border-[#25354B] text-white rounded-xl px-3 py-1.5 text-xs focus:outline-none focus:border-[#38D6C5]"
          >
            <option value="ALL">All Verdicts</option>
            <option value="Malicious">Malicious</option>
            <option value="Benign">Benign</option>
          </select>
        </div>
      </div>

      {/* Grid of Analytics Charts */}
      <div className="grid md:grid-cols-2 gap-6">
        {/* Chart 1: Malware Category Distribution */}
        <div className="p-6 bg-[#111C2E] border border-[#25354B] rounded-2xl">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-base font-bold text-white">Malware Family Categories</h3>
              <p className="text-xs text-[#9AA9BC]">Trojan, Ransomware, Spyware, Backdoor breakdown</p>
            </div>
            <BarChart3 className="w-4 h-4 text-[#38D6C5]" />
          </div>

          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data?.family_distribution || []}>
                <XAxis dataKey="family" stroke="#9AA9BC" fontSize={10} tickLine={false} />
                <YAxis stroke="#9AA9BC" fontSize={10} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0C1423',
                    borderColor: '#25354B',
                    borderRadius: '0.5rem',
                    fontSize: '12px',
                    color: '#F4F7FB',
                  }}
                />
                <Bar dataKey="count" fill="#38D6C5" radius={[6, 6, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Chart 2: Threat Severity Distribution */}
        <div className="p-6 bg-[#111C2E] border border-[#25354B] rounded-2xl">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-base font-bold text-white">Threat Risk Severity Breakdown</h3>
              <p className="text-xs text-[#9AA9BC]">Samples grouped by calculated risk level</p>
            </div>
            <ShieldAlert className="w-4 h-4 text-[#D94C63]" />
          </div>

          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data?.severity_distribution || []}>
                <XAxis dataKey="level" stroke="#9AA9BC" fontSize={10} tickLine={false} />
                <YAxis stroke="#9AA9BC" fontSize={10} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0C1423',
                    borderColor: '#25354B',
                    borderRadius: '0.5rem',
                    fontSize: '12px',
                    color: '#F4F7FB',
                  }}
                />
                <Bar dataKey="count" fill="#668CFF" radius={[6, 6, 0, 0]}>
                  {(data?.severity_distribution || []).map((entry, idx) => {
                    const color =
                      entry.level === 'Critical' ? '#D94C63' :
                      entry.level === 'High' ? '#F16B75' :
                      entry.level === 'Medium' ? '#F5B84B' : '#35C98A';
                    return <Cell key={`cell-${idx}`} fill={color} />;
                  })}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Chart 3: Detection Volume Over Time */}
        <div className="p-6 bg-[#111C2E] border border-[#25354B] rounded-2xl md:col-span-2">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-base font-bold text-white">Timeline Volume Telemetry</h3>
              <p className="text-xs text-[#9AA9BC]">Temporal trends of scanned vs malicious findings</p>
            </div>
            <TrendingUp className="w-4 h-4 text-[#35C98A]" />
          </div>

          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={data?.trends || []}>
                <defs>
                  <linearGradient id="anTot" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#668CFF" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#668CFF" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="anMal" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#D94C63" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#D94C63" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="date" stroke="#9AA9BC" fontSize={10} tickLine={false} />
                <YAxis stroke="#9AA9BC" fontSize={10} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0C1423',
                    borderColor: '#25354B',
                    borderRadius: '0.75rem',
                    fontSize: '12px',
                    color: '#F4F7FB',
                  }}
                />
                <Area type="monotone" dataKey="total" stroke="#668CFF" strokeWidth={2} fillOpacity={1} fill="url(#anTot)" />
                <Area type="monotone" dataKey="malicious" stroke="#D94C63" strokeWidth={2} fillOpacity={1} fill="url(#anMal)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Chart 4: YARA Hit Frequencies */}
        <div className="p-6 bg-[#111C2E] border border-[#25354B] rounded-2xl">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-base font-bold text-white">YARA Signature Trigger Rates</h3>
              <p className="text-xs text-[#9AA9BC]">Most active signature rules</p>
            </div>
          </div>

          <div className="space-y-3">
            {(data?.yara_rule_frequency || []).length > 0 ? (
              (data?.yara_rule_frequency || []).map((yr, idx) => (
                <div key={idx} className="space-y-1">
                  <div className="flex justify-between text-xs font-mono">
                    <span className="text-white">{yr.rule}</span>
                    <span className="text-[#38D6C5] font-bold">{yr.count} hits</span>
                  </div>
                  <div className="w-full bg-[#0C1423] rounded-full h-1.5 overflow-hidden">
                    <div
                      className="bg-[#38D6C5] h-full rounded-full"
                      style={{ width: `${Math.min(100, yr.count * 20)}%` }}
                    ></div>
                  </div>
                </div>
              ))
            ) : (
              <p className="text-xs text-[#9AA9BC] italic py-6">No YARA detections recorded.</p>
            )}
          </div>
        </div>

        {/* Chart 5: Common Suspicious Indicators */}
        <div className="p-6 bg-[#111C2E] border border-[#25354B] rounded-2xl">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-base font-bold text-white">Top Heuristic Anomalies</h3>
              <p className="text-xs text-[#9AA9BC]">Common risk assessment flags</p>
            </div>
          </div>

          <div className="space-y-3">
            {(data?.common_indicators || []).length > 0 ? (
              (data?.common_indicators || []).map((ci, idx) => (
                <div key={idx} className="p-3 bg-[#0C1423] border border-[#25354B] rounded-xl flex items-center justify-between">
                  <p className="text-xs text-[#F4F7FB] max-w-[280px] truncate">{ci.indicator}</p>
                  <span className="text-xs font-mono font-bold text-[#F5B84B]">{ci.count}x</span>
                </div>
              ))
            ) : (
              <p className="text-xs text-[#9AA9BC] italic py-6">No anomalies recorded.</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

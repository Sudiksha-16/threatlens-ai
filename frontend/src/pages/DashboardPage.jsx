import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { 
  FileCheck, ShieldAlert, AlertTriangle, Bug, 
  UploadCloud, ArrowUpRight, Clock, RefreshCw, BarChart2 
} from 'lucide-react';
import { 
  ResponsiveContainer, AreaChart, Area, XAxis, YAxis, 
  Tooltip, PieChart, Pie, Cell, BarChart, Bar, Legend 
} from 'recharts';
import { dashboardAPI } from '../services/api';

const COLORS = {
  Benign: '#35C98A',
  Malicious: '#D94C63',
  Low: '#35C98A',
  Medium: '#F5B84B',
  High: '#F16B75',
  Critical: '#D94C63',
};

export const DashboardPage = () => {
  const [timeRange, setTimeRange] = useState('30d');
  const [stats, setStats] = useState(null);
  const [charts, setCharts] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const fetchData = async (range = timeRange) => {
    try {
      const [statsRes, chartsRes] = await Promise.all([
        dashboardAPI.getStats(range),
        dashboardAPI.getCharts(range),
      ]);
      setStats(statsRes.data);
      setCharts(chartsRes.data);
    } catch (err) {
      console.error('Failed to load dashboard data:', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    setLoading(true);
    fetchData(timeRange);
  }, [timeRange]);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData(timeRange);
  };

  if (loading && !stats) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="w-10 h-10 border-4 border-[#38D6C5] border-t-transparent rounded-full animate-spin"></div>
      </div>
    );
  }

  const hasScans = stats && stats.total_files_scanned > 0;

  return (
    <div className="space-y-6">
      {/* Page Header with Time Filters */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-[#25354B]">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Security Operations Dashboard</h1>
          <p className="text-xs text-[#9AA9BC] mt-1 font-mono">
            LIVE TELEMETRY FROM THREATLENS AI DETECTION ENGINE
          </p>
        </div>

        <div className="flex items-center space-x-3">
          {/* Time range selector */}
          <div className="flex items-center bg-[#111C2E] border border-[#25354B] rounded-xl p-1 text-xs">
            {['24h', '7d', '30d', '90d', 'all'].map((r) => (
              <button
                key={r}
                onClick={() => setTimeRange(r)}
                className={`px-3 py-1 rounded-lg font-medium uppercase transition ${
                  timeRange === r
                    ? 'bg-[#38D6C5] text-[#080D18] font-bold shadow-sm'
                    : 'text-[#9AA9BC] hover:text-white'
                }`}
              >
                {r}
              </button>
            ))}
          </div>

          <button
            onClick={handleRefresh}
            disabled={refreshing}
            className="p-2 bg-[#111C2E] hover:bg-[#162338] border border-[#25354B] rounded-xl text-[#9AA9BC] hover:text-white transition"
            title="Refresh Data"
          >
            <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin text-[#38D6C5]' : ''}`} />
          </button>
        </div>
      </div>

      {/* Empty State */}
      {!hasScans ? (
        <div className="p-12 text-center bg-[#111C2E] border border-[#25354B] rounded-2xl max-w-xl mx-auto my-12 shadow-xl">
          <div className="w-16 h-16 rounded-2xl bg-[#38D6C5]/10 border border-[#38D6C5]/30 flex items-center justify-center mx-auto mb-6 text-[#38D6C5]">
            <UploadCloud className="w-8 h-8" />
          </div>
          <h3 className="text-xl font-bold text-white mb-2">No File Scans Recorded</h3>
          <p className="text-sm text-[#9AA9BC] mb-6">
            Your telemetry queue is currently clear. Upload a suspicious binary or executable to initiate static feature extraction, YARA signature detection, and local ML classification.
          </p>
          <Link
            to="/scan"
            className="inline-flex items-center space-x-2 px-6 py-3 bg-[#38D6C5] hover:bg-[#38D6C5]/90 text-[#080D18] font-bold text-sm rounded-xl transition shadow-lg shadow-[#38D6C5]/20"
          >
            <UploadCloud className="w-4 h-4" />
            <span>Perform Your First Scan</span>
          </Link>
        </div>
      ) : (
        <>
          {/* Key Metric Stats Cards */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            <div className="p-5 bg-[#111C2E] border border-[#25354B] rounded-2xl">
              <div className="flex items-center justify-between text-xs text-[#9AA9BC] font-medium mb-2">
                <span>Total Files Scanned</span>
                <BarChart2 className="w-4 h-4 text-[#668CFF]" />
              </div>
              <p className="text-3xl font-extrabold text-white font-mono">{stats.total_files_scanned}</p>
              <p className="text-[11px] text-[#9AA9BC] mt-1 font-mono">100% analyzed</p>
            </div>

            <div className="p-5 bg-[#111C2E] border border-[#25354B] rounded-2xl">
              <div className="flex items-center justify-between text-xs text-[#9AA9BC] font-medium mb-2">
                <span>Benign Software</span>
                <FileCheck className="w-4 h-4 text-[#35C98A]" />
              </div>
              <p className="text-3xl font-extrabold text-[#35C98A] font-mono">{stats.benign_files}</p>
              <p className="text-[11px] text-[#9AA9BC] mt-1 font-mono">
                {stats.total_files_scanned > 0
                  ? `${Math.round((stats.benign_files / stats.total_files_scanned) * 100)}% of total`
                  : '0%'}
              </p>
            </div>

            <div className="p-5 bg-[#111C2E] border border-[#25354B] rounded-2xl">
              <div className="flex items-center justify-between text-xs text-[#9AA9BC] font-medium mb-2">
                <span>Malicious Detections</span>
                <Bug className="w-4 h-4 text-[#D94C63]" />
              </div>
              <p className="text-3xl font-extrabold text-[#D94C63] font-mono">{stats.malicious_files}</p>
              <p className="text-[11px] text-[#F16B75] mt-1 font-mono">Active threats</p>
            </div>

            <div className="p-5 bg-[#111C2E] border border-[#25354B] rounded-2xl">
              <div className="flex items-center justify-between text-xs text-[#9AA9BC] font-medium mb-2">
                <span>High-Risk Threats</span>
                <AlertTriangle className="w-4 h-4 text-[#F5B84B]" />
              </div>
              <p className="text-3xl font-extrabold text-[#F5B84B] font-mono">{stats.high_risk_threats}</p>
              <p className="text-[11px] text-[#9AA9BC] mt-1 font-mono">Score 56-80</p>
            </div>

            <div className="p-5 bg-[#111C2E] border border-[#25354B] rounded-2xl">
              <div className="flex items-center justify-between text-xs text-[#9AA9BC] font-medium mb-2">
                <span>Critical Threats</span>
                <ShieldAlert className="w-4 h-4 text-[#D94C63]" />
              </div>
              <p className="text-3xl font-extrabold text-[#D94C63] font-mono">{stats.critical_threats}</p>
              <p className="text-[11px] text-[#D94C63] mt-1 font-mono">Score 81-100</p>
            </div>
          </div>

          {/* Charts Row */}
          <div className="grid md:grid-cols-3 gap-6">
            {/* Scan Trends Area Chart */}
            <div className="md:col-span-2 p-6 bg-[#111C2E] border border-[#25354B] rounded-2xl">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-base font-bold text-white">Detection &amp; Scan Volume Trends</h3>
                  <p className="text-xs text-[#9AA9BC]">Daily scan telemetry breakdown</p>
                </div>
                <div className="flex items-center space-x-4 text-xs font-mono">
                  <div className="flex items-center space-x-1.5">
                    <span className="w-2.5 h-2.5 rounded-full bg-[#38D6C5]"></span>
                    <span className="text-[#9AA9BC]">Total</span>
                  </div>
                  <div className="flex items-center space-x-1.5">
                    <span className="w-2.5 h-2.5 rounded-full bg-[#D94C63]"></span>
                    <span className="text-[#9AA9BC]">Malicious</span>
                  </div>
                </div>
              </div>

              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={charts?.scan_trends || []}>
                    <defs>
                      <linearGradient id="colorTotal" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#38D6C5" stopOpacity={0.4} />
                        <stop offset="95%" stopColor="#38D6C5" stopOpacity={0} />
                      </linearGradient>
                      <linearGradient id="colorMal" x1="0" y1="0" x2="0" y2="1">
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
                    <Area type="monotone" dataKey="total" stroke="#38D6C5" strokeWidth={2} fillOpacity={1} fill="url(#colorTotal)" />
                    <Area type="monotone" dataKey="malicious" stroke="#D94C63" strokeWidth={2} fillOpacity={1} fill="url(#colorMal)" />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Classification Donut Chart */}
            <div className="p-6 bg-[#111C2E] border border-[#25354B] rounded-2xl flex flex-col justify-between">
              <div>
                <h3 className="text-base font-bold text-white">Classification Ratio</h3>
                <p className="text-xs text-[#9AA9BC]">Benign vs Malicious proportion</p>
              </div>

              <div className="h-52 relative flex items-center justify-center my-2">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={charts?.classification_distribution || []}
                      innerRadius={55}
                      outerRadius={80}
                      paddingAngle={4}
                      dataKey="value"
                    >
                      {(charts?.classification_distribution || []).map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={COLORS[entry.name] || '#668CFF'} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#0C1423',
                        borderColor: '#25354B',
                        borderRadius: '0.5rem',
                        fontSize: '12px',
                      }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              </div>

              <div className="space-y-2 pt-2 border-t border-[#25354B]">
                {(charts?.classification_distribution || []).map((c) => (
                  <div key={c.name} className="flex items-center justify-between text-xs">
                    <div className="flex items-center space-x-2">
                      <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: COLORS[c.name] || '#668CFF' }}></span>
                      <span className="text-[#9AA9BC]">{c.name}</span>
                    </div>
                    <span className="font-mono font-bold text-white">{c.value}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Recent Scans Table */}
          <div className="p-6 bg-[#111C2E] border border-[#25354B] rounded-2xl">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-base font-bold text-white">Recent File Analyses</h3>
                <p className="text-xs text-[#9AA9BC]">Latest inspected files and classifications</p>
              </div>
              <Link to="/history" className="text-xs text-[#38D6C5] hover:underline flex items-center space-x-1">
                <span>View Full History</span>
                <ArrowUpRight className="w-3.5 h-3.5" />
              </Link>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-[#25354B] text-[#9AA9BC] uppercase tracking-wider font-mono">
                    <th className="py-3 px-4">File Name</th>
                    <th className="py-3 px-4">SHA-256</th>
                    <th className="py-3 px-4">Classification</th>
                    <th className="py-3 px-4">Risk Level</th>
                    <th className="py-3 px-4">Risk Score</th>
                    <th className="py-3 px-4">Date</th>
                    <th className="py-3 px-4 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#25354B]">
                  {stats.recent_scans.map((s) => (
                    <tr key={s.scan_id} className="hover:bg-[#162338]/50 transition">
                      <td className="py-3.5 px-4 font-medium text-white max-w-[180px] truncate">{s.file_name}</td>
                      <td className="py-3.5 px-4 font-mono text-[#9AA9BC]">{s.file_hash?.substring(0, 12)}...</td>
                      <td className="py-3.5 px-4">
                        <span
                          className={`px-2 py-0.5 rounded-md font-semibold text-[11px] ${
                            s.classification === 'Malicious'
                              ? 'bg-[#D94C63]/15 text-[#F16B75] border border-[#D94C63]/30'
                              : 'bg-[#35C98A]/15 text-[#35C98A] border border-[#35C98A]/30'
                          }`}
                        >
                          {s.classification}
                        </span>
                      </td>
                      <td className="py-3.5 px-4">
                        <span
                          className={`font-semibold ${
                            s.risk_level === 'Critical'
                              ? 'text-[#D94C63]'
                              : s.risk_level === 'High'
                              ? 'text-[#F16B75]'
                              : s.risk_level === 'Medium'
                              ? 'text-[#F5B84B]'
                              : 'text-[#35C98A]'
                          }`}
                        >
                          {s.risk_level}
                        </span>
                      </td>
                      <td className="py-3.5 px-4 font-mono font-bold text-white">{s.risk_score}/100</td>
                      <td className="py-3.5 px-4 text-[#9AA9BC] font-mono">
                        {new Date(s.created_at).toLocaleDateString()}
                      </td>
                      <td className="py-3.5 px-4 text-right">
                        <Link
                          to={`/scan/results/${s.scan_id}`}
                          className="px-2.5 py-1 bg-[#162338] hover:bg-[#38D6C5] hover:text-[#080D18] text-[#38D6C5] rounded-md transition font-medium"
                        >
                          Inspect
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  );
};

import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { 
  Search, Filter, Download, Trash2, ArrowUpRight, 
  RefreshCw, FileText, ShieldAlert, ShieldCheck, AlertTriangle 
} from 'lucide-react';
import { scanAPI, reportsAPI } from '../services/api';

export const ScanHistoryPage = () => {
  const [scans, setScans] = useState([]);
  const [total, setTotal] = useState(0);
  const [search, setSearch] = useState('');
  const [riskFilter, setRiskFilter] = useState('ALL');
  const [classFilter, setClassFilter] = useState('ALL');
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const fetchHistory = async () => {
    try {
      const res = await scanAPI.getHistory({
        search: search || undefined,
        risk_level: riskFilter !== 'ALL' ? riskFilter : undefined,
        classification: classFilter !== 'ALL' ? classFilter : undefined,
        limit: 50,
      });
      setScans(res.data.scans || []);
      setTotal(res.data.total || 0);
    } catch (err) {
      console.error('Failed to load scan history:', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, [riskFilter, classFilter]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    setLoading(true);
    fetchHistory();
  };

  const handleDelete = async (scanId) => {
    if (window.confirm('Are you sure you want to delete this scan record?')) {
      try {
        await scanAPI.deleteScan(scanId);
        setScans((prev) => prev.filter((s) => s.scan_id !== scanId));
        setTotal((prev) => prev - 1);
      } catch (err) {
        console.error('Delete error:', err);
      }
    }
  };

  const handleDownloadReport = async (scanId) => {
    try {
      await reportsAPI.generateReport(scanId);
      window.open(reportsAPI.getDownloadUrl(scanId), '_blank');
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-[#25354B]">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Scan Telemetry Records</h1>
          <p className="text-xs text-[#9AA9BC] mt-1 font-mono">
            HISTORICAL AUDIT LOG &bull; {total} TOTAL SCANS RECORDED
          </p>
        </div>

        <Link
          to="/scan"
          className="px-4 py-2 bg-[#38D6C5] hover:bg-[#38D6C5]/90 text-[#080D18] font-bold text-xs rounded-xl transition shadow-md shadow-[#38D6C5]/20 self-start sm:self-auto"
        >
          New Analysis
        </Link>
      </div>

      {/* Filter and Search Bar */}
      <div className="p-4 bg-[#111C2E] border border-[#25354B] rounded-2xl flex flex-col md:flex-row items-center justify-between gap-4">
        {/* Search Input */}
        <form onSubmit={handleSearchSubmit} className="relative w-full md:w-96">
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by file name, SHA-256 hash, scan ID..."
            className="w-full pl-10 pr-4 py-2 bg-[#0C1423] border border-[#25354B] rounded-xl text-xs text-white placeholder-[#9AA9BC]/50 focus:outline-none focus:border-[#38D6C5] transition font-mono"
          />
          <Search className="w-4 h-4 text-[#9AA9BC] absolute left-3.5 top-2.5" />
        </form>

        {/* Filter Dropdowns */}
        <div className="flex items-center space-x-3 w-full md:w-auto">
          <div className="flex items-center space-x-2 text-xs">
            <span className="text-[#9AA9BC]">Risk:</span>
            <select
              value={riskFilter}
              onChange={(e) => setRiskFilter(e.target.value)}
              className="bg-[#0C1423] border border-[#25354B] text-white rounded-xl px-3 py-1.5 text-xs focus:outline-none focus:border-[#38D6C5]"
            >
              <option value="ALL">All Severities</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>
          </div>

          <div className="flex items-center space-x-2 text-xs">
            <span className="text-[#9AA9BC]">Class:</span>
            <select
              value={classFilter}
              onChange={(e) => setClassFilter(e.target.value)}
              className="bg-[#0C1423] border border-[#25354B] text-white rounded-xl px-3 py-1.5 text-xs focus:outline-none focus:border-[#38D6C5]"
            >
              <option value="ALL">All Verdicts</option>
              <option value="Malicious">Malicious</option>
              <option value="Benign">Benign</option>
            </select>
          </div>

          <button
            onClick={() => { setLoading(true); fetchHistory(); }}
            className="p-2 bg-[#0C1423] hover:bg-[#162338] border border-[#25354B] rounded-xl text-[#9AA9BC] hover:text-white transition"
            title="Refresh"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* History Table */}
      <div className="bg-[#111C2E] border border-[#25354B] rounded-2xl overflow-hidden">
        {loading ? (
          <div className="p-12 text-center">
            <div className="w-8 h-8 border-4 border-[#38D6C5] border-t-transparent rounded-full animate-spin mx-auto mb-2"></div>
            <p className="text-xs text-[#9AA9BC] font-mono">LOADING AUDIT RECORDS...</p>
          </div>
        ) : scans.length === 0 ? (
          <div className="p-12 text-center text-[#9AA9BC] space-y-3">
            <FileText className="w-10 h-10 mx-auto text-[#25354B]" />
            <p className="text-sm font-semibold text-white">No Matching Scan Records Found</p>
            <p className="text-xs">Adjust your search parameters or run a new file analysis.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-[#25354B] text-[#9AA9BC] uppercase font-mono tracking-wider bg-[#0C1423]/50">
                  <th className="py-3.5 px-4">File Name</th>
                  <th className="py-3.5 px-4">SHA-256 Hash</th>
                  <th className="py-3.5 px-4">Classification</th>
                  <th className="py-3.5 px-4">Risk Level</th>
                  <th className="py-3.5 px-4">Score</th>
                  <th className="py-3.5 px-4">Result Source</th>
                  <th className="py-3.5 px-4">Scan Date</th>
                  <th className="py-3.5 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#25354B]">
                {scans.map((s) => (
                  <tr key={s.scan_id} className="hover:bg-[#162338]/40 transition">
                    <td className="py-3.5 px-4 font-medium text-white max-w-[180px] truncate">
                      {s.file_name}
                    </td>
                    <td className="py-3.5 px-4 font-mono text-[#9AA9BC]">
                      {s.file_hash ? `${s.file_hash.substring(0, 10)}...` : 'N/A'}
                    </td>
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
                    <td className="py-3.5 px-4 font-mono font-bold text-white">
                      {s.risk_score}/100
                    </td>
                    <td className="py-3.5 px-4 text-[#9AA9BC] font-mono text-[11px]">
                      {s.result_source}
                    </td>
                    <td className="py-3.5 px-4 text-[#9AA9BC] font-mono">
                      {new Date(s.created_at).toLocaleDateString()}
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      <div className="flex items-center justify-end space-x-2">
                        <Link
                          to={`/scan/results/${s.scan_id}`}
                          className="px-2.5 py-1 bg-[#162338] hover:bg-[#38D6C5] hover:text-[#080D18] text-[#38D6C5] rounded-md transition font-medium text-[11px]"
                        >
                          Details
                        </Link>
                        <button
                          onClick={() => handleDownloadReport(s.scan_id)}
                          className="p-1 text-[#9AA9BC] hover:text-white transition"
                          title="Download PDF Report"
                        >
                          <Download className="w-3.5 h-3.5" />
                        </button>
                        <button
                          onClick={() => handleDelete(s.scan_id)}
                          className="p-1 text-[#9AA9BC] hover:text-[#D94C63] transition"
                          title="Delete Record"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { FileText, Download, ExternalLink, Calendar, HardDrive, Shield } from 'lucide-react';
import { scanAPI, reportsAPI } from '../services/api';

export const ReportsPage = () => {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [downloadingId, setDownloadingId] = useState(null);

  useEffect(() => {
    const fetchReports = async () => {
      try {
        const res = await scanAPI.getHistory({ limit: 50 });
        setScans(res.data.scans || []);
      } catch (e) {
        console.error(e);
      } finally {
        setLoading(false);
      }
    };
    fetchReports();
  }, []);

  const handleDownload = async (scanId) => {
    setDownloadingId(scanId);
    try {
      await reportsAPI.generateReport(scanId);
      window.open(reportsAPI.getDownloadUrl(scanId), '_blank');
    } catch (e) {
      console.error(e);
    } finally {
      setDownloadingId(null);
    }
  };

  return (
    <div className="space-y-6">
      <div className="pb-2 border-b border-[#25354B]">
        <h1 className="text-2xl font-bold text-white tracking-tight">Security Audit Reports</h1>
        <p className="text-xs text-[#9AA9BC] mt-1 font-mono">
          DOWNLOADABLE PDF FORENSIC REPORTS &bull; CRYPTOGRAPHIC AUDIT LOGS
        </p>
      </div>

      {loading ? (
        <div className="p-12 text-center bg-[#111C2E] border border-[#25354B] rounded-2xl">
          <div className="w-8 h-8 border-4 border-[#38D6C5] border-t-transparent rounded-full animate-spin mx-auto mb-2"></div>
          <p className="text-xs text-[#9AA9BC] font-mono">LOADING REPORT REPOSITORY...</p>
        </div>
      ) : scans.length === 0 ? (
        <div className="p-12 text-center bg-[#111C2E] border border-[#25354B] rounded-2xl text-[#9AA9BC] space-y-3">
          <FileText className="w-12 h-12 text-[#25354B] mx-auto" />
          <h3 className="text-base font-bold text-white">No Reports Generated Yet</h3>
          <p className="text-xs">Scan a suspicious file to automatically generate your first audit report.</p>
          <Link to="/scan" className="px-4 py-2 bg-[#38D6C5] text-[#080D18] rounded-xl text-xs font-bold inline-block">
            Start a File Scan
          </Link>
        </div>
      ) : (
        <div className="grid md:grid-cols-2 gap-4">
          {scans.map((s) => (
            <div key={s.scan_id} className="p-5 bg-[#111C2E] border border-[#25354B] rounded-2xl flex flex-col justify-between space-y-4">
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="font-mono text-xs text-[#38D6C5]">PDF AUDIT REPORT</span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${s.classification === 'Malicious' ? 'bg-[#D94C63]/20 text-[#D94C63]' : 'bg-[#35C98A]/20 text-[#35C98A]'}`}>
                    {s.classification}
                  </span>
                </div>
                <h3 className="text-base font-bold text-white truncate">{s.file_name}</h3>
                <p className="text-xs font-mono text-[#9AA9BC] mt-1">SHA-256: {s.file_hash?.substring(0, 24)}...</p>
                <div className="mt-3 flex items-center space-x-4 text-[11px] font-mono text-[#9AA9BC]">
                  <span>Score: {s.risk_score}/100</span>
                  <span>&bull;</span>
                  <span>Date: {new Date(s.created_at).toLocaleDateString()}</span>
                </div>
              </div>

              <div className="pt-3 border-t border-[#25354B] flex items-center justify-between">
                <Link
                  to={`/scan/results/${s.scan_id}`}
                  className="text-xs text-[#9AA9BC] hover:text-white flex items-center space-x-1"
                >
                  <span>View Analysis</span>
                  <ExternalLink className="w-3.5 h-3.5" />
                </Link>

                <button
                  onClick={() => handleDownload(s.scan_id)}
                  disabled={downloadingId === s.scan_id}
                  className="px-4 py-2 bg-[#162338] hover:bg-[#38D6C5] hover:text-[#080D18] text-[#38D6C5] rounded-xl text-xs font-semibold transition flex items-center space-x-1.5 border border-[#25354B]"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>{downloadingId === s.scan_id ? 'Generating...' : 'Download PDF'}</span>
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

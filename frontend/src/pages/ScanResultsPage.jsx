import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { 
  ShieldAlert, ShieldCheck, Download, RefreshCw, 
  ArrowLeft, FileCode, CheckCircle2, AlertTriangle, 
  HelpCircle, Info, ChevronDown, ChevronUp, Terminal, 
  Layers, Lock, ExternalLink, Zap
} from 'lucide-react';
import { scanAPI, reportsAPI } from '../services/api';

export const ScanResultsPage = () => {
  const { scanId } = useParams();

  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [downloading, setDownloading] = useState(false);
  const [error, setError] = useState('');
  const [activeTab, setActiveTab] = useState('summary'); // 'summary' | 'forensics' | 'yara'
  const [showExplanation, setShowExplanation] = useState(false);

  useEffect(() => {
    const fetchScanDetail = async () => {
      try {
        const res = await scanAPI.getDetail(scanId);
        setScan(res.data);
      } catch (err) {
        setError(err.response?.data?.detail || 'Scan result not found.');
      } finally {
        setLoading(false);
      }
    };
    fetchScanDetail();
  }, [scanId]);

  const handleDownloadPDF = async () => {
    if (!scan) return;
    setDownloading(true);
    try {
      const cleanName = scan.file_name.replace(/[^a-zA-Z0-9._-]/g, '_');
      await reportsAPI.downloadPDF(scanId, `ThreatLens_Report_${cleanName}.pdf`);
    } catch (e) {
      console.error('Download error:', e);
      // Fallback: direct window open with query token
      window.open(reportsAPI.getDownloadUrl(scanId), '_blank');
    } finally {
      setDownloading(false);
    }
  };

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] space-y-4">
        <div className="w-12 h-12 border-4 border-[#38D6C5] border-t-transparent rounded-full animate-spin"></div>
        <p className="text-xs font-mono text-[#9AA9BC]">GATHERING FORENSIC TELEMETRY...</p>
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div className="p-8 bg-[#111C2E] border border-[#25354B] rounded-2xl max-w-lg mx-auto text-center my-12">
        <AlertTriangle className="w-12 h-12 text-[#D94C63] mx-auto mb-4" />
        <h3 className="text-lg font-bold text-white mb-2">Scan Result Unavailable</h3>
        <p className="text-xs text-[#9AA9BC] mb-6">{error || 'Could not retrieve scan data.'}</p>
        <Link to="/history" className="px-4 py-2 bg-[#162338] text-white rounded-lg text-xs font-semibold">
          Back to Scan History
        </Link>
      </div>
    );
  }

  const isMalicious = scan.classification === 'Malicious';
  const riskColor = 
    scan.risk_level === 'Critical' ? '#D94C63' :
    scan.risk_level === 'High' ? '#F16B75' :
    scan.risk_level === 'Medium' ? '#F5B84B' : '#35C98A';

  const staticAnalysis = scan.static_analysis || {};
  const mlPred = scan.ml_prediction || {};
  const yaraResults = scan.yara_results || [];
  const riskAssessment = scan.risk_assessment || {};

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      {/* Top Breadcrumb & Quick Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-[#25354B]">
        <div className="flex items-center space-x-3">
          <Link
            to="/dashboard"
            className="p-2 bg-[#111C2E] hover:bg-[#162338] border border-[#25354B] rounded-xl text-[#9AA9BC] hover:text-white transition"
            title="Return to Dashboard"
          >
            <ArrowLeft className="w-4 h-4" />
          </Link>
          <div>
            <div className="flex items-center space-x-2">
              <span className="text-xs font-mono uppercase tracking-wider text-[#9AA9BC]">Threat Report:</span>
              <span className="text-base font-bold text-white font-mono truncate max-w-md">{scan.file_name}</span>
            </div>
            <p className="text-[11px] text-[#9AA9BC] font-mono mt-0.5">
              SHA-256: {scan.file_hash?.substring(0, 24)}... &bull; Analyzed on {new Date(scan.created_at).toLocaleString()}
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={handleDownloadPDF}
            disabled={downloading}
            className="px-4 py-2.5 bg-[#162338] hover:bg-[#25354B] border border-[#38D6C5]/40 hover:border-[#38D6C5] rounded-xl text-xs font-bold text-white transition flex items-center space-x-2 shadow-sm"
          >
            <Download className="w-4 h-4 text-[#38D6C5]" />
            <span>{downloading ? 'Downloading PDF...' : 'Download Official PDF Report'}</span>
          </button>
          <Link
            to="/scan"
            className="px-4 py-2.5 bg-[#38D6C5] hover:bg-[#38D6C5]/90 text-[#080D18] rounded-xl text-xs font-bold transition flex items-center space-x-1.5 shadow-md shadow-[#38D6C5]/20"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Scan Another File</span>
          </Link>
        </div>
      </div>

      {/* 1. BIG EASY-TO-UNDERSTAND EXECUTIVE VERDICT CARD */}
      <div 
        className={`p-6 sm:p-8 rounded-3xl border transition shadow-xl relative overflow-hidden ${
          isMalicious
            ? 'bg-gradient-to-br from-[#161320] via-[#111C2E] to-[#1F1218] border-[#D94C63]/50 shadow-[#D94C63]/10'
            : 'bg-gradient-to-br from-[#0F1E1E] via-[#111C2E] to-[#0E1A29] border-[#35C98A]/50 shadow-[#35C98A]/10'
        }`}
      >
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 relative z-10">
          {/* Main Status & Plain English Text */}
          <div className="flex items-start space-x-5">
            <div 
              className={`w-16 h-16 rounded-2xl flex items-center justify-center shrink-0 shadow-lg ${
                isMalicious 
                  ? 'bg-[#D94C63]/20 border border-[#D94C63]/50 text-[#D94C63]' 
                  : 'bg-[#35C98A]/20 border border-[#35C98A]/50 text-[#35C98A]'
              }`}
            >
              {isMalicious ? <ShieldAlert className="w-9 h-9" /> : <ShieldCheck className="w-9 h-9" />}
            </div>

            <div className="space-y-1.5">
              <div className="flex items-center space-x-3">
                <span 
                  className={`px-3 py-1 rounded-full text-xs font-extrabold uppercase tracking-wider font-mono ${
                    isMalicious 
                      ? 'bg-[#D94C63] text-white shadow-md shadow-[#D94C63]/30' 
                      : 'bg-[#35C98A] text-[#080D18] shadow-md shadow-[#35C98A]/30'
                  }`}
                >
                  {isMalicious ? 'DANGEROUS MALWARE DETECTED' : 'CLEAN & SAFE FILE'}
                </span>
                <span className="text-xs text-[#9AA9BC] font-mono">
                  {scan.malware_family || (isMalicious ? 'Malicious Binary' : 'Clean Software')}
                </span>
              </div>

              <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
                {isMalicious 
                  ? 'This file has been classified as a Security Threat.' 
                  : 'No Malicious Threats or Hidden Attacks Detected.'}
              </h2>

              <p className="text-sm text-[#9AA9BC] max-w-2xl leading-relaxed">
                {isMalicious 
                  ? 'ThreatLens AI identified malicious indicators, abnormal file structures, or known attack signatures. Opening or executing this file could compromise your computer or system.'
                  : 'ThreatLens AI scanned this file across 69 structural attributes and verified it against compiled threat rules. The structure matches standard benign software and is safe to use.'}
              </p>
            </div>
          </div>

          {/* Quick Risk Score Gauge */}
          <div className="p-4 bg-[#0C1423]/80 border border-[#25354B] rounded-2xl text-center md:min-w-[180px] shrink-0">
            <span className="text-[10px] font-mono uppercase tracking-wider text-[#9AA9BC] block">Overall Threat Score</span>
            <div className="text-4xl font-black font-mono my-1" style={{ color: riskColor }}>
              {scan.risk_score}
              <span className="text-sm text-[#9AA9BC] font-normal"> / 100</span>
            </div>
            <span 
              className="inline-block px-2.5 py-0.5 rounded-md text-[11px] font-bold uppercase tracking-wider"
              style={{ backgroundColor: `${riskColor}20`, color: riskColor }}
            >
              {scan.risk_level} Severity
            </span>
          </div>
        </div>

        {/* What to do next action box */}
        <div className="mt-6 pt-5 border-t border-[#25354B]/80 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
          <div className="flex items-center space-x-2 text-white">
            <span className="font-bold">Next Steps:</span>
            {isMalicious ? (
              <span className="text-[#F16B75]">
                Do NOT double click or run this file. Delete or quarantine it from your system immediately.
              </span>
            ) : (
              <span className="text-[#35C98A]">
                You can safely open, keep, or distribute this file. Standard computer safety practices apply.
              </span>
            )}
          </div>

          <button
            onClick={() => setShowExplanation(!showExplanation)}
            className="text-[#38D6C5] hover:underline flex items-center space-x-1 shrink-0 font-medium"
          >
            <HelpCircle className="w-3.5 h-3.5" />
            <span>{showExplanation ? 'Hide plain English explanations' : 'How does ThreatLens decide this?'}</span>
            {showExplanation ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          </button>
        </div>
      </div>

      {/* 2. PLAIN-ENGLISH "WHAT DO THESE MEAN?" EXPLAINER (Shown when clicked or for learning) */}
      {showExplanation && (
        <div className="p-6 bg-[#111C2E] border border-[#38D6C5]/40 rounded-2xl space-y-4 animate-in fade-in duration-300">
          <div className="flex items-center space-x-2 text-[#38D6C5]">
            <Info className="w-4 h-4" />
            <h4 className="text-sm font-bold uppercase tracking-wide">Threat Detection Explained in Plain Terms</h4>
          </div>

          <div className="grid sm:grid-cols-3 gap-4 text-xs">
            <div className="p-4 bg-[#0C1423] border border-[#25354B] rounded-xl space-y-1.5">
              <span className="font-bold text-white flex items-center space-x-1">
                <span>🤖</span>
                <span>Local AI Classification</span>
              </span>
              <p className="text-[#9AA9BC] leading-relaxed">
                We trained a <strong>Random Forest machine learning model</strong> on over 5,200 real clean and infected Windows executables. It looks at internal header blueprints to classify files with <strong>98.94% accuracy</strong> without running them.
              </p>
            </div>

            <div className="p-4 bg-[#0C1423] border border-[#25354B] rounded-xl space-y-1.5">
              <span className="font-bold text-white flex items-center space-x-1">
                <span>📊</span>
                <span>Entropy (Randomness)</span>
              </span>
              <p className="text-[#9AA9BC] leading-relaxed">
                Entropy is measured from 0 to 8. Normal software has readable patterns (usually 4 to 6). Scores above <strong>7.2</strong> indicate that content is encrypted or packed, which malware authors often do to hide dangerous code from antiviruses.
              </p>
            </div>

            <div className="p-4 bg-[#0C1423] border border-[#25354B] rounded-xl space-y-1.5">
              <span className="font-bold text-white flex items-center space-x-1">
                <span>🎯</span>
                <span>YARA Signatures</span>
              </span>
              <p className="text-[#9AA9BC] leading-relaxed">
                YARA rules are cybersecurity fingerprints used by security teams worldwide. They scan for known malware behaviors like ransomware wiping backups, stealth downloaders, or reverse shells.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* 3. TAB NAVIGATION (User-Friendly Tabs) */}
      <div className="flex border-b border-[#25354B] space-x-2 text-xs font-medium">
        <button
          onClick={() => setActiveTab('summary')}
          className={`pb-3 px-4 transition flex items-center space-x-2 border-b-2 ${
            activeTab === 'summary'
              ? 'border-[#38D6C5] text-[#38D6C5] font-bold'
              : 'border-transparent text-[#9AA9BC] hover:text-white'
          }`}
        >
          <ShieldCheck className="w-4 h-4" />
          <span>Executive Safety Summary</span>
        </button>

        <button
          onClick={() => setActiveTab('forensics')}
          className={`pb-3 px-4 transition flex items-center space-x-2 border-b-2 ${
            activeTab === 'forensics'
              ? 'border-[#38D6C5] text-[#38D6C5] font-bold'
              : 'border-transparent text-[#9AA9BC] hover:text-white'
          }`}
        >
          <Layers className="w-4 h-4" />
          <span>Technical File Forensics ({staticAnalysis.sections?.length || 0} Sections)</span>
        </button>

        <button
          onClick={() => setActiveTab('yara')}
          className={`pb-3 px-4 transition flex items-center space-x-2 border-b-2 ${
            activeTab === 'yara'
              ? 'border-[#38D6C5] text-[#38D6C5] font-bold'
              : 'border-transparent text-[#9AA9BC] hover:text-white'
          }`}
        >
          <Zap className="w-4 h-4" />
          <span>YARA Signatures ({yaraResults.length} Matches)</span>
        </button>
      </div>

      {/* TAB 1: EXECUTIVE SUMMARY */}
      {activeTab === 'summary' && (
        <div className="space-y-6">
          {/* Key Findings Grid */}
          <div className="grid sm:grid-cols-2 md:grid-cols-4 gap-4 text-xs font-mono">
            <div className="p-4 bg-[#111C2E] border border-[#25354B] rounded-2xl">
              <span className="text-[#9AA9BC] block text-[10px]">FILE FORMAT</span>
              <span className="text-white font-bold text-sm">{staticAnalysis.file_type || 'Binary'}</span>
              <span className="text-[10px] text-[#9AA9BC] block mt-1">{(scan.file_size / 1024).toFixed(1)} KB</span>
            </div>

            <div className="p-4 bg-[#111C2E] border border-[#25354B] rounded-2xl">
              <span className="text-[#9AA9BC] block text-[10px]">AI MODEL USED</span>
              <span className="text-[#38D6C5] font-bold text-sm">
                {mlPred.model_name?.replace('_', ' ') || 'Random Forest'}
              </span>
              <span className="text-[10px] text-[#35C98A] block mt-1">
                {Math.round((mlPred.confidence || 0.98) * 100)}% Certainty
              </span>
            </div>

            <div className="p-4 bg-[#111C2E] border border-[#25354B] rounded-2xl">
              <span className="text-[#9AA9BC] block text-[10px]">FILE RANDOMNESS</span>
              <span className={`font-bold text-sm ${staticAnalysis.entropy > 7.2 ? 'text-[#D94C63]' : 'text-[#35C98A]'}`}>
                {staticAnalysis.entropy} / 8.0
              </span>
              <span className="text-[10px] text-[#9AA9BC] block mt-1">
                {staticAnalysis.entropy > 7.2 ? 'High (Packed/Obfuscated)' : 'Normal Data'}
              </span>
            </div>

            <div className="p-4 bg-[#111C2E] border border-[#25354B] rounded-2xl">
              <span className="text-[#9AA9BC] block text-[10px]">YARA SIGNATURES</span>
              <span className={`font-bold text-sm ${yaraResults.length > 0 ? 'text-[#D94C63]' : 'text-[#35C98A]'}`}>
                {yaraResults.length} Matched
              </span>
              <span className="text-[10px] text-[#9AA9BC] block mt-1">
                {yaraResults.length > 0 ? 'Known Attack Pattern' : 'Zero Signatures Hit'}
              </span>
            </div>
          </div>

          {/* Reasons & Recommended Playbooks */}
          <div className="grid md:grid-cols-2 gap-6">
            <div className="p-6 bg-[#111C2E] border border-[#25354B] rounded-2xl space-y-3">
              <h3 className="text-sm font-bold text-white flex items-center space-x-2">
                <span className="w-2 h-2 rounded-full bg-[#38D6C5]"></span>
                <span>Why Was This Score Given? (Scoring Factors)</span>
              </h3>
              <div className="space-y-2 text-xs">
                {riskAssessment.reasons?.map((reason, idx) => (
                  <div key={idx} className="p-2.5 bg-[#0C1423] border border-[#25354B] rounded-xl flex items-start space-x-2.5">
                    <CheckCircle2 className="w-3.5 h-3.5 text-[#38D6C5] shrink-0 mt-0.5" />
                    <span className="text-[#F4F7FB]">{reason}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="p-6 bg-[#111C2E] border border-[#25354B] rounded-2xl space-y-3">
              <h3 className="text-sm font-bold text-white flex items-center space-x-2">
                <span className="w-2 h-2 rounded-full bg-[#F5B84B]"></span>
                <span>Recommended Action Plan</span>
              </h3>
              <div className="space-y-2 text-xs">
                {riskAssessment.recommended_actions?.map((action, idx) => (
                  <div key={idx} className="p-2.5 bg-[#0C1423] border border-[#25354B] rounded-xl flex items-start space-x-2.5">
                    <span className="text-[#F5B84B] font-bold">&bull;</span>
                    <span className="text-[#F4F7FB]">{action}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Cryptographic Identifiers */}
          <div className="p-6 bg-[#111C2E] border border-[#25354B] rounded-2xl space-y-3">
            <h4 className="text-xs font-bold text-white uppercase font-mono tracking-wider">File Fingerprints (Cryptographic Hashes)</h4>
            <div className="space-y-2 text-xs font-mono">
              <div className="p-3 bg-[#0C1423] border border-[#25354B] rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                <span className="text-[#9AA9BC]">SHA-256:</span>
                <span className="text-[#38D6C5] select-all break-all">{staticAnalysis.sha256}</span>
              </div>
              <div className="p-3 bg-[#0C1423] border border-[#25354B] rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                <span className="text-[#9AA9BC]">MD5:</span>
                <span className="text-[#668CFF] select-all break-all">{staticAnalysis.md5}</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: ADVANCED FORENSICS */}
      {activeTab === 'forensics' && (
        <div className="space-y-6">
          {/* PE Sections */}
          <div className="p-6 bg-[#111C2E] border border-[#25354B] rounded-2xl space-y-4">
            <div>
              <h3 className="text-base font-bold text-white">Executable Sections Structure</h3>
              <p className="text-xs text-[#9AA9BC]">Detailed breakdown of virtual memory layout, raw byte sizes, and section entropy</p>
            </div>

            {staticAnalysis.sections && staticAnalysis.sections.length > 0 ? (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead>
                    <tr className="border-b border-[#25354B] text-[#9AA9BC] bg-[#0C1423]/50">
                      <th className="py-3 px-4">Section Name</th>
                      <th className="py-3 px-4">Virtual Size</th>
                      <th className="py-3 px-4">Raw Size</th>
                      <th className="py-3 px-4">Entropy (0-8)</th>
                      <th className="py-3 px-4 text-right">Assessment</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#25354B]">
                    {staticAnalysis.sections.map((sec, i) => (
                      <tr key={i} className="hover:bg-[#162338]/40">
                        <td className="py-3 px-4 text-white font-bold">{sec.name}</td>
                        <td className="py-3 px-4 text-[#9AA9BC]">{sec.virtual_size.toLocaleString()} bytes</td>
                        <td className="py-3 px-4 text-[#9AA9BC]">{sec.raw_size.toLocaleString()} bytes</td>
                        <td className="py-3 px-4">
                          <span className={sec.entropy > 7.0 ? 'text-[#D94C63] font-bold' : 'text-[#35C98A]'}>
                            {sec.entropy}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-right">
                          {sec.is_suspicious ? (
                            <span className="px-2 py-0.5 bg-[#D94C63]/20 text-[#F16B75] rounded text-[10px] font-bold">
                              Suspicious (High Entropy/Packer)
                            </span>
                          ) : (
                            <span className="text-[#35C98A] text-[10px] font-medium">Standard</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <p className="text-xs text-[#9AA9BC] italic py-4">
                This file is not a Windows Portable Executable (PE). Header sections are only present in compiled binaries (.exe, .dll, .sys).
              </p>
            )}
          </div>

          {/* Sensitive APIs and Strings */}
          <div className="grid md:grid-cols-2 gap-6">
            <div className="p-6 bg-[#111C2E] border border-[#25354B] rounded-2xl space-y-3">
              <h4 className="text-xs font-bold text-white uppercase font-mono tracking-wider">
                Sensitive Windows APIs Imported ({staticAnalysis.imported_apis?.length || 0})
              </h4>
              <p className="text-[11px] text-[#9AA9BC]">Functions commonly targeted for process injection, anti-debugging, or keylogging</p>
              <div className="p-3 bg-[#0C1423] border border-[#25354B] rounded-xl max-h-56 overflow-y-auto space-y-1 text-xs font-mono">
                {staticAnalysis.imported_apis && staticAnalysis.imported_apis.length > 0 ? (
                  staticAnalysis.imported_apis.map((api, i) => (
                    <div key={i} className="text-[#F16B75] flex items-center space-x-1.5">
                      <span className="text-[#9AA9BC]">&bull;</span>
                      <span>{api}</span>
                    </div>
                  ))
                ) : (
                  <p className="text-[#9AA9BC] italic">No high-risk API functions imported.</p>
                )}
              </div>
            </div>

            <div className="p-6 bg-[#111C2E] border border-[#25354B] rounded-2xl space-y-3">
              <h4 className="text-xs font-bold text-white uppercase font-mono tracking-wider">
                Extracted Strings &amp; Commands ({staticAnalysis.suspicious_strings?.length || 0})
              </h4>
              <p className="text-[11px] text-[#9AA9BC]">Embedded shell commands, bitcoin addresses, or URLs</p>
              <div className="p-3 bg-[#0C1423] border border-[#25354B] rounded-xl max-h-56 overflow-y-auto space-y-1 text-xs font-mono">
                {staticAnalysis.suspicious_strings && staticAnalysis.suspicious_strings.length > 0 ? (
                  staticAnalysis.suspicious_strings.map((str, i) => (
                    <div key={i} className="text-[#F5B84B] flex items-center space-x-1.5">
                      <span className="text-[#9AA9BC]">&bull;</span>
                      <span>{str}</span>
                    </div>
                  ))
                ) : (
                  <p className="text-[#9AA9BC] italic">No suspicious commands or malicious patterns found in raw strings.</p>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: YARA SIGNATURES */}
      {activeTab === 'yara' && (
        <div className="p-6 bg-[#111C2E] border border-[#25354B] rounded-2xl space-y-4">
          <div>
            <h3 className="text-base font-bold text-white">YARA Signature Rule Detections</h3>
            <p className="text-xs text-[#9AA9BC]">Scanned against compiled ransomware, trojan, backdoor, and evasion rule definitions</p>
          </div>

          {yaraResults.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-[#25354B] text-[#9AA9BC] font-mono bg-[#0C1423]/50">
                    <th className="py-3 px-4">Rule Name</th>
                    <th className="py-3 px-4">Threat Category</th>
                    <th className="py-3 px-4">Severity</th>
                    <th className="py-3 px-4">Description</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#25354B]">
                  {yaraResults.map((yr, idx) => (
                    <tr key={idx} className="hover:bg-[#162338]/40">
                      <td className="py-3 px-4 font-mono font-bold text-[#38D6C5]">{yr.rule_name}</td>
                      <td className="py-3 px-4 text-[#9AA9BC]">{yr.category}</td>
                      <td className="py-3 px-4">
                        <span className={`font-semibold ${yr.severity === 'Critical' ? 'text-[#D94C63]' : yr.severity === 'High' ? 'text-[#F16B75]' : 'text-[#F5B84B]'}`}>
                          {yr.severity}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-[#F4F7FB]">{yr.description}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="p-6 bg-[#0C1423] border border-[#35C98A]/30 rounded-2xl text-center space-y-2">
              <CheckCircle2 className="w-8 h-8 text-[#35C98A] mx-auto" />
              <h4 className="text-sm font-bold text-white">No Malicious YARA Rules Matched</h4>
              <p className="text-xs text-[#9AA9BC] max-w-md mx-auto">
                The file does not contain signatures matching ransomware wipers, reverse shell listeners, credential stealers, or known packers.
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

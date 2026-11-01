import React, { useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  UploadCloud, FileCode, CheckCircle2, AlertCircle, 
  X, Shield, ArrowRight, Activity, Terminal, Lock 
} from 'lucide-react';
import { scanAPI } from '../services/api';

const SCAN_STAGES = [
  'Validating File Magic Bytes & Structure',
  'Generating Cryptographic Hashes (SHA-256, MD5)',
  'Extracting PE Header Fields & Shannon Entropy',
  'Engineering Normalized 69-Feature Vector',
  'Scanning Against 9 YARA Signature Rule Sets',
  'Executing Local ML Random Forest Classifier',
  'Computing Multi-Factor 0-100 Risk Assessment',
];

export const ScanUploadPage = () => {
  const navigate = useNavigate();
  const fileInputRef = useRef(null);

  const [file, setFile] = useState(null);
  const [scanMode, setScanMode] = useState('standard'); // 'standard' or 'deep'
  const [dragActive, setDragActive] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [scanning, setScanning] = useState(false);
  const [currentStage, setCurrentStage] = useState(0);
  const [error, setError] = useState('');

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleSelectedFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      handleSelectedFile(e.target.files[0]);
    }
  };

  const handleSelectedFile = (selectedFile) => {
    setError('');
    // Max size check: 50 MB
    if (selectedFile.size > 50 * 1024 * 1024) {
      setError('File exceeds 50 MB limit. Please select a smaller sample.');
      return;
    }
    if (selectedFile.size === 0) {
      setError('File is 0 bytes. Empty files cannot be analyzed.');
      return;
    }
    setFile(selectedFile);
  };

  const cancelSelection = () => {
    setFile(null);
    setUploadProgress(0);
    setError('');
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  const handleStartScan = async () => {
    if (!file) return;

    setScanning(true);
    setError('');
    setCurrentStage(0);

    const formData = new FormData();
    formData.append('file', file);
    formData.append('scan_mode', scanMode);

    // Simulate stage progress animation
    const stageInterval = setInterval(() => {
      setCurrentStage((prev) => {
        if (prev < SCAN_STAGES.length - 1) return prev + 1;
        return prev;
      });
    }, 600);

    try {
      const res = await scanAPI.uploadFile(formData, (progressEvent) => {
        const percent = Math.round((progressEvent.loaded * 100) / progressEvent.total);
        setUploadProgress(percent);
      });

      clearInterval(stageInterval);
      setCurrentStage(SCAN_STAGES.length);

      // Brief delay to display completed stages before navigation
      setTimeout(() => {
        navigate(`/scan/results/${res.data.scan_id}`);
      }, 700);

    } catch (err) {
      clearInterval(stageInterval);
      setScanning(false);
      const msg = err.response?.data?.detail || 'Scan failed. Ensure backend and MongoDB are operational.';
      setError(msg);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-8">
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight">Suspicious Binary &amp; File Ingestion</h1>
        <p className="text-xs text-[#9AA9BC] mt-1 font-mono">
          STATIC ANALYSIS &bull; SIGNATURE SCANNING &bull; LOCAL MACHINE LEARNING
        </p>
      </div>

      {error && (
        <div className="p-4 bg-[#D94C63]/10 border border-[#D94C63]/40 rounded-xl flex items-center space-x-3 text-xs text-[#F16B75]">
          <AlertCircle className="w-5 h-5 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Mode Selector */}
      <div className="grid sm:grid-cols-2 gap-4">
        <div
          onClick={() => !scanning && setScanMode('standard')}
          className={`p-5 rounded-2xl border cursor-pointer transition ${
            scanMode === 'standard'
              ? 'bg-[#111C2E] border-[#38D6C5] shadow-lg shadow-[#38D6C5]/10'
              : 'bg-[#0C1423] border-[#25354B] opacity-70 hover:opacity-100'
          }`}
        >
          <div className="flex items-center justify-between mb-2">
            <span className="font-bold text-sm text-white">Standard Analysis</span>
            {scanMode === 'standard' && <CheckCircle2 className="w-4 h-4 text-[#38D6C5]" />}
          </div>
          <p className="text-xs text-[#9AA9BC] leading-relaxed">
            Validation, cryptographic hashing, PE header inspection, YARA signature detection, and 69-feature local ML classification.
          </p>
        </div>

        <div
          onClick={() => !scanning && setScanMode('deep')}
          className={`p-5 rounded-2xl border cursor-pointer transition ${
            scanMode === 'deep'
              ? 'bg-[#111C2E] border-[#668CFF] shadow-lg shadow-[#668CFF]/10'
              : 'bg-[#0C1423] border-[#25354B] opacity-70 hover:opacity-100'
          }`}
        >
          <div className="flex items-center justify-between mb-2">
            <span className="font-bold text-sm text-white">Deep Static Analysis</span>
            {scanMode === 'deep' && <CheckCircle2 className="w-4 h-4 text-[#668CFF]" />}
          </div>
          <p className="text-xs text-[#9AA9BC] leading-relaxed">
            All Standard features + extended string parsing, extensive import function mapping, full obfuscation and packer profiling.
          </p>
        </div>
      </div>

      {/* Upload Box / Drag & Drop Area */}
      {!scanning ? (
        <div
          onDragEnter={handleDrag}
          onDragOver={handleDrag}
          onDragLeave={handleDrag}
          onDrop={handleDrop}
          className={`p-10 border-2 border-dashed rounded-3xl text-center transition-all duration-200 ${
            dragActive
              ? 'border-[#38D6C5] bg-[#38D6C5]/5'
              : 'border-[#25354B] bg-[#111C2E]/50 hover:border-[#38D6C5]/50'
          }`}
        >
          <input
            ref={fileInputRef}
            type="file"
            onChange={handleFileChange}
            className="hidden"
            id="file-upload"
          />

          {!file ? (
            <div className="space-y-4">
              <div className="w-16 h-16 rounded-2xl bg-[#162338] border border-[#25354B] flex items-center justify-center mx-auto text-[#38D6C5]">
                <UploadCloud className="w-8 h-8" />
              </div>

              <div>
                <p className="text-base font-semibold text-white">
                  Drag and drop your suspicious executable or file here
                </p>
                <p className="text-xs text-[#9AA9BC] mt-1">
                  Supports Windows Executables (.exe, .dll, .sys), Binaries, Scripts, Documents up to 50 MB
                </p>
              </div>

              <div className="pt-2">
                <button
                  type="button"
                  onClick={() => fileInputRef.current?.click()}
                  className="px-6 py-2.5 bg-[#162338] hover:bg-[#25354B] text-white border border-[#25354B] font-medium text-xs rounded-xl transition"
                >
                  Browse Files
                </button>
              </div>

              <div className="pt-4 flex items-center justify-center space-x-6 text-[11px] text-[#9AA9BC] font-mono">
                <span className="flex items-center space-x-1.5">
                  <Lock className="w-3.5 h-3.5 text-[#35C98A]" />
                  <span>Zero-Execution Sandbox</span>
                </span>
                <span className="flex items-center space-x-1.5">
                  <Shield className="w-3.5 h-3.5 text-[#38D6C5]" />
                  <span>Privacy-Guaranteed</span>
                </span>
              </div>
            </div>
          ) : (
            <div className="space-y-6">
              <div className="p-4 bg-[#0C1423] border border-[#25354B] rounded-2xl flex items-center justify-between max-w-lg mx-auto text-left">
                <div className="flex items-center space-x-3.5 overflow-hidden">
                  <div className="w-10 h-10 rounded-xl bg-[#38D6C5]/10 border border-[#38D6C5]/30 flex items-center justify-center text-[#38D6C5] shrink-0">
                    <FileCode className="w-5 h-5" />
                  </div>
                  <div className="truncate">
                    <p className="text-sm font-semibold text-white truncate">{file.name}</p>
                    <p className="text-xs text-[#9AA9BC] font-mono">{(file.size / 1024).toFixed(1)} KB &bull; {file.type || 'Binary'}</p>
                  </div>
                </div>

                <button
                  onClick={cancelSelection}
                  className="p-1.5 text-[#9AA9BC] hover:text-[#D94C63] transition"
                  title="Remove File"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              <div className="flex items-center justify-center space-x-4">
                <button
                  type="button"
                  onClick={cancelSelection}
                  className="px-5 py-2.5 bg-[#162338] hover:bg-[#25354B] text-[#9AA9BC] font-medium text-xs rounded-xl transition"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={handleStartScan}
                  className="px-8 py-3 bg-[#38D6C5] hover:bg-[#38D6C5]/90 text-[#080D18] font-bold text-sm rounded-xl transition shadow-lg shadow-[#38D6C5]/20 flex items-center space-x-2"
                >
                  <Activity className="w-4 h-4" />
                  <span>Start Security Analysis</span>
                </button>
              </div>
            </div>
          )}
        </div>
      ) : (
        /* Scanning In-Progress Stage View */
        <div className="p-8 bg-[#111C2E] border border-[#25354B] rounded-3xl space-y-6">
          <div className="text-center space-y-2">
            <div className="w-12 h-12 border-4 border-[#38D6C5] border-t-transparent rounded-full animate-spin mx-auto"></div>
            <h3 className="text-lg font-bold text-white">Analyzing Binary: {file?.name}</h3>
            <p className="text-xs text-[#9AA9BC] font-mono">
              STAGE {Math.min(currentStage + 1, SCAN_STAGES.length)} OF {SCAN_STAGES.length}
            </p>
          </div>

          {/* Progress Bar */}
          <div className="w-full bg-[#0C1423] rounded-full h-2 border border-[#25354B] overflow-hidden">
            <div
              className="bg-gradient-to-r from-[#38D6C5] to-[#668CFF] h-full transition-all duration-500 rounded-full"
              style={{ width: `${Math.max(10, ((currentStage + 1) / SCAN_STAGES.length) * 100)}%` }}
            ></div>
          </div>

          {/* Step-by-Step Breakdown */}
          <div className="space-y-3 pt-4 border-t border-[#25354B] max-w-lg mx-auto">
            {SCAN_STAGES.map((stg, idx) => {
              const isDone = currentStage > idx;
              const isCurrent = currentStage === idx;
              return (
                <div
                  key={stg}
                  className={`flex items-center space-x-3 text-xs transition-opacity duration-200 ${
                    isDone
                      ? 'text-[#35C98A]'
                      : isCurrent
                      ? 'text-white font-semibold'
                      : 'text-[#9AA9BC]/40'
                  }`}
                >
                  {isDone ? (
                    <CheckCircle2 className="w-4 h-4 text-[#35C98A] shrink-0" />
                  ) : isCurrent ? (
                    <div className="w-4 h-4 border-2 border-[#38D6C5] border-t-transparent rounded-full animate-spin shrink-0"></div>
                  ) : (
                    <div className="w-4 h-4 rounded-full border border-[#25354B] shrink-0"></div>
                  )}
                  <span>{stg}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};

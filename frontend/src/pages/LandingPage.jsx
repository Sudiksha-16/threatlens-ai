import React from 'react';
import { Link } from 'react-router-dom';
import { 
  Shield, Terminal, Cpu, FileSearch, Lock, Database, 
  ArrowRight, CheckCircle2, ChevronRight, Activity, Zap, Layers 
} from 'lucide-react';

export const LandingPage = () => {
  return (
    <div className="min-h-screen bg-[#080D18] text-[#F4F7FB] selection:bg-[#38D6C5] selection:text-[#080D18]">
      {/* Top Header Navigation */}
      <nav className="fixed top-0 left-0 right-0 z-50 bg-[#0C1423]/80 backdrop-blur-md border-b border-[#25354B]">
        <div className="max-w-7xl mx-auto px-6 h-20 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-[#38D6C5] to-[#668CFF] flex items-center justify-center shadow-lg shadow-[#38D6C5]/20">
              <Shield className="w-6 h-6 text-[#080D18]" />
            </div>
            <span className="font-bold text-xl tracking-wide text-white">
              Threat<span className="text-[#38D6C5]">Lens</span> <span className="text-xs font-mono px-2 py-0.5 bg-[#111C2E] border border-[#25354B] rounded text-[#668CFF]">AI</span>
            </span>
          </div>

          <div className="hidden md:flex items-center space-x-8 text-sm font-medium text-[#9AA9BC]">
            <a href="#features" className="hover:text-[#38D6C5] transition">Features</a>
            <a href="#workflow" className="hover:text-[#38D6C5] transition">How It Works</a>
            <a href="#technology" className="hover:text-[#38D6C5] transition">Technology</a>
            <a href="#about" className="hover:text-[#38D6C5] transition">About</a>
          </div>

          <div className="flex items-center space-x-4">
            <Link 
              to="/login" 
              className="text-sm font-medium text-[#9AA9BC] hover:text-white transition px-3 py-2"
            >
              Login
            </Link>
            <Link 
              to="/register" 
              className="px-5 py-2.5 bg-[#38D6C5] hover:bg-[#38D6C5]/90 text-[#080D18] font-bold text-sm rounded-lg transition shadow-lg shadow-[#38D6C5]/20 flex items-center space-x-2"
            >
              <span>Get Started</span>
              <ArrowRight className="w-4 h-4" />
            </Link>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="pt-40 pb-24 px-6 relative overflow-hidden">
        {/* Abstract background grid */}
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#25354B15_1px,transparent_1px),linear-gradient(to_bottom,#25354B15_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_0%,#000_70%,transparent_100%)] pointer-events-none"></div>

        <div className="max-w-5xl mx-auto text-center relative z-10">
          <div className="inline-flex items-center space-x-2 px-4 py-1.5 rounded-full bg-[#111C2E] border border-[#25354B] mb-8">
            <span className="w-2 h-2 rounded-full bg-[#38D6C5] animate-ping"></span>
            <span className="text-xs font-mono text-[#38D6C5]">THREATLENS AI PLATFORM v1.0</span>
            <span className="text-xs text-[#9AA9BC]">&bull; SOC-Grade Threat Engine</span>
          </div>

          <h1 className="text-5xl md:text-7xl font-extrabold tracking-tight text-white mb-6 leading-tight">
            See Beyond the Threat. <br />
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-[#38D6C5] via-[#668CFF] to-[#38D6C5]">
              Detect Before It Strikes.
            </span>
          </h1>

          <p className="text-lg md:text-xl text-[#9AA9BC] max-w-3xl mx-auto mb-10 leading-relaxed font-light">
            An intelligent malware classification and threat detection platform powered by machine learning, 
            static file analysis and cybersecurity intelligence.
          </p>

          <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
            <Link 
              to="/register" 
              className="w-full sm:w-auto px-8 py-4 bg-[#38D6C5] hover:bg-[#38D6C5]/90 text-[#080D18] font-bold text-base rounded-xl transition shadow-xl shadow-[#38D6C5]/20 flex items-center justify-center space-x-2"
            >
              <span>Get Started</span>
              <ArrowRight className="w-5 h-5" />
            </Link>
            <a 
              href="#features" 
              className="w-full sm:w-auto px-8 py-4 bg-[#111C2E] hover:bg-[#162338] text-white border border-[#25354B] font-semibold text-base rounded-xl transition flex items-center justify-center space-x-2"
            >
              <span>Explore Features</span>
            </a>
          </div>

          {/* Metrics bar */}
          <div className="mt-16 grid grid-cols-2 md:grid-cols-4 gap-4 max-w-4xl mx-auto">
            <div className="p-4 bg-[#111C2E]/60 border border-[#25354B] rounded-xl text-left">
              <p className="text-2xl md:text-3xl font-extrabold text-[#38D6C5] font-mono">98.94%</p>
              <p className="text-xs text-[#9AA9BC] mt-1 font-medium">Model Accuracy</p>
            </div>
            <div className="p-4 bg-[#111C2E]/60 border border-[#25354B] rounded-xl text-left">
              <p className="text-2xl md:text-3xl font-extrabold text-[#668CFF] font-mono">69 PE</p>
              <p className="text-xs text-[#9AA9BC] mt-1 font-medium">Structural Features</p>
            </div>
            <div className="p-4 bg-[#111C2E]/60 border border-[#25354B] rounded-xl text-left">
              <p className="text-2xl md:text-3xl font-extrabold text-[#35C98A] font-mono">0.012</p>
              <p className="text-xs text-[#9AA9BC] mt-1 font-medium">Ultra-Low False Positives</p>
            </div>
            <div className="p-4 bg-[#111C2E]/60 border border-[#25354B] rounded-xl text-left">
              <p className="text-2xl md:text-3xl font-extrabold text-[#F5B84B] font-mono">0% Exec</p>
              <p className="text-xs text-[#9AA9BC] mt-1 font-medium">Safe Static Analysis</p>
            </div>
          </div>
        </div>
      </section>

      {/* Key Capabilities */}
      <section id="features" className="py-24 px-6 bg-[#0C1423]/40 border-y border-[#25354B]">
        <div className="max-w-7xl mx-auto">
          <div className="text-center max-w-3xl mx-auto mb-16">
            <h2 className="text-xs font-mono uppercase tracking-widest text-[#38D6C5] mb-3">Core Defense Modules</h2>
            <h3 className="text-3xl md:text-4xl font-bold text-white">Engineered for Precision Threat Detection</h3>
            <p className="text-[#9AA9BC] mt-4">Combining local mathematical classification with deep file heuristics without ever executing untrusted code.</p>
          </div>

          <div className="grid md:grid-cols-3 gap-8">
            <div className="p-8 bg-[#111C2E] border border-[#25354B] rounded-2xl hover:border-[#38D6C5]/50 transition duration-300">
              <div className="w-12 h-12 rounded-xl bg-[#38D6C5]/10 border border-[#38D6C5]/30 flex items-center justify-center mb-6 text-[#38D6C5]">
                <Cpu className="w-6 h-6" />
              </div>
              <h4 className="text-xl font-bold text-white mb-3">Local Machine Learning Engine</h4>
              <p className="text-sm text-[#9AA9BC] leading-relaxed">
                Trained locally from scratch on genuine PE malware benchmarks (ClaMP). Evaluates Random Forest, Decision Tree, SVM, and Logistic Regression with 98.94% accuracy. Zero reliance on external AI APIs.
              </p>
            </div>

            <div className="p-8 bg-[#111C2E] border border-[#25354B] rounded-2xl hover:border-[#668CFF]/50 transition duration-300">
              <div className="w-12 h-12 rounded-xl bg-[#668CFF]/10 border border-[#668CFF]/30 flex items-center justify-center mb-6 text-[#668CFF]">
                <FileSearch className="w-6 h-6" />
              </div>
              <h4 className="text-xl font-bold text-white mb-3">Deep Static File Analysis</h4>
              <p className="text-sm text-[#9AA9BC] leading-relaxed">
                Extracts Shannon entropy, PE DOS and File Header characteristics, section attributes, suspicious imported APIs, embedded IP addresses, obfuscated URLs, and packing signatures.
              </p>
            </div>

            <div className="p-8 bg-[#111C2E] border border-[#25354B] rounded-2xl hover:border-[#35C98A]/50 transition duration-300">
              <div className="w-12 h-12 rounded-xl bg-[#35C98A]/10 border border-[#35C98A]/30 flex items-center justify-center mb-6 text-[#35C98A]">
                <Shield className="w-6 h-6" />
              </div>
              <h4 className="text-xl font-bold text-white mb-3">YARA Signature Engine</h4>
              <p className="text-sm text-[#9AA9BC] leading-relaxed">
                Independent compiled signature scanning for Ransomware shadow copy wipers, Trojan downloaders, Reverse Shell backdoors, Infostealers, Worm autorun mechanisms, and packer signatures.
              </p>
            </div>

            <div className="p-8 bg-[#111C2E] border border-[#25354B] rounded-2xl hover:border-[#F5B84B]/50 transition duration-300">
              <div className="w-12 h-12 rounded-xl bg-[#F5B84B]/10 border border-[#F5B84B]/30 flex items-center justify-center mb-6 text-[#F5B84B]">
                <Activity className="w-6 h-6" />
              </div>
              <h4 className="text-xl font-bold text-white mb-3">0-100 Risk Assessment Engine</h4>
              <p className="text-sm text-[#9AA9BC] leading-relaxed">
                Transparent multi-factor risk scoring separating ML confidence from overall danger. Computes Low, Medium, High, and Critical severities with actionable SOC incident response playbooks.
              </p>
            </div>

            <div className="p-8 bg-[#111C2E] border border-[#25354B] rounded-2xl hover:border-[#D94C63]/50 transition duration-300">
              <div className="w-12 h-12 rounded-xl bg-[#D94C63]/10 border border-[#D94C63]/30 flex items-center justify-center mb-6 text-[#D94C63]">
                <Database className="w-6 h-6" />
              </div>
              <h4 className="text-xl font-bold text-white mb-3">VirusTotal Fallback Resilience</h4>
              <p className="text-sm text-[#9AA9BC] leading-relaxed">
                Privacy-first SHA-256 hash lookup. Engaged only when local ML classification encounters an error, ensuring uninterrupted SOC threat triage without exposing raw user binaries.
              </p>
            </div>

            <div className="p-8 bg-[#111C2E] border border-[#25354B] rounded-2xl hover:border-[#38D6C5]/50 transition duration-300">
              <div className="w-12 h-12 rounded-xl bg-[#38D6C5]/10 border border-[#38D6C5]/30 flex items-center justify-center mb-6 text-[#38D6C5]">
                <Layers className="w-6 h-6" />
              </div>
              <h4 className="text-xl font-bold text-white mb-3">SOC Reports &amp; Analytics</h4>
              <p className="text-sm text-[#9AA9BC] leading-relaxed">
                Downloadable PDF forensic reports formatted with enterprise styling, live MongoDB dashboard statistics, threat trends, YARA hit counters, and security alert queues.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* How It Works Workflow */}
      <section id="workflow" className="py-24 px-6">
        <div className="max-w-7xl mx-auto">
          <div className="text-center max-w-3xl mx-auto mb-16">
            <h2 className="text-xs font-mono uppercase tracking-widest text-[#668CFF] mb-3">End-to-End Pipeline</h2>
            <h3 className="text-3xl md:text-4xl font-bold text-white">Detection Lifecycle</h3>
            <p className="text-[#9AA9BC] mt-4">Every file follows this exact validated execution workflow.</p>
          </div>

          <div className="grid md:grid-cols-4 gap-6">
            <div className="p-6 bg-[#0C1423] border border-[#25354B] rounded-xl relative">
              <span className="text-3xl font-extrabold font-mono text-[#38D6C5]/30 absolute top-4 right-4">01</span>
              <h5 className="font-bold text-white text-base mb-2">Ingestion &amp; Hashing</h5>
              <p className="text-xs text-[#9AA9BC]">SHA-256 and MD5 cryptographic hashes calculated. File size and magic bytes validated.</p>
            </div>

            <div className="p-6 bg-[#0C1423] border border-[#25354B] rounded-xl relative">
              <span className="text-3xl font-extrabold font-mono text-[#668CFF]/30 absolute top-4 right-4">02</span>
              <h5 className="font-bold text-white text-base mb-2">Static PE Extraction</h5>
              <p className="text-xs text-[#9AA9BC]">Shannon entropy, section headers, imported APIs, and embedded strings extracted safely.</p>
            </div>

            <div className="p-6 bg-[#0C1423] border border-[#25354B] rounded-xl relative">
              <span className="text-3xl font-extrabold font-mono text-[#35C98A]/30 absolute top-4 right-4">03</span>
              <h5 className="font-bold text-white text-base mb-2">Dual Classification</h5>
              <p className="text-xs text-[#9AA9BC]">YARA signature engine + 69-feature Local Random Forest ML predict Benign vs Malicious.</p>
            </div>

            <div className="p-6 bg-[#0C1423] border border-[#25354B] rounded-xl relative">
              <span className="text-3xl font-extrabold font-mono text-[#F5B84B]/30 absolute top-4 right-4">04</span>
              <h5 className="font-bold text-white text-base mb-2">Risk &amp; Reporting</h5>
              <p className="text-xs text-[#9AA9BC]">0-100 risk score generated with reasons. PDF forensic audit report rendered immediately.</p>
            </div>
          </div>
        </div>
      </section>

      {/* Machine Learning Tech Section */}
      <section id="technology" className="py-24 px-6 bg-[#0C1423]/60 border-t border-[#25354B]">
        <div className="max-w-7xl mx-auto">
          <div className="grid md:grid-cols-2 gap-12 items-center">
            <div>
              <h2 className="text-xs font-mono uppercase tracking-widest text-[#38D6C5] mb-3">Model Benchmark</h2>
              <h3 className="text-3xl md:text-4xl font-bold text-white mb-6">4 Locally Trained Classifiers Compared</h3>
              <p className="text-[#9AA9BC] text-sm leading-relaxed mb-6">
                ThreatLens AI trains four candidate models on real, public PE datasets with stratified 80/20 train/test splits. 
                The active model is chosen strictly based on real mathematical validation:
              </p>
              
              <div className="space-y-4">
                <div className="p-4 bg-[#111C2E] border border-[#38D6C5]/30 rounded-xl flex items-center justify-between">
                  <div>
                    <p className="text-sm font-bold text-white">Random Forest (Active Model)</p>
                    <p className="text-xs text-[#9AA9BC]">100 estimators, depth 20</p>
                  </div>
                  <div className="text-right">
                    <span className="text-lg font-mono font-bold text-[#38D6C5]">98.94%</span>
                    <p className="text-[10px] text-[#35C98A]">F1: 0.9899 | AUC: 0.9992</p>
                  </div>
                </div>

                <div className="p-4 bg-[#111C2E] border border-[#25354B] rounded-xl flex items-center justify-between">
                  <div>
                    <p className="text-sm font-bold text-white">Decision Tree Classifier</p>
                    <p className="text-xs text-[#9AA9BC]">Interpretable classification</p>
                  </div>
                  <div className="text-right">
                    <span className="text-lg font-mono font-bold text-[#668CFF]">96.93%</span>
                    <p className="text-[10px] text-[#9AA9BC]">F1: 0.9707</p>
                  </div>
                </div>

                <div className="p-4 bg-[#111C2E] border border-[#25354B] rounded-xl flex items-center justify-between">
                  <div>
                    <p className="text-sm font-bold text-white">Support Vector Machine (SVM)</p>
                    <p className="text-xs text-[#9AA9BC]">RBF Kernel with probability</p>
                  </div>
                  <div className="text-right">
                    <span className="text-lg font-mono font-bold text-[#F5B84B]">96.26%</span>
                    <p className="text-[10px] text-[#9AA9BC]">F1: 0.9644</p>
                  </div>
                </div>

                <div className="p-4 bg-[#111C2E] border border-[#25354B] rounded-xl flex items-center justify-between">
                  <div>
                    <p className="text-sm font-bold text-white">Logistic Regression (Baseline)</p>
                    <p className="text-xs text-[#9AA9BC]">Linear classification baseline</p>
                  </div>
                  <div className="text-right">
                    <span className="text-lg font-mono font-bold text-[#9AA9BC]">96.16%</span>
                    <p className="text-[10px] text-[#9AA9BC]">F1: 0.9631</p>
                  </div>
                </div>
              </div>
            </div>

            {/* Visual Code / Architecture Card */}
            <div className="bg-[#111C2E] border border-[#25354B] rounded-2xl p-6 font-mono text-xs">
              <div className="flex items-center space-x-2 pb-4 border-b border-[#25354B] text-[#9AA9BC]">
                <div className="w-3 h-3 rounded-full bg-[#D94C63]"></div>
                <div className="w-3 h-3 rounded-full bg-[#F5B84B]"></div>
                <div className="w-3 h-3 rounded-full bg-[#35C98A]"></div>
                <span className="ml-2 text-white">threatlens_pipeline.py</span>
              </div>
              <div className="pt-4 space-y-2 text-[#9AA9BC]">
                <p><span className="text-[#668CFF]">from</span> backend.app.services <span className="text-[#668CFF]">import</span> ml_engine, yara_engine, risk_engine</p>
                <p className="text-[#64748B]"># Extract 69 PE header and structural features</p>
                <p>features = feature_engineer.extract_vector(file_path)</p>
                <p className="text-[#64748B]"># Run local Random Forest binary prediction</p>
                <p>ml_res = ml_engine.predict(features)</p>
                <p className="text-[#38D6C5]">&gt;&gt;&gt; classification: 'Malicious' (Confidence: 98.4%)</p>
                <p className="text-[#38D6C5]">&gt;&gt;&gt; malware_family: 'Ransomware'</p>
                <p className="text-[#64748B]"># Run YARA Signature detection</p>
                <p>yara_res = yara_engine.scan_file(file_path)</p>
                <p className="text-[#F5B84B]">&gt;&gt;&gt; match: 'Ransomware_Vssadmin_ShadowCopy' [Critical]</p>
                <p className="text-[#64748B]"># Calculate multi-factor risk score</p>
                <p>risk = risk_engine.calculate_risk(static, yara_res, ml_res)</p>
                <p className="text-[#D94C63] font-bold">&gt;&gt;&gt; risk_score: 95/100 | level: 'Critical'</p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Security & Privacy */}
      <section id="about" className="py-24 px-6">
        <div className="max-w-4xl mx-auto text-center">
          <div className="w-16 h-16 rounded-2xl bg-[#38D6C5]/10 border border-[#38D6C5]/30 flex items-center justify-center mx-auto mb-6 text-[#38D6C5]">
            <Lock className="w-8 h-8" />
          </div>
          <h3 className="text-3xl font-bold text-white mb-4">Zero-Execution &bull; Privacy First</h3>
          <p className="text-[#9AA9BC] leading-relaxed mb-8">
            ThreatLens AI guarantees your uploaded binaries are never executed in memory or dynamic environments. 
            All feature extraction is performed through pure static binary parsing. 
            Third-party threat intelligence (VirusTotal) operates strictly via cryptographic hash lookups, ensuring proprietary binaries remain completely confidential.
          </p>
          <Link 
            to="/register" 
            className="inline-flex items-center space-x-2 px-8 py-3.5 bg-[#38D6C5] hover:bg-[#38D6C5]/90 text-[#080D18] font-bold text-sm rounded-xl transition shadow-lg shadow-[#38D6C5]/20"
          >
            <span>Deploy ThreatLens AI Now</span>
            <ArrowRight className="w-4 h-4" />
          </Link>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-[#25354B] bg-[#0C1423] py-12 px-6">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-6 text-xs text-[#9AA9BC]">
          <div className="flex items-center space-x-3">
            <div className="w-7 h-7 rounded-lg bg-gradient-to-tr from-[#38D6C5] to-[#668CFF] flex items-center justify-center text-[#080D18]">
              <Shield className="w-4 h-4" />
            </div>
            <span className="font-bold text-sm text-white">ThreatLens AI</span>
            <span>&bull; Security Operations Center</span>
          </div>

          <p>&copy; {new Date().getFullYear()} ThreatLens AI. All rights reserved. Enterprise Malware Classification System.</p>

          <div className="flex space-x-6">
            <Link to="/login" className="hover:text-white transition">Analyst Login</Link>
            <Link to="/register" className="hover:text-white transition">Register Account</Link>
          </div>
        </div>
      </footer>
    </div>
  );
};

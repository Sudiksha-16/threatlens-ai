import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Shield, Lock, Mail, AlertCircle, ArrowRight } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export const LoginPage = () => {
  const { login } = useAuth();
  const navigate = useNavigate();

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [rememberMe, setRememberMe] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      await login(email, password, rememberMe);
      navigate('/dashboard');
    } catch (err) {
      const msg = err.response?.data?.detail || 'Invalid email or password';
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#080D18] flex items-center justify-center p-6 relative">
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#25354B15_1px,transparent_1px),linear-gradient(to_bottom,#25354B15_1px,transparent_1px)] bg-[size:3rem_3rem] pointer-events-none"></div>

      <div className="w-full max-w-md bg-[#0C1423] border border-[#25354B] rounded-2xl p-8 relative z-10 shadow-2xl shadow-black/60">
        <div className="text-center mb-8">
          <Link to="/" className="inline-flex items-center space-x-3 mb-4">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-[#38D6C5] to-[#668CFF] flex items-center justify-center shadow-lg shadow-[#38D6C5]/20">
              <Shield className="w-6 h-6 text-[#080D18]" />
            </div>
            <span className="font-bold text-xl text-white">Threat<span className="text-[#38D6C5]">Lens</span> AI</span>
          </Link>
          <h2 className="text-2xl font-bold text-white">Analyst Authentication</h2>
          <p className="text-xs text-[#9AA9BC] mt-2">Sign in to access the malware threat detection console</p>
        </div>

        {error && (
          <div className="mb-6 p-3.5 bg-[#D94C63]/10 border border-[#D94C63]/40 rounded-xl flex items-center space-x-3 text-xs text-[#F16B75]">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-[#9AA9BC] mb-1.5">Email Address</label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-[#9AA9BC]">
                <Mail className="w-4 h-4" />
              </div>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="analyst@soc.enterprise.io"
                className="w-full pl-10 pr-4 py-2.5 bg-[#111C2E] border border-[#25354B] rounded-xl text-sm text-white placeholder-[#9AA9BC]/50 focus:outline-none focus:border-[#38D6C5] transition"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-[#9AA9BC] mb-1.5">Password</label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-[#9AA9BC]">
                <Lock className="w-4 h-4" />
              </div>
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                className="w-full pl-10 pr-4 py-2.5 bg-[#111C2E] border border-[#25354B] rounded-xl text-sm text-white placeholder-[#9AA9BC]/50 focus:outline-none focus:border-[#38D6C5] transition"
              />
            </div>
          </div>

          <div className="flex items-center justify-between text-xs pt-1">
            <label className="flex items-center space-x-2 text-[#9AA9BC] cursor-pointer">
              <input
                type="checkbox"
                checked={rememberMe}
                onChange={(e) => setRememberMe(e.target.checked)}
                className="rounded bg-[#111C2E] border-[#25354B] text-[#38D6C5] focus:ring-0"
              />
              <span>Remember me</span>
            </label>
            <span className="text-[#9AA9BC] text-[11px] cursor-not-allowed" title="Contact your SOC Administrator for password reset">
              Forgot password?
            </span>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-3 bg-[#38D6C5] hover:bg-[#38D6C5]/90 text-[#080D18] font-bold text-sm rounded-xl transition shadow-lg shadow-[#38D6C5]/20 flex items-center justify-center space-x-2 disabled:opacity-50 mt-4"
          >
            {loading ? (
              <div className="w-5 h-5 border-2 border-[#080D18] border-t-transparent rounded-full animate-spin"></div>
            ) : (
              <>
                <span>Sign In to ThreatLens</span>
                <ArrowRight className="w-4 h-4" />
              </>
            )}
          </button>
        </form>

        <p className="text-center text-xs text-[#9AA9BC] mt-6">
          New analyst?{' '}
          <Link to="/register" className="text-[#38D6C5] font-semibold hover:underline">
            Register Account
          </Link>
        </p>
      </div>
    </div>
  );
};

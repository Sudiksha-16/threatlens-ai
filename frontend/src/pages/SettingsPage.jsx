import React, { useState } from 'react';
import { User, Lock, Bell, Clock, Shield, CheckCircle2, AlertCircle } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { authAPI } from '../services/api';

export const SettingsPage = () => {
  const { user, refreshUser, logout } = useAuth();

  const [fullName, setFullName] = useState(user?.full_name || '');
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [alertsEnabled, setAlertsEnabled] = useState(user?.notification_preferences?.alerts ?? true);
  const [reportsEnabled, setReportsEnabled] = useState(user?.notification_preferences?.reports ?? true);
  const [retentionDays, setRetentionDays] = useState(user?.scan_retention_days || 90);

  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSaveProfile = async (e) => {
    e.preventDefault();
    setMessage('');
    setError('');
    setLoading(true);

    try {
      await authAPI.updateSettings({
        full_name: fullName,
        notification_alerts: alertsEnabled,
        notification_reports: reportsEnabled,
        scan_retention_days: Number(retentionDays),
      });
      setMessage('Profile settings updated successfully.');
      await refreshUser();
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to update settings');
    } finally {
      setLoading(false);
    }
  };

  const handleChangePassword = async (e) => {
    e.preventDefault();
    setMessage('');
    setError('');

    if (newPassword !== confirmPassword) {
      setError('New passwords do not match');
      return;
    }

    if (newPassword.length < 8) {
      setError('New password must be at least 8 characters long');
      return;
    }

    setLoading(true);
    try {
      await authAPI.updateSettings({
        current_password: currentPassword,
        new_password: newPassword,
      });
      setMessage('Password changed successfully.');
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to change password');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-8">
      <div className="pb-2 border-b border-[#25354B]">
        <h1 className="text-2xl font-bold text-white tracking-tight">Analyst Settings &amp; Configuration</h1>
        <p className="text-xs text-[#9AA9BC] mt-1 font-mono">
          PROFILE &bull; NOTIFICATION PREFERENCES &bull; CREDENTIAL RETENTION
        </p>
      </div>

      {message && (
        <div className="p-4 bg-[#35C98A]/10 border border-[#35C98A]/40 rounded-xl flex items-center space-x-3 text-xs text-[#35C98A]">
          <CheckCircle2 className="w-4 h-4 shrink-0" />
          <span>{message}</span>
        </div>
      )}

      {error && (
        <div className="p-4 bg-[#D94C63]/10 border border-[#D94C63]/40 rounded-xl flex items-center space-x-3 text-xs text-[#F16B75]">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      <div className="grid md:grid-cols-2 gap-6">
        {/* Profile & Notification Form */}
        <form onSubmit={handleSaveProfile} className="p-6 bg-[#111C2E] border border-[#25354B] rounded-2xl space-y-4">
          <h3 className="text-base font-bold text-white flex items-center space-x-2">
            <User className="w-4 h-4 text-[#38D6C5]" />
            <span>Profile Information</span>
          </h3>

          <div>
            <label className="block text-xs font-medium text-[#9AA9BC] mb-1.5">Full Name</label>
            <input
              type="text"
              value={fullName}
              onChange={(e) => setFullName(e.target.value)}
              className="w-full px-3.5 py-2.5 bg-[#0C1423] border border-[#25354B] rounded-xl text-sm text-white focus:outline-none focus:border-[#38D6C5]"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-[#9AA9BC] mb-1.5">Email Address</label>
            <input
              type="email"
              disabled
              value={user?.email || ''}
              className="w-full px-3.5 py-2.5 bg-[#0C1423]/50 border border-[#25354B] rounded-xl text-sm text-[#9AA9BC] cursor-not-allowed"
            />
          </div>

          <div className="pt-2">
            <label className="block text-xs font-medium text-[#9AA9BC] mb-2">Notification Preferences</label>
            <div className="space-y-2">
              <label className="flex items-center space-x-2 text-xs text-white cursor-pointer">
                <input
                  type="checkbox"
                  checked={alertsEnabled}
                  onChange={(e) => setAlertsEnabled(e.target.checked)}
                  className="rounded bg-[#0C1423] border-[#25354B] text-[#38D6C5] focus:ring-0"
                />
                <span>Critical Threat In-App Alerts</span>
              </label>
              <label className="flex items-center space-x-2 text-xs text-white cursor-pointer">
                <input
                  type="checkbox"
                  checked={reportsEnabled}
                  onChange={(e) => setReportsEnabled(e.target.checked)}
                  className="rounded bg-[#0C1423] border-[#25354B] text-[#38D6C5] focus:ring-0"
                />
                <span>Automatic PDF Audit Log Generation</span>
              </label>
            </div>
          </div>

          <div className="pt-2">
            <label className="block text-xs font-medium text-[#9AA9BC] mb-1.5">Telemetry Retention (Days)</label>
            <input
              type="number"
              min="7"
              max="365"
              value={retentionDays}
              onChange={(e) => setRetentionDays(e.target.value)}
              className="w-full px-3.5 py-2.5 bg-[#0C1423] border border-[#25354B] rounded-xl text-sm text-white focus:outline-none focus:border-[#38D6C5]"
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-2.5 bg-[#38D6C5] hover:bg-[#38D6C5]/90 text-[#080D18] font-bold text-xs rounded-xl transition shadow-md shadow-[#38D6C5]/20 mt-4"
          >
            Save Profile Settings
          </button>
        </form>

        {/* Change Password Form */}
        <form onSubmit={handleChangePassword} className="p-6 bg-[#111C2E] border border-[#25354B] rounded-2xl space-y-4">
          <h3 className="text-base font-bold text-white flex items-center space-x-2">
            <Lock className="w-4 h-4 text-[#668CFF]" />
            <span>Update Password</span>
          </h3>

          <div>
            <label className="block text-xs font-medium text-[#9AA9BC] mb-1.5">Current Password</label>
            <input
              type="password"
              required
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              placeholder="••••••••"
              className="w-full px-3.5 py-2.5 bg-[#0C1423] border border-[#25354B] rounded-xl text-sm text-white focus:outline-none focus:border-[#668CFF]"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-[#9AA9BC] mb-1.5">New Password</label>
            <input
              type="password"
              required
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              placeholder="Min. 8 chars, 1 digit, 1 letter"
              className="w-full px-3.5 py-2.5 bg-[#0C1423] border border-[#25354B] rounded-xl text-sm text-white focus:outline-none focus:border-[#668CFF]"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-[#9AA9BC] mb-1.5">Confirm New Password</label>
            <input
              type="password"
              required
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              placeholder="••••••••"
              className="w-full px-3.5 py-2.5 bg-[#0C1423] border border-[#25354B] rounded-xl text-sm text-white focus:outline-none focus:border-[#668CFF]"
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-2.5 bg-[#668CFF] hover:bg-[#668CFF]/90 text-white font-bold text-xs rounded-xl transition shadow-md shadow-[#668CFF]/20 mt-4"
          >
            Change Password
          </button>
        </form>
      </div>

      {/* Security & System Info Card */}
      <div className="p-6 bg-[#0C1423] border border-[#25354B] rounded-2xl flex items-center justify-between text-xs text-[#9AA9BC]">
        <div className="space-y-1">
          <p className="font-semibold text-white">ThreatLens AI Security Node</p>
          <p>Database: MongoDB Replica &bull; JWT HMAC-SHA256 Auth &bull; Zero Cloud Execution</p>
        </div>
        <button
          onClick={logout}
          className="px-4 py-2 bg-[#D94C63]/20 hover:bg-[#D94C63]/30 text-[#F16B75] border border-[#D94C63]/40 rounded-xl text-xs font-semibold transition"
        >
          Sign Out of Session
        </button>
      </div>
    </div>
  );
};

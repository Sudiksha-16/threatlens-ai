import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { 
  Bell, ShieldAlert, CheckCircle, Check, 
  ExternalLink, Filter, RefreshCw, AlertTriangle 
} from 'lucide-react';
import { alertsAPI } from '../services/api';

export const AlertsPage = () => {
  const [alerts, setAlerts] = useState([]);
  const [total, setTotal] = useState(0);
  const [unreadCount, setUnreadCount] = useState(0);
  const [statusFilter, setStatusFilter] = useState('ALL'); // 'ALL', 'UNREAD', 'RESOLVED'
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [loading, setLoading] = useState(true);

  const fetchAlerts = async () => {
    try {
      const params = { limit: 50 };
      if (statusFilter === 'UNREAD') params.read_status = false;
      if (severityFilter !== 'ALL') params.severity = severityFilter;

      const res = await alertsAPI.getAlerts(params);
      setAlerts(res.data.alerts || []);
      setTotal(res.data.total || 0);
      setUnreadCount(res.data.unread_count || 0);
    } catch (err) {
      console.error('Failed to load alerts:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    setLoading(true);
    fetchAlerts();
  }, [statusFilter, severityFilter]);

  const handleMarkRead = async (alertId) => {
    try {
      await alertsAPI.markRead(alertId);
      setAlerts((prev) =>
        prev.map((a) => (a.alert_id === alertId ? { ...a, read_status: true } : a))
      );
      setUnreadCount((c) => Math.max(0, c - 1));
    } catch (e) {
      console.error(e);
    }
  };

  const handleResolve = async (alertId) => {
    try {
      await alertsAPI.resolve(alertId);
      setAlerts((prev) =>
        prev.map((a) =>
          a.alert_id === alertId ? { ...a, resolution_status: true, read_status: true } : a
        )
      );
      setUnreadCount((c) => Math.max(0, c - 1));
    } catch (e) {
      console.error(e);
    }
  };

  const handleMarkAllRead = async () => {
    try {
      await alertsAPI.markAllRead();
      setAlerts((prev) => prev.map((a) => ({ ...a, read_status: true })));
      setUnreadCount(0);
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Title & Bulk Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-[#25354B]">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center space-x-3">
            <span>Threat Detection Alerts</span>
            {unreadCount > 0 && (
              <span className="px-2 py-0.5 text-xs font-bold bg-[#D94C63] text-white rounded-full">
                {unreadCount} Unread
              </span>
            )}
          </h1>
          <p className="text-xs text-[#9AA9BC] mt-1 font-mono">
            INCIDENT NOTIFICATION FEED &bull; REAL-TIME HEURISTIC ANOMALIES
          </p>
        </div>

        {unreadCount > 0 && (
          <button
            onClick={handleMarkAllRead}
            className="px-3 py-1.5 bg-[#162338] hover:bg-[#25354B] text-xs font-semibold text-[#38D6C5] rounded-xl transition border border-[#25354B]"
          >
            Mark All as Read
          </button>
        )}
      </div>

      {/* Filter Bar */}
      <div className="p-4 bg-[#111C2E] border border-[#25354B] rounded-2xl flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center space-x-2 text-xs">
          <span className="text-[#9AA9BC]">Status:</span>
          {['ALL', 'UNREAD'].map((s) => (
            <button
              key={s}
              onClick={() => setStatusFilter(s)}
              className={`px-3 py-1 rounded-lg font-medium transition ${
                statusFilter === s
                  ? 'bg-[#38D6C5] text-[#080D18] font-bold'
                  : 'bg-[#0C1423] text-[#9AA9BC] hover:text-white'
              }`}
            >
              {s}
            </button>
          ))}
        </div>

        <div className="flex items-center space-x-2 text-xs">
          <span className="text-[#9AA9BC]">Severity:</span>
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-[#0C1423] border border-[#25354B] text-white rounded-xl px-3 py-1.5 text-xs focus:outline-none focus:border-[#38D6C5]"
          >
            <option value="ALL">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>
        </div>
      </div>

      {/* Alerts List */}
      {loading ? (
        <div className="p-12 text-center bg-[#111C2E] border border-[#25354B] rounded-2xl">
          <div className="w-8 h-8 border-4 border-[#38D6C5] border-t-transparent rounded-full animate-spin mx-auto mb-2"></div>
          <p className="text-xs text-[#9AA9BC] font-mono">LOADING ALERT QUEUE...</p>
        </div>
      ) : alerts.length === 0 ? (
        <div className="p-12 text-center bg-[#111C2E] border border-[#25354B] rounded-2xl text-[#9AA9BC] space-y-3">
          <CheckCircle className="w-12 h-12 text-[#35C98A] mx-auto" />
          <h3 className="text-base font-bold text-white">No Active Threat Alerts</h3>
          <p className="text-xs">All high and critical anomalies have been resolved or queue is clear.</p>
        </div>
      ) : (
        <div className="space-y-3">
          {alerts.map((alert) => {
            const isCrit = alert.severity === 'Critical';
            const isHigh = alert.severity === 'High';
            return (
              <div
                key={alert.alert_id}
                className={`p-5 rounded-2xl border transition ${
                  !alert.read_status
                    ? 'bg-[#111C2E] border-[#38D6C5]/50 shadow-md shadow-[#38D6C5]/5'
                    : 'bg-[#0C1423] border-[#25354B] opacity-80'
                }`}
              >
                <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
                  <div className="space-y-1.5">
                    <div className="flex items-center space-x-2.5">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                          isCrit
                            ? 'bg-[#D94C63]/20 text-[#D94C63] border border-[#D94C63]/40'
                            : isHigh
                            ? 'bg-[#F16B75]/20 text-[#F16B75] border border-[#F16B75]/40'
                            : 'bg-[#F5B84B]/20 text-[#F5B84B] border border-[#F5B84B]/40'
                        }`}
                      >
                        {alert.severity}
                      </span>
                      <h4 className="text-sm font-bold text-white">{alert.title}</h4>
                      {!alert.read_status && (
                        <span className="w-2 h-2 rounded-full bg-[#38D6C5]"></span>
                      )}
                    </div>

                    <p className="text-xs text-[#9AA9BC] leading-relaxed max-w-2xl">{alert.description}</p>

                    <div className="flex items-center space-x-4 text-[11px] font-mono text-[#9AA9BC] pt-1">
                      <span>FILE: {alert.file_name}</span>
                      <span>&bull;</span>
                      <span>TIME: {new Date(alert.created_at).toLocaleString()}</span>
                      {alert.resolution_status && (
                        <>
                          <span>&bull;</span>
                          <span className="text-[#35C98A] font-semibold flex items-center space-x-1">
                            <Check className="w-3 h-3" />
                            <span>RESOLVED</span>
                          </span>
                        </>
                      )}
                    </div>
                  </div>

                  {/* Action Buttons */}
                  <div className="flex items-center space-x-2 shrink-0 pt-2 sm:pt-0">
                    <Link
                      to={`/scan/results/${alert.scan_id}`}
                      className="px-3 py-1.5 bg-[#162338] hover:bg-[#25354B] text-[#38D6C5] rounded-xl text-xs font-semibold flex items-center space-x-1 transition border border-[#25354B]"
                    >
                      <span>Investigate</span>
                      <ExternalLink className="w-3 h-3" />
                    </Link>

                    {!alert.read_status && (
                      <button
                        onClick={() => handleMarkRead(alert.alert_id)}
                        className="px-3 py-1.5 bg-[#162338] hover:bg-[#25354B] text-[#9AA9BC] hover:text-white rounded-xl text-xs font-medium transition"
                      >
                        Mark Read
                      </button>
                    )}

                    {!alert.resolution_status && (
                      <button
                        onClick={() => handleResolve(alert.alert_id)}
                        className="px-3 py-1.5 bg-[#35C98A]/20 hover:bg-[#35C98A]/30 text-[#35C98A] rounded-xl text-xs font-semibold transition border border-[#35C98A]/40"
                      >
                        Resolve
                      </button>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

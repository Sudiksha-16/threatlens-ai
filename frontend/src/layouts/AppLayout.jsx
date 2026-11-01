import React, { useState, useEffect } from 'react';
import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import { 
  Shield, LayoutDashboard, UploadCloud, History, 
  Binary, BarChart3, Bell, FileText, Cpu, Settings, 
  LogOut, ShieldAlert, CheckCircle2, ChevronRight, Menu, X
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { alertsAPI } from '../services/api';

export const AppLayout = () => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [unreadAlerts, setUnreadAlerts] = useState(0);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  useEffect(() => {
    const fetchUnread = async () => {
      try {
        const res = await alertsAPI.getAlerts({ read_status: false, limit: 1 });
        setUnreadAlerts(res.data.unread_count || 0);
      } catch (e) {
        // quiet error
      }
    };
    fetchUnread();
    const interval = setInterval(fetchUnread, 30000); // 30s poll
    return () => clearInterval(interval);
  }, []);

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  const navItems = [
    { name: 'Overview', path: '/dashboard', icon: LayoutDashboard },
    { name: 'Scan File', path: '/scan', icon: UploadCloud },
    { name: 'Scan History', path: '/history', icon: History },
    { name: 'Threat Intelligence', path: '/threat-intel', icon: Binary },
    { name: 'Malware Analytics', path: '/analytics', icon: BarChart3 },
    { name: 'Alerts', path: '/alerts', icon: Bell, badge: unreadAlerts },
    { name: 'Reports', path: '/reports', icon: FileText },
    { name: 'Model Performance', path: '/model-performance', icon: Cpu },
    { name: 'Settings', path: '/settings', icon: Settings },
  ];

  return (
    <div className="flex h-screen bg-[#080D18] text-[#F4F7FB] overflow-hidden font-sans">
      {/* Sidebar Desktop */}
      <aside className="hidden md:flex flex-col w-64 bg-[#0C1423] border-r border-[#25354B] select-none">
        {/* Brand Header */}
        <div className="flex items-center space-x-3 px-6 h-16 border-b border-[#25354B]">
          <div className="w-9 h-9 rounded-lg bg-gradient-to-tr from-[#38D6C5] to-[#668CFF] flex items-center justify-center shadow-lg shadow-[#38D6C5]/20">
            <Shield className="w-5 h-5 text-[#080D18]" />
          </div>
          <div>
            <span className="font-bold text-lg tracking-wide text-white">Threat<span className="text-[#38D6C5]">Lens</span></span>
            <span className="ml-1.5 px-1.5 py-0.5 text-[10px] font-mono uppercase bg-[#111C2E] text-[#668CFF] border border-[#25354B] rounded">AI SOC</span>
          </div>
        </div>

        {/* Engine Status Pill */}
        <div className="px-4 py-3 mx-3 my-3 bg-[#111C2E] border border-[#25354B] rounded-lg flex items-center justify-between text-xs font-mono">
          <div className="flex items-center space-x-2">
            <span className="w-2 h-2 rounded-full bg-[#35C98A] animate-pulse"></span>
            <span className="text-[#9AA9BC]">ML Core:</span>
          </div>
          <span className="text-[#38D6C5] font-semibold">Random Forest (98.9%)</span>
        </div>

        {/* Nav Links */}
        <nav className="flex-1 px-3 py-2 space-y-1 overflow-y-auto">
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.path}
                to={item.path}
                className={({ isActive }) =>
                  `flex items-center justify-between px-3.5 py-2.5 rounded-lg text-sm font-medium transition-all duration-150 ${
                    isActive
                      ? 'bg-[#111C2E] text-[#38D6C5] border border-[#25354B] shadow-sm'
                      : 'text-[#9AA9BC] hover:text-[#F4F7FB] hover:bg-[#111C2E]/60'
                  }`
                }
              >
                <div className="flex items-center space-x-3">
                  <Icon className="w-4 h-4" />
                  <span>{item.name}</span>
                </div>
                {item.badge > 0 && (
                  <span className="px-1.5 py-0.5 text-[10px] font-bold bg-[#D94C63] text-white rounded-full">
                    {item.badge}
                  </span>
                )}
              </NavLink>
            );
          })}
        </nav>

        {/* User Info & Logout */}
        <div className="p-3 border-t border-[#25354B] bg-[#0C1423]">
          <div className="flex items-center justify-between p-2 rounded-lg bg-[#111C2E] border border-[#25354B]">
            <div className="flex items-center space-x-2.5 overflow-hidden">
              <div className="w-8 h-8 rounded-full bg-[#162338] border border-[#38D6C5]/30 flex items-center justify-center font-bold text-xs text-[#38D6C5]">
                {user?.full_name ? user.full_name.charAt(0).toUpperCase() : 'U'}
              </div>
              <div className="truncate">
                <p className="text-xs font-medium text-[#F4F7FB] truncate">{user?.full_name || 'SOC Analyst'}</p>
                <p className="text-[10px] text-[#9AA9BC] truncate">{user?.email}</p>
              </div>
            </div>
            <button
              onClick={handleLogout}
              title="Sign Out"
              className="p-1.5 text-[#9AA9BC] hover:text-[#F16B75] hover:bg-[#162338] rounded-md transition"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Top Navbar */}
        <header className="h-16 bg-[#0C1423]/90 backdrop-blur-md border-b border-[#25354B] px-6 flex items-center justify-between z-10">
          <div className="flex items-center space-x-3">
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="md:hidden p-2 text-[#9AA9BC] hover:text-white"
            >
              {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
            <div className="flex items-center space-x-2 text-xs font-mono text-[#9AA9BC]">
              <span className="text-[#38D6C5] font-semibold">SOC ACTIVE MONITOR</span>
              <span>/</span>
              <span>INTEGRITY SECURE</span>
            </div>
          </div>

          <div className="flex items-center space-x-4">
            <div className="hidden sm:flex items-center space-x-2 px-3 py-1 bg-[#111C2E] border border-[#25354B] rounded-full text-xs">
              <span className="w-2 h-2 rounded-full bg-[#35C98A]"></span>
              <span className="text-[#9AA9BC]">YARA Engine:</span>
              <span className="text-white font-medium">9 Signatures Active</span>
            </div>

            <NavLink
              to="/alerts"
              className="relative p-2 text-[#9AA9BC] hover:text-[#F4F7FB] hover:bg-[#111C2E] rounded-lg transition"
            >
              <Bell className="w-5 h-5" />
              {unreadAlerts > 0 && (
                <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-[#D94C63] rounded-full ring-2 ring-[#0C1423]"></span>
              )}
            </NavLink>

            <NavLink
              to="/scan"
              className="hidden sm:flex items-center space-x-2 px-3 py-1.5 bg-[#38D6C5] hover:bg-[#38D6C5]/90 text-[#080D18] font-semibold text-xs rounded-lg transition shadow-md shadow-[#38D6C5]/20"
            >
              <UploadCloud className="w-4 h-4" />
              <span>Quick Scan</span>
            </NavLink>
          </div>
        </header>

        {/* Mobile Dropdown Menu */}
        {mobileMenuOpen && (
          <div className="md:hidden bg-[#0C1423] border-b border-[#25354B] p-4 space-y-2">
            {navItems.map((item) => (
              <NavLink
                key={item.path}
                to={item.path}
                onClick={() => setMobileMenuOpen(false)}
                className="flex items-center justify-between px-3 py-2 rounded-lg text-sm text-[#9AA9BC] hover:bg-[#111C2E] hover:text-white"
              >
                <div className="flex items-center space-x-3">
                  <item.icon className="w-4 h-4" />
                  <span>{item.name}</span>
                </div>
                {item.badge > 0 && (
                  <span className="px-1.5 py-0.5 text-[10px] bg-[#D94C63] text-white rounded-full">
                    {item.badge}
                  </span>
                )}
              </NavLink>
            ))}
            <button
              onClick={handleLogout}
              className="w-full flex items-center space-x-3 px-3 py-2 text-sm text-[#F16B75] hover:bg-[#111C2E] rounded-lg"
            >
              <LogOut className="w-4 h-4" />
              <span>Sign Out</span>
            </button>
          </div>
        )}

        {/* Page Body Viewport */}
        <main className="flex-1 overflow-y-auto p-6 bg-[#080D18]">
          <Outlet />
        </main>
      </div>
    </div>
  );
};

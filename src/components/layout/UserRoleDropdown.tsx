import React, { useState, useEffect, useRef } from 'react';
import { User, Shield, ShieldCheck, Lock, LogOut, ChevronDown, Key, Check, AlertCircle, Eye } from 'lucide-react';
import { apiClient } from '../../services/apiClient';
import { UserAccount, UserRole } from '../../types/auth';

interface UserRoleDropdownProps {
  onSessionChange?: (user: UserAccount | null) => void;
}

export const UserRoleDropdown: React.FC<UserRoleDropdownProps> = ({ onSessionChange }) => {
  const [isOpen, setIsOpen] = useState(false);
  const [currentUser, setCurrentUser] = useState<UserAccount | null>(apiClient.getCurrentUser());
  const [isSwitching, setIsSwitching] = useState(false);
  const [customLoginMode, setCustomLoginMode] = useState(false);
  const [usernameInput, setUsernameInput] = useState('');
  const [passwordInput, setPasswordInput] = useState('');
  const [loginError, setLoginError] = useState<string | null>(null);
  const dropdownRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const unsub = apiClient.subscribeAuth((user) => {
      setCurrentUser(user);
      if (onSessionChange) onSessionChange(user);
    });
    return () => unsub();
  }, [onSessionChange]);

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setIsOpen(false);
        setCustomLoginMode(false);
        setLoginError(null);
      }
    };
    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [isOpen]);

  const handleQuickSwitch = async (role: UserRole) => {
    setIsSwitching(true);
    setLoginError(null);
    let u = 'admin';
    let p = 'Admin@SOC2026!#Secure';

    if (role === 'ANALYST') {
      u = 'analyst';
      p = 'Analyst@Cyber2026!';
    } else if (role === 'VIEWER') {
      u = 'viewer';
      p = 'Viewer@Auditor2026!';
    }

    const res = await apiClient.login(u, p);
    setIsSwitching(false);
    if (res.success) {
      setIsOpen(false);
    } else {
      setLoginError(res.error || 'Failed to switch role');
    }
  };

  const handleCustomLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!usernameInput || !passwordInput) {
      setLoginError('Please enter both username and password.');
      return;
    }
    setIsSwitching(true);
    setLoginError(null);
    const res = await apiClient.login(usernameInput, passwordInput);
    setIsSwitching(false);
    if (res.success) {
      setIsOpen(false);
      setCustomLoginMode(false);
      setUsernameInput('');
      setPasswordInput('');
    } else {
      setLoginError(res.error || 'Login failed');
    }
  };

  const handleLogout = async () => {
    await apiClient.logout();
    setIsOpen(false);
  };

  const getRoleBadge = (role?: UserRole) => {
    switch (role) {
      case 'ADMIN':
        return {
          bg: 'bg-rose-500/15 text-rose-300 border-rose-500/30',
          dot: 'bg-rose-400',
          label: 'ADMIN'
        };
      case 'ANALYST':
        return {
          bg: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30',
          dot: 'bg-cyan-400',
          label: 'ANALYST'
        };
      case 'VIEWER':
      default:
        return {
          bg: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
          dot: 'bg-emerald-400',
          label: 'VIEWER'
        };
    }
  };

  const badge = getRoleBadge(currentUser?.role);

  return (
    <div className="relative" ref={dropdownRef}>
      <button
        id="btn-user-role-menu"
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-2 px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-200 text-xs transition-colors"
        aria-label="User Account and RBAC Role"
        title="Active Security Role & Credentials"
      >
        <div className="w-5 h-5 rounded-full bg-slate-800 flex items-center justify-center text-cyan-400 border border-slate-700">
          <User className="w-3 h-3" />
        </div>
        <div className="hidden md:flex flex-col items-start text-left leading-tight">
          <span className="font-semibold text-slate-200 text-[11px] truncate max-w-[110px]">
            {currentUser?.displayName || 'Unauthenticated'}
          </span>
          <span className="text-[10px] text-slate-400">
            {currentUser?.role || 'Guest'}
          </span>
        </div>
        <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${badge.bg}`}>
          {badge.label}
        </span>
        <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
      </button>

      {isOpen && (
        <div
          id="user-role-dropdown-menu"
          className="absolute right-0 mt-2 w-80 rounded-xl bg-slate-950 border border-slate-800 shadow-2xl z-50 p-3.5 text-xs text-slate-200 animate-in fade-in zoom-in-95 duration-100"
        >
          {/* Header */}
          <div className="border-b border-slate-800/80 pb-3 mb-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-cyan-400" />
                <span className="font-bold text-slate-100 text-sm">RBAC Access Control</span>
              </div>
              <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${badge.bg}`}>
                {badge.label}
              </span>
            </div>
            <p className="text-[11px] text-slate-400 mt-1">
              Signed in as <span className="text-slate-200 font-semibold">{currentUser?.username || 'None'}</span> ({currentUser?.email || 'N/A'})
            </p>
          </div>

          {loginError && (
            <div className="mb-3 p-2 rounded bg-rose-500/15 border border-rose-500/30 text-rose-300 text-[11px] flex items-center gap-1.5">
              <AlertCircle className="w-3.5 h-3.5 shrink-0" />
              <span>{loginError}</span>
            </div>
          )}

          {!customLoginMode ? (
            <>
              {/* Quick Role Switcher */}
              <div className="space-y-1.5 mb-3">
                <div className="text-[10px] uppercase font-mono font-bold text-slate-400 tracking-wider mb-1">
                  Switch SOC Persona
                </div>

                {/* Admin Button */}
                <button
                  onClick={() => handleQuickSwitch('ADMIN')}
                  disabled={isSwitching}
                  className={`w-full flex items-center justify-between p-2 rounded-lg border text-left transition-all ${
                    currentUser?.role === 'ADMIN'
                      ? 'bg-rose-950/30 border-rose-500/50 text-rose-200'
                      : 'bg-slate-900/60 border-slate-800 hover:bg-slate-900 text-slate-300'
                  }`}
                >
                  <div className="flex items-center gap-2">
                    <Shield className="w-3.5 h-3.5 text-rose-400" />
                    <div>
                      <div className="font-semibold text-xs">Security Administrator</div>
                      <div className="text-[10px] text-slate-400">Full system, ML train & collector control</div>
                    </div>
                  </div>
                  {currentUser?.role === 'ADMIN' && <Check className="w-3.5 h-3.5 text-rose-400" />}
                </button>

                {/* Analyst Button */}
                <button
                  onClick={() => handleQuickSwitch('ANALYST')}
                  disabled={isSwitching}
                  className={`w-full flex items-center justify-between p-2 rounded-lg border text-left transition-all ${
                    currentUser?.role === 'ANALYST'
                      ? 'bg-cyan-950/30 border-cyan-500/50 text-cyan-200'
                      : 'bg-slate-900/60 border-slate-800 hover:bg-slate-900 text-slate-300'
                  }`}
                >
                  <div className="flex items-center gap-2">
                    <Key className="w-3.5 h-3.5 text-cyan-400" />
                    <div>
                      <div className="font-semibold text-xs">SOC Analyst (Tier-2)</div>
                      <div className="text-[10px] text-slate-400">Manage alerts, incidents & trigger analysis</div>
                    </div>
                  </div>
                  {currentUser?.role === 'ANALYST' && <Check className="w-3.5 h-3.5 text-cyan-400" />}
                </button>

                {/* Viewer Button */}
                <button
                  onClick={() => handleQuickSwitch('VIEWER')}
                  disabled={isSwitching}
                  className={`w-full flex items-center justify-between p-2 rounded-lg border text-left transition-all ${
                    currentUser?.role === 'VIEWER'
                      ? 'bg-emerald-950/30 border-emerald-500/50 text-emerald-200'
                      : 'bg-slate-900/60 border-slate-800 hover:bg-slate-900 text-slate-300'
                  }`}
                >
                  <div className="flex items-center gap-2">
                    <Eye className="w-3.5 h-3.5 text-emerald-400" />
                    <div>
                      <div className="font-semibold text-xs">Auditor / Compliance Viewer</div>
                      <div className="text-[10px] text-slate-400">Read-only dashboard, events & reports</div>
                    </div>
                  </div>
                  {currentUser?.role === 'VIEWER' && <Check className="w-3.5 h-3.5 text-emerald-400" />}
                </button>
              </div>

              {/* Action buttons */}
              <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between gap-2">
                <button
                  onClick={() => setCustomLoginMode(true)}
                  className="text-[11px] text-cyan-400 hover:text-cyan-300 underline underline-offset-2"
                >
                  Sign in with credentials
                </button>
                <button
                  onClick={handleLogout}
                  className="flex items-center gap-1 text-[11px] text-rose-400 hover:text-rose-300"
                >
                  <LogOut className="w-3 h-3" />
                  Logout
                </button>
              </div>
            </>
          ) : (
            <form onSubmit={handleCustomLogin} className="space-y-2.5">
              <div className="text-[10px] uppercase font-mono font-bold text-slate-400 tracking-wider">
                Authenticate User
              </div>
              <div>
                <label className="block text-[10px] text-slate-400 mb-1">Username</label>
                <input
                  type="text"
                  value={usernameInput}
                  onChange={(e) => setUsernameInput(e.target.value)}
                  placeholder="e.g. admin or analyst"
                  className="w-full px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-200 text-xs focus:outline-none focus:border-cyan-500"
                />
              </div>
              <div>
                <label className="block text-[10px] text-slate-400 mb-1">Password</label>
                <input
                  type="password"
                  value={passwordInput}
                  onChange={(e) => setPasswordInput(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-200 text-xs focus:outline-none focus:border-cyan-500"
                />
              </div>
              <div className="pt-2 flex items-center justify-between gap-2">
                <button
                  type="button"
                  onClick={() => setCustomLoginMode(false)}
                  className="text-[11px] text-slate-400 hover:text-slate-200"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSwitching}
                  className="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs transition-colors disabled:opacity-50"
                >
                  {isSwitching ? 'Verifying...' : 'Sign In'}
                </button>
              </div>
            </form>
          )}
        </div>
      )}
    </div>
  );
};

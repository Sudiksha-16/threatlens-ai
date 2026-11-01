import React from 'react';
import { Navigate, Outlet } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export const ProtectedRoute = () => {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-[#080D18]">
        <div className="flex flex-col items-center space-y-4">
          <div className="w-12 h-12 border-4 border-[#38D6C5] border-t-transparent rounded-full animate-spin"></div>
          <p className="text-[#9AA9BC] font-mono text-sm tracking-wider">INITIALIZING SOC INTERFACE...</p>
        </div>
      </div>
    );
  }

  return user ? <Outlet /> : <Navigate to="/login" replace />;
};

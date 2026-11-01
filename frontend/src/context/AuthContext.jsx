import React, { createContext, useContext, useState, useEffect } from 'react';
import { authAPI } from '../services/api';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(() => {
    const saved = localStorage.getItem('threatlens_user');
    return saved ? JSON.parse(saved) : null;
  });
  const [token, setToken] = useState(() => localStorage.getItem('threatlens_token'));
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const verifyAuth = async () => {
      const storedToken = localStorage.getItem('threatlens_token');
      if (storedToken) {
        try {
          const res = await authAPI.getMe();
          setUser(res.data);
          localStorage.setItem('threatlens_user', JSON.stringify(res.data));
        } catch (err) {
          console.error("Token verification failed:", err);
          logout();
        }
      }
      setLoading(false);
    };
    verifyAuth();
  }, []);

  const login = async (email, password, rememberMe = false) => {
    const res = await authAPI.login({ email, password, remember_me: rememberMe });
    const { access_token, user: userData } = res.data;
    localStorage.setItem('threatlens_token', access_token);
    localStorage.setItem('threatlens_user', JSON.stringify(userData));
    setToken(access_token);
    setUser(userData);
    return userData;
  };

  const register = async (fullName, email, password, confirmPassword) => {
    const res = await authAPI.register({
      full_name: fullName,
      email,
      password,
      confirm_password: confirmPassword,
    });
    const { access_token, user: userData } = res.data;
    localStorage.setItem('threatlens_token', access_token);
    localStorage.setItem('threatlens_user', JSON.stringify(userData));
    setToken(access_token);
    setUser(userData);
    return userData;
  };

  const logout = () => {
    localStorage.removeItem('threatlens_token');
    localStorage.removeItem('threatlens_user');
    setToken(null);
    setUser(null);
  };

  const refreshUser = async () => {
    try {
      const res = await authAPI.getMe();
      setUser(res.data);
      localStorage.setItem('threatlens_user', JSON.stringify(res.data));
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <AuthContext.Provider value={{ user, token, loading, login, register, logout, refreshUser }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => useContext(AuthContext);

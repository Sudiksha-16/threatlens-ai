import axios from 'axios';

const api = axios.create({
  baseURL: '/api',
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor to append JWT token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('threatlens_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor to handle 401 Unauthenticated
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && error.response.status === 401) {
      // Clear token if invalid or expired
      localStorage.removeItem('threatlens_token');
      localStorage.removeItem('threatlens_user');

      if (
        window.location.pathname !== '/login' &&
        window.location.pathname !== '/register' &&
        window.location.pathname !== '/'
      ) {
        window.location.href = '/login';
      }
    }

    return Promise.reject(error);
  }
);

export const authAPI = {
  register: (data) => api.post('/auth/register', data),
  login: (data) => api.post('/auth/login', data),
  getMe: () => api.get('/auth/me'),
  updateSettings: (data) => api.put('/auth/settings', data),
  logout: () => api.post('/auth/logout'),
};

export const scanAPI = {
  uploadFile: (formData, onProgress) =>
    api.post('/scan/upload', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
      onUploadProgress: onProgress,
    }),

  getHistory: (params) => api.get('/scan/history', { params }),

  getDetail: (scanId) => api.get(`/scan/${scanId}`),

  deleteScan: (scanId) => api.delete(`/scan/${scanId}`),

  // Retrieve simulated scan results
  getSimulation: (scenario) =>
    api.get(`/scan/simulate/${scenario}`),
};

export const dashboardAPI = {
  getStats: (timeRange = '30d') =>
    api.get('/dashboard/stats', {
      params: { time_range: timeRange },
    }),

  getCharts: (timeRange = '30d') =>
    api.get('/dashboard/charts', {
      params: { time_range: timeRange },
    }),
};

export const analyticsAPI = {
  getAnalytics: (params) => api.get('/analytics', { params }),
};

export const alertsAPI = {
  getAlerts: (params) => api.get('/alerts', { params }),

  markRead: (alertId) =>
    api.put(`/alerts/${alertId}/read`),

  resolve: (alertId) =>
    api.put(`/alerts/${alertId}/resolve`),

  markAllRead: () => api.put('/alerts/read-all'),
};

export const reportsAPI = {
  generateReport: (scanId) =>
    api.post(`/reports/generate/${scanId}`),

  getDownloadUrl: (scanId) => {
    const token = localStorage.getItem('threatlens_token') || '';

    return `/api/reports/download/${scanId}?token=${encodeURIComponent(token)}`;
  },

  downloadPDF: async (scanId, filename) => {
    const response = await api.get(`/reports/download/${scanId}`, {
      responseType: 'blob',
    });

    const blob = new Blob([response.data], {
      type: 'application/pdf',
    });

    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');

    link.href = url;
    link.download =
      filename || `ThreatLens_Report_${scanId.substring(0, 8)}.pdf`;

    document.body.appendChild(link);
    link.click();

    setTimeout(() => {
      window.URL.revokeObjectURL(url);
      document.body.removeChild(link);
    }, 100);
  },
};

export const modelAPI = {
  getPerformance: () => api.get('/model/performance'),
};

export default api;

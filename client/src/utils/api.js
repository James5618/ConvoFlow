import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:3001/api';

// Create axios instance with default config
const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  withCredentials: true,
});

// Add auth token to requests
api.interceptors.request.use((config) => {
  // Debug: log server endpoints for easier diagnosis
  try {
    if (config.url && config.url.includes('/servers')) {
      console.log(`[API] Request: ${config.method?.toUpperCase() || 'GET'} ${config.baseURL}${config.url}`);
    }
  } catch (e) {}
  const token = localStorage.getItem('authToken');
  if (token) {
    // Quick expiry check to avoid sending expired tokens
    try {
      const parts = token.split('.');
      if (parts.length === 3) {
        const payload = JSON.parse(atob(parts[1]));
        if (payload.exp && Date.now() / 1000 > payload.exp) {
          console.warn('[API] Auth token expired locally, redirecting to login');
          localStorage.removeItem('authToken');
          localStorage.removeItem('user');
          window.location.href = '/login';
          throw new axios.Cancel('Token expired');
        }
      }
    } catch (e) {
      // If anything goes wrong parsing token, just continue and let server validate
    }
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Handle auth errors
// Response interceptor with refresh token handling
let isRefreshing = false;
let refreshSubscribers = [];

function onRefreshed(token) {
  refreshSubscribers.forEach((cb) => cb(token));
  refreshSubscribers = [];
}

function addRefreshSubscriber(cb) {
  refreshSubscribers.push(cb);
}

api.interceptors.response.use(
  (response) => {
    try {
      if (response.config?.url && response.config.url.includes('/servers')) {
        console.log(`[API] Response: ${response.status} ${response.config.baseURL}${response.config.url}`);
      }
    } catch (e) {}
    return response;
  },
  async (error) => {
    try {
      if (error.config?.url && error.config.url.includes('/servers')) {
        console.error(`[API] Error response for ${error.config.baseURL}${error.config.url}:`, error.response?.status, error.message);
      }
    } catch (e) {}

    const status = error.response?.status;
    if (status === 401 || status === 403) {
      const originalRequest = error.config;

      if (!isRefreshing) {
        isRefreshing = true;
        try {
          const refreshResp = await axios.post((process.env.REACT_APP_API_URL || 'http://localhost:3001') + '/refresh', null, { withCredentials: true });
          const newToken = refreshResp.data?.token;
          const newUser = refreshResp.data?.user;
          if (newToken) {
            localStorage.setItem('authToken', newToken);
            if (newUser) localStorage.setItem('user', JSON.stringify(newUser));
          }
          isRefreshing = false;
          onRefreshed(localStorage.getItem('authToken'));
        } catch (refreshError) {
          isRefreshing = false;
          refreshSubscribers = [];
          localStorage.removeItem('authToken');
          localStorage.removeItem('user');
          window.location.href = '/login';
          return Promise.reject(error);
        }
      }

      // Queue the request until refresh completes
      return new Promise((resolve, reject) => {
        addRefreshSubscriber((token) => {
          try {
            originalRequest.headers = originalRequest.headers || {};
            if (token) originalRequest.headers.Authorization = `Bearer ${token}`;
            resolve(api(originalRequest));
          } catch (e) {
            reject(e);
          }
        });
      });
    }

    if (error.message && error.message.includes('Network Error')) {
      console.error('[API] Network Error detected when contacting API server');
    }
    return Promise.reject(error);
  }
);

export const authAPI = {
  register: (userData) => api.post('/register', userData),
  login: (credentials) => api.post('/login', credentials),
};

export const roomsAPI = {
  getRooms: () => api.get('/rooms'),
  createRoom: (name) => api.post('/rooms', { name }),
  getMessages: (roomId) => api.get(`/rooms/${roomId}/messages`),
};

export const serversAPI = {
  getServers: () => api.get('/servers'),
  createServer: (serverData) => api.post('/servers', serverData),
  joinServer: (inviteCode) => api.post('/servers/join', { inviteCode }),
  getChannels: (serverId) => api.get(`/servers/${serverId}/channels`),
  createChannel: (serverId, name) => api.post(`/servers/${serverId}/channels`, { name }),
  // Voice channels
  createVoiceChannel: (serverId, name) => api.post(`/servers/${serverId}/voice-channels`, { name }),
  joinVoiceChannel: (roomId) => api.post(`/rooms/${roomId}/voice/join`),
  leaveVoiceChannel: (roomId) => api.post(`/rooms/${roomId}/voice/leave`),
  // Members & roles
  getMembers: (serverId) => api.get(`/servers/${serverId}/members`),
  setMemberRole: (serverId, memberId, role) => api.post(`/servers/${serverId}/members/${memberId}/role`, { role }),
};

export const conversationsAPI = {
  getConversations: () => api.get('/conversations'),
  createConversation: (userId) => api.post('/conversations', { userId }),
  getMessages: (conversationId) => api.get(`/conversations/${conversationId}/messages`),
};

export const usersAPI = {
  searchUsers: (query) => api.get(`/users/search?query=${encodeURIComponent(query)}`),
};

export default api;

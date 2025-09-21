const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { Pool } = require('pg');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    // Relaxed for local debugging; tighten in production
    origin: ["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:3000/", "*"],
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true,
    allowedHeaders: ["Content-Type", "Authorization"]
  },
  allowEIO3: true,
  transports: ['polling', 'websocket'],
  pingTimeout: 60000,
  pingInterval: 25000
});

// Environment variables
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
const PORT = process.env.PORT || 3001;
const DATABASE_URL = process.env.DATABASE_URL || 'postgresql://localhost:5432/convoflow';

// Middleware
app.use(helmet());
app.use(cors({
  // Relaxed for local debugging; tighten in production
  origin: ["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:3000/", "*"],
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));
app.use(express.json());
let cookieParser;
try {
  cookieParser = require('cookie-parser');
  app.use(cookieParser());
} catch (e) {
  console.warn('[WARN] cookie-parser not installed. Refresh token cookie parsing will use simple fallback. Run `npm install` to install cookie-parser.');
  // Simple cookie parser fallback
  app.use((req, res, next) => {
    const header = req.headers.cookie;
    req.cookies = {};
    if (header) {
      header.split(';').forEach((cookie) => {
        const parts = cookie.split('=');
        req.cookies[parts[0].trim()] = decodeURIComponent((parts[1] || '').trim());
      });
    }
    next();
  });
}

// Simple request logger to capture incoming requests for debugging
app.use((req, res, next) => {
  try {
    console.log('[REQUEST]', req.method, req.originalUrl, 'from', req.ip, 'headers:', {
      origin: req.headers.origin,
      authorization: req.headers.authorization ? 'present' : 'missing'
    });
  } catch (e) {}
  next();
});

// Serve static files from React build
app.use(express.static(path.join(__dirname, '../client/build')));

// Database setup
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Initialize database tables
async function initializeDatabase() {
  try {
    // Users table
    await pool.query(`CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(255) UNIQUE NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      password VARCHAR(255) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);

    // Messages table (stores encrypted messages)
    await pool.query(`CREATE TABLE IF NOT EXISTS messages (
      id SERIAL PRIMARY KEY,
      room_id VARCHAR(255) NOT NULL,
      sender_id INTEGER NOT NULL,
      encrypted_content TEXT NOT NULL,
      timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (sender_id) REFERENCES users (id)
    )`);

    // Rooms table
    await pool.query(`CREATE TABLE IF NOT EXISTS rooms (
      id VARCHAR(255) PRIMARY KEY,
      name VARCHAR(255) NOT NULL,
      created_by INTEGER NOT NULL,
      server_id VARCHAR(255),
      is_channel BOOLEAN DEFAULT false,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (created_by) REFERENCES users (id)
    )`);

    // Room members table
    await pool.query(`CREATE TABLE IF NOT EXISTS room_members (
      room_id VARCHAR(255) NOT NULL,
      user_id INTEGER NOT NULL,
      joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (room_id, user_id),
      FOREIGN KEY (room_id) REFERENCES rooms (id),
      FOREIGN KEY (user_id) REFERENCES users (id)
    )`);

    // Servers table - containers for multiple rooms/channels
    await pool.query(`CREATE TABLE IF NOT EXISTS servers (
      id VARCHAR(255) PRIMARY KEY,
      name VARCHAR(255) NOT NULL,
      description TEXT,
      owner_id INTEGER NOT NULL,
      invite_code VARCHAR(255) UNIQUE,
      is_public BOOLEAN DEFAULT false,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (owner_id) REFERENCES users (id)
    )`);

    // Server members table
    await pool.query(`CREATE TABLE IF NOT EXISTS server_members (
      server_id VARCHAR(255) NOT NULL,
      user_id INTEGER NOT NULL,
      role VARCHAR(50) DEFAULT 'member',
      joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (server_id, user_id),
      FOREIGN KEY (server_id) REFERENCES servers (id),
      FOREIGN KEY (user_id) REFERENCES users (id)
    )`);

    // Private messages table - direct messages between users
    await pool.query(`CREATE TABLE IF NOT EXISTS private_messages (
      id SERIAL PRIMARY KEY,
      sender_id INTEGER NOT NULL,
      recipient_id INTEGER NOT NULL,
      encrypted_content TEXT NOT NULL,
      timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      is_read BOOLEAN DEFAULT false,
      FOREIGN KEY (sender_id) REFERENCES users (id),
      FOREIGN KEY (recipient_id) REFERENCES users (id)
    )`);

    // Private message conversations table
    await pool.query(`CREATE TABLE IF NOT EXISTS private_conversations (
      id VARCHAR(255) PRIMARY KEY,
      user1_id INTEGER NOT NULL,
      user2_id INTEGER NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      last_message_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user1_id) REFERENCES users (id),
      FOREIGN KEY (user2_id) REFERENCES users (id)
    )`);

    console.log('Database tables initialized successfully');
  } catch (error) {
    console.error('Error initializing database:', error);
  }
}

// Initialize database on startup
initializeDatabase();

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  // Debug logging for auth header presence
  try {
    console.log('[AUTH] Incoming request:', req.method, req.originalUrl, 'Authorization header present:', !!authHeader);
  } catch (e) {}

  if (!token) {
    return res.sendStatus(401);
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.log('[AUTH] JWT verification failed:', err.message);
      return res.sendStatus(403);
    }
    req.user = user;
    next();
  });
};

// Socket.IO authentication middleware
const authenticateSocket = (socket, next) => {
  const token = socket.handshake.auth.token;
  
  if (!token) {
    console.log('No token provided for Socket.IO connection - creating guest user for testing');
    // TEMPORARY: Allow guest access for testing
    socket.user = {
      id: Math.floor(Math.random() * 1000) + 1000, // Random guest ID
      username: `Guest${Math.floor(Math.random() * 100)}`,
      email: 'guest@example.com'
    };
    return next();
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.log('JWT verification failed:', err.message, '- creating guest user for testing');
      // TEMPORARY: Allow guest access even with invalid token for testing
      socket.user = {
        id: Math.floor(Math.random() * 1000) + 1000, // Random guest ID
        username: `Guest${Math.floor(Math.random() * 100)}`,
        email: 'guest@example.com'
      };
      return next();
    }
    console.log(`Socket.IO authentication successful for user: ${user.username}`);
    socket.user = user;
    next();
  });
};

// Routes
// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', message: 'Server is running', timestamp: new Date().toISOString() });
});

app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Insert user
    const result = await pool.query(
      'INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id, username, email',
      [username, email, hashedPassword]
    );

    // Refresh tokens table
    await pool.query(`CREATE TABLE IF NOT EXISTS refresh_tokens (
      token TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      expires_at TIMESTAMP NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users (id)
    )`);
    
    const user = result.rows[0];
    const token = jwt.sign(
      { id: user.id, username: user.username, email: user.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    // Create refresh token
    const refreshToken = crypto.randomBytes(48).toString('hex');
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days
    await pool.query('INSERT INTO refresh_tokens (token, user_id, expires_at) VALUES ($1, $2, $3)', [refreshToken, user.id, expiresAt]);

    // Send refresh token as httpOnly cookie
    res.cookie('refreshToken', refreshToken, { httpOnly: true, sameSite: 'lax' });

    res.json({ token, user });
  } catch (error) {
    if (error.constraint && error.constraint.includes('unique')) {
      return res.status(400).json({ error: 'Username or email already exists' });
    }
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    const result = await pool.query(
      'SELECT * FROM users WHERE username = $1',
      [username]
    );
    
    const user = result.rows[0];
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign(
      { id: user.id, username: user.username, email: user.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    // Create refresh token
    const refreshToken = crypto.randomBytes(48).toString('hex');
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days
    await pool.query('INSERT INTO refresh_tokens (token, user_id, expires_at) VALUES ($1, $2, $3)', [refreshToken, user.id, expiresAt]);
    res.cookie('refreshToken', refreshToken, { httpOnly: true, sameSite: 'lax' });

    res.json({ 
      token, 
      user: { id: user.id, username: user.username, email: user.email } 
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Debugging endpoint: return decoded token/user info for the current auth token
// Only for local development; consider removing in production
app.get('/api/whoami', authenticateToken, (req, res) => {
  try {
    res.json({ user: req.user });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Refresh endpoint: exchanges refresh token cookie for a new access token
app.post('/api/refresh', async (req, res) => {
  try {
    const refreshToken = req.cookies?.refreshToken || null;
    if (!refreshToken) return res.sendStatus(401);

    const result = await pool.query('SELECT * FROM refresh_tokens WHERE token = $1', [refreshToken]);
    const row = result.rows[0];
    if (!row) return res.sendStatus(403);
    if (new Date(row.expires_at) < new Date()) {
      await pool.query('DELETE FROM refresh_tokens WHERE token = $1', [refreshToken]);
      return res.sendStatus(403);
    }

    // Issue new access token
    const userResult = await pool.query('SELECT id, username, email FROM users WHERE id = $1', [row.user_id]);
    const user = userResult.rows[0];
    const newToken = jwt.sign({ id: user.id, username: user.username, email: user.email }, JWT_SECRET, { expiresIn: '24h' });

    // Rotate refresh token: optional
    const newRefreshToken = crypto.randomBytes(48).toString('hex');
    const newExpiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
    await pool.query('DELETE FROM refresh_tokens WHERE token = $1', [refreshToken]);
    await pool.query('INSERT INTO refresh_tokens (token, user_id, expires_at) VALUES ($1, $2, $3)', [newRefreshToken, row.user_id, newExpiresAt]);
    res.cookie('refreshToken', newRefreshToken, { httpOnly: true, sameSite: 'lax' });

    res.json({ token: newToken, user });
  } catch (error) {
    console.error('Refresh token error:', error);
    res.status(500).json({ error: 'Refresh failed' });
  }
});

// Logout: remove refresh token cookie and DB entry
app.post('/api/logout', authenticateToken, async (req, res) => {
  try {
    const refreshToken = req.cookies?.refreshToken || null;
    if (refreshToken) {
      await pool.query('DELETE FROM refresh_tokens WHERE token = $1', [refreshToken]);
    }
    res.clearCookie('refreshToken');
    res.json({ message: 'Logged out' });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ error: 'Logout failed' });
  }
});

app.get('/api/rooms', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT r.*, u.username as creator_name 
       FROM rooms r 
       JOIN users u ON r.created_by = u.id 
       JOIN room_members rm ON r.id = rm.room_id 
       WHERE rm.user_id = $1`,
      [req.user.id]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Get rooms error:', error);
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/rooms', authenticateToken, async (req, res) => {
  try {
    const { name } = req.body;
    const roomId = 'room_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    
    // Insert room
    await pool.query(
      'INSERT INTO rooms (id, name, created_by) VALUES ($1, $2, $3)',
      [roomId, name, req.user.id]
    );
    
    // Add creator to room members
    await pool.query(
      'INSERT INTO room_members (room_id, user_id) VALUES ($1, $2)',
      [roomId, req.user.id]
    );
    
    res.json({ id: roomId, name, created_by: req.user.id });
  } catch (error) {
    console.error('Create room error:', error);
    res.status(500).json({ error: 'Database error' });
  }
});

app.get('/api/rooms/:roomId/messages', authenticateToken, async (req, res) => {
  try {
    const { roomId } = req.params;
    
    const result = await pool.query(
      `SELECT m.*, u.username 
       FROM messages m 
       JOIN users u ON m.sender_id = u.id 
       WHERE m.room_id = $1 
       ORDER BY m.timestamp ASC`,
      [roomId]
    );
    
    res.json(result.rows);
  } catch (error) {
    console.error('Get room messages error:', error);
    res.status(500).json({ error: 'Database error' });
  }
});

// Server management endpoints
app.get('/api/servers', authenticateToken, async (req, res) => {
  try {
    // Debug: print request headers (mask Authorization token to avoid leaking secrets in logs)
    try {
      const headers = { ...req.headers };
      if (headers.authorization) {
        const parts = headers.authorization.split(' ');
        const token = parts[1] || parts[0] || '';
        const masked = token.length > 12 ? `${token.slice(0,8)}...${token.slice(-4)}` : '<<masked>>';
        headers.authorization = `${parts[0] || 'Bearer'} ${masked}`;
      }
      console.log('[SERVERS] Incoming headers:', headers);
    } catch (e) {}
    console.log('[SERVERS] /api/servers request for user id:', req.user?.id);
    const result = await pool.query(
      `SELECT s.*, u.username as owner_name 
       FROM servers s 
       JOIN users u ON s.owner_id = u.id 
       JOIN server_members sm ON s.id = sm.server_id 
       WHERE sm.user_id = $1
       ORDER BY s.created_at DESC`,
      [req.user.id]
    );
    console.log('[SERVERS] Query returned rows:', result.rowCount);
    res.json(result.rows);
  } catch (error) {
    console.error('Get servers error:', error);
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/servers', authenticateToken, async (req, res) => {
  try {
    const { name, description, isPublic } = req.body;
    const serverId = 'server_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    const inviteCode = Math.random().toString(36).substr(2, 8).toUpperCase();
    
    // Insert server
    await pool.query(
      'INSERT INTO servers (id, name, description, owner_id, invite_code, is_public) VALUES ($1, $2, $3, $4, $5, $6)',
      [serverId, name, description || null, req.user.id, inviteCode, isPublic || false]
    );
    
    // Add owner to server members as admin
    await pool.query(
      'INSERT INTO server_members (server_id, user_id, role) VALUES ($1, $2, $3)',
      [serverId, req.user.id, 'admin']
    );
    
    // Create default general channel
    const channelId = 'channel_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    await pool.query(
      'INSERT INTO rooms (id, name, created_by, server_id, is_channel) VALUES ($1, $2, $3, $4, $5)',
      [channelId, 'general', req.user.id, serverId, true]
    );
    
    // Add owner to the general channel
    await pool.query(
      'INSERT INTO room_members (room_id, user_id) VALUES ($1, $2)',
      [channelId, req.user.id]
    );
    
    res.json({ 
      id: serverId, 
      name, 
      description, 
      owner_id: req.user.id, 
      invite_code: inviteCode,
      is_public: isPublic || false 
    });
  } catch (error) {
    console.error('Create server error:', error);
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/servers/join', authenticateToken, async (req, res) => {
  try {
    const { inviteCode } = req.body;
    
    // Find server by invite code
    const serverResult = await pool.query(
      'SELECT * FROM servers WHERE invite_code = $1',
      [inviteCode]
    );
    
    const server = serverResult.rows[0];
    if (!server) {
      return res.status(404).json({ error: 'Invalid invite code' });
    }
    
    // Check if user is already a member
    const memberResult = await pool.query(
      'SELECT * FROM server_members WHERE server_id = $1 AND user_id = $2',
      [server.id, req.user.id]
    );
    
    if (memberResult.rows.length > 0) {
      return res.status(400).json({ error: 'You are already a member of this server' });
    }
    
    // Add user to server
    await pool.query(
      'INSERT INTO server_members (server_id, user_id) VALUES ($1, $2)',
      [server.id, req.user.id]
    );
    
    // Add user to all public channels in the server
    const channelsResult = await pool.query(
      'SELECT id FROM rooms WHERE server_id = $1 AND is_channel = true',
      [server.id]
    );
    
    // Add user to all channels
    for (const channel of channelsResult.rows) {
      await pool.query(
        'INSERT INTO room_members (room_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
        [channel.id, req.user.id]
      );
    }
    
    res.json({ message: 'Successfully joined server', server });
  } catch (error) {
    console.error('Join server error:', error);
    res.status(500).json({ error: 'Database error' });
  }
});

app.get('/api/servers/:serverId/channels', authenticateToken, async (req, res) => {
  try {
    const { serverId } = req.params;
    
    // Verify user is a member of the server
    const memberResult = await pool.query(
      'SELECT * FROM server_members WHERE server_id = $1 AND user_id = $2',
      [serverId, req.user.id]
    );
    
    if (memberResult.rows.length === 0) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    // Get all channels in the server
    const channelsResult = await pool.query(
      `SELECT r.*, u.username as creator_name 
       FROM rooms r 
       JOIN users u ON r.created_by = u.id 
       WHERE r.server_id = $1 AND r.is_channel = true
       ORDER BY r.created_at ASC`,
      [serverId]
    );
    
    res.json(channelsResult.rows);
  } catch (error) {
    console.error('Get channels error:', error);        
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/servers/:serverId/channels', authenticateToken, async (req, res) => {
  try {
    const { serverId } = req.params;
    const { name } = req.body;
    
    // Verify user is an admin or owner of the server
    const memberResult = await pool.query(
      'SELECT role FROM server_members WHERE server_id = $1 AND user_id = $2',
      [serverId, req.user.id]
    );
    
    const member = memberResult.rows[0];
    if (!member || (member.role !== 'admin' && member.role !== 'owner')) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    
    const channelId = 'channel_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    
    // Insert new channel
    await pool.query(
      'INSERT INTO rooms (id, name, created_by, server_id, is_channel) VALUES ($1, $2, $3, $4, $5)',
      [channelId, name, req.user.id, serverId, true]
    );
    
    // Add all server members to the new channel
    const membersResult = await pool.query(
      'SELECT user_id FROM server_members WHERE server_id = $1',
      [serverId]
    );
    
    // Add each member to the channel
    for (const member of membersResult.rows) {
      await pool.query(
        'INSERT INTO room_members (room_id, user_id) VALUES ($1, $2)',
        [channelId, member.user_id]
      );
    }
    
    res.json({ id: channelId, name, created_by: req.user.id, server_id: serverId, is_channel: true });
  } catch (error) {
    console.error('Create channel error:', error);
    res.status(500).json({ error: 'Database error' });
  }
});

// Private messaging endpoints
app.get('/api/conversations', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT 
         pc.id as conversation_id,
         pc.last_message_at,
         CASE 
           WHEN pc.user1_id = $1 THEN u2.id 
           ELSE u1.id 
         END as other_user_id,
         CASE 
           WHEN pc.user1_id = $2 THEN u2.username 
           ELSE u1.username 
         END as other_username,
         pm.encrypted_content as last_message,
         pm.timestamp as last_message_time,
         pm.sender_id as last_sender_id
       FROM private_conversations pc
       JOIN users u1 ON pc.user1_id = u1.id
       JOIN users u2 ON pc.user2_id = u2.id
       LEFT JOIN private_messages pm ON pm.id = (
         SELECT id FROM private_messages 
         WHERE (sender_id = pc.user1_id AND recipient_id = pc.user2_id) 
            OR (sender_id = pc.user2_id AND recipient_id = pc.user1_id)
         ORDER BY timestamp DESC 
         LIMIT 1
       )
       WHERE pc.user1_id = $3 OR pc.user2_id = $4
       ORDER BY pc.last_message_at DESC`,
      [req.user.id, req.user.id, req.user.id, req.user.id]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Get conversations error:', error);
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/conversations', authenticateToken, async (req, res) => {
  const { userId } = req.body;
  
  if (userId === req.user.id) {
    return res.status(400).json({ error: 'Cannot create conversation with yourself' });
  }
  
  // Check if conversation already exists
  try {
    const existingResult = await pool.query(
      `SELECT * FROM private_conversations 
       WHERE (user1_id = $1 AND user2_id = $2) 
          OR (user1_id = $2 AND user2_id = $1)`,
      [req.user.id, userId]
    );
    
    if (existingResult.rows.length > 0) {
      return res.json({ id: existingResult.rows[0].id, message: 'Conversation already exists' });
    }
    
    const conversationId = 'conv_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    
    await pool.query(
      'INSERT INTO private_conversations (id, user1_id, user2_id) VALUES ($1, $2, $3)',
      [conversationId, Math.min(req.user.id, userId), Math.max(req.user.id, userId)]
    );
    
    res.json({ id: conversationId, message: 'Conversation created' });
  } catch (err) {
    console.error('Database error:', err);
    return res.status(500).json({ error: 'Database error' });
  }
});

app.get('/api/conversations/:conversationId/messages', authenticateToken, async (req, res) => {
  const { conversationId } = req.params;
  
  try {
    // Verify user is part of the conversation
    const conversationResult = await pool.query(
      'SELECT * FROM private_conversations WHERE id = $1 AND (user1_id = $2 OR user2_id = $2)',
      [conversationId, req.user.id]
    );
    
    if (conversationResult.rows.length === 0) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    const conversation = conversationResult.rows[0];
    const otherUserId = conversation.user1_id === req.user.id ? conversation.user2_id : conversation.user1_id;
    
    const messagesResult = await pool.query(
      `SELECT pm.*, u.username 
       FROM private_messages pm 
       JOIN users u ON pm.sender_id = u.id 
       WHERE (pm.sender_id = $1 AND pm.recipient_id = $2) 
          OR (pm.sender_id = $2 AND pm.recipient_id = $1)
       ORDER BY pm.timestamp ASC`,
      [req.user.id, otherUserId]
    );
    
    res.json(messagesResult.rows);
  } catch (err) {
    console.error('Database error:', err);
    return res.status(500).json({ error: 'Database error' });
  }
});

app.get('/api/users/search', authenticateToken, async (req, res) => {
  const { query } = req.query;
  
  if (!query || query.length < 2) {
    return res.status(400).json({ error: 'Query must be at least 2 characters' });
  }
  
  try {
    const result = await pool.query(
      'SELECT id, username FROM users WHERE username ILIKE $1 AND id != $2 LIMIT 10',
      [`%${query}%`, req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Database error:', err);
    return res.status(500).json({ error: 'Database error' });
  }
});

// Socket.IO connection handling
io.use(authenticateSocket);

io.on('connection', (socket) => {
  console.log(`✅ User ${socket.user.username} connected with ID: ${socket.id}`);

  // Log transport details
  try {
    console.log('[SOCKET] transport:', socket.conn.transport.name, 'remoteAddress:', socket.handshake.address);
  } catch (e) {}

  // Listen for socket errors
  socket.on('error', (err) => {
    console.error('[SOCKET] socket error for', socket.id, err);
  });

  // Listen for engine errors (transport-level)
  try {
    socket.conn.on('error', (err) => {
      console.error('[SOCKET] engine/transport error for', socket.id, err);
    });
  } catch (e) {}

  socket.on('join-room', (roomId) => {
    socket.join(roomId);
    console.log(`User ${socket.user.username} joined room ${roomId}`);
    
    // Notify other users in the room that this user joined
    socket.to(roomId).emit('user-joined-room', {
      id: socket.user.id,
      username: socket.user.username
    });
    
    // Send the current user list to the joining user
    const roomSockets = io.sockets.adapter.rooms.get(roomId);
    if (roomSockets) {
      const roomUsers = [];
      for (const socketId of roomSockets) {
        const clientSocket = io.sockets.sockets.get(socketId);
        if (clientSocket && clientSocket.user) {
          roomUsers.push({
            id: clientSocket.user.id,
            username: clientSocket.user.username
          });
        }
      }
      socket.emit('room-users-list', roomUsers);
    }
  });

  socket.on('leave-room', (roomId) => {
    socket.leave(roomId);
    console.log(`User ${socket.user.username} left room ${roomId}`);
    
    // Notify other users in the room that this user left
    socket.to(roomId).emit('user-left-room', {
      id: socket.user.id,
      username: socket.user.username
    });
  });

  socket.on('get-room-users', (roomId) => {
    const roomSockets = io.sockets.adapter.rooms.get(roomId);
    if (roomSockets) {
      const roomUsers = [];
      for (const socketId of roomSockets) {
        const clientSocket = io.sockets.sockets.get(socketId);
        if (clientSocket && clientSocket.user) {
          roomUsers.push({
            id: clientSocket.user.id,
            username: clientSocket.user.username
          });
        }
      }
      socket.emit('room-users-list', roomUsers);
    }
  });

  socket.on('send-message', async (data) => {
    const { roomId, encryptedMessage } = data;
    
    console.log(`=== SEND MESSAGE DEBUG ===`);
    console.log(`User: ${socket.user.username} (ID: ${socket.user.id})`);
    console.log(`Room: ${roomId}`);
    console.log(`Message: ${encryptedMessage}`);
    console.log(`Socket rooms:`, [...socket.rooms]);
    
    // Validate message length (5000 character limit for encrypted content)
    if (!encryptedMessage || encryptedMessage.length > 5000) {
      console.error('Message validation failed: length exceeds 5000 characters');
      socket.emit('message-error', { error: 'Message too long (max 5000 characters)' });
      return;
    }
    
    if (!roomId) {
      console.error('Message validation failed: no room ID provided');
      socket.emit('message-error', { error: 'Room ID required' });
      return;
    }
    
    // Ensure socket is in the room
    if (!socket.rooms.has(roomId)) {
      console.log(`Socket not in room ${roomId}, joining now`);
      socket.join(roomId);
    }
    
    try {
      // Store encrypted message in database
      const result = await pool.query(
        'INSERT INTO messages (room_id, sender_id, encrypted_content) VALUES ($1, $2, $3) RETURNING id',
        [roomId, socket.user.id, encryptedMessage]
      );
      
      const messageId = result.rows[0].id;
      console.log(`✅ Message saved: ID ${messageId} in room ${roomId} by user ${socket.user.username}`);
      
      // Emit the encrypted message to all users in the room
      const messageData = {
        id: messageId,
        room_id: roomId,
        sender_id: socket.user.id,
        username: socket.user.username,
        encrypted_content: encryptedMessage,
        timestamp: new Date().toISOString()
      };
      
      // Get room info for debugging
      const roomSockets = io.sockets.adapter.rooms.get(roomId);
      const socketsInRoom = roomSockets ? roomSockets.size : 0;
      
      console.log(`📡 Emitting message to room: ${roomId}`);
      console.log(`👥 Sockets in room: ${socketsInRoom}`);
      console.log(`📨 Message data:`, messageData);
      
      // Emit to room AND back to sender to ensure immediate display
      io.to(roomId).emit('new-message', messageData);
      
      // Also emit directly to sender for immediate feedback
      socket.emit('message-sent', messageData);
      
      console.log(`✅ Message emitted successfully`);
      
    } catch (error) {
      console.error('❌ Error saving message:', error);
      socket.emit('message-error', { error: 'Failed to save message' });
    }
  });

  // WebRTC signaling events
  socket.on('webrtc-offer', (data) => {
    const { roomId, offer, targetUserId } = data;
    console.log(`WebRTC offer from ${socket.user.username} to user ${targetUserId} in room ${roomId}`);
    
    // Send offer to specific user in the room
    socket.to(roomId).emit('webrtc-offer', {
      offer,
      fromUserId: socket.user.id,
      fromUsername: socket.user.username
    });
  });

  socket.on('webrtc-answer', (data) => {
    const { roomId, answer, targetUserId } = data;
    console.log(`WebRTC answer from ${socket.user.username} to user ${targetUserId} in room ${roomId}`);
    
    // Send answer to specific user in the room
    socket.to(roomId).emit('webrtc-answer', {
      answer,
      fromUserId: socket.user.id,
      fromUsername: socket.user.username
    });
  });

  socket.on('webrtc-ice-candidate', (data) => {
    const { roomId, candidate, targetUserId } = data;
    
    // Send ICE candidate to specific user in the room
    socket.to(roomId).emit('webrtc-ice-candidate', {
      candidate,
      fromUserId: socket.user.id,
      fromUsername: socket.user.username
    });
  });

  socket.on('video-call-start', (data) => {
    const { roomId, callType } = data; // callType: 'video' or 'audio'
    console.log(`${callType} call started by ${socket.user.username} in room ${roomId}`);
    
    // Notify all users in the room about the call
    socket.to(roomId).emit('video-call-started', {
      fromUserId: socket.user.id,
      fromUsername: socket.user.username,
      callType,
      timestamp: new Date().toISOString()
    });
  });

  socket.on('video-call-join', (data) => {
    const { roomId } = data;
    console.log(`User ${socket.user.username} joined video call in room ${roomId}`);
    
    // Notify all users in the room
    socket.to(roomId).emit('video-call-user-joined', {
      userId: socket.user.id,
      username: socket.user.username
    });
  });

  socket.on('video-call-leave', (data) => {
    const { roomId } = data;
    console.log(`User ${socket.user.username} left video call in room ${roomId}`);
    
    // Notify all users in the room
    socket.to(roomId).emit('video-call-user-left', {
      userId: socket.user.id,
      username: socket.user.username
    });
  });

  socket.on('video-call-end', (data) => {
    const { roomId } = data;
    console.log(`Video call ended by ${socket.user.username} in room ${roomId}`);
    
    // Notify all users in the room
    socket.to(roomId).emit('video-call-ended', {
      byUserId: socket.user.id,
      byUsername: socket.user.username,
      timestamp: new Date().toISOString()
    });
  });

  socket.on('screen-share-start', (data) => {
    const { roomId } = data;
    console.log(`Screen sharing started by ${socket.user.username} in room ${roomId}`);
    
    // Notify all users in the room
    socket.to(roomId).emit('screen-share-started', {
      fromUserId: socket.user.id,
      fromUsername: socket.user.username
    });
  });

  socket.on('screen-share-stop', (data) => {
    const { roomId } = data;
    console.log(`Screen sharing stopped by ${socket.user.username} in room ${roomId}`);
    
    // Notify all users in the room
    socket.to(roomId).emit('screen-share-stopped', {
      fromUserId: socket.user.id,
      fromUsername: socket.user.username
    });
  });

  // Private messaging events
  socket.on('join-conversation', (conversationId) => {
    socket.join(`conversation_${conversationId}`);
    console.log(`User ${socket.user.username} joined conversation ${conversationId}`);
  });

  socket.on('leave-conversation', (conversationId) => {
    socket.leave(`conversation_${conversationId}`);
    console.log(`User ${socket.user.username} left conversation ${conversationId}`);
  });

  socket.on('send-private-message', async (data) => {
    const { recipientId, encryptedMessage } = data;
    
    // Validate message length (5000 character limit for encrypted content)
    if (!encryptedMessage || encryptedMessage.length > 5000) {
      console.error('Private message validation failed: length exceeds 5000 characters');
      socket.emit('message-error', { error: 'Message too long (max 5000 characters)' });
      return;
    }
    
    if (!recipientId) {
      console.error('Private message validation failed: no recipient ID provided');
      socket.emit('message-error', { error: 'Recipient ID required' });
      return;
    }
    
    try {
      // Store encrypted private message in database
      const result = await pool.query(
        'INSERT INTO private_messages (sender_id, recipient_id, encrypted_content) VALUES ($1, $2, $3) RETURNING id',
        [socket.user.id, recipientId, encryptedMessage]
      );
      
      const messageId = result.rows[0].id;
      console.log(`Private message saved: ID ${messageId} from user ${socket.user.username} to user ${recipientId}`);
      
      // Update conversation's last message time
      await pool.query(
        `UPDATE private_conversations 
         SET last_message_at = CURRENT_TIMESTAMP 
         WHERE (user1_id = $1 AND user2_id = $2) OR (user1_id = $2 AND user2_id = $1)`,
        [Math.min(socket.user.id, recipientId), Math.max(socket.user.id, recipientId)]
      );
      
      const messageData = {
        id: messageId,
        sender_id: socket.user.id,
        recipient_id: recipientId,
        username: socket.user.username,
        encrypted_content: encryptedMessage,
        timestamp: new Date().toISOString(),
        is_read: false
      };
      
      // Send message to both sender and recipient
      // Find recipient's socket and send the message
      const recipientSockets = Array.from(io.sockets.sockets.values())
        .filter(s => s.user && s.user.id === recipientId);
      
      recipientSockets.forEach(recipientSocket => {
        recipientSocket.emit('new-private-message', messageData);
      });
      
      // Also send to sender for confirmation
      socket.emit('private-message-sent', messageData);
    } catch (error) {
      console.error('Error saving private message:', error);
      socket.emit('message-error', { error: 'Failed to save private message' });
    }
  });

  // Server events
  socket.on('join-server', (serverId) => {
    socket.join(`server_${serverId}`);
    console.log(`User ${socket.user.username} joined server ${serverId}`);
    
    // Notify other server members that user came online
    socket.to(`server_${serverId}`).emit('user-online', {
      userId: socket.user.id,
      username: socket.user.username
    });
  });

  socket.on('leave-server', (serverId) => {
    socket.leave(`server_${serverId}`);
    console.log(`User ${socket.user.username} left server ${serverId}`);
    
    // Notify other server members that user went offline
    socket.to(`server_${serverId}`).emit('user-offline', {
      userId: socket.user.id,
      username: socket.user.username
    });
  });

  socket.on('disconnect', () => {
    console.log(`User ${socket.user.username} disconnected`);
    
    // Notify all rooms that this user has left
    const rooms = Object.keys(socket.rooms);
    rooms.forEach(roomId => {
      if (roomId !== socket.id) { // Skip the default room (socket's own ID)
        socket.to(roomId).emit('user-left-room', {
          id: socket.user.id,
          username: socket.user.username
        });
      }
    });
  });
});

// Catch-all handler: send back React's index.html file for client-side routing
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../client/build/index.html'));
});

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

console.log('Starting server...');
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const path = require('path');
const OpenAI = require('openai');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'your-secret-key'; // In production, use environment variable

let openai = null;
if (process.env.OPENAI_API_KEY) {
  openai = new OpenAI({
    apiKey: process.env.OPENAI_API_KEY,
  });
}

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../frontend')));

// Serve login.html for root path
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/login.html'));
});

// Database setup
const db = new sqlite3.Database('./chat.db', (err) => {
  if (err) {
    console.error('Error opening database:', err.message);
  } else {
    console.log('Connected to SQLite database.');
    initDatabase();
  }
});

function initDatabase() {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS friends (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    friend_id INTEGER,
    status TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id),
    FOREIGN KEY (friend_id) REFERENCES users (id),
    UNIQUE(user_id, friend_id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER,
    recipient_id INTEGER,
    content TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sender_id) REFERENCES users (id),
    FOREIGN KEY (recipient_id) REFERENCES users (id)
  )`);
}

// Authentication routes
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], function(err) {
      if (err) {
        if (err.message.includes('UNIQUE constraint failed')) {
          return res.status(400).json({ error: 'Username already exists' });
        }
        return res.status(500).json({ error: 'Database error' });
      }
      res.status(201).json({ message: 'User registered successfully' });
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET);
    res.json({ token, username: user.username, id: user.id });
  });
});

// Middleware to verify JWT
function authenticateToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access token required' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
}

// Get messages with a specific user
app.get('/messages', authenticateToken, (req, res) => {
  const { recipient_id } = req.query;
  if (!recipient_id) {
    return res.status(400).json({ error: 'recipient_id required' });
  }
  const userId = req.user.id;
  db.all(`
    SELECT messages.*, users.username as sender_username
    FROM messages
    JOIN users ON messages.sender_id = users.id
    WHERE (sender_id = ? AND recipient_id = ?) OR (sender_id = ? AND recipient_id = ?)
    ORDER BY timestamp ASC
  `, [userId, recipient_id, recipient_id, userId], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(rows);
  });
});

// Get friends
app.get('/friends', authenticateToken, (req, res) => {
  const userId = req.user.id;
  db.all(`
    SELECT DISTINCT u.id, u.username
    FROM friends f
    JOIN users u ON (f.friend_id = u.id OR f.user_id = u.id) AND u.id != ?
    WHERE (f.user_id = ? OR f.friend_id = ?) AND f.status = 'accepted'
  `, [userId, userId, userId], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(rows);
  });
});

// Send friend request
app.post('/friends/request', authenticateToken, (req, res) => {
  const { friend_id } = req.body;
  const userId = req.user.id;

  if (!friend_id || friend_id === userId) return res.status(400).json({ error: 'Invalid friend ID' });

  db.get('SELECT id FROM users WHERE id = ?', [friend_id], (err, friend) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!friend) return res.status(404).json({ error: 'User not found' });

    db.run('INSERT OR IGNORE INTO friends (user_id, friend_id) VALUES (?, ?)', [userId, friend.id], function(err) {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json({ message: 'Friend request sent' });
    });
  });
});

// Accept friend request
app.post('/friends/accept', authenticateToken, (req, res) => {
  const { friend_id } = req.body;
  const userId = req.user.id;

  db.run('UPDATE friends SET status = "accepted" WHERE user_id = ? AND friend_id = ? AND status = "pending"', [friend_id, userId], function(err) {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (this.changes === 0) return res.status(404).json({ error: 'Request not found' });
    // Also add reverse
    db.run('INSERT OR IGNORE INTO friends (user_id, friend_id, status) VALUES (?, ?, "accepted")', [userId, friend_id], function(err) {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json({ message: 'Friend request accepted' });
    });
  });
});

// Get pending requests
app.get('/friends/requests', authenticateToken, (req, res) => {
  const userId = req.user.id;
  db.all(`
    SELECT f.id, u.id as sender_id, u.username
    FROM friends f
    JOIN users u ON f.user_id = u.id
    WHERE f.friend_id = ? AND f.status = 'pending'
  `, [userId], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(rows);
  });
});

// Get all users
app.get('/users', authenticateToken, (req, res) => {
  db.all('SELECT id, username FROM users WHERE id != ?', [req.user.id], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(rows);
  });
});

// AI response function
async function generateAIResponse(userMessage) {
  if (!openai) {
    return 'Désolé, je ne peux pas répondre pour le moment.';
  }
  try {
    const completion = await openai.chat.completions.create({
      model: 'gpt-3.5-turbo',
      messages: [
        { role: 'system', content: 'You are a helpful AI assistant in a chat application. Respond naturally and helpfully to user messages.' },
        { role: 'user', content: userMessage }
      ],
      max_tokens: 150
    });
    return completion.choices[0].message.content.trim();
  } catch (error) {
    console.error('OpenAI API error:', error);
    return 'Désolé, je ne peux pas répondre pour le moment.';
  }
}

// Socket.io for real-time messaging
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  console.log('Auth attempt, token:', !!token);
  if (!token) return next(new Error('Authentication error'));

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.log('JWT verify error:', err);
      return next(new Error('Authentication error'));
    }
    socket.user = user;
    console.log('User authenticated:', user.username);
    next();
  });
});

io.on('connection', (socket) => {
  console.log('User connected:', socket.user.username);

  socket.on('joinChat', (data) => {
    const { friendId } = data;
    const room = `chat_${Math.min(socket.user.id, friendId)}_${Math.max(socket.user.id, friendId)}`;
    socket.join(room);
    console.log(`${socket.user.username} joined room ${room}`);
  });

  socket.on('sendMessage', (data) => {
    console.log('Message received from', socket.user.username, ':', data.content);
    const { content, recipientId } = data;
    const senderId = socket.user.id;

    // Check if they are friends
    db.get('SELECT * FROM friends WHERE ((user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)) AND status = "accepted"', [senderId, recipientId, recipientId, senderId], (err, friendship) => {
      if (err) {
        console.error('Error checking friendship:', err);
        return;
      }
      if (!friendship) {
        socket.emit('error', 'You can only message friends');
        return;
      }

      db.run('INSERT INTO messages (sender_id, recipient_id, content) VALUES (?, ?, ?)', [senderId, recipientId, content], function(err) {
        if (err) {
          console.error('Error saving message:', err);
          return;
        }

        const message = {
          id: this.lastID,
          sender_id: senderId,
          recipient_id: recipientId,
          content,
          timestamp: new Date().toISOString(),
          sender_username: socket.user.username
        };

        const room = `chat_${Math.min(senderId, recipientId)}_${Math.max(senderId, recipientId)}`;
        io.to(room).emit('newMessage', message);
        console.log('Emitting message to room', room);
      });
    });
  });

  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.user.username);
  });
});

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});


const express = require('express');
const bodyParser = require('body-parser');
const http = require('http');
const path = require('path');
const helmet = require('helmet');
const cors = require('cors');
const crypto = require('crypto');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const csurf = require('csurf');
const cookieParser = require('cookie-parser');
require('dotenv').config();

const app = express();
const port = 3000;

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net"],
      connectSrc: ["'self'"],
      imgSrc: ["'self'", "data:"],
      styleSrc: ["'self'", "'unsafe-inline'"]
    },
  },
}));
app.use(cors());
app.use(bodyParser.json({ limit: '100kb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '100kb' }));
app.use(cookieParser());

app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 3600000,
    sameSite: 'lax'
  }
}));

// Create CSRF protection middleware but exclude API endpoints
const csrfProtection = csurf({ cookie: true });

// Apply CSRF protection to all routes except the API endpoint
app.use((req, res, next) => {
  // Exclude API endpoints from CSRF protection
  if ((req.path === '/api/player' && req.method === 'POST') || 
      (req.path === '/api/players/all' && req.method === 'DELETE') ||
      (req.path.startsWith('/api/player/') && req.method === 'DELETE')) {
    return next();
  }
  csrfProtection(req, res, next);
});

app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }
  next(err);
});

app.use((req, res, next) => {
  if (req.csrfToken) {
    res.locals.csrfToken = req.csrfToken();
  }
  next();
});

const fs = require('fs');

app.get('/csrf-token', (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

let players = new Map();
const dataFilePath = path.join(__dirname, 'playerData.json');
try {
  if (fs.existsSync(dataFilePath)) {
    const loadedData = JSON.parse(fs.readFileSync(dataFilePath, 'utf8'));
    Object.entries(loadedData).forEach(([key, value]) => {
      players.set(key, value);
    });
    console.log('Loaded player data from disk');
  }
} catch (error) {
  console.error('Error loading player data:', error);
}

function savePlayerData() {
  try {
    const playerObj = {};
    for (const [key, value] of players.entries()) {
      playerObj[key] = value;
    }
    fs.writeFileSync(dataFilePath, JSON.stringify(playerObj, null, 2));
  } catch (error) {
    console.error('Error saving player data:', error);
  }
}

setInterval(savePlayerData, 60000);
process.on('SIGINT', () => {
  savePlayerData();
  process.exit(0);
});

const limiter = rateLimit({
  windowMs: 10 * 1000, // 10 seconds
  max: 20, // limit each IP to 20 requests per windowMs
  message: { error: 'Rate limit exceeded' }
});

app.use(limiter);

function sanitizePlayerData(data) {
  const sanitized = {};

  for (const [key, value] of Object.entries(data)) {
    if (typeof value === 'string') {
      sanitized[key] = value
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/&/g, '&amp;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .replace(/\//g, '&#x2F;')
        .trim();
    } else if (typeof value === 'number') {
      sanitized[key] = isNaN(value) ? 0 : value;
    } else {
      sanitized[key] = value;
    }
  }

  return sanitized;
}

function verifyApiKey(req, res, next) {
  next();
}

app.use((req, res, next) => {
  const start = Date.now();

  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(`${req.method} ${req.url} ${res.statusCode} - ${duration}ms`);
  });

  next();
});

app.post('/api/player', verifyApiKey, (req, res) => {
  const clientIp = req.headers['x-forwarded-for'] || req.ip;

  try {
    const data = req.body;
    console.log("Received player data:", data);

    if (!data.playerName) {
      return res.status(200).json({ error: 'Missing playerName', received: data });
    }

    const defaults = {
      displayName: data.playerName,
      gameName: 'Unknown Game',
      serverPlayers: 1,
      maxPlayers: 10,
      placeId: '0',
      jobId: Date.now().toString(),
      executor: 'Unknown',
      version: 'Unknown'
    };

    const mergedData = { ...defaults, ...data };
    const playerId = `${mergedData.playerName}-${mergedData.jobId}`;
    const sanitizedData = sanitizePlayerData(mergedData);

    players.set(playerId, {
      ...sanitizedData,
      lastUpdated: new Date(),
      ip: clientIp
    });

    savePlayerData();
    return res.status(200).json({ success: true });
  } catch (error) {
    console.error("Error processing player data:", error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/api/player/:playerId', requireAdmin, (req, res) => {
  try {
    const playerId = req.params.playerId;
    if (players.has(playerId)) {
      players.delete(playerId);
      savePlayerData();
      return res.status(200).json({ success: true });
    } else {
      return res.status(404).json({ error: 'Player not found' });
    }
  } catch (error) {
    console.error('Error removing player:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/api/players/all', requireAdmin, (req, res) => {
  try {
    players.clear();
    savePlayerData();
    console.log('All player data has been removed');
    return res.status(200).json({ success: true, message: 'All player data has been removed' });
  } catch (error) {
    console.error('Error removing all player data:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/players', (req, res) => {
  try {
    const playerList = Array.from(players.values())
      .map(player => {
        const { ip, ...playerData } = player;
        return sanitizePlayerData(playerData);
      });

    res.set('Cache-Control', 'private, max-age=5');
    return res.status(200).json(playerList);
  } catch (error) {
    console.error('Error fetching player data:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/admin/login.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin/login.html'));
});

app.use('/admin', (req, res, next) => {
  if (req.path === '/login.html' || req.path === '/login') {
    next();
  } else if (req.session.isAdmin) {
    next();
  } else {
    res.redirect('/admin/login.html');
  }
});

app.use('/admin', express.static(path.join(__dirname, 'admin')));

app.get('/', (req, res) => {
  res.redirect('/admin/login.html');
});

app.get('/admin/tracker', requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'admin/index.html'));
});

app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok' });
});

app.post('/admin/login', (req, res) => {
  console.log('Login attempt received');
  const { username, password } = req.body;

  if (!username || !password) {
    console.log('Missing username or password');
    return res.status(400).json({ error: 'Username and password are required' });
  }

  console.log('Login attempt for username:', username);

  const passwordHash = crypto.createHash('sha256').update(password).digest('hex');
  console.log('Expected username:', process.env.ADMIN_USERNAME);
  console.log('Provided hash:', passwordHash);

  if (username === process.env.ADMIN_USERNAME && 
      passwordHash === process.env.ADMIN_PASSWORD_HASH) {
    console.log('Login successful');
    req.session.isAdmin = true;
    return res.status(200).json({ success: true });
  }

  console.log('Login failed - invalid credentials');
  return res.status(401).json({ error: 'Invalid credentials' });
});

app.get('/admin/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/admin/login.html');
});

app.get('/raw', (req, res) => {
  try {
    const fullIpString = req.headers['x-forwarded-for'] || req.ip;
    const clientIp = fullIpString.split(',')[0].trim();

    let foundPlayerId = null;
    for (const [key, player] of players.entries()) {
      if (player.ip) {
        const playerIpFirst = player.ip.split(',')[0].trim();
        if (playerIpFirst === clientIp) {
          foundPlayerId = key;
          break;
        }
      }
    }
    if (foundPlayerId) {
      res.setHeader('Content-Type', 'text/plain');
      return res.status(200).send(foundPlayerId);
    } else {
      res.setHeader('Content-Type', 'text/plain');
      return res.status(404).send(`No player data found`);
    }
  } catch (error) {
    console.error('Error accessing auto-detected player data:', error);
    res.setHeader('Content-Type', 'text/plain');
    return res.status(500).send('Internal server error');
  }
});

function requireAdmin(req, res, next) {
  if (req.session.isAdmin) {
    next();
  } else {
    res.redirect('/admin/login.html');
  }
}

app.get('/admin', requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

app.get('/csrf-token', (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

const server = http.createServer(app);

server.timeout = 10000;
server.keepAliveTimeout = 5000;

app.listen(port, '0.0.0.0', () => {
  console.log(`Server running on http://0.0.0.0:${port}`);
});
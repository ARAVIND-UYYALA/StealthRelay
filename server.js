require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// ==========================================
// PHASE 3: FILE VAULT STORAGE ENGINE CONFIG
// ==========================================
const uploadDir = path.join(__dirname, 'vault_storage');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadDir); 
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname)); 
    }
});

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 50 * 1024 * 1024 } // Cap uploads at 50 Megabytes
});

// ==========================================
// SERVER & DATABASE APP INITIALIZATION
// ==========================================
const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

// Database Connection & Security Lockdown Upgrade
pool.connect()
    .then(async () => {
        console.log('Database connection locked in.');
        
        try {
            // Auto-create users table if it doesn't exist (for fresh deployments)
            await pool.query(`
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(100) UNIQUE NOT NULL,
                    passcode VARCHAR(255) NOT NULL,
                    role VARCHAR(20) DEFAULT 'personnel',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            `);

            // Adds role column if missing (upgrade for existing DBs)
            await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(20) DEFAULT 'personnel';");

            // Forcefully seed/reset default admin so you can always log in
            const bcrypt = require('bcrypt');
            const hashedPass = await bcrypt.hash('admin123', 10);
            
            await pool.query(`
                INSERT INTO users (username, passcode, role) 
                VALUES ('commander_zero', $1, 'admin')
                ON CONFLICT (username) 
                DO UPDATE SET passcode = EXCLUDED.passcode, role = 'admin';
            `, [hashedPass]);

            console.log('Schema verified. Admin commander_zero access guaranteed (passcode: admin123).');
        } catch (e) {
            console.error("Schema setup failed:", e.message);
        }
    })
    .catch(err => console.error('Database connection failed:', err.stack));  

const server = http.createServer(app);

const io = new Server(server, {
    cors: {
        origin: "*", 
        methods: ["GET", "POST"]
    }
});

// ==========================================
// ONLINE USERS TRACKING
// ==========================================
const onlineUsers = new Map(); // socketId -> { username, role, socketId }

function broadcastOnlineUsers() {
    const usersList = Array.from(onlineUsers.values());
    io.emit('online-users', usersList);
}

// ==========================================
// HTTP BOUNCER MIDDLEWARE
// ==========================================
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = (authHeader && authHeader.startsWith('Bearer '))
        ? authHeader.split(' ')[1]
        : req.query.token;

    if (!token) {
        return res.status(401).json({ error: "Access Denied: Missing security token." });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ error: "Access Denied: Invalid or expired token." });
        req.user = decoded; 
        next();
    });
};

// ==========================================
// PHASE 1: SECURE AUTHENTICATION ROUTES
// ==========================================
// Serve PWA static assets + frontend (everything in /public)
app.use(express.static(path.join(__dirname, 'public')));

// Fallback: serve index.html for the root route
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// --- GUARDED REGISTRATION ROUTE (Requires Admin Token) ---
app.post('/register', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: "Clearance Denied: Only Administrators can provision new personnel." });
        }

        const { username, passcode } = req.body;
        if (!username || !passcode) {
            return res.status(400).json({ error: "Username and passcode required." });
        }

        const hashedPasscode = await bcrypt.hash(passcode, 10);
        const newPersonnel = await pool.query(
            "INSERT INTO users (username, passcode) VALUES ($1, $2) RETURNING id, username, role",
            [username, hashedPasscode]
        );
        res.status(201).json({ message: `Personnel '${newPersonnel.rows[0].username}' registered securely.` });
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ error: "Registration failed. Username might already exist." });
    }
});

// --- LOGIN ROUTE (Injects User Role into Token) ---
app.post('/login', async (req, res) => {
    try {
        const { username, passcode } = req.body;
        const user = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
        
        if (user.rows.length === 0) {
            return res.status(401).json({ error: "Access denied. User not found." });
        }

        const validPasscode = await bcrypt.compare(passcode, user.rows[0].passcode);
        if (!validPasscode) {
            return res.status(401).json({ error: "Access denied. Incorrect passcode." });
        }

        const token = jwt.sign(
            { 
                userId: user.rows[0].id, 
                username: user.rows[0].username,
                role: user.rows[0].role 
            },
            process.env.JWT_SECRET,
            { expiresIn: "24h" }
        );

        res.json({ message: "Login successful.", token: token });
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ error: "Server error during authentication execution." });
    }
});

// ==========================================
// PHASE 3: SECURE FILE VAULT ROUTES
// ==========================================
app.post('/vault/upload', authenticateToken, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: "No target file was selected." });
        
        res.status(201).json({
            message: "File encrypted and stored in operational vault.",
            originalName: req.file.originalname,
            fileName: req.file.filename,
            size: req.file.size,
            downloadLink: `/vault/download/${req.file.filename}`
        });
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ error: "Vault storage internal breakdown." });
    }
});

// --- LIST ALL FILES IN VAULT ---
app.get('/vault/files', authenticateToken, (req, res) => {
    try {
        const files = fs.readdirSync(uploadDir).map(filename => {
            const filePath = path.join(uploadDir, filename);
            const stats = fs.statSync(filePath);
            return {
                fileName: filename,
                size: stats.size,
                uploadedAt: stats.mtime,
                downloadLink: `/vault/download/${filename}`
            };
        }).filter(f => !f.fileName.startsWith('.')); // exclude hidden files

        res.json({ files });
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ error: "Failed to list vault contents." });
    }
});

app.get('/vault/download/:filename', authenticateToken, (req, res) => {
    const filePath = path.join(uploadDir, req.params.filename);
    if (!fs.existsSync(filePath)) {
        return res.status(404).json({ error: "Target data file not found inside vault registry." });
    }
    res.download(filePath);
});

// ==========================================
// PHASE 2: WEBSOCKET BOUNCER MIDDLEWARE
// ==========================================
io.use((socket, next) => {
    const token = socket.handshake.auth.token || socket.handshake.query.token;
    if (!token) return next(new Error("Access Denied: No security token provided."));

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) return next(new Error("Access Denied: Invalid or expired token."));
        socket.user = decoded; 
        next();
    });
});

// ==========================================
// PHASE 2 & 4: REAL-TIME COMMUNICATION ENGINE
// ==========================================
io.on('connection', (socket) => {
    console.log(`Secure channel opened for: ${socket.user.username} (ID: ${socket.id})`);

    // Track online user
    onlineUsers.set(socket.id, {
        username: socket.user.username,
        role: socket.user.role,
        socketId: socket.id
    });
    broadcastOnlineUsers();

    // --- PHASE 2: MESSAGE HANDLERS ---
    socket.on('send_message', (raw_data) => {
        let data = raw_data;
        if (typeof raw_data === 'string') {
            try { 
                data = JSON.parse(raw_data); 
            } catch (e) {
                console.error("Failed to parse message payload:", raw_data);
            }
        }
        
        console.log(`[CHAT] ${socket.user.username}: ${data.content}`);
        
        socket.broadcast.emit('receive_message', {
            sender: socket.user.username,
            content: data.content,
            timestamp: new Date()
        });
    });

    // --- PHASE 4: WebRTC P2P SIGNALING RELAYS ---
    socket.on('video-offer', (data) => {
        console.log(`[VIDEO] Offer from ${socket.user.username} to ${data.targetSocketId}`);
        socket.to(data.targetSocketId).emit('video-offer', {
            senderSocketId: socket.id,
            senderUsername: socket.user.username,
            offer: data.offer
        });
    });

    socket.on('video-answer', (data) => {
        console.log(`[VIDEO] Answer from ${socket.user.username} to ${data.targetSocketId}`);
        socket.to(data.targetSocketId).emit('video-answer', {
            senderSocketId: socket.id,
            answer: data.answer
        });
    });

    socket.on('ice-candidate', (data) => {
        socket.to(data.targetSocketId).emit('ice-candidate', {
            senderSocketId: socket.id,
            candidate: data.candidate
        });
    });

    // --- VIDEO CALL REJECTION ---
    socket.on('video-reject', (data) => {
        socket.to(data.targetSocketId).emit('video-rejected', {
            senderSocketId: socket.id,
            senderUsername: socket.user.username
        });
    });

    // --- VIDEO CALL HANG UP ---
    socket.on('video-hangup', (data) => {
        socket.to(data.targetSocketId).emit('video-hangup', {
            senderSocketId: socket.id
        });
    });

    socket.on('disconnect', () => {
        console.log(`Channel closed for: ${socket.user.username}`);
        onlineUsers.delete(socket.id);
        broadcastOnlineUsers();
    });
});

// ==========================================
// START EXECUTING LISTENER
// ==========================================
const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
    console.log(`Server is locked in and listening on port ${PORT}`);
});
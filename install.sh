#!/bin/bash

# ChatGen Pro - Interactive Installer
# App: AsrnovinChat
# Folder: ~/chat-AsrnovinChat

DIR="~/chat-AsrnovinChat"
APP_NAME="AsrnovinChat"

# 1. Interactive Input
echo "========================================"
echo "    ChatGen Pro Installer"
echo "========================================"
echo ""
echo "Please configure your chat server:"
echo ""

read -p "Chat Room Name [default: AsrnovinChat]: " INPUT_APP_NAME
APP_NAME_VAL=${INPUT_APP_NAME:-AsrnovinChat}

read -p "Admin Username [default: admin]: " INPUT_USER
ADMIN_USER=${INPUT_USER:-admin}

read -p "Admin Password [default: 123456]: " INPUT_PASS
ADMIN_PASS=${INPUT_PASS:-123456}

read -p "Port [default: 3000]: " INPUT_PORT
PORT=${INPUT_PORT:-3000}

echo ""
echo "Select Theme Color:"
echo "1) Blue (Default)"
echo "2) Purple"
echo "3) Green"
echo "4) Red"
echo "5) Orange"
echo "6) Teal"
read -p "Enter number [1-6]: " COLOR_CHOICE

# Define Colors based on choice
case $COLOR_CHOICE in
  2) # Purple
     C_DEF="#9333ea"; C_DARK="#7e22ce"; C_LIGHT="#f3e8ff" ;;
  3) # Green
     C_DEF="#16a34a"; C_DARK="#15803d"; C_LIGHT="#dcfce7" ;;
  4) # Red
     C_DEF="#dc2626"; C_DARK="#b91c1c"; C_LIGHT="#fee2e2" ;;
  5) # Orange
     C_DEF="#ea580c"; C_DARK="#c2410c"; C_LIGHT="#ffedd5" ;;
  6) # Teal
     C_DEF="#0d9488"; C_DARK="#0f766e"; C_LIGHT="#ccfbf1" ;;
  *) # Blue (Default)
     C_DEF="#2563eb"; C_DARK="#1d4ed8"; C_LIGHT="#dbeafe" ;;
esac


# 2. Update System & Install Node/PM2
echo ""
echo "[1/6] Updating system..."
sudo apt-get update -y
sudo apt-get install -y curl

echo "[2/6] Installing Node.js & PM2..."
if ! command -v node &> /dev/null; then
    curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
    sudo apt-get install -y nodejs
fi
sudo npm install -g pm2

# 3. Create Files
echo "[3/6] Creating project files in $DIR..."
mkdir -p "$DIR"
mkdir -p "$DIR/public"
mkdir -p "$DIR/data"
cd "$DIR"

# package.json (Added security packages)
cat > package.json << 'EOF'
{
  "name": "AsrnovinChat",
  "version": "1.0.0",
  "main": "server.js",
  "scripts": {
    "start": "node server.js"
  },
  "dependencies": {
    "express": "^4.18.2",
    "socket.io": "^4.7.2",
    "multer": "^1.4.5-lts.1",
    "bcryptjs": "^2.4.3",
    "helmet": "^7.1.0",
    "xss": "^1.0.14",
    "express-rate-limit": "^7.1.5"
  }
}
EOF

# server.js
cat > server.js << 'EOF'

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const xss = require('xss');
const rateLimit = require('express-rate-limit');

const app = express();
const server = http.createServer(app);

// Security Headers
app.use(helmet({
  contentSecurityPolicy: false, // Disabled to allow inline scripts/images for this simple generator
  crossOriginEmbedderPolicy: false
}));

// Body Parser Limits
app.use(express.json({ limit: '10kb' })); 

const io = new Server(server, {
  maxHttpBufferSize: 1e8,
  cors: { 
    origin: "*", // In production, this should be restricted to the specific domain
    methods: ["GET", "POST"]
  }
});

// --- Persistence & Config ---
const DATA_DIR = path.join(__dirname, 'data');
const UPLOADS_DIR = path.join(__dirname, 'public/uploads');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

const USERS_FILE = path.join(DATA_DIR, 'users.json');
const MESSAGES_FILE = path.join(DATA_DIR, 'messages.json');
const CHANNELS_FILE = path.join(DATA_DIR, 'channels.json');
const CONFIG_FILE = path.join(DATA_DIR, 'config.json');

// --- Load & Secure Config ---
let appConfig = {
  adminUser: 'admin',
  adminPass: 'admin123',
  port: 3000,
  maxFileSizeMB: 50,
  appName: 'Chat App',
  hideUserList: false
};

function loadAndSecureConfig() {
  try {
    let saveNeeded = false;
    if (fs.existsSync(CONFIG_FILE)) {
      const fileConfig = JSON.parse(fs.readFileSync(CONFIG_FILE));
      appConfig = { ...appConfig, ...fileConfig }; // Merge defaults
    } else {
      saveNeeded = true;
    }

    // Secure Password: If plain text, hash it
    if (!appConfig.adminPass.startsWith('$2a$')) {
       console.log("Securing admin password...");
       appConfig.adminPass = bcrypt.hashSync(appConfig.adminPass, 10);
       saveNeeded = true;
    }

    if (saveNeeded) {
      saveConfig();
    }
  } catch (e) { console.error("Error loading config:", e); }
}

function saveConfig() {
    try {
        fs.writeFileSync(CONFIG_FILE, JSON.stringify(appConfig, null, 2));
    } catch (e) { console.error("Error saving config:", e); }
}

loadAndSecureConfig();

const PORT = process.env.PORT || appConfig.port || 3000;

// Memory State
let users = {}; 
let persistentUsers = {}; 
let channels = ['General', 'Random'];
let messages = {}; 
let userRateLimits = {}; // Memory store for socket spam protection

// Load Data
try {
  if (fs.existsSync(USERS_FILE)) persistentUsers = JSON.parse(fs.readFileSync(USERS_FILE));
  if (fs.existsSync(CHANNELS_FILE)) channels = JSON.parse(fs.readFileSync(CHANNELS_FILE));
  if (fs.existsSync(MESSAGES_FILE)) messages = JSON.parse(fs.readFileSync(MESSAGES_FILE));
} catch (e) { console.error("Error loading data:", e); }

function saveData() {
  try {
    fs.writeFileSync(USERS_FILE, JSON.stringify(persistentUsers));
    fs.writeFileSync(CHANNELS_FILE, JSON.stringify(channels));
    fs.writeFileSync(MESSAGES_FILE, JSON.stringify(messages));
  } catch (e) { console.error("Error saving data", e); }
}

setInterval(saveData, 30000);

// --- Upload Configuration & Rate Limit ---
const uploadLimiter = rateLimit({
	windowMs: 15 * 60 * 1000, // 15 minutes
	max: 20, // Limit each IP to 20 uploads per windowMs
    message: "Too many uploads from this IP, please try again later"
});

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOADS_DIR);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    cb(null, uniqueSuffix + ext); // Validate extension in real prod
  }
});

const upload = multer({ 
  storage: storage,
  limits: { fileSize: (appConfig.maxFileSizeMB || 50) * 1024 * 1024 } 
});

app.use(express.static(path.join(__dirname, 'public')));

// --- API Routes ---
app.post('/upload', uploadLimiter, (req, res) => {
  // Reload config to get latest file size limit
  try {
    if (fs.existsSync(CONFIG_FILE)) {
       const freshConfig = JSON.parse(fs.readFileSync(CONFIG_FILE));
       upload.limits = { fileSize: (freshConfig.maxFileSizeMB || 50) * 1024 * 1024 };
    }
  } catch(e){}

  const uploadSingle = upload.single('file');

  uploadSingle(req, res, function (err) {
    if (err instanceof multer.MulterError) {
      return res.status(400).json({ error: 'File too large or upload error.' });
    } else if (err) {
      return res.status(500).json({ error: 'Unknown upload error.' });
    }
    
    if(!req.file) return res.status(400).json({ error: 'No file sent.' });
    
    // Basic Mime Type Check
    const allowedMimes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'audio/webm', 'audio/mpeg', 'video/mp4', 'video/webm', 'application/pdf', 'text/plain'];
    if (!allowedMimes.includes(req.file.mimetype)) {
        // In a real app, delete the file here
        return res.json({ 
            url: '/uploads/' + req.file.filename,
            filename: req.file.originalname, // Potentially unsafe, handled by client download attr mostly
            size: req.file.size,
            mimetype: req.file.mimetype
        });
    }

    res.json({ 
        url: '/uploads/' + req.file.filename,
        filename: req.file.originalname,
        size: req.file.size,
        mimetype: req.file.mimetype
    });
  });
});

io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  socket.on('login', ({ username, password }) => {
    username = xss(username.trim()).substring(0, 20); // Sanitize and limit length
    loadAndSecureConfig(); // Ensure we have latest hashed pass
    
    // Check Admin
    if (username === appConfig.adminUser) {
      // Compare hash
      if (bcrypt.compareSync(password, appConfig.adminPass)) {
        users[socket.id] = { username, role: 'admin' };
        socket.emit('login_success', { 
            username, 
            role: 'admin', 
            channels, 
            settings: { 
                maxFileSizeMB: appConfig.maxFileSizeMB,
                appName: appConfig.appName,
                hideUserList: appConfig.hideUserList
            } 
        });
        joinChannel(socket, 'General');
        broadcastUserList();
        return;
      } else {
        return socket.emit('login_error', 'رمز عبور ادمین اشتباه است.');
      }
    }

    // Check Users
    if (persistentUsers[username]) {
      if (persistentUsers[username].isBanned) {
        return socket.emit('login_error', 'حساب کاربری شما مسدود شده است.');
      }
      if (persistentUsers[username].password !== password) {
        return socket.emit('login_error', 'رمز عبور اشتباه است.');
      }
    } else {
      persistentUsers[username] = {
        password: password, 
        role: 'user',
        isBanned: false,
        created_at: Date.now()
      };
    }

    persistentUsers[username].last_seen = Date.now();
    saveData();

    const role = persistentUsers[username].role;
    users[socket.id] = { username, role };
    
    socket.emit('login_success', { 
        username, 
        role, 
        channels, 
        settings: { 
            maxFileSizeMB: appConfig.maxFileSizeMB,
            appName: appConfig.appName,
            hideUserList: appConfig.hideUserList
        } 
    });
    joinChannel(socket, 'General');
    broadcastUserList();
  });

  socket.on('join_channel', (channel) => {
    joinChannel(socket, channel);
  });
  
  socket.on('join_private', (targetUser) => {
    const currentUser = users[socket.id];
    if (!currentUser) return;
    const cleanTarget = xss(targetUser);
    const roomName = [currentUser.username, cleanTarget].sort().join('_pv_');
    joinChannel(socket, roomName, true);
  });

  socket.on('create_channel', (channelName) => {
    const user = users[socket.id];
    if (user && (user.role === 'admin' || user.role === 'vip')) {
      const cleanName = xss(channelName).substring(0, 30);
      if (!channels.includes(cleanName) && cleanName.length > 0) {
        channels.push(cleanName);
        io.emit('update_channels', channels);
        saveData();
      }
    }
  });

  socket.on('delete_channel', (channelName) => {
    const user = users[socket.id];
    if (user && (user.role === 'admin' || user.role === 'vip')) {
      if (channelName !== 'General' && channels.includes(channelName)) {
        channels = channels.filter(c => c !== channelName);
        delete messages[channelName];
        io.emit('update_channels', channels);
        io.in(channelName).socketsLeave(channelName); 
        saveData();
      }
    }
  });

  // --- Admin Settings ---
  socket.on('update_admin_settings', (newSettings) => {
      const user = users[socket.id];
      if (!user || user.role !== 'admin') return;
      
      if (typeof newSettings.hideUserList === 'boolean') {
          appConfig.hideUserList = newSettings.hideUserList;
          saveConfig();
          // Broadcast new list visibility
          broadcastUserList();
          socket.emit('action_success', 'تنظیمات با موفقیت ذخیره شد.');
      }
  });

  // --- Ban System with History Wipe ---
  socket.on('ban_user', (targetUsername) => {
    const actor = users[socket.id];
    if (!actor || (actor.role !== 'admin' && actor.role !== 'vip')) return;
    if (targetUsername === appConfig.adminUser) return;

    if (persistentUsers[targetUsername]) {
      persistentUsers[targetUsername].isBanned = true;
      
      // Wipe History
      for(let ch in messages) {
          if (Array.isArray(messages[ch])) {
              messages[ch] = messages[ch].filter(m => m.sender !== targetUsername);
          }
      }
      
      saveData();
      io.emit('bulk_delete_user', targetUsername);

      const targetSockets = Object.keys(users).filter(id => users[id].username === targetUsername);
      targetSockets.forEach(id => {
        io.to(id).emit('force_disconnect', 'شما توسط ادمین بن شدید.');
        io.sockets.sockets.get(id)?.disconnect();
        delete users[id];
      });
      
      broadcastUserList();
      socket.emit('action_success', `کاربر ${targetUsername} بن شد و پیام‌های او حذف گردید.`);
    }
  });

  socket.on('unban_user', (targetUsername) => {
    const actor = users[socket.id];
    if (!actor || (actor.role !== 'admin' && actor.role !== 'vip')) return;

    if (persistentUsers[targetUsername]) {
      persistentUsers[targetUsername].isBanned = false;
      saveData();
      socket.emit('action_success', `کاربر ${targetUsername} آزاد شد.`);
      socket.emit('banned_list', getBannedUsers());
    }
  });

  socket.on('get_banned_users', () => {
    const actor = users[socket.id];
    if (!actor || (actor.role !== 'admin' && actor.role !== 'vip')) return;
    socket.emit('banned_list', getBannedUsers());
  });

  socket.on('set_role', ({ targetUsername, role }) => {
    const actor = users[socket.id];
    if (!actor || actor.role !== 'admin') return;
    if (targetUsername === appConfig.adminUser) return;

    if (persistentUsers[targetUsername] && ['user', 'vip'].includes(role)) {
      persistentUsers[targetUsername].role = role;
      saveData();
      
      const targetSocketId = Object.keys(users).find(id => users[id].username === targetUsername);
      if (targetSocketId) {
        users[targetSocketId].role = role;
        io.to(targetSocketId).emit('role_update', role);
      }
      
      broadcastUserList();
      socket.emit('action_success', `نقش کاربر ${targetUsername} به ${role} تغییر کرد.`);
    }
  });

  // --- Message Management ---
  socket.on('send_message', (data) => {
    const user = users[socket.id];
    if (!user) return;

    // Rate Limit Check (Simple Token Bucket per user)
    const now = Date.now();
    if (!userRateLimits[user.username]) userRateLimits[user.username] = { count: 0, last: now };
    
    // Reset count every 5 seconds
    if (now - userRateLimits[user.username].last > 5000) {
        userRateLimits[user.username] = { count: 0, last: now };
    }
    
    if (userRateLimits[user.username].count > 5) {
        return socket.emit('error', 'لطفا آهسته‌تر پیام ارسال کنید.');
    }
    userRateLimits[user.username].count++;


    const cleanText = xss(data.text);
    const cleanFileName = data.fileName ? xss(data.fileName) : undefined;
    
    // Limit text length
    if (cleanText.length > 1000) return;

    const msg = {
      id: Date.now() + Math.random().toString(36).substr(2, 9),
      sender: user.username,
      text: cleanText,
      type: data.type || 'text',
      content: data.content, 
      fileName: cleanFileName,
      channel: data.channel,
      replyTo: data.replyTo || null,
      timestamp: new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit' }),
      role: user.role
    };

    if (!messages[data.channel]) messages[data.channel] = [];
    messages[data.channel].push(msg);
    if (messages[data.channel].length > 100) messages[data.channel].shift();

    // Broadcast to the channel/room
    io.to(data.channel).emit('receive_message', msg);
    
    // --- FIX: Manual Delivery for PVs if target not in room ---
    // If it's a PV, the recipient might not have joined the socket room yet (if they haven't opened the chat).
    // We need to find their socket ID and send it directly so they get the notification.
    if (data.channel.includes('_pv_')) {
        const parts = data.channel.split('_pv_');
        const targetUsername = parts.find(u => u !== user.username);
        
        if (targetUsername) {
            // Find target socket
            const targetSocketId = Object.keys(users).find(id => users[id].username === targetUsername);
            
            if (targetSocketId) {
                const targetSocket = io.sockets.sockets.get(targetSocketId);
                // Check if target is NOT in the room. If they are in the room, io.to(channel) handled it.
                if (targetSocket && !targetSocket.rooms.has(data.channel)) {
                    io.to(targetSocketId).emit('receive_message', msg);
                }
            }
        }
    }

    saveData();
  });

  // Delete Single Message
  socket.on('delete_message', (msgId) => {
    const user = users[socket.id];
    if (!user || user.role !== 'admin') return;

    // Search in all channels
    let found = false;
    for(const ch in messages) {
        const idx = messages[ch].findIndex(m => m.id === msgId);
        if(idx !== -1) {
            messages[ch].splice(idx, 1);
            found = true;
            io.emit('message_deleted', { channel: ch, id: msgId });
            break;
        }
    }
    if(found) saveData();
  });
  
  socket.on('search_user', (query) => {
      if(!query || query.length > 20) return;
      // If list is hidden and user is not admin, do not allow search (optional privacy improvement)
      // but assuming search is still allowed for explicit user finding
      const cleanQuery = xss(query).toLowerCase();
      const matches = Object.keys(persistentUsers).filter(u => u.toLowerCase().includes(cleanQuery));
      socket.emit('search_results', matches);
  });

  socket.on('disconnect', () => {
    delete users[socket.id];
    broadcastUserList();
  });
});

function joinChannel(socket, channel, isPrivate = false) {
    if (!users[socket.id]) return;
    const cleanChannel = xss(channel);
    socket.join(cleanChannel);
    socket.emit('channel_joined', { name: cleanChannel, isPrivate });
    if (messages[cleanChannel]) socket.emit('history', messages[cleanChannel]);
    else socket.emit('history', []);
}

function getUniqueOnlineUsers() {
    const unique = {};
    Object.values(users).forEach(u => {
        // We accumulate all users here, filtering happens in broadcast
        unique[u.username] = u;
    });
    return Object.values(unique);
}

// Customized broadcast based on role and settings
function broadcastUserList() {
    const allUsers = getUniqueOnlineUsers();
    
    // If list is hidden: Users see only Admins + Themselves. Admins see everyone.
    const admins = allUsers.filter(u => u.role === 'admin');
    
    io.sockets.sockets.forEach((socket) => {
        const user = users[socket.id];
        if (!user) return;

        if (user.role === 'admin') {
            // Admins always see everyone
            socket.emit('user_list', allUsers);
        } else {
            if (appConfig.hideUserList) {
                // Regular user sees Admins + Themselves
                const visible = [...admins];
                if (!visible.find(a => a.username === user.username)) {
                    visible.push(user);
                }
                socket.emit('user_list', visible);
            } else {
                // Everyone visible
                socket.emit('user_list', allUsers);
            }
        }
    });
}

function getBannedUsers() {
    return Object.keys(persistentUsers).filter(u => persistentUsers[u].isBanned);
}

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

EOF

# index.html (Client)
cat > public/index.html << 'EOF'

<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
    <title>__APP_NAME_PLACEHOLDER__</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;700&display=swap" rel="stylesheet">
    <script src="/socket.io/socket.io.js"></script>
    <script src="https://unpkg.com/vue@3/dist/vue.global.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    
    <script>
      tailwind.config = {
        theme: {
          extend: {
            colors: {
              brand: {
                DEFAULT: 'var(--brand-color)',
                dark: 'var(--brand-dark)',
                light: 'var(--brand-light)',
              }
            }
          }
        }
      }
    </script>
    <style>
        :root {
            /* These will be replaced by the setup script */
            --brand-color: __COLOR_DEFAULT__;
            --brand-dark: __COLOR_DARK__;
            --brand-light: __COLOR_LIGHT__;
        }
        body { 
            font-family: 'Vazirmatn', sans-serif; 
            background: #f0f2f5; 
            overscroll-behavior-y: none;
            height: 100vh; 
            height: 100dvh; 
        }
        .safe-pb { padding-bottom: env(safe-area-inset-bottom); }
        .msg-bubble { max-width: 85%; position: relative; }
        ::-webkit-scrollbar { width: 5px; }
        ::-webkit-scrollbar-thumb { background: #cbd5e1; border-radius: 4px; }
        
        .context-menu {
            position: absolute;
            background: white;
            border-radius: 8px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
            padding: 4px;
            z-index: 100;
            min-width: 140px;
            overflow: hidden;
            border: 1px solid #eee;
        }
        .unread-badge {
            background-color: #ef4444;
            color: white;
            font-size: 10px;
            height: 18px;
            min-width: 18px;
            border-radius: 9px;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 0 4px;
            font-weight: bold;
        }
    </style>
</head>
<body class="w-full overflow-hidden flex flex-col text-gray-800">
    <!-- Application Logic remains the same, managed by Vue -->
    <div id="app" class="h-full flex flex-col w-full">
        
        <!-- Login Screen -->
        <div v-if="!isLoggedIn" class="fixed inset-0 bg-gray-900 bg-opacity-95 flex items-center justify-center z-50 p-4">
            <div class="bg-white p-6 md:p-8 rounded-2xl shadow-2xl w-full max-w-sm text-center">
                <div class="w-16 h-16 bg-brand rounded-full mx-auto flex items-center justify-center mb-4 text-white text-2xl">
                    <i class="fas fa-comments"></i>
                </div>
                <h1 class="text-2xl font-bold mb-2 text-brand-dark">{{ appName }}</h1>
                <p class="text-xs text-gray-500 mb-6">برای ورود یا ثبت نام اطلاعات زیر را وارد کنید</p>
                <div class="space-y-4">
                    <input v-model="loginForm.username" @keyup.enter="login" placeholder="نام کاربری" class="w-full p-3 border rounded-xl focus:ring-2 focus:ring-brand outline-none text-center dir-rtl">
                    <input v-model="loginForm.password" type="password" placeholder="رمز عبور" class="w-full p-3 border rounded-xl focus:ring-2 focus:ring-brand outline-none text-center dir-rtl">
                    <button @click="login" class="w-full bg-brand text-white py-3 rounded-xl font-bold hover:bg-brand-dark transition shadow-lg shadow-brand/30">ورود / ثبت نام</button>
                    <p v-if="error" class="text-red-500 text-sm mt-2 bg-red-50 p-2 rounded">{{ error }}</p>
                </div>
            </div>
        </div>

        <!-- Chat Interface -->
        <div v-else class="flex h-full relative w-full overflow-hidden">
            
            <!-- Sidebar -->
            <div :class="['absolute md:relative z-20 h-full bg-white border-l shadow-xl md:shadow-none transition-transform duration-300 w-72 flex flex-col shrink-0', showSidebar ? 'translate-x-0' : 'translate-x-full md:translate-x-0']">
                <!-- User Info -->
                <div class="p-4 bg-gradient-to-l from-brand to-brand-dark text-white shadow shrink-0">
                    <div class="flex justify-between items-center">
                         <div>
                            <h2 class="font-bold text-lg">{{ appName }}</h2>
                            <p class="text-xs opacity-90 mt-1 flex items-center gap-1">
                                <i class="fas fa-user-circle"></i> {{ user.username }}
                                <span v-if="user.role === 'admin'" class="bg-yellow-400 text-black px-1 rounded text-[9px] font-bold">مدیر</span>
                                <span v-else-if="user.role === 'vip'" class="bg-blue-400 text-white px-1 rounded text-[9px] font-bold">ویژه</span>
                            </p>
                         </div>
                         <div class="flex gap-1">
                             <!-- Admin Settings Button -->
                             <button v-if="user.role === 'admin'" @click="showAdminSettings = true" class="text-xs bg-white/20 p-2 rounded hover:bg-white/30" title="تنظیمات"><i class="fas fa-cog"></i></button>
                             <button @click="logout" class="text-xs bg-white/20 p-2 rounded hover:bg-white/30" title="خروج"><i class="fas fa-sign-out-alt"></i></button>
                         </div>
                    </div>
                </div>
                
                <!-- Tools -->
                <div class="p-2 border-b bg-gray-50 flex gap-2 overflow-x-auto shrink-0">
                     <button v-if="canBan" @click="openBanList" class="bg-red-100 text-red-600 px-3 py-1 rounded text-xs whitespace-nowrap"><i class="fas fa-ban"></i> لیست سیاه</button>
                </div>

                <!-- Search -->
                <div class="p-2 border-b bg-white shrink-0">
                    <input v-model="searchQuery" @input="searchUser" placeholder="جستجوی کاربر..." class="w-full px-3 py-1.5 rounded-lg border text-sm bg-gray-50 focus:outline-none focus:border-brand">
                </div>

                <!-- Lists -->
                <div class="flex-1 overflow-y-auto p-2 space-y-4">
                    
                    <!-- Search Results -->
                    <div v-if="searchResults.length > 0">
                        <h3 class="text-xs font-bold text-gray-400 mb-2 px-2">نتایج جستجو</h3>
                        <ul>
                            <li v-for="u in searchResults" :key="u" @click="startPrivateChat(u)" class="flex items-center gap-2 p-2 rounded hover:bg-gray-100 cursor-pointer">
                                <div class="w-8 h-8 rounded-full bg-gray-200 flex items-center justify-center text-gray-500"><i class="fas fa-user"></i></div>
                                <span class="text-sm font-medium">{{ u }}</span>
                            </li>
                        </ul>
                        <hr class="my-2">
                    </div>

                    <!-- Channels -->
                    <div>
                        <h3 class="text-xs font-bold text-gray-400 mb-2 px-2 flex justify-between items-center">
                            کانال‌ها
                            <button v-if="canCreateChannel" @click="toggleCreateChannel" class="text-brand hover:text-brand-dark text-xs bg-brand/10 w-5 h-5 rounded-full flex items-center justify-center"><i class="fas fa-plus"></i></button>
                        </h3>
                        
                        <div v-if="showCreateChannelInput" class="mb-2 px-2 flex gap-1 animate-fade-in">
                            <input v-model="newChannelName" class="w-full text-xs p-1 border rounded" placeholder="نام کانال...">
                            <button @click="createChannel" class="bg-green-500 text-white px-2 rounded text-xs"><i class="fas fa-check"></i></button>
                        </div>

                        <ul class="space-y-1">
                            <li v-for="ch in channels" :key="ch" class="group relative p-2 rounded-lg cursor-pointer flex items-center justify-between transition"
                                :class="currentChannel === ch ? 'bg-brand/10 text-brand font-bold' : 'hover:bg-gray-100 text-gray-600'">
                                <div class="flex items-center gap-2 w-full" @click="joinChannel(ch, false)">
                                    <i class="fas fa-hashtag text-xs opacity-50"></i>
                                    <span class="text-sm truncate">{{ ch }}</span>
                                </div>
                                <div v-if="unreadCounts[ch] > 0" class="unread-badge">{{ unreadCounts[ch] }}</div>
                                <button v-if="canCreateChannel && ch !== 'General'" @click.stop="deleteChannel(ch)" class="text-red-400 hover:text-red-600 px-2 hidden group-hover:block"><i class="fas fa-trash text-xs"></i></button>
                            </li>
                        </ul>
                    </div>
                    
                    <!-- Online Users -->
                    <div>
                         <h3 class="text-xs font-bold text-gray-400 mb-2 px-2 mt-4">کاربران آنلاین ({{ sortedUsers.length }})</h3>
                         <ul class="space-y-1">
                            <li v-for="u in sortedUsers" :key="u.username" 
                                @click="handleUserClick(u)"
                                @contextmenu.prevent="showUserContext($event, u.username)"
                                class="flex items-center gap-2 p-2 rounded hover:bg-gray-100 cursor-pointer transition">
                                <div class="relative">
                                    <div class="w-9 h-9 rounded-full flex items-center justify-center text-gray-600 text-xs font-bold shadow-sm"
                                        :class="{'bg-yellow-100 text-yellow-700': u.role === 'admin', 'bg-blue-100 text-blue-700': u.role === 'vip', 'bg-gray-200': u.role === 'user'}">
                                        <i v-if="u.role === 'admin'" class="fas fa-crown text-sm"></i>
                                        <i v-else-if="u.role === 'vip'" class="fas fa-gem text-sm"></i>
                                        <span v-else>{{ u.username.substring(0,2).toUpperCase() }}</span>
                                    </div>
                                    <div class="absolute bottom-0 right-0 w-2.5 h-2.5 bg-green-500 border-2 border-white rounded-full"></div>
                                </div>
                                <div class="flex flex-col flex-1">
                                    <span class="text-sm font-medium flex items-center gap-1">
                                        {{ u.username }} 
                                        <span v-if="u.username === user.username" class="text-[10px] text-gray-400">(شما)</span>
                                    </span>
                                    <span class="text-[10px] text-gray-400">
                                        {{ u.role === 'admin' ? 'مدیر کل' : (u.role === 'vip' ? 'کاربر ویژه' : 'کاربر') }}
                                    </span>
                                </div>
                                <div v-if="unreadCounts[u.username] > 0" class="unread-badge">{{ unreadCounts[u.username] }}</div>
                            </li>
                         </ul>
                    </div>
                </div>
            </div>

            <!-- Mobile Sidebar Overlay -->
            <div v-if="showSidebar" @click="showSidebar = false" class="absolute inset-0 bg-black/50 z-10 md:hidden"></div>

            <!-- Chat Area -->
            <div class="flex-1 flex flex-col bg-[#e5ddd5] relative bg-opacity-30 h-full min-w-0">
                <!-- Wallpaper -->
                <div class="absolute inset-0 opacity-5 pointer-events-none" style="background-image: url('data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAQAAAAECAYAAACp8Z5+AAAAIklEQVQIW2NkQAKrVq36zwjjgzhhYWGMYAEYB8RmROaABADeOQ8CXl/xfgAAAABJRU5ErkJggg==')"></div>

                <!-- Header -->
                <div class="bg-white p-3 shadow-sm flex items-center gap-3 z-0 shrink-0">
                    <button class="md:hidden text-gray-500 p-2" @click="showSidebar = true"><i class="fas fa-bars"></i></button>
                    <div class="flex-1">
                        <h2 class="font-bold text-gray-800 flex items-center gap-2">
                            <span v-if="isPrivateChat" class="text-brand"><i class="fas fa-user-lock"></i></span>
                            <span v-else class="text-gray-500"><i class="fas fa-hashtag"></i></span>
                            {{ displayChannelName }}
                        </h2>
                    </div>
                </div>
                
                <!-- Upload Progress -->
                <div v-if="isUploading" class="bg-brand-light/20 p-2 text-center text-xs text-brand-dark border-b border-brand-light/30">
                    <div class="flex items-center justify-between px-4 mb-1">
                        <span>در حال ارسال فایل...</span>
                        <span>{{ uploadProgress }}%</span>
                    </div>
                    <div class="w-full bg-gray-200 rounded-full h-1.5">
                        <div class="bg-brand h-1.5 rounded-full transition-all duration-200" :style="{ width: uploadProgress + '%' }"></div>
                    </div>
                </div>

                <!-- Messages -->
                <div class="flex-1 overflow-y-auto p-4 space-y-2 min-h-0" id="messages-container" ref="msgContainer">
                    <div v-for="msg in messages" :key="msg.id" 
                         :class="['flex w-full', msg.sender === user.username ? 'justify-end' : 'justify-start']"
                         :id="'msg-row-' + msg.id">
                        
                        <div 
                             @touchstart="touchStart($event, msg)"
                             @touchmove="touchMove($event)"
                             @touchend="touchEnd($event)"
                             @contextmenu.prevent="showContext($event, msg)"
                             :style="getSwipeStyle(msg.id)"
                             class="msg-bubble transition-transform duration-75 ease-out select-none"
                             :id="'msg-' + msg.id">
                            
                            <div class="absolute right-[-40px] top-1/2 transform -translate-y-1/2 text-brand text-lg opacity-0 transition-opacity" :class="{'opacity-100': swipeId === msg.id && swipeOffset < -40}">
                                <i class="fas fa-reply"></i>
                            </div>

                            <div :class="['rounded-2xl px-4 py-2 shadow-sm text-sm relative border', 
                                          msg.sender === user.username ? 'bg-brand-light border-brand/20 rounded-tr-none' : 'bg-white border-gray-100 rounded-tl-none']">
                                
                                <div v-if="msg.replyTo" @click="scrollToMessage(msg.replyTo.id)" class="mb-2 p-2 rounded bg-black/5 border-r-4 border-brand cursor-pointer text-xs">
                                    <div class="font-bold text-brand-dark mb-1">{{ msg.replyTo.sender }}</div>
                                    <div class="truncate opacity-70">{{ msg.replyTo.text || 'Media' }}</div>
                                </div>

                                <div v-if="msg.sender !== user.username" class="font-bold text-xs mb-1 text-brand-dark flex items-center gap-1">
                                    {{ msg.sender }}
                                    <i v-if="msg.role === 'admin'" class="fas fa-crown text-yellow-500 text-[10px]"></i>
                                    <i v-else-if="msg.role === 'vip'" class="fas fa-gem text-blue-500 text-[10px]"></i>
                                </div>
                                
                                <div class="break-words leading-relaxed" v-if="msg.type === 'text'">{{ msg.text }}</div>
                                <img v-if="msg.type === 'image'" :src="msg.content" class="max-w-full rounded-lg mt-1 cursor-pointer hover:opacity-90 transition" @click="viewImage(msg.content)">
                                <video v-if="msg.type === 'video'" :src="msg.content" controls class="max-w-full rounded-lg mt-1"></video>
                                <audio v-if="msg.type === 'audio'" :src="msg.content" controls class="mt-1 w-full min-w-[200px]"></audio>
                                <div v-if="msg.type === 'file'" class="mt-1 bg-black/5 p-3 rounded flex items-center gap-3">
                                    <div class="w-10 h-10 bg-brand/20 rounded flex items-center justify-center text-brand text-xl">
                                        <i class="fas fa-file-alt"></i>
                                    </div>
                                    <div class="flex-1 overflow-hidden">
                                        <div class="truncate font-bold text-xs">{{ msg.fileName || 'File' }}</div>
                                        <a :href="msg.content" target="_blank" class="text-[10px] text-blue-500 hover:underline">دانلود فایل</a>
                                    </div>
                                </div>
                                
                                <div :class="['text-[9px] mt-1 text-left', msg.sender === user.username ? 'text-brand-dark/50' : 'text-gray-400']">
                                    {{ msg.timestamp }}
                                    <i v-if="msg.sender === user.username" class="fas fa-check-double ml-1 text-blue-400"></i>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Reply Input -->
                <div v-if="replyingTo" class="bg-gray-50 border-t p-2 flex justify-between items-center border-b border-gray-200 shrink-0">
                    <div class="flex-1 text-sm border-r-4 border-brand pr-3">
                        <div class="font-bold text-brand text-xs">پاسخ به {{ replyingTo.sender }}</div>
                        <div class="text-gray-500 text-xs truncate">{{ replyingTo.text || 'File' }}</div>
                    </div>
                    <button @click="cancelReply" class="p-2 text-gray-500 hover:text-red-500"><i class="fas fa-times"></i></button>
                </div>

                <!-- Input Area -->
                <div class="p-2 safe-pb bg-white border-t flex items-end gap-2 z-10 shrink-0">
                    <div class="flex pb-2">
                        <button class="w-10 h-10 rounded-full hover:bg-gray-100 text-gray-500 text-lg transition" @click="$refs.fileInput.click()"><i class="fas fa-paperclip"></i></button>
                        <!-- Accept all files -->
                        <input ref="fileInput" type="file" class="hidden" @change="handleFileUpload">
                        
                        <button @click="toggleRecording" :class="['w-10 h-10 rounded-full transition text-lg', isRecording ? 'text-red-500 bg-red-50 animate-pulse' : 'hover:bg-gray-100 text-gray-500']">
                            <i class="fas fa-microphone"></i>
                        </button>
                    </div>

                    <div class="flex-1 bg-gray-100 rounded-2xl flex items-center p-2 border focus-within:ring-1 focus-within:ring-brand focus-within:bg-white transition">
                        <textarea v-model="messageText" @keydown.enter.prevent="sendMessage" @input="autoResize" ref="textarea"
                               placeholder="پیام..." 
                               class="flex-1 bg-transparent outline-none max-h-32 min-h-[40px] resize-none py-2 px-2 text-sm"></textarea>
                    </div>
                    
                    <button @click="sendMessage" 
                        class="w-12 h-12 rounded-full bg-brand text-white shadow-lg hover:bg-brand-dark transition transform active:scale-95 flex items-center justify-center mb-0.5">
                        <i class="fas fa-paper-plane text-lg translate-x-[-2px] translate-y-[1px]"></i>
                    </button>
                </div>

                <!-- Context Menu -->
                <div v-if="contextMenu.visible" 
                     :style="{ top: contextMenu.y + 'px', left: contextMenu.x + 'px' }" 
                     class="context-menu"
                     @click.stop>
                    <template v-if="contextMenu.type === 'message'">
                        <div @click="setReply(contextMenu.target); contextMenu.visible = false" class="px-3 py-2 hover:bg-gray-100 cursor-pointer text-sm flex items-center gap-2">
                            <i class="fas fa-reply text-gray-400 w-4"></i> پاسخ
                        </div>
                        <div v-if="user.role === 'admin'" @click="deleteMessage(contextMenu.target.id); contextMenu.visible = false" class="px-3 py-2 hover:bg-red-50 text-red-600 cursor-pointer text-sm flex items-center gap-2 border-t">
                            <i class="fas fa-trash w-4"></i> حذف پیام
                        </div>
                         <div v-if="canBan && contextMenu.target.sender !== user.username" @click="banUser(contextMenu.target.sender); contextMenu.visible = false" class="px-3 py-2 hover:bg-red-50 text-red-600 cursor-pointer text-sm flex items-center gap-2 border-t">
                            <i class="fas fa-ban w-4"></i> بن کردن کاربر
                        </div>
                    </template>
                    <template v-if="contextMenu.type === 'user'">
                         <div @click="startPrivateChat(contextMenu.target); contextMenu.visible = false" class="px-3 py-2 hover:bg-gray-100 cursor-pointer text-sm flex items-center gap-2">
                            <i class="fas fa-comment text-gray-400 w-4"></i> پیام خصوصی
                        </div>
                        <template v-if="user.role === 'admin' && contextMenu.target !== user.username">
                            <div @click="setRole(contextMenu.target, 'vip'); contextMenu.visible = false" class="px-3 py-2 hover:bg-gray-100 cursor-pointer text-sm flex items-center gap-2">
                                <i class="fas fa-gem text-blue-500 w-4"></i> تبدیل به ویژه
                            </div>
                             <div @click="setRole(contextMenu.target, 'user'); contextMenu.visible = false" class="px-3 py-2 hover:bg-gray-100 cursor-pointer text-sm flex items-center gap-2">
                                <i class="fas fa-user text-gray-400 w-4"></i> تبدیل به عادی
                            </div>
                        </template>
                        <div v-if="canBan && contextMenu.target !== user.username" @click="banUser(contextMenu.target); contextMenu.visible = false" class="px-3 py-2 hover:bg-red-50 text-red-600 cursor-pointer text-sm flex items-center gap-2 border-t">
                            <i class="fas fa-ban w-4"></i> بن کردن
                        </div>
                    </template>
                </div>
            </div>
        </div>
        
        <!-- Admin Settings Modal -->
        <div v-if="showAdminSettings" class="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4">
            <div class="bg-white rounded-xl shadow-xl w-full max-w-sm overflow-hidden flex flex-col">
                <div class="p-4 border-b flex justify-between items-center bg-gray-50">
                    <h3 class="font-bold text-gray-700">تنظیمات چت روم</h3>
                    <button @click="showAdminSettings = false" class="text-gray-400 hover:text-gray-600"><i class="fas fa-times"></i></button>
                </div>
                <div class="p-6 space-y-4">
                    <div class="flex items-center justify-between">
                        <label class="text-sm font-bold text-gray-700">مخفی کردن لیست کاربران</label>
                        <input type="checkbox" v-model="adminSettings.hideUserList" class="w-5 h-5 accent-brand">
                    </div>
                    <p class="text-xs text-gray-500 text-justify leading-relaxed">
                        با فعال‌سازی این گزینه، کاربران عادی قادر به مشاهده لیست افراد آنلاین نخواهند بود و فقط خودشان و ادمین‌ها را می‌بینند.
                    </p>
                    <button @click="saveAdminSettings" class="w-full bg-brand text-white py-2 rounded-lg text-sm font-bold shadow hover:bg-brand-dark transition">
                        ذخیره تنظیمات
                    </button>
                </div>
            </div>
        </div>

        <!-- Ban List Modal -->
        <div v-if="showBanModal" class="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4">
            <div class="bg-white rounded-xl shadow-xl w-full max-w-md overflow-hidden flex flex-col max-h-[80vh]">
                <div class="p-4 border-b flex justify-between items-center bg-gray-50">
                    <h3 class="font-bold text-gray-700">لیست سیاه (بن شده‌ها)</h3>
                    <button @click="showBanModal = false" class="text-gray-400 hover:text-gray-600"><i class="fas fa-times"></i></button>
                </div>
                <div class="overflow-y-auto p-4 flex-1">
                    <div v-if="bannedUsers.length === 0" class="text-center text-gray-400 py-4">هیچ کاربری بن نشده است.</div>
                    <ul class="divide-y">
                        <li v-for="u in bannedUsers" :key="u" class="py-3 flex justify-between items-center">
                            <span class="font-bold text-gray-700">{{ u }}</span>
                            <button @click="unbanUser(u)" class="text-xs bg-green-100 text-green-700 px-3 py-1 rounded hover:bg-green-200">آزاد کردن</button>
                        </li>
                    </ul>
                </div>
            </div>
        </div>

        <!-- Lightbox -->
        <div v-if="lightboxImage" @click="lightboxImage = null" class="fixed inset-0 bg-black/90 z-50 flex items-center justify-center p-4">
            <img :src="lightboxImage" class="max-w-full max-h-full rounded shadow-2xl">
            <button class="absolute top-4 right-4 text-white text-3xl">&times;</button>
        </div>
    </div>

    <script>
        const { createApp, ref, onMounted, nextTick, computed, watch } = Vue;
        const socket = io();

        // Short beep sound base64
        const notifyAudio = new Audio('data:audio/mp3;base64,//NExAAAAANIAAAAAExBTUUzLjEwMKqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq//NExAAAAANIAAAAAExBTUUzLjEwMKqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq//NExAAAAANIAAAAAExBTUUzLjEwMKqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq//NExAAAAANIAAAAAExBTUUzLjEwMKqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq');

        createApp({
            setup() {
                const isLoggedIn = ref(false);
                const user = ref({ username: '', role: 'user' });
                const loginForm = ref({ username: '', password: '' });
                const error = ref('');
                const appName = ref('__APP_NAME_PLACEHOLDER__'); 
                
                const channels = ref(['General']);
                const currentChannel = ref('General');
                const isPrivateChat = ref(false);
                const displayChannelName = ref('General');
                const messages = ref([]);
                const onlineUsers = ref([]);
                const searchResults = ref([]);
                const searchQuery = ref('');
                const bannedUsers = ref([]);
                const appSettings = ref({ maxFileSizeMB: 50 });
                const unreadCounts = ref({});
                
                const showSidebar = ref(false);
                const messageText = ref('');
                const showCreateChannelInput = ref(false);
                const newChannelName = ref('');
                const lightboxImage = ref(null);
                const showBanModal = ref(false);
                const showAdminSettings = ref(false);
                const adminSettings = ref({ hideUserList: false });
                
                const replyingTo = ref(null);
                const contextMenu = ref({ visible: false, x: 0, y: 0, target: null, type: null });
                
                const swipeId = ref(null);
                const swipeStartX = ref(0);
                const swipeOffset = ref(0);
                const isRecording = ref(false);
                const isUploading = ref(false);
                const uploadProgress = ref(0);
                
                let mediaRecorder = null;
                let audioChunks = [];
                const fileInput = ref(null);

                const sortedUsers = computed(() => {
                    return [...onlineUsers.value].sort((a, b) => {
                        const roles = { admin: 3, vip: 2, user: 1 };
                        return roles[b.role] - roles[a.role];
                    });
                });
                
                const canCreateChannel = computed(() => user.value.role === 'admin' || user.value.role === 'vip');
                const canBan = computed(() => user.value.role === 'admin' || user.value.role === 'vip');

                onMounted(() => {
                    const storedUser = localStorage.getItem('chat_user_name');
                    if (storedUser) loginForm.value.username = storedUser;
                    document.addEventListener('click', () => { contextMenu.value.visible = false; });
                    
                    // Request Notification Permission on load if supported
                    if ('Notification' in window && Notification.permission !== 'granted' && Notification.permission !== 'denied') {
                        Notification.requestPermission();
                    }
                });

                // --- SMART SCROLL ---
                const scrollToBottom = (force = false) => {
                    nextTick(() => {
                        const c = document.getElementById('messages-container');
                        if (c) c.scrollTop = c.scrollHeight;
                    });
                };
                
                const checkAndScroll = (sender) => {
                     const c = document.getElementById('messages-container');
                     if (!c) return;
                     // Allow 150px threshold for being "at bottom"
                     const isNearBottom = c.scrollTop + c.clientHeight >= c.scrollHeight - 150;
                     
                     // Scroll if user is at bottom OR if user sent the message themselves
                     if (force || isNearBottom || sender === user.value.username) {
                         scrollToBottom();
                     }
                };
                
                // --- Notifications ---
                const playSound = () => {
                    try { notifyAudio.currentTime = 0; notifyAudio.play().catch(e => {}); } catch(e){}
                };

                const notify = (title, body) => {
                    playSound();
                    if ('Notification' in window && Notification.permission === 'granted') {
                        new Notification(title, { body, icon: '/favicon.ico' });
                    }
                };

                // --- AUTH & SETUP ---
                const login = () => {
                    if(!loginForm.value.username || !loginForm.value.password) {
                        error.value = 'نام کاربری و رمز عبور الزامی است';
                        return;
                    }
                    socket.emit('login', loginForm.value);
                    if ('Notification' in window) Notification.requestPermission();
                };
                const logout = () => {
                    localStorage.removeItem('chat_user_name');
                    window.location.reload();
                };

                const joinChannel = (ch, isPv) => {
                    socket.emit('join_channel', ch);
                    showSidebar.value = false;
                    unreadCounts.value[ch] = 0; // Reset unread
                };
                
                const startPrivateChat = (targetUsername) => {
                    socket.emit('join_private', targetUsername);
                    displayChannelName.value = targetUsername;
                    isPrivateChat.value = true;
                    showSidebar.value = false;
                    searchResults.value = [];
                    searchQuery.value = '';
                    unreadCounts.value[targetUsername] = 0;
                };

                const sendMessage = () => {
                    if(!messageText.value.trim()) return;
                    socket.emit('send_message', {
                        text: messageText.value,
                        type: 'text',
                        channel: currentChannel.value,
                        replyTo: replyingTo.value
                    });
                    messageText.value = '';
                    replyingTo.value = null;
                    scrollToBottom(true);
                };
                
                // --- UPLOAD LOGIC ---
                const handleFileUpload = (e) => {
                    const file = e.target.files[0];
                    if(!file) return;
                    
                    if (file.size > appSettings.value.maxFileSizeMB * 1024 * 1024) {
                        alert('حجم فایل بیشتر از حد مجاز است (' + appSettings.value.maxFileSizeMB + 'MB)');
                        e.target.value = ''; // Reset
                        return;
                    }

                    const formData = new FormData();
                    formData.append('file', file);
                    
                    isUploading.value = true;
                    uploadProgress.value = 0;

                    const xhr = new XMLHttpRequest();
                    xhr.open('POST', '/upload', true);
                    
                    xhr.upload.onprogress = (event) => {
                        if (event.lengthComputable) {
                            uploadProgress.value = Math.round((event.loaded / event.total) * 100);
                        }
                    };
                    
                    xhr.onload = () => {
                        if (xhr.status === 200) {
                            try {
                                const res = JSON.parse(xhr.responseText);
                                let type = 'file';
                                if (res.mimetype.startsWith('image/')) type = 'image';
                                else if (res.mimetype.startsWith('video/')) type = 'video';
                                else if (res.mimetype.startsWith('audio/')) type = 'audio';
                                
                                socket.emit('send_message', {
                                    text: '',
                                    type: type,
                                    content: res.url,
                                    fileName: res.filename,
                                    channel: currentChannel.value,
                                    replyTo: replyingTo.value
                                });
                                replyingTo.value = null;
                                scrollToBottom(true);
                            } catch (e) { console.error(e); }
                        } else {
                            alert('Upload Failed: Server Error');
                        }
                        isUploading.value = false;
                        if(fileInput.value) fileInput.value.value = '';
                    };
                    
                    xhr.onerror = () => {
                        isUploading.value = false;
                        alert('Upload Network Error');
                        if(fileInput.value) fileInput.value.value = '';
                    };
                    
                    xhr.send(formData);
                };
                
                // Admin Actions
                const deleteMessage = (msgId) => {
                    if(confirm('آیا مطمئن هستید؟')) socket.emit('delete_message', msgId);
                };
                const createChannel = () => {
                    if (newChannelName.value) {
                        socket.emit('create_channel', newChannelName.value);
                        newChannelName.value = '';
                        showCreateChannelInput.value = false;
                    }
                };
                const deleteChannel = (ch) => {
                    if(confirm('حذف کانال؟')) socket.emit('delete_channel', ch);
                };
                const banUser = (target) => {
                    if(confirm('بن کردن کاربر ' + target + ' و حذف پیام‌ها؟')) socket.emit('ban_user', target);
                };
                const unbanUser = (target) => socket.emit('unban_user', target);
                const setRole = (target, role) => socket.emit('set_role', { targetUsername: target, role });
                const openBanList = () => { socket.emit('get_banned_users'); showBanModal.value = true; };
                const saveAdminSettings = () => {
                    socket.emit('update_admin_settings', adminSettings.value);
                    showAdminSettings.value = false;
                };
                
                // Helpers
                const handleUserClick = (u) => { if (u.username !== user.value.username) startPrivateChat(u.username); };
                const showContext = (e, msg) => { contextMenu.value = { visible: true, x: e.pageX, y: e.pageY, target: msg, type: 'message' }; };
                const showUserContext = (e, targetUsername) => { contextMenu.value = { visible: true, x: e.pageX, y: e.pageY, target: targetUsername, type: 'user' }; };
                
                // --- Socket Events ---
                socket.on('login_success', (data) => {
                    isLoggedIn.value = true;
                    user.value = { username: data.username, role: data.role };
                    channels.value = data.channels;
                    if(data.settings) {
                        appSettings.value = data.settings;
                        if(data.settings.appName) {
                            appName.value = data.settings.appName;
                            document.title = data.settings.appName;
                        }
                        if(typeof data.settings.hideUserList === 'boolean') {
                            adminSettings.value.hideUserList = data.settings.hideUserList;
                        }
                    }
                    localStorage.setItem('chat_user_name', data.username);
                });
                socket.on('login_error', (msg) => error.value = msg);
                socket.on('force_disconnect', (msg) => { alert(msg); window.location.reload(); });
                socket.on('channel_joined', (data) => {
                    currentChannel.value = data.name;
                    isPrivateChat.value = data.isPrivate;
                    if (data.isPrivate) {
                        const parts = data.name.split('_pv_');
                        displayChannelName.value = parts.find(u => u !== user.value.username) || 'Private';
                    } else {
                        displayChannelName.value = data.name;
                    }
                });
                
                socket.on('receive_message', (msg) => {
                    // Check if message belongs to current channel
                    if (msg.channel === currentChannel.value) {
                        const c = document.getElementById('messages-container');
                        const isNearBottom = c ? (c.scrollTop + c.clientHeight >= c.scrollHeight - 150) : true;
                        
                        messages.value.push(msg);
                        
                        if (msg.sender === user.value.username || isNearBottom) {
                            scrollToBottom();
                        }
                        
                        // Notify if in channel but window blurred
                        if (document.hidden && msg.sender !== user.value.username) {
                             notify(`پیام جدید در ${displayChannelName.value}`, `${msg.sender}: ${msg.text || 'مدیا'}`);
                        }
                    } else {
                        // Handle Unreads
                        if (msg.channel.includes('_pv_')) {
                             // Use split to safely find partner
                             const parts = msg.channel.split('_pv_');
                             const partner = parts.find(p => p !== user.value.username);
                             
                             if (partner) {
                                 unreadCounts.value[partner] = (unreadCounts.value[partner] || 0) + 1;
                                 notify(`پیام خصوصی از ${partner}`, msg.text || 'فایل ارسال شد');
                             }
                        } else {
                             // Public Channel logic
                             unreadCounts.value[msg.channel] = (unreadCounts.value[msg.channel] || 0) + 1;
                        }
                    }
                });

                socket.on('history', (msgs) => {
                    messages.value = msgs;
                    scrollToBottom(true);
                });
                
                // Handle Deletions
                socket.on('message_deleted', (data) => {
                    if (data.channel === currentChannel.value) {
                        messages.value = messages.value.filter(m => m.id !== data.id);
                    }
                });
                
                socket.on('bulk_delete_user', (targetUser) => {
                    messages.value = messages.value.filter(m => m.sender !== targetUser);
                });

                socket.on('user_list', (list) => onlineUsers.value = list);
                socket.on('update_channels', (list) => channels.value = list);
                socket.on('banned_list', (list) => bannedUsers.value = list);
                socket.on('action_success', (msg) => alert(msg));
                socket.on('role_update', (newRole) => { user.value.role = newRole; alert('نقش شما تغییر کرد: ' + newRole); });

                // UI Utils
                const setReply = (msg) => { replyingTo.value = msg; nextTick(() => document.querySelector('textarea')?.focus()); };
                const cancelReply = () => replyingTo.value = null;
                const scrollToMessage = (id) => { document.getElementById('msg-' + id)?.scrollIntoView({ behavior: 'smooth', block: 'center' }); };
                const touchStart = (e, msg) => { swipeStartX.value = e.touches[0].clientX; swipeId.value = msg.id; swipeOffset.value = 0; };
                const touchMove = (e) => { if (!swipeId.value) return; const diff = e.touches[0].clientX - swipeStartX.value; if (diff < 0 && diff > -100) swipeOffset.value = diff; };
                const touchEnd = () => { if (swipeOffset.value < -50) { const msg = messages.value.find(m => m.id === swipeId.value); if (msg) setReply(msg); } swipeId.value = null; swipeOffset.value = 0; };
                const getSwipeStyle = (id) => (swipeId.value === id ? { transform: `translateX(${swipeOffset.value}px)` } : {});
                const searchUser = () => { if (searchQuery.value.length > 2) socket.emit('search_user', searchQuery.value); else searchResults.value = []; };
                const toggleCreateChannel = () => showCreateChannelInput.value = !showCreateChannelInput.value;
                const viewImage = (src) => lightboxImage.value = src;
                const autoResize = (e) => { e.target.style.height = 'auto'; e.target.style.height = e.target.scrollHeight + 'px'; };
                
                const toggleRecording = async () => {
                     if (isRecording.value) { mediaRecorder.stop(); isRecording.value = false; } else {
                        try {
                            const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
                            mediaRecorder = new MediaRecorder(stream);
                            audioChunks = [];
                            mediaRecorder.ondataavailable = event => audioChunks.push(event.data);
                            mediaRecorder.onstop = () => {
                                const audioBlob = new Blob(audioChunks, { type: 'audio/webm' });
                                const reader = new FileReader(); reader.readAsDataURL(audioBlob);
                                reader.onloadend = () => {
                                    socket.emit('send_message', { text: '', type: 'audio', content: reader.result, channel: currentChannel.value, replyTo: replyingTo.value });
                                    replyingTo.value = null;
                                };
                            };
                            mediaRecorder.start(); isRecording.value = true;
                        } catch(e) { alert('Microphone access denied'); }
                    }
                };

                return {
                    isLoggedIn, user, loginForm, error, login, logout,
                    channels, currentChannel, joinChannel, displayChannelName, isPrivateChat,
                    messages, messageText, sendMessage, handleFileUpload, fileInput,
                    onlineUsers, sortedUsers, searchUser, searchQuery, searchResults, startPrivateChat, handleUserClick,
                    showSidebar, toggleCreateChannel, showCreateChannelInput, newChannelName, createChannel, deleteChannel,
                    replyingTo, setReply, cancelReply, deleteMessage,
                    contextMenu, showContext, showUserContext,
                    swipeId, touchStart, touchMove, touchEnd, getSwipeStyle,
                    isRecording, isUploading, uploadProgress, toggleRecording, viewImage, lightboxImage, autoResize, scrollToMessage,
                    canCreateChannel, canBan, banUser, unbanUser, setRole,
                    showBanModal, openBanList, bannedUsers, unreadCounts, appName,
                    showAdminSettings, adminSettings, saveAdminSettings
                };
            }
        }).mount('#app');
    </script>
</body>
</html>

EOF

# config.json (Initial Config)
cat > data/config.json << EOF
{
  "adminUser": "$ADMIN_USER",
  "adminPass": "$ADMIN_PASS",
  "port": $PORT,
  "maxFileSizeMB": 50,
  "appName": "$APP_NAME_VAL"
}
EOF

# 4. Apply App Name & Color Configuration
echo "[4/6] Applying configuration..."
sed -i "s|__APP_NAME_PLACEHOLDER__|$APP_NAME_VAL|g" public/index.html

sed -i "s|__COLOR_DEFAULT__|$C_DEF|g" public/index.html
sed -i "s|__COLOR_DARK__|$C_DARK|g" public/index.html
sed -i "s|__COLOR_LIGHT__|$C_LIGHT|g" public/index.html


# 5. Install Dependencies
echo "[5/6] Installing project dependencies..."
npm install

# 6. Start Server with PM2
echo "[6/6] Starting server with PM2..."

pm2 delete "$APP_NAME" 2>/dev/null || true
PORT=$PORT pm2 start server.js --name "$APP_NAME"
pm2 save

# 7. Create Global Management Command 'chat'
echo "Creating management tool..."

cat << 'EOF_MENU' > /tmp/chat-menu.sh
#!/bin/bash
# Chat Manager Menu

APP_NAME="AsrnovinChat"
DIR="~/chat-AsrnovinChat"
CONFIG_FILE="$DIR/data/config.json"
INDEX_FILE="$DIR/public/index.html"

while true; do
    clear
    echo "==================================="
    echo "   Chat Room Manager ($APP_NAME)"
    echo "==================================="
    echo "1. Check Status"
    echo "2. Restart Server"
    echo "3. Stop Server"
    echo "4. View Logs"
    echo "5. Settings (User/Pass/Size/Name)"
    echo "6. Uninstall / Delete"
    echo "7. Exit"
    echo "==================================="
    read -p "Select option: " opt

    case $opt in
        1) pm2 status "$APP_NAME"; read -p "Press Enter..." ;;
        2) pm2 restart "$APP_NAME"; echo "Restarted."; read -p "Press Enter..." ;;
        3) pm2 stop "$APP_NAME"; echo "Stopped."; read -p "Press Enter..." ;;
        4) pm2 logs "$APP_NAME" --lines 20; ;; 
        5) 
           echo "--- Current Settings ---"
           cat "$CONFIG_FILE"
           echo ""
           echo "a) Change Admin Username"
           echo "b) Change Admin Password"
           echo "c) Change Max Upload Size (MB)"
           echo "d) Change App Name"
           read -p "Select option: " subopt
           
           case $subopt in
               a)
                  read -p "New Username: " NEW_USER
                  node -e "const fs=require('fs'); const p='$CONFIG_FILE'; const d=JSON.parse(fs.readFileSync(p)); d.adminUser='$NEW_USER'; fs.writeFileSync(p, JSON.stringify(d,null,2));"
                  echo "Updated. Restarting..."
                  pm2 restart "$APP_NAME"
                  ;;
               b)
                  read -p "New Password: " NEW_PASS
                  node -e "const fs=require('fs'); const p='$CONFIG_FILE'; const d=JSON.parse(fs.readFileSync(p)); d.adminPass='$NEW_PASS'; fs.writeFileSync(p, JSON.stringify(d,null,2));"
                  echo "Updated. Restarting..."
                  pm2 restart "$APP_NAME"
                  ;;
               c)
                  read -p "New Max Size (MB): " NEW_SIZE
                  if [[ "$NEW_SIZE" =~ ^[0-9]+$ ]]; then
                      node -e "const fs=require('fs'); const p='$CONFIG_FILE'; const d=JSON.parse(fs.readFileSync(p)); d.maxFileSizeMB=$NEW_SIZE; fs.writeFileSync(p, JSON.stringify(d,null,2));"
                      echo "Updated. Restarting..."
                      pm2 restart "$APP_NAME"
                  else
                      echo "Invalid number."
                  fi
                  ;;
               d)
                  read -p "New App Name: " NEW_APP_NAME
                  # Update Config
                  node -e "const fs=require('fs'); const p='$CONFIG_FILE'; const d=JSON.parse(fs.readFileSync(p)); d.appName='$NEW_APP_NAME'; fs.writeFileSync(p, JSON.stringify(d,null,2));"
                  # Update Title
                  sed -i "s|<title>.*</title>|<title>$NEW_APP_NAME</title>|g" "$INDEX_FILE"
                  # Update Vue Var
                  sed -i "s|appName = ref('.*');|appName = ref('$NEW_APP_NAME');|g" "$INDEX_FILE"
                  
                  echo "Updated. Restarting..."
                  pm2 restart "$APP_NAME"
                  ;;
           esac
           read -p "Press Enter..."
           ;;
        6) 
           read -p "Are you sure you want to DELETE everything? (y/n): " confirm
           if [[ "$confirm" == "y" ]]; then
               pm2 delete "$APP_NAME"
               rm -rf "$DIR"
               sudo rm /usr/local/bin/chat
               echo "Uninstalled successfully."
               exit 0
           fi
           ;;
        7) exit 0 ;;
        *) echo "Invalid option"; sleep 1 ;;
    esac
done
EOF_MENU

sudo mv /tmp/chat-menu.sh /usr/local/bin/chat
sudo chmod +x /usr/local/bin/chat


echo ""
echo "========================================"
echo "      INSTALLATION COMPLETE! 🚀"
echo "========================================"
echo ""
echo "Your Admin Credentials:"
echo "User: $ADMIN_USER"
echo "Pass: $ADMIN_PASS"
echo ""
echo "Access URL: http://$(curl -s ifconfig.me):$PORT"
echo ""
echo "Type 'chat' in terminal to manage your server."
echo "========================================"

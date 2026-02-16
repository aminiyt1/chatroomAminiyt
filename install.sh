#!/bin/bash

# ChatGen Pro - Interactive Installer
# App: asrno
# Folder: ~/chat-asrno

DIR="~/chat-asrno"
APP_NAME="asrno"

# 1. Interactive Input
echo "========================================"
echo "    ChatGen Pro Installer"
echo "========================================"
echo ""
echo "Please configure your chat server:"
echo ""

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
# Install PM2 globally
sudo npm install -g pm2

# 3. Create Files
echo "[3/6] Creating project files in $DIR..."
mkdir -p "$DIR"
mkdir -p "$DIR/public"
mkdir -p "$DIR/data"
cd "$DIR"

# package.json
cat > package.json << 'EOF'
{
  "name": "asrno",
  "version": "1.0.0",
  "main": "server.js",
  "scripts": {
    "start": "node server.js"
  },
  "dependencies": {
    "express": "^4.18.2",
    "socket.io": "^4.7.2"
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

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  maxHttpBufferSize: 1e8,
  cors: { origin: "*" }
});

// --- Configuration ---
// These values are injected by the installer via environment variables or fallback
const PORT = process.env.PORT || 3000;
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'admin123';

// --- Persistence ---
const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);

const USERS_FILE = path.join(DATA_DIR, 'users.json');
const MESSAGES_FILE = path.join(DATA_DIR, 'messages.json');
const CHANNELS_FILE = path.join(DATA_DIR, 'channels.json');

// Memory State
let users = {}; 
let persistentUsers = {}; 
let channels = ['General', 'Random'];
let messages = {}; 

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

app.use(express.static(path.join(__dirname, 'public')));

io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  socket.on('login', ({ username, password }) => {
    username = username.trim();
    
    // Check Admin
    if (username === ADMIN_USER) {
      if (password === ADMIN_PASS) {
        users[socket.id] = { username, role: 'admin' };
        socket.emit('login_success', { username, role: 'admin', channels });
        joinChannel(socket, 'General');
        io.emit('user_list', getUniqueOnlineUsers());
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
    
    socket.emit('login_success', { username, role, channels });
    joinChannel(socket, 'General');
    io.emit('user_list', getUniqueOnlineUsers());
  });

  socket.on('join_channel', (channel) => {
    joinChannel(socket, channel);
  });
  
  socket.on('join_private', (targetUser) => {
    const currentUser = users[socket.id];
    if (!currentUser) return;
    const roomName = [currentUser.username, targetUser].sort().join('_pv_');
    joinChannel(socket, roomName, true);
  });

  socket.on('create_channel', (channelName) => {
    const user = users[socket.id];
    if (user && (user.role === 'admin' || user.role === 'vip')) {
      if (!channels.includes(channelName)) {
        channels.push(channelName);
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

  socket.on('ban_user', (targetUsername) => {
    const actor = users[socket.id];
    if (!actor || (actor.role !== 'admin' && actor.role !== 'vip')) return;
    if (targetUsername === ADMIN_USER) return;

    if (persistentUsers[targetUsername]) {
      persistentUsers[targetUsername].isBanned = true;
      saveData();
      
      const targetSockets = Object.keys(users).filter(id => users[id].username === targetUsername);
      targetSockets.forEach(id => {
        io.to(id).emit('force_disconnect', 'شما توسط ادمین بن شدید.');
        io.sockets.sockets.get(id)?.disconnect();
        delete users[id];
      });
      
      io.emit('user_list', getUniqueOnlineUsers());
      socket.emit('action_success', `کاربر ${targetUsername} بن شد.`);
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
    if (targetUsername === ADMIN_USER) return;

    if (persistentUsers[targetUsername] && ['user', 'vip'].includes(role)) {
      persistentUsers[targetUsername].role = role;
      saveData();
      
      const targetSocketId = Object.keys(users).find(id => users[id].username === targetUsername);
      if (targetSocketId) {
        users[targetSocketId].role = role;
        io.to(targetSocketId).emit('role_update', role);
      }
      
      io.emit('user_list', getUniqueOnlineUsers());
      socket.emit('action_success', `نقش کاربر ${targetUsername} به ${role} تغییر کرد.`);
    }
  });

  socket.on('send_message', (data) => {
    const user = users[socket.id];
    if (!user) return;

    const msg = {
      id: Date.now() + Math.random().toString(36).substr(2, 9),
      sender: user.username,
      text: data.text,
      type: data.type || 'text',
      content: data.content,
      channel: data.channel,
      replyTo: data.replyTo || null,
      timestamp: new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit' }),
      role: user.role
    };

    if (!messages[data.channel]) messages[data.channel] = [];
    messages[data.channel].push(msg);
    if (messages[data.channel].length > 100) messages[data.channel].shift();

    io.to(data.channel).emit('receive_message', msg);
    saveData();
  });
  
  socket.on('search_user', (query) => {
      const matches = Object.keys(persistentUsers).filter(u => u.toLowerCase().includes(query.toLowerCase()));
      socket.emit('search_results', matches);
  });

  socket.on('disconnect', () => {
    delete users[socket.id];
    io.emit('user_list', getUniqueOnlineUsers());
  });
});

function joinChannel(socket, channel, isPrivate = false) {
    if (!users[socket.id]) return;
    socket.join(channel);
    socket.emit('channel_joined', { name: channel, isPrivate });
    if (messages[channel]) socket.emit('history', messages[channel]);
    else socket.emit('history', []);
}

function getUniqueOnlineUsers() {
    const unique = {};
    Object.values(users).forEach(u => {
        if (!unique[u.username] || (u.role === 'admin') || (u.role === 'vip' && unique[u.username].role === 'user')) {
            unique[u.username] = u;
        }
    });
    return Object.values(unique);
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
    <title>asrno</title>
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
            /* These placeholders will be replaced by the installer script */
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
        .swipe-active { transition: transform 0.1s; }
        .reply-indicator { display: none; }
        .swiping-right .reply-indicator { display: block; }
        ::-webkit-scrollbar { width: 5px; }
        ::-webkit-scrollbar-thumb { background: #cbd5e1; border-radius: 4px; }
        
        .context-menu {
            position: absolute;
            background: white;
            border-radius: 8px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            padding: 4px;
            z-index: 50;
            min-width: 140px;
            overflow: hidden;
            border: 1px solid #eee;
        }
    </style>
</head>
<body class="w-full overflow-hidden flex flex-col text-gray-800">
    <div id="app" class="h-full flex flex-col w-full">
        
        <!-- Login Screen -->
        <div v-if="!isLoggedIn" class="fixed inset-0 bg-gray-900 bg-opacity-95 flex items-center justify-center z-50 p-4">
            <div class="bg-white p-6 md:p-8 rounded-2xl shadow-2xl w-full max-w-sm text-center">
                <div class="w-16 h-16 bg-brand rounded-full mx-auto flex items-center justify-center mb-4 text-white text-2xl">
                    <i class="fas fa-comments"></i>
                </div>
                <h1 class="text-2xl font-bold mb-2 text-brand-dark">asrno</h1>
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
                            <h2 class="font-bold text-lg">asrno</h2>
                            <p class="text-xs opacity-90 mt-1 flex items-center gap-1">
                                <i class="fas fa-user-circle"></i> {{ user.username }}
                                <span v-if="user.role === 'admin'" class="bg-yellow-400 text-black px-1 rounded text-[9px] font-bold">مدیر</span>
                                <span v-else-if="user.role === 'vip'" class="bg-blue-400 text-white px-1 rounded text-[9px] font-bold">ویژه</span>
                            </p>
                         </div>
                         <button @click="logout" class="text-xs bg-white/20 p-2 rounded hover:bg-white/30" title="خروج"><i class="fas fa-sign-out-alt"></i></button>
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
                                <div class="flex flex-col">
                                    <span class="text-sm font-medium flex items-center gap-1">
                                        {{ u.username }} 
                                        <span v-if="u.username === user.username" class="text-[10px] text-gray-400">(شما)</span>
                                    </span>
                                    <span class="text-[10px] text-gray-400">
                                        {{ u.role === 'admin' ? 'مدیر کل' : (u.role === 'vip' ? 'کاربر ویژه' : 'کاربر') }}
                                    </span>
                                </div>
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

                <!-- Messages -->
                <div class="flex-1 overflow-y-auto p-4 space-y-2 min-h-0" id="messages-container" ref="msgContainer">
                    <div v-for="msg in messages" :key="msg.id" 
                         :class="['flex w-full', msg.sender === user.username ? 'justify-end' : 'justify-start']">
                        
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
                    
                    <!-- Message Context -->
                    <template v-if="contextMenu.type === 'message'">
                        <div @click="setReply(contextMenu.target); contextMenu.visible = false" class="px-3 py-2 hover:bg-gray-100 cursor-pointer text-sm flex items-center gap-2">
                            <i class="fas fa-reply text-gray-400 w-4"></i> پاسخ
                        </div>
                        <div v-if="canBan && contextMenu.target.sender !== user.username" @click="banUser(contextMenu.target.sender); contextMenu.visible = false" class="px-3 py-2 hover:bg-red-50 text-red-600 cursor-pointer text-sm flex items-center gap-2 border-t">
                            <i class="fas fa-ban w-4"></i> بن کردن کاربر
                        </div>
                    </template>
                    
                    <!-- User Context -->
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
        const { createApp, ref, onMounted, nextTick, computed } = Vue;
        const socket = io();

        createApp({
            setup() {
                const isLoggedIn = ref(false);
                const user = ref({ username: '', role: 'user' });
                const loginForm = ref({ username: '', password: '' });
                const error = ref('');
                
                const channels = ref(['General']);
                const currentChannel = ref('General');
                const isPrivateChat = ref(false);
                const displayChannelName = ref('General');
                const messages = ref([]);
                const onlineUsers = ref([]);
                const searchResults = ref([]);
                const searchQuery = ref('');
                const bannedUsers = ref([]);
                
                const showSidebar = ref(false);
                const messageText = ref('');
                const showCreateChannelInput = ref(false);
                const newChannelName = ref('');
                const lightboxImage = ref(null);
                const showBanModal = ref(false);
                
                const replyingTo = ref(null);
                const contextMenu = ref({ visible: false, x: 0, y: 0, target: null, type: null });
                
                const swipeId = ref(null);
                const swipeStartX = ref(0);
                const swipeOffset = ref(0);
                const isRecording = ref(false);
                let mediaRecorder = null;
                let audioChunks = [];

                // Computed
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
                });

                // Auth
                const login = () => {
                    if(!loginForm.value.username || !loginForm.value.password) {
                        error.value = 'نام کاربری و رمز عبور الزامی است';
                        return;
                    }
                    socket.emit('login', loginForm.value);
                };
                const logout = () => {
                    localStorage.removeItem('chat_user_name');
                    window.location.reload();
                };

                // Channels & Chat
                const joinChannel = (ch, isPv) => {
                    socket.emit('join_channel', ch);
                    showSidebar.value = false;
                };
                const startPrivateChat = (targetUsername) => {
                    socket.emit('join_private', targetUsername);
                    displayChannelName.value = targetUsername;
                    isPrivateChat.value = true;
                    showSidebar.value = false;
                    searchResults.value = [];
                    searchQuery.value = '';
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
                };
                
                // Admin Actions
                const createChannel = () => {
                    if (newChannelName.value) {
                        socket.emit('create_channel', newChannelName.value);
                        newChannelName.value = '';
                        showCreateChannelInput.value = false;
                    }
                };
                const deleteChannel = (ch) => {
                    if(confirm('آیا از حذف کانال ' + ch + ' مطمئن هستید؟')) {
                        socket.emit('delete_channel', ch);
                    }
                };
                const banUser = (target) => {
                    if(confirm('آیا مطمئن هستید که میخواهید ' + target + ' را بن کنید؟')) {
                        socket.emit('ban_user', target);
                    }
                };
                const unbanUser = (target) => {
                    socket.emit('unban_user', target);
                };
                const setRole = (target, role) => {
                    socket.emit('set_role', { targetUsername: target, role });
                };
                const openBanList = () => {
                    socket.emit('get_banned_users');
                    showBanModal.value = true;
                };
                
                // UI Helpers
                const handleUserClick = (u) => {
                    if (u.username !== user.value.username) startPrivateChat(u.username);
                };
                const showContext = (e, msg) => {
                    contextMenu.value = { visible: true, x: e.pageX, y: e.pageY, target: msg, type: 'message' };
                };
                const showUserContext = (e, targetUsername) => {
                    contextMenu.value = { visible: true, x: e.pageX, y: e.pageY, target: targetUsername, type: 'user' };
                };
                
                // Socket Events
                socket.on('login_success', (data) => {
                    isLoggedIn.value = true;
                    user.value = { username: data.username, role: data.role };
                    channels.value = data.channels;
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
                    messages.value.push(msg);
                    nextTick(() => { const c = document.getElementById('messages-container'); if(c) c.scrollTop = c.scrollHeight; });
                });
                socket.on('history', (msgs) => {
                    messages.value = msgs;
                    nextTick(() => { const c = document.getElementById('messages-container'); if(c) c.scrollTop = c.scrollHeight; });
                });
                socket.on('user_list', (list) => onlineUsers.value = list);
                socket.on('update_channels', (list) => channels.value = list);
                socket.on('banned_list', (list) => bannedUsers.value = list);
                socket.on('action_success', (msg) => alert(msg));
                socket.on('role_update', (newRole) => { user.value.role = newRole; alert('نقش شما تغییر کرد: ' + newRole); });

                // ... (Keep existing media/swipe logic same as before, omitted for brevity but assumed present)
                 const sendMedia = (content, type) => {
                    socket.emit('send_message', { text: '', type, content, channel: currentChannel.value, replyTo: replyingTo.value });
                    replyingTo.value = null;
                };
                const setReply = (msg) => { replyingTo.value = msg; nextTick(() => document.querySelector('textarea')?.focus()); };
                const cancelReply = () => replyingTo.value = null;
                const scrollToMessage = (id) => { document.getElementById('msg-' + id)?.scrollIntoView({ behavior: 'smooth', block: 'center' }); };
                const touchStart = (e, msg) => { swipeStartX.value = e.touches[0].clientX; swipeId.value = msg.id; swipeOffset.value = 0; };
                const touchMove = (e) => { if (!swipeId.value) return; const diff = e.touches[0].clientX - swipeStartX.value; if (diff < 0 && diff > -100) swipeOffset.value = diff; };
                const touchEnd = () => { if (swipeOffset.value < -50) { const msg = messages.value.find(m => m.id === swipeId.value); if (msg) setReply(msg); } swipeId.value = null; swipeOffset.value = 0; };
                const getSwipeStyle = (id) => (swipeId.value === id ? { transform: `translateX(${swipeOffset.value}px)` } : {});
                const searchUser = () => { if (searchQuery.value.length > 2) socket.emit('search_user', searchQuery.value); else searchResults.value = []; };
                const toggleCreateChannel = () => showCreateChannelInput.value = !showCreateChannelInput.value;
                const handleFileUpload = (e) => {
                    const file = e.target.files[0]; if(!file) return;
                    const reader = new FileReader();
                    reader.onload = (ev) => {
                        const type = file.type.startsWith('image/') ? 'image' : (file.type.startsWith('video/') ? 'video' : 'file');
                        if (type !== 'file') sendMedia(ev.target.result, type); else alert('Format not supported');
                    };
                    reader.readAsDataURL(file);
                };
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
                                reader.onloadend = () => sendMedia(reader.result, 'audio');
                            };
                            mediaRecorder.start(); isRecording.value = true;
                        } catch(e) { alert('Microphone access denied'); }
                    }
                };
                const viewImage = (src) => lightboxImage.value = src;
                const autoResize = (e) => { e.target.style.height = 'auto'; e.target.style.height = e.target.scrollHeight + 'px'; };

                return {
                    isLoggedIn, user, loginForm, error, login, logout,
                    channels, currentChannel, joinChannel, displayChannelName, isPrivateChat,
                    messages, messageText, sendMessage, handleFileUpload,
                    onlineUsers, sortedUsers, searchUser, searchQuery, searchResults, startPrivateChat, handleUserClick,
                    showSidebar, toggleCreateChannel, showCreateChannelInput, newChannelName, createChannel, deleteChannel,
                    replyingTo, setReply, cancelReply,
                    contextMenu, showContext, showUserContext,
                    swipeId, touchStart, touchMove, touchEnd, getSwipeStyle,
                    isRecording, toggleRecording, viewImage, lightboxImage, autoResize, scrollToMessage,
                    canCreateChannel, canBan, banUser, unbanUser, setRole,
                    showBanModal, openBanList, bannedUsers
                };
            }
        }).mount('#app');
    </script>
</body>
</html>

EOF

# 4. Apply Color Configuration (Sed Replacement)
echo "[4/6] Applying color theme..."
# Use | as delimiter for sed to avoid conflict with # in hex codes
sed -i "s|__COLOR_DEFAULT__|$C_DEF|g" public/index.html
sed -i "s|__COLOR_DARK__|$C_DARK|g" public/index.html
sed -i "s|__COLOR_LIGHT__|$C_LIGHT|g" public/index.html


# 5. Install Dependencies
echo "[5/6] Installing project dependencies..."
npm install

# 6. Start Server with PM2
echo "[6/6] Starting server with PM2..."

# Stop previous instance if exists
pm2 delete "$APP_NAME" 2>/dev/null || true

# Start with environment variables
PORT=$PORT ADMIN_USER=$ADMIN_USER ADMIN_PASS=$ADMIN_PASS pm2 start server.js --name "$APP_NAME"

# Save PM2 list
pm2 save
# Setup PM2 startup hook (requires sudo, might need user interaction or simply print instructions)
# We try to run it, but it might fail without sudo passwordless. 
# Usually 'pm2 startup' prints a command to run. We'll skip forcing it to avoid breaking script.

# 7. Create Global Management Command 'chat'
echo "Creating management tool..."

cat << 'EOF_MENU' > /tmp/chat-menu.sh
#!/bin/bash
# Chat Manager Menu

APP_NAME="asrno"
DIR="~/chat-asrno"

while true; do
    clear
    echo "==================================="
    echo "   Chat Room Manager ($APP_NAME)"
    echo "==================================="
    echo "1. Check Status"
    echo "2. Restart Server"
    echo "3. Stop Server"
    echo "4. View Logs"
    echo "5. Uninstall / Delete"
    echo "6. Exit"
    echo "==================================="
    read -p "Select option: " opt

    case $opt in
        1) pm2 status "$APP_NAME"; read -p "Press Enter..." ;;
        2) pm2 restart "$APP_NAME"; echo "Restarted."; read -p "Press Enter..." ;;
        3) pm2 stop "$APP_NAME"; echo "Stopped."; read -p "Press Enter..." ;;
        4) pm2 logs "$APP_NAME" --lines 20; ;; 
        5) 
           read -p "Are you sure you want to DELETE everything? (y/n): " confirm
           if [[ "$confirm" == "y" ]]; then
               pm2 delete "$APP_NAME"
               rm -rf "$DIR"
               sudo rm /usr/local/bin/chat
               echo "Uninstalled successfully."
               exit 0
           fi
           ;;
        6) exit 0 ;;
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

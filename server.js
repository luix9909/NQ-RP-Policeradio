const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { nanoid } = require('nanoid');
const { db, seededOwnerCode } = require('./db');

const app = express();
app.use(express.json());
app.use(express.static('public'));

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

// ---- in-memory session + realtime state (fine for single-process deploys) ----
const sessions = new Map();           // token -> userId
const roomPresence = new Map();       // roomId -> Map(socketId -> userPublic)
const roomSpeaker = new Map();        // roomId -> { userId, socketId, name }

const ROLE_RANK = { owner: 3, admin_high: 2, admin_low: 1, member: 0 };

function publicUser(u) {
  return { id: u.id, name: u.name, rank: u.rank, department: u.department, role: u.role };
}

function getUserById(id) {
  return db.prepare('SELECT * FROM users WHERE id = ?').get(id);
}

function requireAuth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  const userId = sessions.get(token);
  if (!userId) return res.status(401).json({ error: 'غير مصرح' });
  const user = getUserById(userId);
  if (!user || user.banned) return res.status(403).json({ error: 'الحساب محظور' });
  req.user = user;
  next();
}

function requireRole(minRole) {
  return (req, res, next) => {
    if (ROLE_RANK[req.user.role] < ROLE_RANK[minRole]) {
      return res.status(403).json({ error: 'صلاحيات غير كافية' });
    }
    next();
  };
}

// ---------------- AUTH ----------------
app.post('/api/login', (req, res) => {
  const { email, code } = req.body;
  if (!email || !code) return res.status(400).json({ error: 'أدخل الإيميل والرمز' });
  const user = db.prepare('SELECT * FROM users WHERE code = ?').get(code.trim());
  if (!user) return res.status(401).json({ error: 'الرمز غير صحيح' });
  if (user.email.trim().toLowerCase() !== email.trim().toLowerCase()) {
    return res.status(401).json({ error: 'الإيميل لا يطابق هذا الرمز' });
  }
  if (user.banned) return res.status(403).json({ error: 'تم حظر هذا الحساب' });
  const token = nanoid(32);
  sessions.set(token, user.id);
  res.json({ token, user: publicUser(user) });
});

app.get('/api/me', requireAuth, (req, res) => res.json({ user: publicUser(req.user) }));

// ---------------- ROOMS ----------------
app.get('/api/rooms', requireAuth, (req, res) => {
  res.json(db.prepare('SELECT * FROM rooms ORDER BY id').all());
});

app.post('/api/rooms', requireAuth, requireRole('admin_high'), (req, res) => {
  const { name } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ error: 'اسم الموجة مطلوب' });
  const info = db.prepare('INSERT INTO rooms (name) VALUES (?)').run(name.trim());
  const room = db.prepare('SELECT * FROM rooms WHERE id = ?').get(info.lastInsertRowid);
  io.emit('room:new', room);
  res.json(room);
});

app.get('/api/rooms/:id/messages', requireAuth, (req, res) => {
  const rows = db.prepare(
    `SELECT * FROM messages WHERE room_id = ? AND deleted = 0 ORDER BY id DESC LIMIT 50`
  ).all(req.params.id);
  res.json(rows.reverse());
});

// ---------------- ADMIN: USERS ----------------
app.get('/api/admin/users', requireAuth, requireRole('admin_high'), (req, res) => {
  res.json(db.prepare('SELECT id, code, email, name, rank, department, role, banned FROM users ORDER BY id').all());
});

app.post('/api/admin/users', requireAuth, requireRole('admin_high'), (req, res) => {
  const { email, name, rank, department, role, code } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ error: 'الاسم مطلوب' });
  if (!email || !email.trim()) return res.status(400).json({ error: 'الإيميل مطلوب — يحتاجه الشخص لتسجيل الدخول' });
  if (!code || !code.trim()) return res.status(400).json({ error: 'الرمز (كلمة المرور) مطلوب' });
  let assignRole = role || 'member';
  // only owner can create admins/owners
  if (req.user.role !== 'owner' && assignRole !== 'member') {
    return res.status(403).json({ error: 'فقط الأونر يقدر يحدد رتبة إداري' });
  }
  try {
    const info = db.prepare(
      `INSERT INTO users (code, email, name, rank, department, role) VALUES (?, ?, ?, ?, ?, ?)`
    ).run(code.trim(), email.trim(), name.trim(), rank || '', department || '', assignRole);
    res.json(db.prepare('SELECT id, code, email, name, rank, department, role, banned FROM users WHERE id = ?').get(info.lastInsertRowid));
  } catch (e) {
    if (String(e.message).includes('UNIQUE')) {
      return res.status(409).json({ error: 'هذا الرمز مستخدم من قبل لشخص ثاني، اختر رمز مختلف' });
    }
    return res.status(500).json({ error: 'خطأ غير متوقع' });
  }
});

// ban/unban — owner only
app.post('/api/admin/users/:id/ban', requireAuth, requireRole('owner'), (req, res) => {
  const target = getUserById(req.params.id);
  if (!target) return res.status(404).json({ error: 'غير موجود' });
  if (target.role === 'owner') return res.status(400).json({ error: 'لا يمكن حظر الأونر' });
  db.prepare('UPDATE users SET banned = 1 WHERE id = ?').run(req.params.id);
  // kick any live sockets for that user
  for (const [id, sock] of io.sockets.sockets) {
    if (sock.user && sock.user.id === Number(req.params.id)) {
      sock.emit('banned');
      sock.disconnect(true);
    }
  }
  res.json({ ok: true });
});

app.post('/api/admin/users/:id/unban', requireAuth, requireRole('owner'), (req, res) => {
  db.prepare('UPDATE users SET banned = 0 WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// delete a code entirely — owner, or admin_high deleting a member only
app.delete('/api/admin/users/:id', requireAuth, requireRole('admin_high'), (req, res) => {
  const target = getUserById(req.params.id);
  if (!target) return res.status(404).json({ error: 'غير موجود' });
  if (req.user.role !== 'owner' && target.role !== 'member') {
    return res.status(403).json({ error: 'ما تقدر تحذف إداري أو أونر' });
  }
  db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// ---------------- REPORTS (بلاغات) ----------------
function publicReport(r) { return r; }

function userHasActiveReport(userId) {
  return db.prepare(
    `SELECT COUNT(*) c FROM reports WHERE accepted_by_id = ? AND status = 'accepted'`
  ).get(userId).c > 0;
}

app.get('/api/reports', requireAuth, (req, res) => {
  const rows = db.prepare(
    `SELECT * FROM reports WHERE status IN ('pending','accepted')
     ORDER BY is_panic DESC, created_at ASC`
  ).all();
  res.json(rows);
});

app.post('/api/reports', requireAuth, (req, res) => {
  const { location, description } = req.body;
  if (!location || !location.trim()) return res.status(400).json({ error: 'اسم الموقع مطلوب' });
  const info = db.prepare(
    `INSERT INTO reports (location, description, reporter_id, reporter_name) VALUES (?, ?, ?, ?)`
  ).run(location.trim(), (description || '').trim(), req.user.id, req.user.name);
  const report = db.prepare('SELECT * FROM reports WHERE id = ?').get(info.lastInsertRowid);
  io.emit('report:new', report);
  res.json(report);
});

app.post('/api/reports/panic', requireAuth, (req, res) => {
  const { location } = req.body;
  if (!location || !location.trim()) return res.status(400).json({ error: 'اكتب الموقع' });
  const info = db.prepare(
    `INSERT INTO reports (location, description, is_panic, reporter_id, reporter_name) VALUES (?, '', 1, ?, ?)`
  ).run(location.trim(), req.user.id, req.user.name);
  const report = db.prepare('SELECT * FROM reports WHERE id = ?').get(info.lastInsertRowid);
  io.emit('report:panic', report);
  io.emit('report:new', report);
  res.json(report);
});

app.post('/api/reports/:id/accept', requireAuth, (req, res) => {
  const report = db.prepare('SELECT * FROM reports WHERE id = ?').get(req.params.id);
  if (!report) return res.status(404).json({ error: 'البلاغ غير موجود' });
  if (report.status !== 'pending') return res.status(409).json({ error: 'البلاغ تم التعامل معه بالفعل' });
  if (userHasActiveReport(req.user.id)) {
    return res.status(409).json({ error: 'عندك بلاغ نشط الآن — أنهِه أولاً قبل استلام بلاغ جديد' });
  }
  db.prepare(
    `UPDATE reports SET status = 'accepted', accepted_by_id = ?, accepted_by_name = ?, accepted_at = datetime('now') WHERE id = ?`
  ).run(req.user.id, req.user.name, req.params.id);
  const updated = db.prepare('SELECT * FROM reports WHERE id = ?').get(req.params.id);
  io.emit('report:accepted', updated);
  io.emit('user:busy', { userId: req.user.id, name: req.user.name, busy: true, location: report.location });
  res.json(updated);
});

app.post('/api/reports/:id/reject', requireAuth, requireRole('admin_low'), (req, res) => {
  const report = db.prepare('SELECT * FROM reports WHERE id = ?').get(req.params.id);
  if (!report) return res.status(404).json({ error: 'البلاغ غير موجود' });
  if (report.status !== 'pending') return res.status(409).json({ error: 'البلاغ تم التعامل معه بالفعل' });
  db.prepare(`UPDATE reports SET status = 'rejected' WHERE id = ?`).run(req.params.id);
  io.emit('report:rejected', { id: Number(req.params.id) });
  res.json({ ok: true });
});

app.post('/api/reports/:id/finish', requireAuth, (req, res) => {
  const report = db.prepare('SELECT * FROM reports WHERE id = ?').get(req.params.id);
  if (!report) return res.status(404).json({ error: 'البلاغ غير موجود' });
  if (report.accepted_by_id !== req.user.id && req.user.role !== 'owner') {
    return res.status(403).json({ error: 'فقط من استلم البلاغ يقدر ينهيه' });
  }
  db.prepare(`UPDATE reports SET status = 'resolved', resolved_at = datetime('now') WHERE id = ?`).run(req.params.id);
  io.emit('report:resolved', { id: Number(req.params.id) });
  io.emit('user:busy', { userId: report.accepted_by_id, busy: false });
  res.json({ ok: true });
});

// ---------------- SOCKET.IO ----------------
io.use((socket, next) => {
  const token = socket.handshake.auth?.token;
  const userId = sessions.get(token);
  const user = userId ? getUserById(userId) : null;
  if (!user || user.banned) return next(new Error('unauthorized'));
  socket.user = user;
  next();
});

function presenceList(roomId) {
  const map = roomPresence.get(roomId);
  if (!map) return [];
  return [...map.values()];
}

function broadcastPresence(roomId) {
  io.to('room:' + roomId).emit('presence:list', presenceList(roomId));
}

io.on('connection', (socket) => {
  const u = socket.user;

  socket.on('room:join', (roomId) => {
    roomId = String(roomId);
    socket.join('room:' + roomId);
    if (!roomPresence.has(roomId)) roomPresence.set(roomId, new Map());
    roomPresence.get(roomId).set(socket.id, { socketId: socket.id, ...publicUser(u) });
    broadcastPresence(roomId);
    const speaker = roomSpeaker.get(roomId);
    if (speaker) socket.emit('ptt:started', { userId: speaker.userId, name: speaker.name, socketId: speaker.socketId });
  });

  socket.on('room:leave', (roomId) => {
    roomId = String(roomId);
    socket.leave('room:' + roomId);
    roomPresence.get(roomId)?.delete(socket.id);
    broadcastPresence(roomId);
    releaseIfSpeaker(roomId, socket);
  });

  socket.on('chat:send', ({ roomId, content }) => {
    if (!content || !content.trim()) return;
    const info = db.prepare(
      `INSERT INTO messages (room_id, user_id, name, rank, content) VALUES (?, ?, ?, ?, ?)`
    ).run(roomId, u.id, u.name, u.rank, content.trim().slice(0, 1000));
    const msg = db.prepare('SELECT * FROM messages WHERE id = ?').get(info.lastInsertRowid);
    io.to('room:' + roomId).emit('chat:new', msg);
  });

  socket.on('chat:delete', ({ roomId, messageId }) => {
    if (ROLE_RANK[u.role] < ROLE_RANK['admin_low']) return;
    db.prepare('UPDATE messages SET deleted = 1 WHERE id = ?').run(messageId);
    io.to('room:' + roomId).emit('chat:deleted', { messageId });
  });

  // ---- Owner-only slash commands (/kick, /ban, /clear, /announce) ----
  socket.on('chat:command', ({ roomId, raw }) => {
    if (u.role !== 'owner') { socket.emit('system:notice', 'الأوامر خاصة بالأونر فقط'); return; }
    const parts = String(raw || '').trim().replace(/^\//, '').split(/\s+/);
    const cmd = (parts.shift() || '').toLowerCase();
    const arg = parts.join(' ').trim();

    if (cmd === 'clear') {
      db.prepare('UPDATE messages SET deleted = 1 WHERE room_id = ?').run(roomId);
      io.to('room:' + roomId).emit('chat:cleared', { roomId });
      socket.emit('system:notice', 'تم مسح رسائل الموجة');
      return;
    }

    if (cmd === 'kick') {
      if (!arg) { socket.emit('system:notice', 'استخدم: /kick الاسم'); return; }
      let found = false;
      for (const [, s] of io.sockets.sockets) {
        if (s.user && s.user.name === arg) { found = true; s.emit('kicked'); s.disconnect(true); }
      }
      socket.emit('system:notice', found ? `تم فصل ${arg}` : `ما فيه شخص متصل بالاسم ${arg}`);
      return;
    }

    if (cmd === 'ban') {
      if (!arg) { socket.emit('system:notice', 'استخدم: /ban الاسم'); return; }
      const target = db.prepare('SELECT * FROM users WHERE name = ? COLLATE NOCASE').get(arg);
      if (!target) { socket.emit('system:notice', `ما لقيت مستخدم بالاسم ${arg}`); return; }
      if (target.role === 'owner') { socket.emit('system:notice', 'لا يمكن حظر الأونر'); return; }
      db.prepare('UPDATE users SET banned = 1 WHERE id = ?').run(target.id);
      for (const [, s] of io.sockets.sockets) {
        if (s.user && s.user.id === target.id) { s.emit('banned'); s.disconnect(true); }
      }
      socket.emit('system:notice', `تم حظر ${arg}`);
      return;
    }

    if (cmd === 'announce') {
      if (!arg) { socket.emit('system:notice', 'استخدم: /announce النص'); return; }
      io.emit('system:announce', arg);
      return;
    }

    socket.emit('system:notice', `أمر غير معروف: /${cmd} — الأوامر المتاحة: /clear /kick /ban /announce`);
  });

  // ---- Push to talk ----
  socket.on('ptt:request', (roomId) => {
    roomId = String(roomId);
    const current = roomSpeaker.get(roomId);
    if (current && current.socketId !== socket.id) {
      socket.emit('ptt:denied');
      return;
    }
    roomSpeaker.set(roomId, { userId: u.id, socketId: socket.id, name: u.name });
    const listeners = [...(roomPresence.get(roomId)?.values() || [])]
      .filter(p => p.socketId !== socket.id)
      .map(p => p.socketId);
    socket.emit('ptt:granted', { listeners });
    io.to('room:' + roomId).emit('ptt:started', { userId: u.id, name: u.name, socketId: socket.id });
    io.emit('room:speaking', { roomId: Number(roomId), speaking: true });
  });

  socket.on('ptt:release', (roomId) => {
    releaseIfSpeaker(String(roomId), socket);
  });

  function releaseIfSpeaker(roomId, sock) {
    const current = roomSpeaker.get(roomId);
    if (current && current.socketId === sock.id) {
      roomSpeaker.delete(roomId);
      io.to('room:' + roomId).emit('ptt:stopped', { userId: current.userId });
      io.emit('room:speaking', { roomId: Number(roomId), speaking: false });
    }
  }

  // ---- WebRTC signaling relay (speaker -> each listener, mesh) ----
  socket.on('rtc:offer', ({ toSocketId, sdp }) => {
    io.to(toSocketId).emit('rtc:offer', { fromSocketId: socket.id, sdp });
  });
  socket.on('rtc:answer', ({ toSocketId, sdp }) => {
    io.to(toSocketId).emit('rtc:answer', { fromSocketId: socket.id, sdp });
  });
  socket.on('rtc:ice', ({ toSocketId, candidate }) => {
    io.to(toSocketId).emit('rtc:ice', { fromSocketId: socket.id, candidate });
  });

  socket.on('disconnect', () => {
    for (const [roomId, map] of roomPresence) {
      if (map.delete(socket.id)) broadcastPresence(roomId);
      releaseIfSpeaker(roomId, socket);
    }
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log('Server running on port', PORT);
  if (seededOwnerCode) {
    console.log('================================================');
    console.log(' رمز دخول المالك (احفظه، ما يظهر مرة ثانية):');
    console.log(' ' + seededOwnerCode);
    console.log('================================================');
  }
});

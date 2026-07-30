/**
 * 科室轮转打卡系统 - Cloudflare Pages Functions 后端
 * _middleware.js 处理所有 /api/* 请求
 */
function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-Admin-Token',
    'Access-Control-Max-Age': '86400',
  };
}
function json(data, status) {
  return new Response(JSON.stringify(data), { status: status || 200, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...corsHeaders() } });
}
function randomToken(len) {
  var arr = new Uint8Array(len || 32);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(function(b) { return b.toString(16).padStart(2, '0'); }).join('');
}
function getDistance(lat1, lng1, lat2, lng2) {
  var R = 6371000, rad = Math.PI / 180;
  var dLat = (lat2 - lat1) * rad, dLng = (lng2 - lng1) * rad;
  var a = Math.sin(dLat / 2) * Math.sin(dLat / 2) + Math.cos(lat1 * rad) * Math.cos(lat2 * rad) * Math.sin(dLng / 2) * Math.sin(dLng / 2);
  return R * (2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a)));
}
function getCheckType(ts) {
  var d = new Date(ts + 8 * 3600 * 1000);
  var total = d.getUTCHours() * 60 + d.getUTCMinutes();
  if (total >= 360 && total <= 480) return { type: '上午上班打卡', status: 'normal' };
  if (total >= 660 && total <= 780) return { type: '上午下班打卡', status: 'normal' };
  if (total >= 780 && total <= 840) return { type: '下午上班打卡', status: 'normal' };
  if (total >= 1020 && total <= 1140) return { type: '下午下班打卡', status: 'normal' };
  return { type: '补卡', status: 'abnormal' };
}
function getIp(req) {
  return req.headers.get('CF-Connecting-IP') || (req.headers.get('X-Forwarded-For') || '').split(',')[0].trim() || 'unknown';
}

export async function onRequest(context) {
  var req = context.request, env = context.env;
  var url = new URL(req.url);
  var path = url.pathname;
  var method = req.method;

  if (method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders() });

  // 数据库懒初始化
  try { await env.DB.prepare('SELECT 1 FROM checkins LIMIT 1').run(); } catch (e) { await initDb(env); }

  try {
    // 公开接口
    if (path === '/api/health' && method === 'GET') return json({ ok: true, time: Date.now() });
    if (path === '/api/admin/login' && method === 'POST') return handleAdminLogin(req, env);
    if (path === '/api/checkin/init' && method === 'POST') return handleCheckinInit(req, env);
    if (path === '/api/checkin/submit' && method === 'POST') return handleCheckinSubmit(req, env);
    if (path === '/api/records/mine' && method === 'GET') return handleMyRecords(req, env);

    // 管理员权限
    if (path.startsWith('/api/admin') || path === '/api/audit') {
      var token = req.headers.get('X-Admin-Token');
      if (!token) return json({ error: '未授权' }, 401);
      var sess = await env.DB.prepare('SELECT expires_at FROM admin_sessions WHERE token = ?').bind(token).first();
      if (!sess || Date.now() > sess.expires_at) return json({ error: '未授权或登录已过期' }, 401);

      if (path === '/api/records/all' && method === 'GET') return handleAllRecords(req, env);
      if (path === '/api/admin/unbind' && method === 'POST') return handleUnbind(req, env);
      if (path === '/api/admin/whitelist' && method === 'GET') return handleGetWhitelist(req, env);
      if (path === '/api/admin/whitelist' && method === 'POST') return handleUpsertWhitelist(req, env);
      if (path === '/api/admin/whitelist' && method === 'DELETE') return handleDeleteWhitelist(req, env);
      if (path === '/api/admin/devices' && method === 'GET') return handleDevices(req, env);
      if (path === '/api/audit' && method === 'GET') return handleAudit(req, env);
    }

    return json({ error: '接口不存在' }, 404);
  } catch (err) {
    return json({ error: '服务器内部错误', message: err.message }, 500);
  }
}

// ============== 数据库初始化 ==============
async function initDb(env) {
  var stmts = [
    'CREATE TABLE IF NOT EXISTS nfc_tags (uid TEXT PRIMARY KEY, dept TEXT NOT NULL, created_at INTEGER NOT NULL)',
    'CREATE TABLE IF NOT EXISTS users (user_code TEXT PRIMARY KEY, name TEXT NOT NULL, created_at INTEGER NOT NULL)',
    'CREATE TABLE IF NOT EXISTS dept_positions (dept TEXT PRIMARY KEY, lat REAL NOT NULL, lng REAL NOT NULL, radius INTEGER NOT NULL)',
    'CREATE TABLE IF NOT EXISTS device_binds (device_id TEXT PRIMARY KEY, tag_uid TEXT NOT NULL, user_code TEXT, bound_at INTEGER NOT NULL, last_seen_at INTEGER NOT NULL)',
    'CREATE TABLE IF NOT EXISTS checkins (id INTEGER PRIMARY KEY AUTOINCREMENT, tag_uid TEXT NOT NULL, user_code TEXT NOT NULL, user_name TEXT NOT NULL, dept TEXT NOT NULL, check_type TEXT NOT NULL, status TEXT NOT NULL, check_time INTEGER NOT NULL, lat REAL NOT NULL, lng REAL NOT NULL, distance REAL NOT NULL, device_id TEXT NOT NULL, ip TEXT, ua TEXT, created_at INTEGER NOT NULL, checkin_date TEXT NOT NULL, UNIQUE(tag_uid, checkin_date))',
    'CREATE TABLE IF NOT EXISTS nonces (nonce TEXT PRIMARY KEY, tag_uid TEXT NOT NULL, device_id TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, used INTEGER DEFAULT 0)',
    'CREATE TABLE IF NOT EXISTS audit_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, event TEXT NOT NULL, detail TEXT, device_id TEXT, ip TEXT, created_at INTEGER NOT NULL)',
    'CREATE TABLE IF NOT EXISTS admin_sessions (token TEXT PRIMARY KEY, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL)',
    'CREATE INDEX IF NOT EXISTS idx_checkins_time ON checkins(check_time)',
    'CREATE INDEX IF NOT EXISTS idx_checkins_tag ON checkins(tag_uid)',
    'CREATE INDEX IF NOT EXISTS idx_nonces_expires ON nonces(expires_at)',
  ];
  for (var i = 0; i < stmts.length; i++) { await env.DB.exec(stmts[i]).catch(function(){}); }
  var now = Date.now();
  await env.DB.prepare("INSERT OR IGNORE INTO nfc_tags (uid, dept, created_at) VALUES ('538b1cce330001', '急诊', ?), ('04b771cc223311', '护士站', ?)").bind(now, now).run();
  await env.DB.prepare("INSERT OR IGNORE INTO users (user_code, name, created_at) VALUES ('001', '刘六六', ?), ('002', '李四', ?)").bind(now, now).run();
  await env.DB.prepare("INSERT OR IGNORE INTO dept_positions (dept, lat, lng, radius) VALUES ('急诊', 29.362, 106.2929, 15), ('护士站', 29.4570, 106.5895, 15)").run();
}

async function audit(env, event, detail, deviceId, ip) {
  await env.DB.prepare('INSERT INTO audit_logs (event, detail, device_id, ip, created_at) VALUES (?, ?, ?, ?, ?)').bind(event, detail, deviceId || null, ip || null, Date.now()).run();
}

// ============== API 处理函数 ==============

async function handleAdminLogin(req, env) {
  var body = await req.json();
  if (!body.password) return json({ error: '请输入口令' }, 400);
  if (body.password !== env.ADMIN_PASSWORD) {
    await audit(env, 'admin_login_failed', '口令错误', null, getIp(req));
    return json({ error: '口令错误' }, 401);
  }
  var token = randomToken(32), now = Date.now(), expires = now + 7200000;
  await env.DB.prepare('INSERT INTO admin_sessions (token, created_at, expires_at) VALUES (?, ?, ?)').bind(token, now, expires).run();
  await audit(env, 'admin_login_ok', '管理员登录成功', null, getIp(req));
  return json({ token: token, expiresAt: expires });
}

async function handleCheckinInit(req, env) {
  var body = await req.json();
  if (!body.tagUid || !body.deviceId) return json({ error: '参数缺失' }, 400);
  var uid = String(body.tagUid).toLowerCase().trim();
  var tag = await env.DB.prepare('SELECT uid, dept FROM nfc_tags WHERE uid = ?').bind(uid).first();
  if (!tag) { await audit(env, 'nfc_invalid', '非法 UID: ' + uid, body.deviceId, getIp(req)); return json({ error: 'NFC 标签未注册，访问拒绝' }, 403); }
  var bind = await env.DB.prepare('SELECT tag_uid, user_code FROM device_binds WHERE device_id = ?').bind(body.deviceId).first();
  if (bind && bind.tag_uid !== uid) {
    await audit(env, 'device_switch_blocked', '设备 ' + body.deviceId + ' 已绑定 ' + bind.tag_uid + '，尝试访问 ' + uid, body.deviceId, getIp(req));
    return json({ error: 'DEVICE_BIND_CONFLICT', message: '该设备已绑定其他卡号（' + bind.tag_uid + '），无法为 ' + uid + ' 打卡。请联系管理员解绑后重试。', boundUid: bind.tag_uid }, 409);
  }
  var nonce = randomToken(24), now = Date.now(), expires = now + 300000;
  await env.DB.prepare('INSERT INTO nonces (nonce, tag_uid, device_id, created_at, expires_at, used) VALUES (?, ?, ?, ?, ?, 0)').bind(nonce, uid, body.deviceId, now, expires).run();
  if (!bind) {
    await env.DB.prepare('INSERT INTO device_binds (device_id, tag_uid, user_code, bound_at, last_seen_at) VALUES (?, ?, NULL, ?, ?)').bind(body.deviceId, uid, now, now).run();
  } else {
    await env.DB.prepare('UPDATE device_binds SET last_seen_at = ? WHERE device_id = ?').bind(now, body.deviceId).run();
  }
  return json({ nonce: nonce, nonceExpiresAt: expires, dept: tag.dept, serverTime: now });
}

async function handleCheckinSubmit(req, env) {
  var body = await req.json();
  var n = body.nonce, t = body.tagUid, d = body.deviceId, u = body.userCode, lat = body.lat, lng = body.lng;
  if (!n || !t || !d || !u) return json({ error: '参数缺失' }, 400);
  if (typeof lat !== 'number' || typeof lng !== 'number') return json({ error: '定位数据格式错误' }, 400);
  var uid = String(t).toLowerCase().trim(), now = Date.now(), ip = getIp(req), ua = req.headers.get('User-Agent') || '';

  var nc = await env.DB.prepare('SELECT nonce, tag_uid, device_id, expires_at, used FROM nonces WHERE nonce = ?').bind(n).first();
  if (!nc) return json({ error: 'nonce 无效，请重新触碰 NFC 标签' }, 403);
  if (nc.used) return json({ error: '本次打卡已提交，请勿重复提交' }, 409);
  if (now > nc.expires_at) return json({ error: '打卡超时，请重新触碰 NFC 标签' }, 410);
  if (nc.tag_uid !== uid) return json({ error: 'UID 与本次会话不匹配' }, 403);
  if (nc.device_id !== d) return json({ error: '设备与本次会话不匹配' }, 403);

  var bind = await env.DB.prepare('SELECT tag_uid, user_code FROM device_binds WHERE device_id = ?').bind(d).first();
  if (!bind || bind.tag_uid !== uid) { await audit(env, 'device_mismatch', '设备 ' + d + ' 与 UID ' + uid + ' 不匹配', d, ip); return json({ error: '设备绑定异常' }, 403); }

  var user = await env.DB.prepare('SELECT user_code, name FROM users WHERE user_code = ?').bind(u).first();
  if (!user) { await audit(env, 'user_invalid', '非法工号: ' + u, d, ip); return json({ error: '工号不在白名单内' }, 403); }

  var ts = new Date(now + 28800000); ts.setUTCHours(0,0,0,0);
  var todayTs = ts.getTime() - 28800000;
  var exist = await env.DB.prepare('SELECT id, check_time, check_type FROM checkins WHERE tag_uid = ? AND check_time >= ? ORDER BY check_time DESC LIMIT 1').bind(uid, todayTs).first();
  if (exist) return json({ error: '今日已打卡', lastCheckTime: exist.check_time, lastCheckType: exist.check_type }, 409);

  var tag = await env.DB.prepare('SELECT dept FROM nfc_tags WHERE uid = ?').bind(uid).first();
  if (!tag) return json({ error: 'NFC 标签已失效' }, 403);
  var pos = await env.DB.prepare('SELECT lat, lng, radius FROM dept_positions WHERE dept = ?').bind(tag.dept).first();
  if (!pos) return json({ error: '科室「' + tag.dept + '」未配置坐标' }, 500);

  var dis = getDistance(lat, lng, pos.lat, pos.lng);
  if (dis > pos.radius) {
    await audit(env, 'location_abnormal', 'UID ' + uid + ' 定位超出范围 ' + dis.toFixed(1) + 'm', d, ip);
    return json({ error: '定位异常', distance: dis.toFixed(1), limit: pos.radius, message: '超出打卡范围 ' + dis.toFixed(1) + ' 米，禁止打卡' }, 403);
  }

  var ct = getCheckType(now);
  var cdate = new Date(now + 28800000).toISOString().slice(0, 10);

  var stmt = env.DB.prepare('INSERT INTO checkins (tag_uid, user_code, user_name, dept, check_type, status, check_time, lat, lng, distance, device_id, ip, ua, created_at, checkin_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').bind(uid, u, user.name, tag.dept, ct.type, ct.status, now, lat, lng, dis, d, ip, ua, now, cdate);
  try { await stmt.run(); } catch (e) { if (String(e.message).indexOf('UNIQUE') >= 0) return json({ error: '今日已打卡' }, 409); throw e; }

  await env.DB.prepare('UPDATE nonces SET used = 1 WHERE nonce = ?').bind(n).run();
  await env.DB.prepare('UPDATE device_binds SET user_code = ?, last_seen_at = ? WHERE device_id = ?').bind(u, now, d).run();
  await audit(env, 'checkin_ok', user.name + '(' + u + ') 打卡: ' + tag.dept + ' - ' + ct.type + ', 距离 ' + dis.toFixed(1) + 'm', d, ip);

  return json({ ok: true, record: { userName: user.name, userCode: u, dept: tag.dept, checkType: ct.type, checkTime: now, distance: dis.toFixed(1) } });
}

async function handleMyRecords(req, env) {
  var deviceId = new URL(req.url).searchParams.get('deviceId');
  if (!deviceId) return json({ error: '缺少 deviceId' }, 400);
  var bind = await env.DB.prepare('SELECT tag_uid, user_code FROM device_binds WHERE device_id = ?').bind(deviceId).first();
  if (!bind) return json({ records: [] });
  var rows = await env.DB.prepare('SELECT check_time, dept, check_type, status, distance FROM checkins WHERE tag_uid = ? ORDER BY check_time DESC LIMIT 30').bind(bind.tag_uid).all();
  return json({ boundUid: bind.tag_uid, boundUserCode: bind.user_code, records: rows.results || [] });
}

async function handleAllRecords(req, env) {
  var u = new URL(req.url);
  var sql = 'SELECT * FROM checkins WHERE 1=1', params = [];
  if (u.searchParams.get('startDate')) { params.push(new Date(u.searchParams.get('startDate') + 'T00:00:00+08:00').getTime()); sql += ' AND check_time >= ?'; }
  if (u.searchParams.get('endDate')) { params.push(new Date(u.searchParams.get('endDate') + 'T23:59:59+08:00').getTime()); sql += ' AND check_time <= ?'; }
  if (u.searchParams.get('dept')) { params.push(u.searchParams.get('dept')); sql += ' AND dept = ?'; }
  if (u.searchParams.get('userCode')) { params.push(u.searchParams.get('userCode')); sql += ' AND user_code = ?'; }
  sql += ' ORDER BY check_time DESC LIMIT 5000';
  var stmt = env.DB.prepare(sql);
  var rows = params.length ? await stmt.bind.apply(stmt, params).all() : await stmt.all();
  return json({ records: rows.results || [] });
}

async function handleUnbind(req, env) {
  var body = await req.json();
  if (!body.deviceId) return json({ error: '缺少 deviceId' }, 400);
  await env.DB.prepare('DELETE FROM device_binds WHERE device_id = ?').bind(body.deviceId).run();
  await audit(env, 'device_unbind', '管理员解绑设备 ' + body.deviceId, null, getIp(req));
  return json({ ok: true });
}

async function handleGetWhitelist(req, env) {
  var tags = await env.DB.prepare('SELECT uid, dept, created_at FROM nfc_tags ORDER BY dept').all();
  var users = await env.DB.prepare('SELECT user_code, name, created_at FROM users ORDER BY user_code').all();
  var depts = await env.DB.prepare('SELECT dept, lat, lng, radius FROM dept_positions ORDER BY dept').all();
  return json({ nfcTags: tags.results || [], users: users.results || [], depts: depts.results || [] });
}

async function handleUpsertWhitelist(req, env) {
  var body = await req.json(), now = Date.now();
  if (body.type === 'nfc') {
    if (!body.uid || !body.dept) return json({ error: '参数缺失' }, 400);
    await env.DB.prepare('INSERT INTO nfc_tags (uid, dept, created_at) VALUES (?, ?, ?) ON CONFLICT(uid) DO UPDATE SET dept = excluded.dept').bind(String(body.uid).toLowerCase().trim(), body.dept, now).run();
  } else if (body.type === 'user') {
    if (!body.userCode || !body.name) return json({ error: '参数缺失' }, 400);
    await env.DB.prepare('INSERT INTO users (user_code, name, created_at) VALUES (?, ?, ?) ON CONFLICT(user_code) DO UPDATE SET name = excluded.name').bind(body.userCode, body.name, now).run();
  } else if (body.type === 'dept') {
    if (!body.dept || typeof body.lat !== 'number') return json({ error: '参数缺失' }, 400);
    await env.DB.prepare('INSERT INTO dept_positions (dept, lat, lng, radius) VALUES (?, ?, ?, ?) ON CONFLICT(dept) DO UPDATE SET lat = excluded.lat, lng = excluded.lng, radius = excluded.radius').bind(body.dept, body.lat, body.lng, body.radius || 15).run();
  } else { return json({ error: '未知白名单类型' }, 400); }
  await audit(env, 'whitelist_upsert', body.type + ': ' + JSON.stringify(body), null, getIp(req));
  return json({ ok: true });
}

async function handleDeleteWhitelist(req, env) {
  var body = await req.json();
  if (body.type === 'nfc') await env.DB.prepare('DELETE FROM nfc_tags WHERE uid = ?').bind(String(body.key).toLowerCase()).run();
  else if (body.type === 'user') await env.DB.prepare('DELETE FROM users WHERE user_code = ?').bind(body.key).run();
  else if (body.type === 'dept') await env.DB.prepare('DELETE FROM dept_positions WHERE dept = ?').bind(body.key).run();
  else return json({ error: '未知类型' }, 400);
  await audit(env, 'whitelist_delete', body.type + ': ' + body.key, null, getIp(req));
  return json({ ok: true });
}

async function handleDevices(req, env) {
  var rows = await env.DB.prepare('SELECT device_id, tag_uid, user_code, bound_at, last_seen_at FROM device_binds ORDER BY last_seen_at DESC').all();
  return json({ devices: rows.results || [] });
}

async function handleAudit(req, env) {
  var limit = Math.min(parseInt(new URL(req.url).searchParams.get('limit') || '200'), 1000);
  var rows = await env.DB.prepare('SELECT id, event, detail, device_id, ip, created_at FROM audit_logs ORDER BY created_at DESC LIMIT ?').bind(limit).all();
  return json({ logs: rows.results || [] });
}
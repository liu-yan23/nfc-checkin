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
  var d = new Date(ts + 8 * 3600 * 1000); // 转 UTC+8
  var total = d.getUTCHours() * 60 + d.getUTCMinutes();
  // 00:00-06:59 夜班补卡(跨日,归前一天)
  if (total < 420) return { type: '夜班', status: 'abnormal', crossDay: true };
  // 07:00-08:02 上午上班正常(结束宽裕2分钟,避免边界争议)
  if (total <= 482) return { type: '上午上班', status: 'normal' };
  // 08:03-11:29 上午上班补卡
  if (total < 690) return { type: '上午上班', status: 'abnormal' };
  // 11:30-12:59 上午下班正常
  if (total < 780) return { type: '上午下班', status: 'normal' };
  // 13:00-14:02 下午上班正常(结束宽裕2分钟)
  if (total <= 842) return { type: '下午上班', status: 'normal' };
  // 14:03-16:59 下午上班补卡
  if (total < 1020) return { type: '下午上班', status: 'abnormal' };
  // 17:00-20:59 下午下班正常
  if (total < 1260) return { type: '下午下班', status: 'normal' };
  // 21:00-23:59 夜班正常
  return { type: '夜班', status: 'normal' };
}
function getIp(req) {
  return req.headers.get('CF-Connecting-IP') || (req.headers.get('X-Forwarded-For') || '').split(',')[0].trim() || 'unknown';
}

// 生成每时段动态码:HMAC(tagUid + 日期 + 时段, SECRET_KEY)
// 复制URL跨时段/跨天使用时,code不匹配,服务端拒绝
async function getSlotCode(tagUid, ts, env) {
  var d = new Date(ts + 8 * 3600 * 1000);
  var dateStr = d.getUTCFullYear() + '-' + String(d.getUTCMonth() + 1).padStart(2, '0') + '-' + String(d.getUTCDate()).padStart(2, '0');
  var ct = getCheckType(ts);
  var slotKey = dateStr + '|' + ct.type + '|' + ct.status;
  var secret = (env.SECRET_KEY || 'default-secret-key-change-me') + '|' + tagUid;
  var data = new TextEncoder().encode(slotKey);
  var key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  var sig = await crypto.subtle.sign('HMAC', key, data);
  var arr = Array.from(new Uint8Array(sig));
  return arr.slice(0, 8).map(function(b) { return b.toString(16).padStart(2, '0'); }).join('');
}

// 校验动态码
async function verifySlotCode(tagUid, ts, code, env) {
  if (!code) return false;
  var expected = await getSlotCode(tagUid, ts, env);
  return code === expected;
}

export async function onRequest(context) {
  var req = context.request, env = context.env;
  var url = new URL(req.url);
  var path = url.pathname;
  var method = req.method;

  if (method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders() });

  // /go 动态跳转路由:NFC贴片写入此URL,服务端自动跳转到带动态码的打卡页
  if (path === '/go' && method === 'GET') {
    var tagParam = url.searchParams.get('tag');
    if (!tagParam) return json({ error: '缺少 tag 参数' }, 400);
    var tagUid = String(tagParam).toLowerCase().trim();
    var tagRow = await env.DB.prepare('SELECT uid, dept FROM nfc_tags WHERE uid = ?').bind(tagUid).first();
    if (!tagRow) return json({ error: 'NFC 标签未注册' }, 403);
    var now = Date.now();
    var code = await getSlotCode(tagUid, now, env);
    var redirectUrl = '/index.html?tagUid=' + encodeURIComponent(tagUid) + '&code=' + code;
    return new Response(null, { status: 302, headers: { 'Location': redirectUrl, 'Cache-Control': 'no-store' } });
  }

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
    if (path.startsWith('/api/admin') || path === '/api/audit' || path === '/api/records/all') {
      var token = req.headers.get('X-Admin-Token');
      if (!token) return json({ error: '未授权' }, 401);
      var sess = await env.DB.prepare('SELECT expires_at FROM admin_sessions WHERE token = ?').bind(token).first();
      if (!sess || Date.now() > sess.expires_at) return json({ error: '未授权或登录已过期' }, 401);

      if (path === '/api/records/all' && method === 'GET') return handleAllRecords(req, env);
      if (path === '/api/admin/unbind' && method === 'POST') return handleUnbind(req, env);
      if (path === '/api/admin/whitelist' && method === 'GET') return handleGetWhitelist(req, env);
      if (path === '/api/admin/whitelist' && method === 'POST') return handleUpsertWhitelist(req, env);
      if (path === '/api/admin/whitelist/batch' && method === 'POST') return handleBatchWhitelist(req, env);
      if (path === '/api/admin/whitelist' && method === 'DELETE') return handleDeleteWhitelist(req, env);
      if (path === '/api/admin/reset-db' && method === 'POST') return handleResetDb(req, env);
      if (path === '/api/admin/backups' && method === 'GET') return handleListBackups(req, env);
      if (path === '/api/admin/backups/download' && method === 'GET') return handleDownloadBackup(req, env);
      if (path === '/api/admin/rotate-tag' && method === 'POST') return handleRotateTag(req, env);
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
    'CREATE TABLE IF NOT EXISTS checkins (id INTEGER PRIMARY KEY AUTOINCREMENT, tag_uid TEXT NOT NULL, user_code TEXT NOT NULL, user_name TEXT NOT NULL, dept TEXT NOT NULL, check_type TEXT NOT NULL, status TEXT NOT NULL, check_time INTEGER NOT NULL, lat REAL NOT NULL, lng REAL NOT NULL, distance REAL NOT NULL, device_id TEXT NOT NULL, ip TEXT, ua TEXT, created_at INTEGER NOT NULL, checkin_date TEXT NOT NULL, reason TEXT, UNIQUE(user_code, checkin_date, check_type))',
    'CREATE TABLE IF NOT EXISTS nonces (nonce TEXT PRIMARY KEY, tag_uid TEXT NOT NULL, device_id TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, used INTEGER DEFAULT 0)',
    'CREATE TABLE IF NOT EXISTS audit_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, event TEXT NOT NULL, detail TEXT, device_id TEXT, ip TEXT, created_at INTEGER NOT NULL)',
    'CREATE TABLE IF NOT EXISTS admin_sessions (token TEXT PRIMARY KEY, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL)',
    'CREATE INDEX IF NOT EXISTS idx_checkins_time ON checkins(check_time)',
    'CREATE INDEX IF NOT EXISTS idx_checkins_tag ON checkins(tag_uid)',
    'CREATE INDEX IF NOT EXISTS idx_checkins_user_date ON checkins(user_code, checkin_date)',
    'CREATE INDEX IF NOT EXISTS idx_nonces_expires ON nonces(expires_at)',
  ];
  for (var i = 0; i < stmts.length; i++) { await env.DB.exec(stmts[i]).catch(function(){}); }
  // 已有表向前兼容:自动添加 reason / location_status 字段(若不存在)
  try { await env.DB.prepare('SELECT reason FROM checkins LIMIT 1').run(); } catch (e) { await env.DB.exec('ALTER TABLE checkins ADD COLUMN reason TEXT').catch(function(){}); }
  try { await env.DB.prepare('SELECT location_status FROM checkins LIMIT 1').run(); } catch (e) { await env.DB.exec('ALTER TABLE checkins ADD COLUMN location_status TEXT').catch(function(){}); }
  // 数据备份表(reset 前自动备份用)
  await env.DB.exec('CREATE TABLE IF NOT EXISTS data_backups (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at INTEGER NOT NULL, data_json TEXT NOT NULL)').catch(function(){});
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
  var ip = getIp(req), now = Date.now();
  // 登录限速:同 IP 最近 15 分钟内失败 5 次即锁定 15 分钟
  var fails = await env.DB.prepare('SELECT COUNT(*) as cnt FROM audit_logs WHERE event = ? AND ip = ? AND created_at > ?').bind('admin_login_failed', ip, now - 900000).first();
  if (fails && fails.cnt >= 5) {
    return json({ error: '登录失败次数过多,已锁定 15 分钟,请稍后再试' }, 429);
  }
  if (body.password !== env.ADMIN_PASSWORD) {
    await audit(env, 'admin_login_failed', '口令错误', null, ip);
    return json({ error: '口令错误' }, 401);
  }
  var token = randomToken(32), expires = now + 7200000;
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
  // 纵深防御:校验动态码,防止复制旧URL跨时段使用
  var now = Date.now();
  if (body.code) {
    var codeOk = await verifySlotCode(uid, now, body.code, env);
    if (!codeOk) {
      await audit(env, 'code_invalid', '动态码校验失败 UID=' + uid + ' code=' + body.code, body.deviceId, getIp(req));
      return json({ error: '打卡链接已过期，请重新触碰 NFC 标签获取新链接' }, 403);
    }
  } else {
    // 没有code,说明是直接访问 index.html 而非通过 /go 跳转
    return json({ error: '请通过触碰 NFC 标签进入打卡页面' }, 403);
  }
  // 防代码复用:如果该设备已在此科室打过当天同一类型的卡,拒绝发 nonce
  // 这会阻止"刷新页面获取新 nonce 再次打卡"的攻击
  var ct = getCheckType(now);
  var dateStr = new Date(now + 8 * 3600 * 1000).toISOString().slice(0, 10);
  var alreadyChecked = await env.DB.prepare('SELECT 1 FROM checkins WHERE device_id = ? AND tag_uid = ? AND checkin_date = ? AND check_type = ? LIMIT 1').bind(body.deviceId, uid, dateStr, ct.type).first();
  if (alreadyChecked) {
    await audit(env, 'code_reuse', '设备已打卡,尝试复用 code UID=' + uid + ' 类型=' + ct.type, body.deviceId, getIp(req));
    return json({ error: '该设备今日已在此科室打过此类型卡，请勿重复打卡，如需打卡请重新触碰 NFC 标签' }, 409);
  }
  // 设备绑定说明:
  //   - NFC 贴片是科室共用,任何设备都可以扫任意贴片,不在此处限制
  //   - 设备↔工号 的绑定限制在 handleCheckinSubmit 中检查(首次提交工号时绑定)
  //   - 此处仅记录/更新设备最近访问的 tag_uid 与 last_seen_at
  var bind = await env.DB.prepare('SELECT tag_uid, user_code FROM device_binds WHERE device_id = ?').bind(body.deviceId).first();
  var nonce = randomToken(24), expires = now + 120000; // 纵深防御:nonce 120秒,防止书签 URL 长时间有效
  await env.DB.prepare('INSERT INTO nonces (nonce, tag_uid, device_id, created_at, expires_at, used) VALUES (?, ?, ?, ?, ?, 0)').bind(nonce, uid, body.deviceId, now, expires).run();
  if (!bind) {
    await env.DB.prepare('INSERT INTO device_binds (device_id, tag_uid, user_code, bound_at, last_seen_at) VALUES (?, ?, NULL, ?, ?)').bind(body.deviceId, uid, now, now).run();
  } else {
    await env.DB.prepare('UPDATE device_binds SET tag_uid = ?, last_seen_at = ? WHERE device_id = ?').bind(uid, now, body.deviceId).run();
  }
  // 若设备已绑定工号,返回给前端用于预填(只读)
  return json({ nonce: nonce, nonceExpiresAt: expires, dept: tag.dept, serverTime: now, boundUserCode: bind ? bind.user_code : null });
}

async function handleCheckinSubmit(req, env) {
  var body = await req.json();
  var n = body.nonce, t = body.tagUid, d = body.deviceId, u = body.userCode, lat = body.lat, lng = body.lng, reason = body.reason;
  if (!n || !t || !d || !u) return json({ error: '参数缺失' }, 400);
  if (typeof lat !== 'number' || typeof lng !== 'number') return json({ error: '定位数据格式错误' }, 400);
  var uid = String(t).toLowerCase().trim(), now = Date.now(), ip = getIp(req), ua = req.headers.get('User-Agent') || '';
  // 打卡提交限速:同 IP 1分钟最多5次操作
  var recentActions = await env.DB.prepare('SELECT COUNT(*) as cnt FROM audit_logs WHERE ip = ? AND created_at > ?').bind(ip, now - 60000).first();
  if (recentActions && recentActions.cnt >= 5) {
    return json({ error: '操作过于频繁,请 1 分钟后再试' }, 429);
  }

  var nc = await env.DB.prepare('SELECT nonce, tag_uid, device_id, expires_at, used FROM nonces WHERE nonce = ?').bind(n).first();
  if (!nc) return json({ error: 'nonce 无效，请重新触碰 NFC 标签' }, 403);
  if (nc.used) return json({ error: '本次打卡已提交，请勿重复提交' }, 409);
  if (now > nc.expires_at) return json({ error: '打卡超时，请重新触碰 NFC 标签' }, 410);
  if (nc.tag_uid !== uid) return json({ error: 'UID 与本次会话不匹配' }, 403);
  if (nc.device_id !== d) return json({ error: '设备与本次会话不匹配' }, 403);

  var bind = await env.DB.prepare('SELECT tag_uid, user_code FROM device_binds WHERE device_id = ?').bind(d).first();
  if (!bind) { await audit(env, 'device_mismatch', '设备 ' + d + ' 未绑定', d, ip); return json({ error: '设备绑定异常，请重新触碰 NFC 标签' }, 403); }
  // 设备↔工号绑定校验:一台手机只能给一个工号打卡(首次提交时绑定,之后不可更改)
  if (bind.user_code && bind.user_code !== u) {
    await audit(env, 'device_user_conflict', '设备 ' + d + ' 已绑定工号 ' + bind.user_code + '，本次提交工号 ' + u, d, ip);
    return json({ error: 'DEVICE_USER_CONFLICT', message: '该设备已绑定工号 ' + bind.user_code + '，无法为 ' + u + ' 打卡。请联系管理员解绑后重试。', boundUserCode: bind.user_code }, 409);
  }

  var user = await env.DB.prepare('SELECT user_code, name FROM users WHERE user_code = ?').bind(u).first();
  if (!user) { await audit(env, 'user_invalid', '非法工号: ' + u, d, ip); return json({ error: '工号不在白名单内' }, 403); }

  // 计算卡类型和 checkin_date(UTC+8),夜班补卡跨日归前一天
  var ct = getCheckType(now);
  var d8 = new Date(now + 28800000);
  if (ct.crossDay) d8.setUTCDate(d8.getUTCDate() - 1);
  var cdate = d8.toISOString().slice(0, 10);

  // 防重复:同一工号 + 同一天 + 同一卡类型 只能打一次
  var exist = await env.DB.prepare('SELECT id, check_time, check_type FROM checkins WHERE user_code = ? AND checkin_date = ? AND check_type = ? ORDER BY check_time DESC LIMIT 1').bind(u, cdate, ct.type).first();
  if (exist) return json({ error: '今日该卡类型已打卡', lastCheckTime: exist.check_time, lastCheckType: exist.check_type }, 409);

  // 补卡状态下,reason 必填且不超过 20 字,且月度补卡不超过5次
  if (ct.status === 'abnormal') {
    if (!reason || !String(reason).trim()) return json({ error: '补卡状态下必须填写补卡原因(不超过20字)' }, 400);
    if (String(reason).trim().length > 20) return json({ error: '补卡原因不超过 20 字' }, 400);
    // 月度补卡次数上限:5次(按 UTC+8 当月)
    var mStart = new Date(now + 28800000); mStart.setUTCDate(1); mStart.setUTCHours(0, 0, 0, 0);
    var monthStartTs = mStart.getTime() - 28800000;
    var makeupCount = await env.DB.prepare('SELECT COUNT(*) as cnt FROM checkins WHERE user_code = ? AND status = ? AND check_time >= ?').bind(u, 'abnormal', monthStartTs).first();
    if (makeupCount && makeupCount.cnt >= 5) {
      return json({ error: '本月补卡次数已达上限(5次),无法继续补卡' }, 403);
    }
  }
  var reasonVal = ct.status === 'abnormal' ? String(reason).trim() : null;

  var tag = await env.DB.prepare('SELECT dept FROM nfc_tags WHERE uid = ?').bind(uid).first();
  if (!tag) return json({ error: 'NFC 标签已失效' }, 403);
  var pos = await env.DB.prepare('SELECT lat, lng, radius FROM dept_positions WHERE dept = ?').bind(tag.dept).first();
  if (!pos) return json({ error: '科室「' + tag.dept + '」未配置坐标' }, 500);

  var dis = getDistance(lat, lng, pos.lat, pos.lng);
  var maxRadius = pos.radius + 300; // 范围外300米内允许打卡但标记定位异常
  var locationAbnormal = false;
  if (dis > pos.radius) {
    locationAbnormal = true;
    await audit(env, 'location_abnormal', 'UID ' + uid + ' 定位超出范围 ' + dis.toFixed(1) + 'm (半径' + pos.radius + 'm,上限' + maxRadius + 'm)', d, ip);
    if (dis > maxRadius) {
      return json({ error: '定位异常', distance: dis.toFixed(1), limit: maxRadius, message: '超出打卡范围 ' + dis.toFixed(1) + ' 米(上限 ' + maxRadius + ' 米),禁止打卡' }, 403);
    }
  }
  // 坐标跳跃检测:同设备5分钟内坐标跳跃>1km 标记异常
  var recentChk = await env.DB.prepare('SELECT lat, lng FROM checkins WHERE device_id = ? AND check_time > ? ORDER BY check_time DESC LIMIT 1').bind(d, now - 300000).first();
  if (recentChk) {
    var jumpDist = getDistance(lat, lng, recentChk.lat, recentChk.lng);
    if (jumpDist > 1000) {
      locationAbnormal = true;
      await audit(env, 'location_jump', '设备 ' + d + ' 5分钟内坐标跳跃 ' + jumpDist.toFixed(1) + 'm', d, ip);
    }
  }
  var locStatus = locationAbnormal ? 'abnormal' : 'normal';

  var stmt = env.DB.prepare('INSERT INTO checkins (tag_uid, user_code, user_name, dept, check_type, status, check_time, lat, lng, distance, device_id, ip, ua, created_at, checkin_date, reason, location_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').bind(uid, u, user.name, tag.dept, ct.type, ct.status, now, lat, lng, dis, d, ip, ua, now, cdate, reasonVal, locStatus);
  try { await stmt.run(); } catch (e) { if (String(e.message).indexOf('UNIQUE') >= 0) return json({ error: '今日该卡类型已打卡' }, 409); throw e; }

  await env.DB.prepare('UPDATE nonces SET used = 1 WHERE nonce = ?').bind(n).run();
  await env.DB.prepare('UPDATE device_binds SET user_code = ?, last_seen_at = ? WHERE device_id = ?').bind(u, now, d).run();
  await audit(env, 'checkin_ok', user.name + '(' + u + ') 打卡: ' + tag.dept + ' - ' + ct.type + (ct.status === 'abnormal' ? '(补卡:' + reasonVal + ')' : '') + ', 距离 ' + dis.toFixed(1) + 'm' + (locationAbnormal ? '[定位异常]' : ''), d, ip);

  return json({ ok: true, record: { userName: user.name, userCode: u, dept: tag.dept, checkType: ct.type, checkTime: now, distance: dis.toFixed(1), status: ct.status, reason: reasonVal, locationStatus: locStatus } });
}

async function handleMyRecords(req, env) {
  var deviceId = new URL(req.url).searchParams.get('deviceId');
  if (!deviceId) return json({ error: '缺少 deviceId' }, 400);
  var bind = await env.DB.prepare('SELECT tag_uid, user_code FROM device_binds WHERE device_id = ?').bind(deviceId).first();
  if (!bind) return json({ records: [] });
  // 按 device_id 查询该设备对应工号的记录,而非按 tag_uid 查询所有记录
  if (bind.user_code) {
    var rows = await env.DB.prepare('SELECT check_time, dept, check_type, status, distance FROM checkins WHERE device_id = ? ORDER BY check_time DESC LIMIT 30').bind(deviceId).all();
    return json({ boundUid: bind.tag_uid, boundUserCode: bind.user_code, records: rows.results || [] });
  }
  return json({ boundUid: bind.tag_uid, boundUserCode: null, records: [] });
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

// 批量导入白名单(支持 user / dept / nfc 三类)
// 入参: { type: 'user'|'dept'|'nfc', items: [...] , mode: 'upsert'|'replace'}
//   - mode='upsert'(默认): 仅插入/更新,不动现有数据
//   - mode='replace': 先清空该类型数据,再批量插入(谨慎使用)
async function handleBatchWhitelist(req, env) {
  var body = await req.json(), now = Date.now();
  if (!body.type || !Array.isArray(body.items)) return json({ error: '参数缺失或 items 不是数组' }, 400);
  var type = body.type, items = body.items, mode = body.mode === 'replace' ? 'replace' : 'upsert';
  if (items.length === 0) return json({ error: 'items 为空' }, 400);
  if (items.length > 2000) return json({ error: '单次最多 2000 条' }, 400);

  var ok = 0, fail = 0, errors = [];
  try {
    if (type === 'user') {
      if (mode === 'replace') await env.DB.prepare('DELETE FROM users').run();
      for (var i = 0; i < items.length; i++) {
        var it = items[i];
        var code = it.userCode != null ? String(it.userCode).trim() : (it.user_code != null ? String(it.user_code).trim() : '');
        var name = it.name != null ? String(it.name).trim() : '';
        if (!code || !name) { fail++; errors.push('第 ' + (i + 1) + ' 行: 工号或姓名为空'); continue; }
        try {
          await env.DB.prepare('INSERT INTO users (user_code, name, created_at) VALUES (?, ?, ?) ON CONFLICT(user_code) DO UPDATE SET name = excluded.name').bind(code, name, now).run();
          ok++;
        } catch (e) { fail++; errors.push('第 ' + (i + 1) + ' 行: ' + e.message); }
      }
    } else if (type === 'dept') {
      if (mode === 'replace') await env.DB.prepare('DELETE FROM dept_positions').run();
      for (var j = 0; j < items.length; j++) {
        var d = items[j];
        var dname = d.dept != null ? String(d.dept).trim() : '';
        var lat = parseFloat(d.lat), lng = parseFloat(d.lng), radius = parseInt(d.radius) || 15;
        if (!dname || isNaN(lat) || isNaN(lng)) { fail++; errors.push('第 ' + (j + 1) + ' 行: 科室名/经纬度无效'); continue; }
        try {
          await env.DB.prepare('INSERT INTO dept_positions (dept, lat, lng, radius) VALUES (?, ?, ?, ?) ON CONFLICT(dept) DO UPDATE SET lat = excluded.lat, lng = excluded.lng, radius = excluded.radius').bind(dname, lat, lng, radius).run();
          ok++;
        } catch (e) { fail++; errors.push('第 ' + (j + 1) + ' 行: ' + e.message); }
      }
    } else if (type === 'nfc') {
      if (mode === 'replace') await env.DB.prepare('DELETE FROM nfc_tags').run();
      for (var k = 0; k < items.length; k++) {
        var t = items[k];
        var uid = t.uid != null ? String(t.uid).toLowerCase().trim() : '';
        var dept = t.dept != null ? String(t.dept).trim() : '';
        if (!uid || !dept) { fail++; errors.push('第 ' + (k + 1) + ' 行: UID 或科室为空'); continue; }
        try {
          await env.DB.prepare('INSERT INTO nfc_tags (uid, dept, created_at) VALUES (?, ?, ?) ON CONFLICT(uid) DO UPDATE SET dept = excluded.dept').bind(uid, dept, now).run();
          ok++;
        } catch (e) { fail++; errors.push('第 ' + (k + 1) + ' 行: ' + e.message); }
      }
    } else {
      return json({ error: '未知类型,应为 user / dept / nfc' }, 400);
    }
    await audit(env, 'whitelist_batch', type + ' mode=' + mode + ' ok=' + ok + ' fail=' + fail, null, getIp(req));
    return json({ ok: true, type: type, mode: mode, success: ok, failed: fail, errors: errors.slice(0, 50) });
  } catch (e) {
    return json({ error: '批量导入失败: ' + e.message, success: ok, failed: fail, errors: errors.slice(0, 50) }, 500);
  }
}

// 危险操作:重置数据库(清空前强制备份,保留白名单)
// 入参: { confirm: 'YES_RESET' }  防止误触发
async function handleResetDb(req, env) {
  var body = await req.json().catch(function () { return {}; });
  if (body.confirm !== 'YES_RESET') {
    return json({ error: '请确认重置操作(confirm 参数必须为 YES_RESET)' }, 400);
  }
  // 强制备份:导出5张表数据到 data_backups
  await env.DB.exec('CREATE TABLE IF NOT EXISTS data_backups (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at INTEGER NOT NULL, data_json TEXT NOT NULL)').catch(function(){});
  var backup = { created_at: Date.now(), tables: {} };
  var tableNames = ['checkins', 'device_binds', 'nonces', 'admin_sessions', 'audit_logs'];
  for (var i = 0; i < tableNames.length; i++) {
    var rows = await env.DB.prepare('SELECT * FROM ' + tableNames[i]).all().catch(function () { return { results: [] }; });
    backup.tables[tableNames[i]] = (rows && rows.results) || [];
  }
  var backupJson = JSON.stringify(backup);
  var backupRes = await env.DB.prepare('INSERT INTO data_backups (created_at, data_json) VALUES (?, ?)').bind(backup.created_at, backupJson).run();
  var backupId = backupRes.meta ? backupRes.meta.last_row_id : null;

  // 按顺序删除 5 张表(保留 nfc_tags / users / dept_positions / data_backups 白名单和备份)
  var drops = [
    'DROP TABLE IF EXISTS checkins',
    'DROP TABLE IF EXISTS device_binds',
    'DROP TABLE IF EXISTS nonces',
    'DROP TABLE IF EXISTS admin_sessions',
    'DROP TABLE IF EXISTS audit_logs',
  ];
  for (var j = 0; j < drops.length; j++) {
    await env.DB.exec(drops[j]).catch(function () {});
  }
  // 重建表 + 索引(调用 initDb,INSERT OR IGNORE 不会覆盖已有白名单)
  await initDb(env);
  // 重新写入审计日志表(reset 删了 audit_logs,需要重建后写一条记录)
  await env.DB.exec('CREATE TABLE IF NOT EXISTS audit_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, event TEXT NOT NULL, detail TEXT, device_id TEXT, ip TEXT, created_at INTEGER NOT NULL)').catch(function(){});
  await env.DB.prepare('INSERT INTO audit_logs (event, detail, device_id, ip, created_at) VALUES (?, ?, ?, ?, ?)').bind('db_reset', '管理员重置数据库,备份ID=' + backupId + ',已清空打卡/设备/会话数据,保留白名单', null, getIp(req), Date.now()).run();
  return json({ ok: true, backupId: backupId, message: '数据库已重置。清空前已自动备份(备份ID: ' + backupId + ')。打卡记录、设备绑定、nonce、管理员会话已清空,白名单已保留。当前管理员会话已失效,请重新登录。' });
}

// 查看备份列表
async function handleListBackups(req, env) {
  var rows = await env.DB.prepare('SELECT id, created_at, length(data_json) as size FROM data_backups ORDER BY id DESC LIMIT 50').all().catch(function () { return { results: [] }; });
  return json({ backups: (rows && rows.results) || [] });
}

// 下载备份JSON
async function handleDownloadBackup(req, env) {
  var u = new URL(req.url);
  var id = parseInt(u.searchParams.get('id'));
  if (!id) return json({ error: '缺少 id' }, 400);
  var row = await env.DB.prepare('SELECT id, created_at, data_json FROM data_backups WHERE id = ?').bind(id).first();
  if (!row) return json({ error: '备份不存在' }, 404);
  return new Response(row.data_json, { status: 200, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Content-Disposition': 'attachment; filename="backup-' + id + '-' + row.created_at + '.json"', ...corsHeaders() } });
}

// NFC 标签 UID 轮换(针对 NFC 贴片被复制的风险)
// 生成新 UID,旧 UID 立即失效,需重新写贴片
async function handleRotateTag(req, env) {
  var body = await req.json();
  if (!body.uid) return json({ error: '缺少 uid(要轮换的旧UID)' }, 400);
  var oldUid = String(body.uid).toLowerCase().trim();
  var tag = await env.DB.prepare('SELECT uid, dept FROM nfc_tags WHERE uid = ?').bind(oldUid).first();
  if (!tag) return json({ error: 'NFC 标签不存在' }, 404);
  var newUid = randomToken(7); // 14位十六进制,模拟NFC UID格式
  await env.DB.prepare('DELETE FROM nfc_tags WHERE uid = ?').bind(oldUid).run();
  await env.DB.prepare('INSERT INTO nfc_tags (uid, dept, created_at) VALUES (?, ?, ?)').bind(newUid, tag.dept, Date.now()).run();
  await audit(env, 'tag_rotate', 'NFC标签轮换: ' + oldUid + ' → ' + newUid + ' (科室: ' + tag.dept + ')', null, getIp(req));
  return json({ ok: true, oldUid: oldUid, newUid: newUid, dept: tag.dept, url: 'https://nfc-checkin-1om.pages.dev/index.html?tagUid=' + newUid });
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
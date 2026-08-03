/**
 * 科室轮转打卡系统 - Cloudflare Workers 后端
 *
 * 路由总览：
 *   公开：
 *     GET  /api/health        健康检查
 *     POST /api/admin/login   管理员登录
 *     POST /api/checkin/init   NFC 链接进入 → 校验 tagUid + 生成 nonce
 *     POST /api/checkin/submit 提交打卡（校验 nonce + 设备绑定 + 定位 + 时间 + 防重复）
 *     GET  /api/records/mine   学生查本人记录（按 deviceId 绑定）
 *   需管理员 token：
 *     GET  /api/records/all    全部记录
 *     POST /api/admin/unbind   设备解绑
 *     GET  /api/admin/whitelist 白名单查询
 *     POST /api/admin/whitelist 白名单增改
 *     DELETE /api/admin/whitelist 白名单删除
 *     GET  /api/admin/devices   设备列表
 *     GET  /api/audit           审计日志
 *
 * 环境变量（wrangler.toml / dashboard 配置）：
 *   DB                  D1 数据库绑定
 *   ADMIN_PASSWORD      管理员口令（建议强口令）
 *   JWT_SECRET          签发 token 的密钥
 *   ALLOWED_ORIGIN      前端域名（CORS 白名单，如 https://yourname.github.io）
 */

// ============== 工具函数 ==============

// CORS 响应头
function corsHeaders(env) {
  return {
    'Access-Control-Allow-Origin': env.ALLOWED_ORIGIN || '*',
    'Access-Control-Allow-Methods': 'GET,POST,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-Admin-Token',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin',
  };
}

// 统一 JSON 响应
function json(data, status = 200, env) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      ...corsHeaders(env),
    },
  });
}

// 简易 SHA-256 (Web Crypto)
async function sha256(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// 生成随机 token
function randomToken(len = 32) {
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Haversine 距离（米）
function getDistance(lat1, lng1, lat2, lng2) {
  const R = 6371000;
  const rad = Math.PI / 180;
  const dLat = (lat2 - lat1) * rad;
  const dLng = (lng2 - lng1) * rad;
  const a = Math.sin(dLat / 2) ** 2 +
    Math.cos(lat1 * rad) * Math.cos(lat2 * rad) * Math.sin(dLng / 2) ** 2;
  return R * (2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a)));
}

// 打卡类型判定（基于服务器时间，东八区）
function getCheckType(ts) {
  // ts 是毫秒；转 UTC+8
  const d = new Date(ts + 8 * 3600 * 1000);
  const total = d.getUTCHours() * 60 + d.getUTCMinutes();
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

// 校验管理员 token
async function verifyAdminToken(request, env) {
  const token = request.headers.get('X-Admin-Token');
  if (!token) return false;
  const row = await env.DB.prepare(
    'SELECT expires_at FROM admin_sessions WHERE token = ?'
  ).bind(token).first();
  if (!row) return false;
  if (Date.now() > row.expires_at) return false;
  return true;
}

// 写审计日志
async function audit(env, event, detail, deviceId = null, ip = null) {
  await env.DB.prepare(
    'INSERT INTO audit_logs (event, detail, device_id, ip, created_at) VALUES (?, ?, ?, ?, ?)'
  ).bind(event, detail, deviceId, ip, Date.now()).run();
}

// 从请求中获取 IP
function getClientIp(request) {
  return request.headers.get('CF-Connecting-IP') ||
         request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() ||
         'unknown';
}

// ============== 路由分发 ==============

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // 处理 CORS 预检
    if (method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(env) });
    }

    // 数据库懒初始化（首次部署或重置后自动建表）
    try {
      await env.DB.prepare('SELECT 1 FROM checkins LIMIT 1').run();
    } catch (e) {
      await initDb(env);
    }

    try {
      // ---------- 公开接口 ----------
      if (path === '/api/health' && method === 'GET') {
        return json({ ok: true, time: Date.now() }, 200, env);
      }

      if (path === '/api/admin/login' && method === 'POST') {
        return await handleAdminLogin(request, env);
      }

      if (path === '/api/checkin/init' && method === 'POST') {
        return await handleCheckinInit(request, env);
      }

      if (path === '/api/checkin/submit' && method === 'POST') {
        return await handleCheckinSubmit(request, env);
      }

      if (path === '/api/records/mine' && method === 'GET') {
        return await handleGetMyRecords(request, env);
      }

      // ---------- 需管理员权限 ----------
      if (path.startsWith('/api/admin') || path === '/api/audit') {
        const ok = await verifyAdminToken(request, env);
        if (!ok) return json({ error: '未授权或登录已过期' }, 401, env);

        if (path === '/api/records/all' && method === 'GET') {
          return await handleGetAllRecords(request, env);
        }
        if (path === '/api/admin/unbind' && method === 'POST') {
          return await handleUnbindDevice(request, env);
        }
        if (path === '/api/admin/whitelist' && method === 'GET') {
          return await handleGetWhitelist(request, env);
        }
        if (path === '/api/admin/whitelist' && method === 'POST') {
          return await handleUpsertWhitelist(request, env);
        }
        if (path === '/api/admin/whitelist/batch' && method === 'POST') {
          return await handleBatchWhitelist(request, env);
        }
        if (path === '/api/admin/whitelist' && method === 'DELETE') {
          return await handleDeleteWhitelist(request, env);
        }
        if (path === '/api/admin/reset-db' && method === 'POST') {
          return await handleResetDb(request, env);
        }
        if (path === '/api/admin/backups' && method === 'GET') return await handleListBackups(request, env);
        if (path === '/api/admin/backups/download' && method === 'GET') return await handleDownloadBackup(request, env);
        if (path === '/api/admin/rotate-tag' && method === 'POST') return await handleRotateTag(request, env);
        if (path === '/api/admin/devices' && method === 'GET') {
          return await handleGetDevices(request, env);
        }
        if (path === '/api/audit' && method === 'GET') {
          return await handleGetAudit(request, env);
        }
      }

      return json({ error: '接口不存在', path }, 404, env);
    } catch (err) {
      console.error('Unhandled error:', err);
      return json({ error: '服务器内部错误', message: err.message }, 500, env);
    }
  },

  // 定时任务：清理过期 nonce 和 admin session
  async scheduled(event, env) {
    const now = Date.now();
    await env.DB.prepare('DELETE FROM nonces WHERE expires_at < ?').bind(now - 86400000).run();
    await env.DB.prepare('DELETE FROM admin_sessions WHERE expires_at < ?').bind(now).run();
  },
};

// ============== 数据库初始化 ==============

async function initDb(env) {
  const stmts = [
    `CREATE TABLE IF NOT EXISTS nfc_tags (
      uid TEXT PRIMARY KEY,
      dept TEXT NOT NULL,
      created_at INTEGER NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS users (
      user_code TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      created_at INTEGER NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS dept_positions (
      dept TEXT PRIMARY KEY,
      lat REAL NOT NULL,
      lng REAL NOT NULL,
      radius INTEGER NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS device_binds (
      device_id TEXT PRIMARY KEY,
      tag_uid TEXT NOT NULL,
      user_code TEXT,
      bound_at INTEGER NOT NULL,
      last_seen_at INTEGER NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS checkins (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tag_uid TEXT NOT NULL,
      user_code TEXT NOT NULL,
      user_name TEXT NOT NULL,
      dept TEXT NOT NULL,
      check_type TEXT NOT NULL,
      status TEXT NOT NULL,
      check_time INTEGER NOT NULL,
      lat REAL NOT NULL,
      lng REAL NOT NULL,
      distance REAL NOT NULL,
      device_id TEXT NOT NULL,
      ip TEXT,
      ua TEXT,
      created_at INTEGER NOT NULL,
      checkin_date TEXT NOT NULL,
      reason TEXT,
      UNIQUE(user_code, checkin_date, check_type)
    )`,
    `CREATE TABLE IF NOT EXISTS nonces (
      nonce TEXT PRIMARY KEY,
      tag_uid TEXT NOT NULL,
      device_id TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      used INTEGER DEFAULT 0
    )`,
    `CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      event TEXT NOT NULL,
      detail TEXT,
      device_id TEXT,
      ip TEXT,
      created_at INTEGER NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS admin_sessions (
      token TEXT PRIMARY KEY,
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL
    )`,
    `CREATE INDEX IF NOT EXISTS idx_checkins_time ON checkins(check_time)`,
    `CREATE INDEX IF NOT EXISTS idx_checkins_tag ON checkins(tag_uid)`,
    `CREATE INDEX IF NOT EXISTS idx_checkins_user_date ON checkins(user_code, checkin_date)`,
    `CREATE INDEX IF NOT EXISTS idx_nonces_expires ON nonces(expires_at)`,
  ];
  for (const sql of stmts) {
    await env.DB.exec(sql).catch(() => {});
  }
  // 已有表向前兼容:自动添加 reason / location_status 字段(若不存在)
  try { await env.DB.prepare('SELECT reason FROM checkins LIMIT 1').run(); } catch (e) { await env.DB.exec('ALTER TABLE checkins ADD COLUMN reason TEXT').catch(() => {}); }
  try { await env.DB.prepare('SELECT location_status FROM checkins LIMIT 1').run(); } catch (e) { await env.DB.exec('ALTER TABLE checkins ADD COLUMN location_status TEXT').catch(() => {}); }
  // 数据备份表(reset 前自动备份用)
  await env.DB.exec('CREATE TABLE IF NOT EXISTS data_backups (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at INTEGER NOT NULL, data_json TEXT NOT NULL)').catch(() => {});
  // 首次初始化写入示例数据（仅在表为空时）
  await env.DB.prepare(
    `INSERT OR IGNORE INTO nfc_tags (uid, dept, created_at) VALUES
      ('538b1cce330001', '急诊', ?),
      ('04b771cc223311', '护士站', ?)`
  ).bind(Date.now(), Date.now()).run();

  await env.DB.prepare(
    `INSERT OR IGNORE INTO users (user_code, name, created_at) VALUES
      ('001', '刘六六', ?),
      ('002', '李四', ?)`
  ).bind(Date.now(), Date.now()).run();

  await env.DB.prepare(
    `INSERT OR IGNORE INTO dept_positions (dept, lat, lng, radius) VALUES
      ('急诊', 29.362, 106.2929, 15),
      ('护士站', 29.4570, 106.5895, 15)`
  ).run();
}

// ============== 接口实现 ==============

// 管理员登录
async function handleAdminLogin(request, env) {
  const { password } = await request.json();
  if (!password) return json({ error: '请输入口令' }, 400, env);

  const ip = getClientIp(request), now = Date.now();
  // 登录限速:同 IP 最近 15 分钟内失败 5 次即锁定 15 分钟
  const fails = await env.DB.prepare('SELECT COUNT(*) as cnt FROM audit_logs WHERE event = ? AND ip = ? AND created_at > ?').bind('admin_login_failed', ip, now - 900000).first();
  if (fails && fails.cnt >= 5) {
    return json({ error: '登录失败次数过多,已锁定 15 分钟,请稍后再试' }, 429, env);
  }

  // 简单比对（生产环境建议 bcrypt，Cloudflare Workers 也可用 bcryptjs）
  if (password !== env.ADMIN_PASSWORD) {
    await audit(env, 'admin_login_failed', '口令错误', null, ip);
    return json({ error: '口令错误' }, 401, env);
  }

  const token = randomToken(32);
  const expires = now + 2 * 3600 * 1000; // 2 小时
  await env.DB.prepare(
    'INSERT INTO admin_sessions (token, created_at, expires_at) VALUES (?, ?, ?)'
  ).bind(token, now, expires).run();
  await audit(env, 'admin_login_ok', '管理员登录成功', null, ip);
  return json({ token, expiresAt: expires }, 200, env);
}

// NFC 进入 → 校验 + 生成 nonce
async function handleCheckinInit(request, env) {
  const { tagUid, deviceId } = await request.json();
  if (!tagUid || !deviceId) {
    return json({ error: '参数缺失' }, 400, env);
  }
  const uid = String(tagUid).toLowerCase().trim();

  // 校验 tagUid 是否在白名单
  const tag = await env.DB.prepare(
    'SELECT uid, dept FROM nfc_tags WHERE uid = ?'
  ).bind(uid).first();
  if (!tag) {
    await audit(env, 'nfc_invalid', `非法 UID: ${uid}`, deviceId, getClientIp(request));
    return json({ error: 'NFC 标签未注册，访问拒绝' }, 403, env);
  }

  // 设备绑定说明:
  //   - NFC 贴片是科室共用,任何设备都可以扫任意贴片,不在此处限制
  //   - 设备↔工号 的绑定限制在 handleCheckinSubmit 中检查(首次提交工号时绑定)
  //   - 此处仅记录/更新设备最近访问的 tag_uid 与 last_seen_at
  const bind = await env.DB.prepare(
    'SELECT tag_uid, user_code FROM device_binds WHERE device_id = ?'
  ).bind(deviceId).first();

  // 纵深防御:非打卡时段拒绝页面初始化,防止书签 URL 滥用
  const now = Date.now();
  const ct = getCheckType(now);
  // 允许补卡时段初始化(上午上班补卡/下午上班补卡/夜班补卡均允许)
  // 正常时段总是允许;补卡时段也允许(因为系统支持补卡)
  // 非打卡时段:理论上所有时段都允许打卡(正常+补卡覆盖24小时),所以不做额外拒绝

  // 生成 nonce（120 秒有效,纵深防御:防止书签 URL 长时间有效）
  const nonce = randomToken(24);
  const expires = now + 120000;
  await env.DB.prepare(
    'INSERT INTO nonces (nonce, tag_uid, device_id, created_at, expires_at, used) VALUES (?, ?, ?, ?, ?, 0)'
  ).bind(nonce, uid, deviceId, now, expires).run();

  if (!bind) {
    await env.DB.prepare(
      'INSERT INTO device_binds (device_id, tag_uid, user_code, bound_at, last_seen_at) VALUES (?, ?, NULL, ?, ?)'
    ).bind(deviceId, uid, now, now).run();
  } else {
    await env.DB.prepare(
      'UPDATE device_binds SET tag_uid = ?, last_seen_at = ? WHERE device_id = ?'
    ).bind(uid, now, deviceId).run();
  }

  // 若设备已绑定工号,返回给前端用于预填(只读)
  return json({
    nonce,
    nonceExpiresAt: expires,
    dept: tag.dept,
    serverTime: now,
    boundUserCode: bind ? bind.user_code : null,
  }, 200, env);
}

// 提交打卡
async function handleCheckinSubmit(request, env) {
  const body = await request.json();
  const { nonce, tagUid, deviceId, userCode, lat, lng, reason } = body;

  // 基础参数校验
  if (!nonce || !tagUid || !deviceId || !userCode) {
    return json({ error: '参数缺失' }, 400, env);
  }
  if (typeof lat !== 'number' || typeof lng !== 'number') {
    return json({ error: '定位数据格式错误' }, 400, env);
  }

  const uid = String(tagUid).toLowerCase().trim();
  const now = Date.now();
  const ip = getClientIp(request);
  const ua = request.headers.get('User-Agent') || '';

  // 打卡提交限速:同 IP 1分钟最多5次操作
  const recentActions = await env.DB.prepare('SELECT COUNT(*) as cnt FROM audit_logs WHERE ip = ? AND created_at > ?').bind(ip, now - 60000).first();
  if (recentActions && recentActions.cnt >= 5) {
    return json({ error: '操作过于频繁,请 1 分钟后再试' }, 429, env);
  }

  // 1) nonce 校验
  const n = await env.DB.prepare(
    'SELECT nonce, tag_uid, device_id, expires_at, used FROM nonces WHERE nonce = ?'
  ).bind(nonce).first();
  if (!n) return json({ error: 'nonce 无效，请重新触碰 NFC 标签' }, 403, env);
  if (n.used) return json({ error: '本次打卡已提交，请勿重复提交' }, 409, env);
  if (now > n.expires_at) return json({ error: '打卡超时，请重新触碰 NFC 标签' }, 410, env);
  if (n.tag_uid !== uid) return json({ error: 'UID 与本次会话不匹配' }, 403, env);
  if (n.device_id !== deviceId) return json({ error: '设备与本次会话不匹配' }, 403, env);

  // 2) 设备绑定校验（防绕过）
  const bind = await env.DB.prepare(
    'SELECT tag_uid, user_code FROM device_binds WHERE device_id = ?'
  ).bind(deviceId).first();
  if (!bind) {
    await audit(env, 'device_mismatch', `设备 ${deviceId} 未绑定`, deviceId, ip);
    return json({ error: '设备绑定异常，请重新触碰 NFC 标签' }, 403, env);
  }
  // 设备↔工号绑定校验:一台手机只能给一个工号打卡(首次提交时绑定,之后不可更改)
  if (bind.user_code && bind.user_code !== userCode) {
    await audit(env, 'device_user_conflict',
      `设备 ${deviceId} 已绑定工号 ${bind.user_code}，本次提交工号 ${userCode}`,
      deviceId, ip);
    return json({
      error: 'DEVICE_USER_CONFLICT',
      message: `该设备已绑定工号 ${bind.user_code}，无法为 ${userCode} 打卡。请联系管理员解绑后重试。`,
      boundUserCode: bind.user_code,
    }, 409, env);
  }

  // 3) 工号白名单校验
  const user = await env.DB.prepare(
    'SELECT user_code, name FROM users WHERE user_code = ?'
  ).bind(userCode).first();
  if (!user) {
    await audit(env, 'user_invalid', `非法工号: ${userCode}`, deviceId, ip);
    return json({ error: '工号不在白名单内' }, 403, env);
  }

  // 4) 计算卡类型和 checkin_date(UTC+8),夜班补卡跨日归前一天
  const ct = getCheckType(now);
  const d8 = new Date(now + 8 * 3600 * 1000);
  if (ct.crossDay) d8.setUTCDate(d8.getUTCDate() - 1);
  const checkinDate = d8.toISOString().slice(0, 10);

  // 5) 防重复:同一工号 + 同一天 + 同一卡类型 只能打一次
  const exist = await env.DB.prepare(
    'SELECT id, check_time, check_type FROM checkins WHERE user_code = ? AND checkin_date = ? AND check_type = ? ORDER BY check_time DESC LIMIT 1'
  ).bind(userCode, checkinDate, ct.type).first();
  if (exist) {
    return json({
      error: '今日该卡类型已打卡',
      lastCheckTime: exist.check_time,
      lastCheckType: exist.check_type,
    }, 409, env);
  }

  // 6) 补卡状态下,reason 必填且不超过 20 字,且月度补卡不超过5次
  if (ct.status === 'abnormal') {
    if (!reason || !String(reason).trim()) {
      return json({ error: '补卡状态下必须填写补卡原因(不超过20字)' }, 400, env);
    }
    if (String(reason).trim().length > 20) {
      return json({ error: '补卡原因不超过 20 字' }, 400, env);
    }
    // 月度补卡次数上限:5次(按 UTC+8 当月)
    const mStart = new Date(now + 28800000); mStart.setUTCDate(1); mStart.setUTCHours(0, 0, 0, 0);
    const monthStartTs = mStart.getTime() - 28800000;
    const makeupCount = await env.DB.prepare('SELECT COUNT(*) as cnt FROM checkins WHERE user_code = ? AND status = ? AND check_time >= ?').bind(userCode, 'abnormal', monthStartTs).first();
    if (makeupCount && makeupCount.cnt >= 5) {
      return json({ error: '本月补卡次数已达上限(5次),无法继续补卡' }, 403, env);
    }
  }
  const reasonVal = ct.status === 'abnormal' ? String(reason).trim() : null;

  // 7) 定位校验
  const tag = await env.DB.prepare(
    'SELECT dept FROM nfc_tags WHERE uid = ?'
  ).bind(uid).first();
  if (!tag) return json({ error: 'NFC 标签已失效' }, 403, env);

  const pos = await env.DB.prepare(
    'SELECT lat, lng, radius FROM dept_positions WHERE dept = ?'
  ).bind(tag.dept).first();
  if (!pos) return json({ error: `科室「${tag.dept}」未配置坐标` }, 500, env);

  const distance = getDistance(lat, lng, pos.lat, pos.lng);
  const maxRadius = pos.radius + 300; // 范围外300米内允许打卡但标记定位异常
  let locationAbnormal = false;
  if (distance > pos.radius) {
    locationAbnormal = true;
    await audit(env, 'location_abnormal', `UID ${uid} 定位超出范围 ${distance.toFixed(1)}m (半径${pos.radius}m,上限${maxRadius}m)`, deviceId, ip);
    if (distance > maxRadius) {
      return json({
        error: '定位异常',
        distance: distance.toFixed(1),
        limit: maxRadius,
        message: `超出打卡范围 ${distance.toFixed(1)} 米(上限 ${maxRadius} 米),禁止打卡`,
      }, 403, env);
    }
  }
  // 坐标跳跃检测:同设备5分钟内坐标跳跃>1km标记异常
  const recentChk = await env.DB.prepare('SELECT lat, lng FROM checkins WHERE device_id = ? AND check_time > ? ORDER BY check_time DESC LIMIT 1').bind(deviceId, now - 300000).first();
  if (recentChk) {
    const jumpDist = getDistance(lat, lng, recentChk.lat, recentChk.lng);
    if (jumpDist > 1000) {
      locationAbnormal = true;
      await audit(env, 'location_jump', `设备 ${deviceId} 5分钟内坐标跳跃 ${jumpDist.toFixed(1)}m`, deviceId, ip);
    }
  }
  const locStatus = locationAbnormal ? 'abnormal' : 'normal';

  // 8) 写入打卡记录
  const stmt = env.DB.prepare(
    `INSERT INTO checkins
      (tag_uid, user_code, user_name, dept, check_type, status, check_time,
       lat, lng, distance, device_id, ip, ua, created_at, checkin_date, reason, location_status)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    uid, userCode, user.name, tag.dept, ct.type, ct.status, now,
    lat, lng, distance, deviceId, ip, ua, now, checkinDate, reasonVal, locStatus
  );
  try {
    await stmt.run();
  } catch (e) {
    // UNIQUE 约束冲突 → 重复打卡
    if (String(e.message).includes('UNIQUE')) {
      return json({ error: '今日该卡类型已打卡' }, 409, env);
    }
    throw e;
  }

  // 9) nonce 标记已使用
  await env.DB.prepare('UPDATE nonces SET used = 1 WHERE nonce = ?').bind(nonce).run();

  // 10) 设备绑定 user_code（首次提交时绑定工号）
  await env.DB.prepare(
    'UPDATE device_binds SET user_code = ?, last_seen_at = ? WHERE device_id = ?'
  ).bind(userCode, now, deviceId).run();

  await audit(env, 'checkin_ok',
    `${user.name}(${userCode}) 打卡: ${tag.dept} - ${ct.type}${ct.status === 'abnormal' ? `(补卡:${reasonVal})` : ''}, 距离 ${distance.toFixed(1)}m${locationAbnormal ? '[定位异常]' : ''}`,
    deviceId, ip);

  return json({
    ok: true,
    record: {
      userName: user.name,
      userCode: userCode,
      dept: tag.dept,
      checkType: ct.type,
      checkTime: now,
      distance: distance.toFixed(1),
      status: ct.status,
      reason: reasonVal,
      locationStatus: locStatus,
    },
  }, 200, env);
}

// 学生查本人记录（按 deviceId 绑定的 tag_uid 查询）
async function handleGetMyRecords(request, env) {
  const url = new URL(request.url);
  const deviceId = url.searchParams.get('deviceId');
  if (!deviceId) return json({ error: '缺少 deviceId' }, 400, env);

  const bind = await env.DB.prepare(
    'SELECT tag_uid, user_code FROM device_binds WHERE device_id = ?'
  ).bind(deviceId).first();
  if (!bind) return json({ records: [] }, 200, env);

  // 按 device_id 查询该设备对应工号的记录,而非按 tag_uid 查询所有记录
  if (bind.user_code) {
    const rows = await env.DB.prepare(
      `SELECT check_time, dept, check_type, status, distance
       FROM checkins
       WHERE device_id = ?
       ORDER BY check_time DESC
       LIMIT 30`
    ).bind(deviceId).all();
    return json({
      boundUid: bind.tag_uid,
      boundUserCode: bind.user_code,
      records: rows.results || [],
    }, 200, env);
  }
  return json({ boundUid: bind.tag_uid, boundUserCode: null, records: [] }, 200, env);
}

// 管理员查全部记录（支持日期/科室/工号筛选）
async function handleGetAllRecords(request, env) {
  const url = new URL(request.url);
  const startDate = url.searchParams.get('startDate');
  const endDate = url.searchParams.get('endDate');
  const dept = url.searchParams.get('dept');
  const userCode = url.searchParams.get('userCode');

  let sql = 'SELECT * FROM checkins WHERE 1=1';
  const params = [];
  if (startDate) {
    const s = new Date(startDate + 'T00:00:00+08:00').getTime();
    sql += ' AND check_time >= ?';
    params.push(s);
  }
  if (endDate) {
    const e = new Date(endDate + 'T23:59:59+08:00').getTime();
    sql += ' AND check_time <= ?';
    params.push(e);
  }
  if (dept) {
    sql += ' AND dept = ?';
    params.push(dept);
  }
  if (userCode) {
    sql += ' AND user_code = ?';
    params.push(userCode);
  }
  sql += ' ORDER BY check_time DESC LIMIT 5000';
  const stmt = env.DB.prepare(sql);
  const rows = params.length ? await stmt.bind(...params).all() : await stmt.all();
  return json({ records: rows.results || [] }, 200, env);
}

// 设备解绑
async function handleUnbindDevice(request, env) {
  const { deviceId } = await request.json();
  if (!deviceId) return json({ error: '缺少 deviceId' }, 400, env);
  await env.DB.prepare('DELETE FROM device_binds WHERE device_id = ?').bind(deviceId).run();
  await audit(env, 'device_unbind', `管理员解绑设备 ${deviceId}`, null, getClientIp(request));
  return json({ ok: true }, 200, env);
}

// 白名单查询（含 NFC 标签、学生、科室配置）
async function handleGetWhitelist(request, env) {
  const [tags, users, depts] = await Promise.all([
    env.DB.prepare('SELECT uid, dept, created_at FROM nfc_tags ORDER BY dept').all(),
    env.DB.prepare('SELECT user_code, name, created_at FROM users ORDER BY user_code').all(),
    env.DB.prepare('SELECT dept, lat, lng, radius FROM dept_positions ORDER BY dept').all(),
  ]);
  return json({
    nfcTags: tags.results || [],
    users: users.results || [],
    depts: depts.results || [],
  }, 200, env);
}

// 白名单增改
async function handleUpsertWhitelist(request, env) {
  const { type, ...data } = await request.json();
  const now = Date.now();
  if (type === 'nfc') {
    if (!data.uid || !data.dept) return json({ error: '参数缺失' }, 400, env);
    const uid = String(data.uid).toLowerCase().trim();
    await env.DB.prepare(
      'INSERT INTO nfc_tags (uid, dept, created_at) VALUES (?, ?, ?) ' +
      'ON CONFLICT(uid) DO UPDATE SET dept = excluded.dept'
    ).bind(uid, data.dept, now).run();
  } else if (type === 'user') {
    if (!data.userCode || !data.name) return json({ error: '参数缺失' }, 400, env);
    await env.DB.prepare(
      'INSERT INTO users (user_code, name, created_at) VALUES (?, ?, ?) ' +
      'ON CONFLICT(user_code) DO UPDATE SET name = excluded.name'
    ).bind(data.userCode, data.name, now).run();
  } else if (type === 'dept') {
    if (!data.dept || typeof data.lat !== 'number') return json({ error: '参数缺失' }, 400, env);
    await env.DB.prepare(
      'INSERT INTO dept_positions (dept, lat, lng, radius) VALUES (?, ?, ?, ?) ' +
      'ON CONFLICT(dept) DO UPDATE SET lat = excluded.lat, lng = excluded.lng, radius = excluded.radius'
    ).bind(data.dept, data.lat, data.lng, data.radius || 15).run();
  } else {
    return json({ error: '未知白名单类型' }, 400, env);
  }
  await audit(env, 'whitelist_upsert', `${type}: ${JSON.stringify(data)}`, null, getClientIp(request));
  return json({ ok: true }, 200, env);
}

// 批量导入白名单(支持 user / dept / nfc 三类)
// 入参: { type: 'user'|'dept'|'nfc', items: [...] , mode: 'upsert'|'replace'}
//   - mode='upsert'(默认): 仅插入/更新,不动现有数据
//   - mode='replace': 先清空该类型数据,再批量插入(谨慎使用)
async function handleBatchWhitelist(request, env) {
  const body = await request.json();
  const now = Date.now();
  if (!body.type || !Array.isArray(body.items)) {
    return json({ error: '参数缺失或 items 不是数组' }, 400, env);
  }
  const { type, items } = body;
  const mode = body.mode === 'replace' ? 'replace' : 'upsert';
  if (items.length === 0) return json({ error: 'items 为空' }, 400, env);
  if (items.length > 2000) return json({ error: '单次最多 2000 条' }, 400, env);

  let ok = 0, fail = 0;
  const errors = [];
  try {
    if (type === 'user') {
      if (mode === 'replace') await env.DB.prepare('DELETE FROM users').run();
      for (let i = 0; i < items.length; i++) {
        const it = items[i];
        const code = it.userCode != null ? String(it.userCode).trim() : (it.user_code != null ? String(it.user_code).trim() : '');
        const name = it.name != null ? String(it.name).trim() : '';
        if (!code || !name) { fail++; errors.push(`第 ${i + 1} 行: 工号或姓名为空`); continue; }
        try {
          await env.DB.prepare(
            'INSERT INTO users (user_code, name, created_at) VALUES (?, ?, ?) ' +
            'ON CONFLICT(user_code) DO UPDATE SET name = excluded.name'
          ).bind(code, name, now).run();
          ok++;
        } catch (e) { fail++; errors.push(`第 ${i + 1} 行: ${e.message}`); }
      }
    } else if (type === 'dept') {
      if (mode === 'replace') await env.DB.prepare('DELETE FROM dept_positions').run();
      for (let j = 0; j < items.length; j++) {
        const d = items[j];
        const dname = d.dept != null ? String(d.dept).trim() : '';
        const lat = parseFloat(d.lat), lng = parseFloat(d.lng), radius = parseInt(d.radius) || 15;
        if (!dname || isNaN(lat) || isNaN(lng)) { fail++; errors.push(`第 ${j + 1} 行: 科室名/经纬度无效`); continue; }
        try {
          await env.DB.prepare(
            'INSERT INTO dept_positions (dept, lat, lng, radius) VALUES (?, ?, ?, ?) ' +
            'ON CONFLICT(dept) DO UPDATE SET lat = excluded.lat, lng = excluded.lng, radius = excluded.radius'
          ).bind(dname, lat, lng, radius).run();
          ok++;
        } catch (e) { fail++; errors.push(`第 ${j + 1} 行: ${e.message}`); }
      }
    } else if (type === 'nfc') {
      if (mode === 'replace') await env.DB.prepare('DELETE FROM nfc_tags').run();
      for (let k = 0; k < items.length; k++) {
        const t = items[k];
        const uid = t.uid != null ? String(t.uid).toLowerCase().trim() : '';
        const dept = t.dept != null ? String(t.dept).trim() : '';
        if (!uid || !dept) { fail++; errors.push(`第 ${k + 1} 行: UID 或科室为空`); continue; }
        try {
          await env.DB.prepare(
            'INSERT INTO nfc_tags (uid, dept, created_at) VALUES (?, ?, ?) ' +
            'ON CONFLICT(uid) DO UPDATE SET dept = excluded.dept'
          ).bind(uid, dept, now).run();
          ok++;
        } catch (e) { fail++; errors.push(`第 ${k + 1} 行: ${e.message}`); }
      }
    } else {
      return json({ error: '未知类型,应为 user / dept / nfc' }, 400, env);
    }
    await audit(env, 'whitelist_batch', `${type} mode=${mode} ok=${ok} fail=${fail}`, null, getClientIp(request));
    return json({ ok: true, type, mode, success: ok, failed: fail, errors: errors.slice(0, 50) }, 200, env);
  } catch (e) {
    return json({ error: '批量导入失败: ' + e.message, success: ok, failed: fail, errors: errors.slice(0, 50) }, 500, env);
  }
}

// 危险操作:重置数据库(清空前强制备份,保留白名单)
// 入参: { confirm: 'YES_RESET' }  防止误触发
async function handleResetDb(request, env) {
  const body = await request.json().catch(() => ({}));
  if (body.confirm !== 'YES_RESET') {
    return json({ error: '请确认重置操作(confirm 参数必须为 YES_RESET)' }, 400, env);
  }
  // 强制备份:导出5张表数据到 data_backups
  await env.DB.exec('CREATE TABLE IF NOT EXISTS data_backups (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at INTEGER NOT NULL, data_json TEXT NOT NULL)').catch(() => {});
  const backup = { created_at: Date.now(), tables: {} };
  const tableNames = ['checkins', 'device_binds', 'nonces', 'admin_sessions', 'audit_logs'];
  for (const name of tableNames) {
    const rows = await env.DB.prepare(`SELECT * FROM ${name}`).all().catch(() => ({ results: [] }));
    backup.tables[name] = (rows && rows.results) || [];
  }
  const backupJson = JSON.stringify(backup);
  const backupRes = await env.DB.prepare('INSERT INTO data_backups (created_at, data_json) VALUES (?, ?)').bind(backup.created_at, backupJson).run();
  const backupId = backupRes.meta ? backupRes.meta.last_row_id : null;

  // 按顺序删除 5 张表(保留 nfc_tags / users / dept_positions / data_backups 白名单和备份)
  const drops = [
    'DROP TABLE IF EXISTS checkins',
    'DROP TABLE IF EXISTS device_binds',
    'DROP TABLE IF EXISTS nonces',
    'DROP TABLE IF EXISTS admin_sessions',
    'DROP TABLE IF EXISTS audit_logs',
  ];
  for (const sql of drops) {
    await env.DB.exec(sql).catch(() => {});
  }
  // 重建表 + 索引(调用 initDb,INSERT OR IGNORE 不会覆盖已有白名单)
  await initDb(env);
  // 重新写入审计日志表(reset 删了 audit_logs,需要重建后写一条记录)
  await env.DB.exec('CREATE TABLE IF NOT EXISTS audit_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, event TEXT NOT NULL, detail TEXT, device_id TEXT, ip TEXT, created_at INTEGER NOT NULL)').catch(() => {});
  await env.DB.prepare('INSERT INTO audit_logs (event, detail, device_id, ip, created_at) VALUES (?, ?, ?, ?, ?)').bind('db_reset', `管理员重置数据库,备份ID=${backupId},已清空打卡/设备/会话数据,保留白名单`, null, getClientIp(request), Date.now()).run();
  return json({ ok: true, backupId, message: `数据库已重置。清空前已自动备份(备份ID: ${backupId})。打卡记录、设备绑定、nonce、管理员会话已清空,白名单已保留。当前管理员会话已失效,请重新登录。` }, 200, env);
}

// 查看备份列表
async function handleListBackups(request, env) {
  const rows = await env.DB.prepare('SELECT id, created_at, length(data_json) as size FROM data_backups ORDER BY id DESC LIMIT 50').all().catch(() => ({ results: [] }));
  return json({ backups: (rows && rows.results) || [] }, 200, env);
}

// 下载备份JSON
async function handleDownloadBackup(request, env) {
  const u = new URL(request.url);
  const id = parseInt(u.searchParams.get('id'));
  if (!id) return json({ error: '缺少 id' }, 400, env);
  const row = await env.DB.prepare('SELECT id, created_at, data_json FROM data_backups WHERE id = ?').bind(id).first();
  if (!row) return json({ error: '备份不存在' }, 404, env);
  return new Response(row.data_json, {
    status: 200,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Disposition': `attachment; filename="backup-${id}-${row.created_at}.json"`,
      ...corsHeaders(env),
    },
  });
}

// NFC 标签 UID 轮换(针对 NFC 贴片被复制的风险)
// 生成新 UID,旧 UID 立即失效,需重新写贴片
async function handleRotateTag(request, env) {
  const body = await request.json();
  if (!body.uid) return json({ error: '缺少 uid(要轮换的旧UID)' }, 400, env);
  const oldUid = String(body.uid).toLowerCase().trim();
  const tag = await env.DB.prepare('SELECT uid, dept FROM nfc_tags WHERE uid = ?').bind(oldUid).first();
  if (!tag) return json({ error: 'NFC 标签不存在' }, 404, env);
  const newUid = randomToken(7); // 14位十六进制,模拟NFC UID格式
  await env.DB.prepare('DELETE FROM nfc_tags WHERE uid = ?').bind(oldUid).run();
  await env.DB.prepare('INSERT INTO nfc_tags (uid, dept, created_at) VALUES (?, ?, ?)').bind(newUid, tag.dept, Date.now()).run();
  await audit(env, 'tag_rotate', `NFC标签轮换: ${oldUid} → ${newUid} (科室: ${tag.dept})`, null, getClientIp(request));
  return json({ ok: true, oldUid, newUid, dept: tag.dept, url: `https://nfc-checkin-1om.pages.dev/index.html?tagUid=${newUid}` }, 200, env);
}

// 白名单删除
async function handleDeleteWhitelist(request, env) {
  const { type, key } = await request.json();
  if (type === 'nfc') {
    await env.DB.prepare('DELETE FROM nfc_tags WHERE uid = ?').bind(String(key).toLowerCase()).run();
  } else if (type === 'user') {
    await env.DB.prepare('DELETE FROM users WHERE user_code = ?').bind(key).run();
  } else if (type === 'dept') {
    await env.DB.prepare('DELETE FROM dept_positions WHERE dept = ?').bind(key).run();
  } else {
    return json({ error: '未知类型' }, 400, env);
  }
  await audit(env, 'whitelist_delete', `${type}: ${key}`, null, getClientIp(request));
  return json({ ok: true }, 200, env);
}

// 设备列表
async function handleGetDevices(request, env) {
  const rows = await env.DB.prepare(
    'SELECT device_id, tag_uid, user_code, bound_at, last_seen_at FROM device_binds ORDER BY last_seen_at DESC'
  ).all();
  return json({ devices: rows.results || [] }, 200, env);
}

// 审计日志
async function handleGetAudit(request, env) {
  const url = new URL(request.url);
  const limit = Math.min(parseInt(url.searchParams.get('limit') || '200'), 1000);
  const rows = await env.DB.prepare(
    'SELECT id, event, detail, device_id, ip, created_at FROM audit_logs ORDER BY created_at DESC LIMIT ?'
  ).bind(limit).all();
  return json({ logs: rows.results || [] }, 200, env);
}

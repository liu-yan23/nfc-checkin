-- ====================================================================
-- 科室轮转打卡系统 - Cloudflare D1 数据库初始化脚本
-- 使用方法：
--   本地：wrangler d1 execute nfc-checkin-db --local --file=schema.sql
--   远程：wrangler d1 execute nfc-checkin-db --remote --file=schema.sql
--   或在 Cloudflare Dashboard > D1 > 你的库 > Execute SQL 直接粘贴执行
-- ====================================================================

-- NFC 标签白名单（uid 已归一化为小写）
CREATE TABLE IF NOT EXISTS nfc_tags (
  uid TEXT PRIMARY KEY,
  dept TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

-- 学生白名单
CREATE TABLE IF NOT EXISTS users (
  user_code TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

-- 科室位置配置
CREATE TABLE IF NOT EXISTS dept_positions (
  dept TEXT PRIMARY KEY,
  lat REAL NOT NULL,
  lng REAL NOT NULL,
  radius INTEGER NOT NULL
);

-- 设备绑定（一设备绑定一卡号）
CREATE TABLE IF NOT EXISTS device_binds (
  device_id TEXT PRIMARY KEY,
  tag_uid TEXT NOT NULL,
  user_code TEXT,
  bound_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL
);

-- 打卡记录
-- 防重复约束:同一工号 + 同一天 + 同一卡类型 只能 1 条
CREATE TABLE IF NOT EXISTS checkins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tag_uid TEXT NOT NULL,
  user_code TEXT NOT NULL,
  user_name TEXT NOT NULL,
  dept TEXT NOT NULL,
  check_type TEXT NOT NULL,
  status TEXT NOT NULL,          -- normal 正常 / abnormal 补卡
  check_time INTEGER NOT NULL,
  lat REAL NOT NULL,
  lng REAL NOT NULL,
  distance REAL NOT NULL,
  device_id TEXT NOT NULL,
  ip TEXT,
  ua TEXT,
  created_at INTEGER NOT NULL,
  checkin_date TEXT NOT NULL,    -- YYYY-MM-DD (UTC+8),夜班补卡跨日归前一天
  reason TEXT,                    -- 补卡原因(补卡时必填,≤20字;正常打卡为 NULL)
  UNIQUE(user_code, checkin_date, check_type)
);

-- 一次性 nonce（防复用）
CREATE TABLE IF NOT EXISTS nonces (
  nonce TEXT PRIMARY KEY,
  tag_uid TEXT NOT NULL,
  device_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  used INTEGER DEFAULT 0
);

-- 审计日志
CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event TEXT NOT NULL,
  detail TEXT,
  device_id TEXT,
  ip TEXT,
  created_at INTEGER NOT NULL
);

-- 管理员会话
CREATE TABLE IF NOT EXISTS admin_sessions (
  token TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

-- 索引
CREATE INDEX IF NOT EXISTS idx_checkins_time ON checkins(check_time);
CREATE INDEX IF NOT EXISTS idx_checkins_tag ON checkins(tag_uid);
CREATE INDEX IF NOT EXISTS idx_checkins_user_date ON checkins(user_code, checkin_date);
CREATE INDEX IF NOT EXISTS idx_nonces_expires ON nonces(expires_at);

-- ============== 初始示例数据（按需修改后执行） ==============
INSERT OR IGNORE INTO nfc_tags (uid, dept, created_at) VALUES
  ('538b1cce330001', '急诊', strftime('%s','now') * 1000),
  ('04b771cc223311', '护士站', strftime('%s','now') * 1000);

INSERT OR IGNORE INTO users (user_code, name, created_at) VALUES
  ('001', '刘六六', strftime('%s','now') * 1000),
  ('002', '李四', strftime('%s','now') * 1000);

INSERT OR IGNORE INTO dept_positions (dept, lat, lng, radius) VALUES
  ('急诊', 29.362, 106.2929, 15),
  ('护士站', 29.4570, 106.5895, 15);

-- 清理过期 nonce（建议在 Cloudflare Cron Trigger 中定期执行）
-- DELETE FROM nonces WHERE expires_at < (strftime('%s','now') * 1000 - 86400000);
-- DELETE FROM admin_sessions WHERE expires_at < (strftime('%s','now') * 1000);

-- ====================================================================
-- 【清空所有打卡/设备/会话数据,重建表结构】
-- 适用场景:从旧版本(按 tag_uid 防重复)升级到新版本(按 user_code+卡类型防重复),
--           需要丢弃旧的打卡记录和设备绑定,重新开始。
-- 使用方法:在 Cloudflare Dashboard > D1 > 你的库 > Execute SQL 中整段粘贴执行。
-- 注意:执行后所有打卡记录、设备绑定、nonce、管理员会话都会被清空,
--       但 nfc_tags / users / dept_positions 白名单数据会保留。
-- ====================================================================
-- DROP TABLE IF EXISTS checkins;
-- DROP TABLE IF EXISTS device_binds;
-- DROP TABLE IF EXISTS nonces;
-- DROP TABLE IF EXISTS admin_sessions;
-- DROP TABLE IF EXISTS audit_logs;
--
-- CREATE TABLE checkins (
--   id INTEGER PRIMARY KEY AUTOINCREMENT,
--   tag_uid TEXT NOT NULL,
--   user_code TEXT NOT NULL,
--   user_name TEXT NOT NULL,
--   dept TEXT NOT NULL,
--   check_type TEXT NOT NULL,
--   status TEXT NOT NULL,
--   check_time INTEGER NOT NULL,
--   lat REAL NOT NULL,
--   lng REAL NOT NULL,
--   distance REAL NOT NULL,
--   device_id TEXT NOT NULL,
--   ip TEXT,
--   ua TEXT,
--   created_at INTEGER NOT NULL,
--   checkin_date TEXT NOT NULL,
--   reason TEXT,
--   UNIQUE(user_code, checkin_date, check_type)
-- );
--
-- CREATE TABLE device_binds (
--   device_id TEXT PRIMARY KEY,
--   tag_uid TEXT NOT NULL,
--   user_code TEXT,
--   bound_at INTEGER NOT NULL,
--   last_seen_at INTEGER NOT NULL
-- );
--
-- CREATE TABLE nonces (
--   nonce TEXT PRIMARY KEY,
--   tag_uid TEXT NOT NULL,
--   device_id TEXT NOT NULL,
--   created_at INTEGER NOT NULL,
--   expires_at INTEGER NOT NULL,
--   used INTEGER DEFAULT 0
-- );
--
-- CREATE TABLE admin_sessions (
--   token TEXT PRIMARY KEY,
--   created_at INTEGER NOT NULL,
--   expires_at INTEGER NOT NULL
-- );
--
-- CREATE TABLE audit_logs (
--   id INTEGER PRIMARY KEY AUTOINCREMENT,
--   event TEXT NOT NULL,
--   detail TEXT,
--   device_id TEXT,
--   ip TEXT,
--   created_at INTEGER NOT NULL
-- );
--
-- CREATE INDEX idx_checkins_time ON checkins(check_time);
-- CREATE INDEX idx_checkins_tag ON checkins(tag_uid);
-- CREATE INDEX idx_checkins_user_date ON checkins(user_code, checkin_date);
-- CREATE INDEX idx_nonces_expires ON nonces(expires_at);

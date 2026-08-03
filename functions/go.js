// /go 动态跳转路由:NFC贴片写入此URL,服务端自动跳转到带动态码的打卡页
// Cloudflare Pages Functions 基于文件系统路由:/go 路径由 functions/go.js 处理

// 打卡时段判定(与 _middleware.js 保持一致)
function getCheckType(ts) {
  var d = new Date(ts + 8 * 3600 * 1000); // 转 UTC+8
  var total = d.getUTCHours() * 60 + d.getUTCMinutes();
  if (total < 420) return { type: '夜班', status: 'abnormal', crossDay: true };
  if (total <= 482) return { type: '上午上班', status: 'normal' };
  if (total < 690) return { type: '上午上班', status: 'abnormal' };
  if (total < 780) return { type: '上午下班', status: 'normal' };
  if (total <= 842) return { type: '下午上班', status: 'normal' };
  if (total < 1020) return { type: '下午上班', status: 'abnormal' };
  if (total < 1260) return { type: '下午下班', status: 'normal' };
  return { type: '夜班', status: 'normal' };
}

// 生成每时段动态码:HMAC(tagUid + 日期 + 时段, SECRET_KEY)
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

export async function onRequest(context) {
  var req = context.request, env = context.env;
  var url = new URL(req.url);

  if (req.method !== 'GET') {
    return new Response(JSON.stringify({ error: '仅支持 GET 请求' }), { status: 405, headers: { 'Content-Type': 'application/json' } });
  }

  var tagParam = url.searchParams.get('tag');
  if (!tagParam) {
    return new Response(JSON.stringify({ error: '缺少 tag 参数' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
  }

  var tagUid = String(tagParam).toLowerCase().trim();

  // 数据库懒初始化(确保表存在)
  try {
    await env.DB.prepare('SELECT 1 FROM nfc_tags LIMIT 1').run();
  } catch (e) {
    // 表不存在,创建
    await env.DB.exec('CREATE TABLE IF NOT EXISTS nfc_tags (uid TEXT PRIMARY KEY, dept TEXT NOT NULL, created_at INTEGER NOT NULL)').catch(function(){});
  }

  // 查询 NFC 标签白名单
  var tagRow = await env.DB.prepare('SELECT uid, dept FROM nfc_tags WHERE uid = ?').bind(tagUid).first();
  if (!tagRow) {
    return new Response(JSON.stringify({ error: 'NFC 标签未注册' }), { status: 403, headers: { 'Content-Type': 'application/json' } });
  }

  // 生成当前时段动态码
  var now = Date.now();
  var code = await getSlotCode(tagUid, now, env);

  // 302 重定向到带动态码的打卡页
  var redirectUrl = '/index.html?tagUid=' + encodeURIComponent(tagUid) + '&code=' + code;
  return new Response(null, {
    status: 302,
    headers: {
      'Location': redirectUrl,
      'Cache-Control': 'no-store, no-cache, must-revalidate'
    }
  });
}

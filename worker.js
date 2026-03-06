/**
 * =====================================================
 *   NEXUSBOT DASHBOARD — CLOUDFLARE WORKERS BACKEND
 *   Deploy: wrangler deploy
 * =====================================================
 *
 * Environment Variables (set via wrangler.toml atau Cloudflare dashboard):
 *   DISCORD_CLIENT_ID      - ID aplikasi Discord
 *   DISCORD_CLIENT_SECRET  - Secret OAuth2 Discord
 *   DISCORD_BOT_TOKEN      - Token bot Discord
 *   FRONTEND_URL           - URL frontend kamu (untuk CORS)
 *   REDIRECT_URI           - OAuth2 redirect URI
 *   KV_SETTINGS            - KV namespace binding untuk simpan settings
 */

const DISCORD_API = 'https://discord.com/api/v10';

// =============================================
//   CORS HEADERS
// =============================================
function corsHeaders(env) {
  return {
    'Access-Control-Allow-Origin': env.FRONTEND_URL || '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  };
}

function jsonResponse(data, status = 200, env) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(env) },
  });
}

function errorResponse(msg, status = 400, env) {
  return jsonResponse({ error: msg }, status, env);
}

// =============================================
//   TOKEN VALIDATION (verifikasi user token)
// =============================================
async function validateToken(request) {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader?.startsWith('Bearer ')) return null;

  const token = authHeader.slice(7);
  try {
    const res = await fetch(`${DISCORD_API}/users/@me`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) return null;
    return { token, user: await res.json() };
  } catch {
    return null;
  }
}

// =============================================
//   ROUTER UTAMA
// =============================================
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // Handle preflight CORS
    if (method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders(env) });
    }

    // ── Route: POST /auth/callback ──────────────────────
    // Tukar authorization code jadi access token
    if (path === '/auth/callback' && method === 'POST') {
      return handleAuthCallback(request, env);
    }

    // ── Semua route lain butuh autentikasi ──────────────
    const auth = await validateToken(request);
    if (!auth) return errorResponse('Unauthorized', 401, env);

    // ── Route: GET /guilds/bot-status ───────────────────
    // Kembalikan list server di mana bot sudah ada
    if (path === '/guilds/bot-status' && method === 'GET') {
      return handleBotStatus(request, env, auth);
    }

    // ── Route: GET /guilds/:id/channels ────────────────
    const channelMatch = path.match(/^\/guilds\/(\d+)\/channels$/);
    if (channelMatch && method === 'GET') {
      return handleGetChannels(channelMatch[1], env, auth);
    }

    // ── Route: GET /guilds/:id/members ─────────────────
    const memberMatch = path.match(/^\/guilds\/(\d+)\/members$/);
    if (memberMatch && method === 'GET') {
      return handleGetMembers(memberMatch[1], env, auth);
    }

    // ── Route: POST /send-message ───────────────────────
    if (path === '/send-message' && method === 'POST') {
      return handleSendMessage(request, env, auth);
    }

    // ── Route: POST /moderation ─────────────────────────
    if (path === '/moderation' && method === 'POST') {
      return handleModeration(request, env, auth);
    }

    // ── Route: POST /settings ───────────────────────────
    if (path === '/settings' && method === 'POST') {
      return handleSaveSettings(request, env, auth);
    }

    // ── Route: GET /settings/:guildId ──────────────────
    const settingsMatch = path.match(/^\/settings\/(\d+)$/);
    if (settingsMatch && method === 'GET') {
      return handleGetSettings(settingsMatch[1], env, auth);
    }

    return errorResponse('Not Found', 404, env);
  },
};

// =============================================
//   HANDLER: OAuth2 Callback
// =============================================
async function handleAuthCallback(request, env) {
  let body;
  try { body = await request.json(); } catch { return errorResponse('Invalid JSON', 400, env); }

  const { code, redirect_uri } = body;
  if (!code || !redirect_uri) return errorResponse('Missing code or redirect_uri', 400, env);

  // Tukar code dengan access token ke Discord
  const params = new URLSearchParams({
    client_id: env.DISCORD_CLIENT_ID,
    client_secret: env.DISCORD_CLIENT_SECRET,
    grant_type: 'authorization_code',
    code,
    redirect_uri,
  });

  const tokenRes = await fetch(`${DISCORD_API}/oauth2/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params,
  });

  if (!tokenRes.ok) {
    const errData = await tokenRes.text();
    return errorResponse('Token exchange failed: ' + errData, 400, env);
  }

  const tokenData = await tokenRes.json();
  return jsonResponse({ access_token: tokenData.access_token }, 200, env);
}

// =============================================
//   HANDLER: Bot Guild Status
// =============================================
async function handleBotStatus(request, env, auth) {
  // Ambil semua server yang sudah ada bot menggunakan Bot Token
  const res = await fetch(`${DISCORD_API}/users/@me/guilds?limit=200`, {
    headers: { Authorization: `Bot ${env.DISCORD_BOT_TOKEN}` },
  });

  if (!res.ok) return errorResponse('Failed to fetch bot guilds', 500, env);
  const guilds = await res.json();
  const guild_ids = guilds.map(g => g.id);

  return jsonResponse({ guild_ids }, 200, env);
}

// =============================================
//   HANDLER: Get Channels
// =============================================
async function handleGetChannels(guildId, env, auth) {
  // Verifikasi user punya akses ke server ini
  const hasAccess = await checkUserGuildAccess(auth.token, guildId);
  if (!hasAccess) return errorResponse('Access denied to this guild', 403, env);

  // Ambil channels menggunakan bot token
  const res = await fetch(`${DISCORD_API}/guilds/${guildId}/channels`, {
    headers: { Authorization: `Bot ${env.DISCORD_BOT_TOKEN}` },
  });

  if (!res.ok) return errorResponse('Failed to fetch channels', 500, env);
  const allChannels = await res.json();

  // Filter hanya text channels (type 0) dan sort by position
  const textChannels = allChannels
    .filter(c => c.type === 0)
    .sort((a, b) => a.position - b.position)
    .map(c => ({ id: c.id, name: c.name, type: c.type, position: c.position }));

  return jsonResponse({ channels: textChannels }, 200, env);
}

// =============================================
//   HANDLER: Get Members
// =============================================
async function handleGetMembers(guildId, env, auth) {
  const hasAccess = await checkUserGuildAccess(auth.token, guildId);
  if (!hasAccess) return errorResponse('Access denied', 403, env);

  const res = await fetch(`${DISCORD_API}/guilds/${guildId}/members?limit=100`, {
    headers: { Authorization: `Bot ${env.DISCORD_BOT_TOKEN}` },
  });

  if (!res.ok) return errorResponse('Failed to fetch members', 500, env);
  const members = await res.json();

  // Filter bots
  const humans = members
    .filter(m => !m.user?.bot)
    .map(m => ({
      user: { id: m.user.id, username: m.user.username, avatar: m.user.avatar },
      nick: m.nick,
    }));

  return jsonResponse({ members: humans }, 200, env);
}

// =============================================
//   HANDLER: Send Message
// =============================================
async function handleSendMessage(request, env, auth) {
  let body;
  try { body = await request.json(); } catch { return errorResponse('Invalid JSON', 400, env); }

  const { guild_id, channel_id, content } = body;
  if (!guild_id || !channel_id || !content) return errorResponse('Missing fields', 400, env);
  if (content.length > 2000) return errorResponse('Pesan terlalu panjang (maks 2000 karakter)', 400, env);

  const hasAccess = await checkUserGuildAccess(auth.token, guild_id);
  if (!hasAccess) return errorResponse('Access denied', 403, env);

  // Kirim pesan lewat bot
  const res = await fetch(`${DISCORD_API}/channels/${channel_id}/messages`, {
    method: 'POST',
    headers: {
      Authorization: `Bot ${env.DISCORD_BOT_TOKEN}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ content }),
  });

  if (!res.ok) {
    const err = await res.json();
    return errorResponse('Failed to send message: ' + (err.message || res.status), 500, env);
  }

  return jsonResponse({ success: true, message: 'Pesan berhasil dikirim' }, 200, env);
}

// =============================================
//   HANDLER: Moderation
// =============================================
async function handleModeration(request, env, auth) {
  let body;
  try { body = await request.json(); } catch { return errorResponse('Invalid JSON', 400, env); }

  const { guild_id, user_id, action, reason, duration, log_channel_id } = body;
  if (!guild_id || !user_id || !action) return errorResponse('Missing fields', 400, env);

  const validActions = ['timeout', 'kick', 'ban'];
  if (!validActions.includes(action)) return errorResponse('Invalid action', 400, env);

  const hasAccess = await checkUserGuildAccess(auth.token, guild_id);
  if (!hasAccess) return errorResponse('Access denied', 403, env);

  let apiUrl, apiMethod, apiBody = null;

  if (action === 'timeout') {
    // Timeout: PATCH guild member dengan communication_disabled_until
    const durationSec = duration || 3600;
    const until = new Date(Date.now() + durationSec * 1000).toISOString();
    apiUrl = `${DISCORD_API}/guilds/${guild_id}/members/${user_id}`;
    apiMethod = 'PATCH';
    apiBody = JSON.stringify({ communication_disabled_until: until });

  } else if (action === 'kick') {
    apiUrl = `${DISCORD_API}/guilds/${guild_id}/members/${user_id}`;
    apiMethod = 'DELETE';

  } else if (action === 'ban') {
    apiUrl = `${DISCORD_API}/guilds/${guild_id}/bans/${user_id}`;
    apiMethod = 'PUT';
    apiBody = JSON.stringify({ reason: reason || '' });
  }

  // Ambil info user yang dimoderasi
  const userRes = await fetch(`${DISCORD_API}/users/${user_id}`, {
    headers: { Authorization: `Bot ${env.DISCORD_BOT_TOKEN}` },
  });
  const targetUser = userRes.ok ? await userRes.json() : { username: user_id };

  // Lakukan aksi moderasi
  const modRes = await fetch(apiUrl, {
    method: apiMethod,
    headers: {
      Authorization: `Bot ${env.DISCORD_BOT_TOKEN}`,
      'Content-Type': 'application/json',
      'X-Audit-Log-Reason': encodeURIComponent(reason || 'No reason provided'),
    },
    ...(apiBody ? { body: apiBody } : {}),
  });

  if (!modRes.ok && modRes.status !== 204) {
    const err = await modRes.json().catch(() => ({}));
    return errorResponse(`Moderation failed: ${err.message || modRes.status}`, 500, env);
  }

  // Ambil case number dari KV atau increment
  let caseNumber = 1;
  if (env.KV_SETTINGS) {
    const caseKey = `case_count_${guild_id}`;
    const currentCase = await env.KV_SETTINGS.get(caseKey);
    caseNumber = currentCase ? parseInt(currentCase) + 1 : 1;
    await env.KV_SETTINGS.put(caseKey, String(caseNumber));
  }

  // Kirim log ke channel moderasi jika ada
  const logChId = log_channel_id || (env.KV_SETTINGS ? await env.KV_SETTINGS.get(`log_channel_${guild_id}`) : null);
  if (logChId) {
    const actionLabels = { timeout: 'Timeout', kick: 'Kick', ban: 'Ban' };
    const actionEmoji = { timeout: '⏱️', kick: '👢', ban: '🔨' };
    const now = new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC';

    let durationText = '';
    if (action === 'timeout' && duration) {
      const hrs = Math.floor(duration / 3600);
      const min = Math.floor((duration % 3600) / 60);
      durationText = hrs > 0 ? `\n⏳ **Duration:** ${hrs} hour${hrs>1?'s':''} ${min>0?min+' min':''}` : `\n⏳ **Duration:** ${min} minutes`;
    }

    const logMessage = [
      `📋 **MODERATION LOG**`,
      `━━━━━━━━━━━━━━━━━━`,
      `📌 Case #${caseNumber}`,
      `${actionEmoji[action]} Action: **${actionLabels[action]}**`,
      `👤 User: <@${user_id}> (${targetUser.username} · ID: ${user_id})`,
      `🛡️ Moderator: <@${auth.user.id}> (${auth.user.username})`,
      `📝 Reason: ${reason || 'Tidak ada alasan'}`,
      durationText,
      `🕐 Time: ${now}`,
      `━━━━━━━━━━━━━━━━━━`,
    ].filter(Boolean).join('\n');

    await fetch(`${DISCORD_API}/channels/${logChId}/messages`, {
      method: 'POST',
      headers: {
        Authorization: `Bot ${env.DISCORD_BOT_TOKEN}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ content: logMessage }),
    });
  }

  return jsonResponse({
    success: true,
    case_number: caseNumber,
    message: `${action} berhasil dilakukan`,
  }, 200, env);
}

// =============================================
//   HANDLER: Save Settings
// =============================================
async function handleSaveSettings(request, env, auth) {
  let body;
  try { body = await request.json(); } catch { return errorResponse('Invalid JSON', 400, env); }

  const { guild_id, log_channel_id } = body;
  if (!guild_id) return errorResponse('Missing guild_id', 400, env);

  const hasAccess = await checkUserGuildAccess(auth.token, guild_id);
  if (!hasAccess) return errorResponse('Access denied', 403, env);

  if (env.KV_SETTINGS && log_channel_id) {
    await env.KV_SETTINGS.put(`log_channel_${guild_id}`, log_channel_id);
  }

  return jsonResponse({ success: true }, 200, env);
}

// =============================================
//   HANDLER: Get Settings
// =============================================
async function handleGetSettings(guildId, env, auth) {
  const hasAccess = await checkUserGuildAccess(auth.token, guildId);
  if (!hasAccess) return errorResponse('Access denied', 403, env);

  let log_channel_id = null;
  if (env.KV_SETTINGS) {
    log_channel_id = await env.KV_SETTINGS.get(`log_channel_${guildId}`);
  }

  return jsonResponse({ log_channel_id }, 200, env);
}

// =============================================
//   HELPER: Cek apakah user punya akses ke guild
// =============================================
async function checkUserGuildAccess(userToken, guildId) {
  const res = await fetch(`${DISCORD_API}/users/@me/guilds`, {
    headers: { Authorization: `Bearer ${userToken}` },
  });
  if (!res.ok) return false;

  const guilds = await res.json();
  const MANAGE_GUILD = 0x20n;
  return guilds.some(g =>
    g.id === guildId && (g.owner || (BigInt(g.permissions) & MANAGE_GUILD) === MANAGE_GUILD)
  );
}

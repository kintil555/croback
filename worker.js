/**
 * =====================================================
 *   CROBACK BOT DASHBOARD — CLOUDFLARE WORKERS API
 * =====================================================
 *
 * Environment Variables (set di Cloudflare Dashboard):
 *   DISCORD_CLIENT_ID      - Application ID Discord
 *   DISCORD_CLIENT_SECRET  - Client Secret OAuth2
 *   DISCORD_BOT_TOKEN      - Bot Token
 *   DISCORD_PUBLIC_KEY     - Public Key (dari General Information)
 *   FRONTEND_URL           - https://crobot-3v6.pages.dev
 *   REDIRECT_URI           - https://crobot-3v6.pages.dev/callback.html
 *   KV_SETTINGS            - KV Namespace binding
 */

const DISCORD_API = 'https://discord.com/api/v10';

// ─────────────────────────────────────────────
//   VERIFY ED25519 SIGNATURE (untuk /interactions)
// ─────────────────────────────────────────────
async function verifySignature(request, publicKey) {
  const sig = request.headers.get('x-signature-ed25519');
  const ts  = request.headers.get('x-signature-timestamp');
  if (!sig || !ts) return { ok: false, body: null };

  const body = await request.text();

  try {
    const key = await crypto.subtle.importKey(
      'raw',
      hexToU8(publicKey),
      { name: 'Ed25519' },
      false,
      ['verify']
    );
    const ok = await crypto.subtle.verify(
      'Ed25519',
      key,
      hexToU8(sig),
      new TextEncoder().encode(ts + body)
    );
    return { ok, body };
  } catch {
    return { ok: false, body };
  }
}

function hexToU8(hex) {
  const b = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2)
    b[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  return b;
}

// ─────────────────────────────────────────────
//   CORS & RESPONSE HELPERS
// ─────────────────────────────────────────────
function cors(env) {
  return {
    'Access-Control-Allow-Origin': env.FRONTEND_URL || '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  };
}

function json(data, status = 200, env) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...cors(env) },
  });
}

function err(msg, status = 400, env) {
  return json({ error: msg }, status, env);
}

function interactionReply(content, ephemeral = false) {
  return new Response(
    JSON.stringify({ type: 4, data: { content, flags: ephemeral ? 64 : 0 } }),
    { headers: { 'Content-Type': 'application/json' } }
  );
}

// ─────────────────────────────────────────────
//   VALIDATE USER OAUTH TOKEN
// ─────────────────────────────────────────────
async function validateToken(request) {
  const h = request.headers.get('Authorization');
  if (!h?.startsWith('Bearer ')) return null;
  const token = h.slice(7);
  try {
    const r = await fetch(`${DISCORD_API}/users/@me`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!r.ok) return null;
    return { token, user: await r.json() };
  } catch { return null; }
}

// ─────────────────────────────────────────────
//   CHECK USER ACCESS TO GUILD
// ─────────────────────────────────────────────
async function hasGuildAccess(token, guildId) {
  const r = await fetch(`${DISCORD_API}/users/@me/guilds`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!r.ok) return false;
  const guilds = await r.json();
  const MANAGE = 0x20n;
  return guilds.some(g =>
    g.id === guildId && (g.owner || (BigInt(g.permissions) & MANAGE) === MANAGE)
  );
}

// ─────────────────────────────────────────────
//   SEND MODERATION LOG
// ─────────────────────────────────────────────
async function sendModLog({ guildId, userId, moderator, action, reason, duration, env }) {
  if (!env.KV_SETTINGS) return;
  const logChId = await env.KV_SETTINGS.get(`log_channel_${guildId}`);
  if (!logChId) return;

  const caseKey = `case_count_${guildId}`;
  const cur     = await env.KV_SETTINGS.get(caseKey);
  const caseNum = cur ? parseInt(cur) + 1 : 1;
  await env.KV_SETTINGS.put(caseKey, String(caseNum));

  const emoji = { timeout: '⏱️', kick: '👢', ban: '🔨' };
  const label = { timeout: 'Timeout', kick: 'Kick', ban: 'Ban' };
  const now   = new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC';

  let durLine = '';
  if (action === 'timeout' && duration) {
    const h = Math.floor(duration / 3600);
    const m = Math.floor((duration % 3600) / 60);
    durLine = `\n⏳ **Duration:** ${h > 0 ? h + ' jam ' : ''}${m > 0 ? m + ' menit' : ''}`;
  }

  const msg = [
    `📋 **MODERATION LOG**`,
    `━━━━━━━━━━━━━━━━━━`,
    `📌 Case #${caseNum}`,
    `${emoji[action]} Action: **${label[action]}**`,
    `👤 User: <@${userId}>`,
    `🛡️ Moderator: <@${moderator?.id}> (${moderator?.username ?? 'Dashboard'})`,
    `📝 Reason: ${reason || 'Tidak ada alasan'}`,
    durLine,
    `🕐 Time: ${now}`,
    `━━━━━━━━━━━━━━━━━━`,
  ].filter(Boolean).join('\n');

  await fetch(`${DISCORD_API}/channels/${logChId}/messages`, {
    method: 'POST',
    headers: { Authorization: `Bot ${env.DISCORD_BOT_TOKEN}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ content: msg }),
  });
}

// ─────────────────────────────────────────────
//   MAIN FETCH HANDLER
// ─────────────────────────────────────────────
export default {
  async fetch(request, env) {
    const url    = new URL(request.url);
    const path   = url.pathname;
    const method = request.method;

    // CORS preflight
    if (method === 'OPTIONS')
      return new Response(null, { headers: cors(env) });

    // /interactions — Discord slash commands (no auth needed)
    if (path === '/interactions' && method === 'POST')
      return handleInteractions(request, env);

    // /register-commands — daftarkan slash commands (GET, sekali aja)
    if (path === '/register-commands')
      return handleRegisterCommands(env);

    // /auth/callback
    if (path === '/auth/callback' && method === 'POST')
      return handleAuthCallback(request, env);

    // Semua route di bawah butuh user token
    const auth = await validateToken(request);
    if (!auth) return err('Unauthorized', 401, env);

    if (path === '/guilds/bot-status' && method === 'GET')
      return handleBotStatus(env, auth);

    const chMatch = path.match(/^\/guilds\/(\d+)\/channels$/);
    if (chMatch && method === 'GET')
      return handleGetChannels(chMatch[1], env, auth);

    const mbMatch = path.match(/^\/guilds\/(\d+)\/members$/);
    if (mbMatch && method === 'GET')
      return handleGetMembers(mbMatch[1], env, auth);

    if (path === '/send-message' && method === 'POST')
      return handleSendMessage(request, env, auth);

    if (path === '/moderation' && method === 'POST')
      return handleModeration(request, env, auth);

    if (path === '/settings' && method === 'POST')
      return handleSaveSettings(request, env, auth);

    const stMatch = path.match(/^\/settings\/(\d+)$/);
    if (stMatch && method === 'GET')
      return handleGetSettings(stMatch[1], env, auth);

    return err('Not Found', 404, env);
  },
};

// ─────────────────────────────────────────────
//   AUTH CALLBACK
// ─────────────────────────────────────────────
async function handleAuthCallback(request, env) {
  let body;
  try { body = await request.json(); }
  catch { return err('Invalid JSON', 400, env); }

  const { code, redirect_uri } = body;
  if (!code || !redirect_uri) return err('Missing code or redirect_uri', 400, env);

  const r = await fetch(`${DISCORD_API}/oauth2/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: env.DISCORD_CLIENT_ID,
      client_secret: env.DISCORD_CLIENT_SECRET,
      grant_type: 'authorization_code',
      code, redirect_uri,
    }),
  });

  if (!r.ok) return err('Token exchange failed: ' + await r.text(), 400, env);
  const data = await r.json();
  return json({ access_token: data.access_token }, 200, env);
}

// ─────────────────────────────────────────────
//   BOT STATUS
// ─────────────────────────────────────────────
async function handleBotStatus(env, auth) {
  const r = await fetch(`${DISCORD_API}/users/@me/guilds?limit=200`, {
    headers: { Authorization: `Bot ${env.DISCORD_BOT_TOKEN}` },
  });
  if (!r.ok) return err('Failed to fetch bot guilds', 500, env);
  const guilds = await r.json();
  return json({ guild_ids: guilds.map(g => g.id) }, 200, env);
}

// ─────────────────────────────────────────────
//   GET CHANNELS
// ─────────────────────────────────────────────
async function handleGetChannels(guildId, env, auth) {
  if (!await hasGuildAccess(auth.token, guildId))
    return err('Access denied', 403, env);

  const r = await fetch(`${DISCORD_API}/guilds/${guildId}/channels`, {
    headers: { Authorization: `Bot ${env.DISCORD_BOT_TOKEN}` },
  });
  if (!r.ok) return err('Failed to fetch channels', 500, env);

  const channels = (await r.json())
    .filter(c => c.type === 0)
    .sort((a, b) => a.position - b.position)
    .map(c => ({ id: c.id, name: c.name }));

  return json({ channels }, 200, env);
}

// ─────────────────────────────────────────────
//   GET MEMBERS
// ─────────────────────────────────────────────
async function handleGetMembers(guildId, env, auth) {
  if (!await hasGuildAccess(auth.token, guildId))
    return err('Access denied', 403, env);

  const r = await fetch(`${DISCORD_API}/guilds/${guildId}/members?limit=100`, {
    headers: { Authorization: `Bot ${env.DISCORD_BOT_TOKEN}` },
  });
  if (!r.ok) return err('Failed to fetch members', 500, env);

  const members = (await r.json())
    .filter(m => !m.user?.bot)
    .map(m => ({ user: { id: m.user.id, username: m.user.username }, nick: m.nick }));

  return json({ members }, 200, env);
}

// ─────────────────────────────────────────────
//   SEND MESSAGE
// ─────────────────────────────────────────────
async function handleSendMessage(request, env, auth) {
  let body;
  try { body = await request.json(); }
  catch { return err('Invalid JSON', 400, env); }

  const { guild_id, channel_id, content } = body;
  if (!guild_id || !channel_id || !content) return err('Missing fields', 400, env);
  if (content.length > 2000) return err('Pesan terlalu panjang (maks 2000)', 400, env);
  if (!await hasGuildAccess(auth.token, guild_id)) return err('Access denied', 403, env);

  const r = await fetch(`${DISCORD_API}/channels/${channel_id}/messages`, {
    method: 'POST',
    headers: { Authorization: `Bot ${env.DISCORD_BOT_TOKEN}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ content }),
  });

  if (!r.ok) {
    const e = await r.json().catch(() => ({}));
    return err('Gagal kirim pesan: ' + (e.message || r.status), 500, env);
  }
  return json({ success: true }, 200, env);
}

// ─────────────────────────────────────────────
//   MODERATION (dari dashboard)
// ─────────────────────────────────────────────
async function handleModeration(request, env, auth) {
  let body;
  try { body = await request.json(); }
  catch { return err('Invalid JSON', 400, env); }

  const { guild_id, user_id, action, reason, duration, log_channel_id } = body;
  if (!guild_id || !user_id || !action) return err('Missing fields', 400, env);
  if (!['timeout', 'kick', 'ban'].includes(action)) return err('Invalid action', 400, env);
  if (!await hasGuildAccess(auth.token, guild_id)) return err('Access denied', 403, env);

  let apiUrl, apiMethod, apiBody = null;

  if (action === 'timeout') {
    const until = new Date(Date.now() + (duration || 3600) * 1000).toISOString();
    apiUrl    = `${DISCORD_API}/guilds/${guild_id}/members/${user_id}`;
    apiMethod = 'PATCH';
    apiBody   = JSON.stringify({ communication_disabled_until: until });
  } else if (action === 'kick') {
    apiUrl    = `${DISCORD_API}/guilds/${guild_id}/members/${user_id}`;
    apiMethod = 'DELETE';
  } else if (action === 'ban') {
    apiUrl    = `${DISCORD_API}/guilds/${guild_id}/bans/${user_id}`;
    apiMethod = 'PUT';
    apiBody   = JSON.stringify({ reason: reason || '' });
  }

  const r = await fetch(apiUrl, {
    method: apiMethod,
    headers: {
      Authorization: `Bot ${env.DISCORD_BOT_TOKEN}`,
      'Content-Type': 'application/json',
      'X-Audit-Log-Reason': encodeURIComponent(reason || 'No reason'),
    },
    ...(apiBody ? { body: apiBody } : {}),
  });

  if (!r.ok && r.status !== 204) {
    const e = await r.json().catch(() => ({}));
    return err(`Moderation failed: ${e.message || r.status}`, 500, env);
  }

  if (log_channel_id && env.KV_SETTINGS)
    await env.KV_SETTINGS.put(`log_channel_${guild_id}`, log_channel_id);

  await sendModLog({ guildId: guild_id, userId: user_id, moderator: auth.user, action, reason, duration, env });

  return json({ success: true }, 200, env);
}

// ─────────────────────────────────────────────
//   SAVE SETTINGS
// ─────────────────────────────────────────────
async function handleSaveSettings(request, env, auth) {
  let body;
  try { body = await request.json(); }
  catch { return err('Invalid JSON', 400, env); }

  const { guild_id, log_channel_id } = body;
  if (!guild_id) return err('Missing guild_id', 400, env);
  if (!await hasGuildAccess(auth.token, guild_id)) return err('Access denied', 403, env);

  if (env.KV_SETTINGS && log_channel_id)
    await env.KV_SETTINGS.put(`log_channel_${guild_id}`, log_channel_id);

  return json({ success: true }, 200, env);
}

// ─────────────────────────────────────────────
//   GET SETTINGS
// ─────────────────────────────────────────────
async function handleGetSettings(guildId, env, auth) {
  if (!await hasGuildAccess(auth.token, guildId)) return err('Access denied', 403, env);
  const log_channel_id = env.KV_SETTINGS
    ? await env.KV_SETTINGS.get(`log_channel_${guildId}`) : null;
  return json({ log_channel_id }, 200, env);
}

// ─────────────────────────────────────────────
//   DISCORD SLASH COMMAND INTERACTIONS
// ─────────────────────────────────────────────
async function handleInteractions(request, env) {
  const { ok, body } = await verifySignature(request, env.DISCORD_PUBLIC_KEY);
  if (!ok) return new Response('Invalid request signature', { status: 401 });

  const interaction = JSON.parse(body);

  // PING dari Discord — wajib dibalas
  if (interaction.type === 1)
    return new Response(JSON.stringify({ type: 1 }), {
      headers: { 'Content-Type': 'application/json' },
    });

  // Slash commands
  if (interaction.type === 2) {
    const name      = interaction.data.name;
    const options   = interaction.data.options || [];
    const guildId   = interaction.guild_id;
    const moderator = interaction.member?.user;

    if (name === 'to')  return slashTimeout(options, guildId, moderator, env);
    if (name === 'b')   return slashBan(options, guildId, moderator, env);
    if (name === 'kk')  return slashKick(options, guildId, moderator, env);
  }

  return interactionReply('Command tidak dikenal.');
}

async function slashTimeout(options, guildId, moderator, env) {
  const userId   = options.find(o => o.name === 'user')?.value;
  const duration = options.find(o => o.name === 'durasi')?.value || 3600;
  const reason   = options.find(o => o.name === 'alasan')?.value || 'Tidak ada alasan';
  const until    = new Date(Date.now() + duration * 1000).toISOString();

  const r = await fetch(`${DISCORD_API}/guilds/${guildId}/members/${userId}`, {
    method: 'PATCH',
    headers: {
      Authorization: `Bot ${env.DISCORD_BOT_TOKEN}`,
      'Content-Type': 'application/json',
      'X-Audit-Log-Reason': encodeURIComponent(reason),
    },
    body: JSON.stringify({ communication_disabled_until: until }),
  });

  if (!r.ok && r.status !== 204) {
    const e = await r.json().catch(() => ({}));
    return interactionReply(`❌ Gagal timeout: ${e.message || r.status}`, true);
  }

  await sendModLog({ guildId, userId, moderator, action: 'timeout', reason, duration, env });

  const h = Math.floor(duration / 3600);
  const m = Math.floor((duration % 3600) / 60);
  const durText = h > 0 ? `${h} jam${m > 0 ? ' ' + m + ' menit' : ''}` : `${m} menit`;
  return interactionReply(`✅ <@${userId}> di-timeout selama **${durText}**\n📝 Alasan: ${reason}`);
}

async function slashBan(options, guildId, moderator, env) {
  const userId = options.find(o => o.name === 'user')?.value;
  const reason = options.find(o => o.name === 'alasan')?.value || 'Tidak ada alasan';

  const r = await fetch(`${DISCORD_API}/guilds/${guildId}/bans/${userId}`, {
    method: 'PUT',
    headers: {
      Authorization: `Bot ${env.DISCORD_BOT_TOKEN}`,
      'Content-Type': 'application/json',
      'X-Audit-Log-Reason': encodeURIComponent(reason),
    },
    body: JSON.stringify({ reason }),
  });

  if (!r.ok && r.status !== 204) {
    const e = await r.json().catch(() => ({}));
    return interactionReply(`❌ Gagal ban: ${e.message || r.status}`, true);
  }

  await sendModLog({ guildId, userId, moderator, action: 'ban', reason, env });
  return interactionReply(`✅ <@${userId}> telah di-ban\n📝 Alasan: ${reason}`);
}

async function slashKick(options, guildId, moderator, env) {
  const userId = options.find(o => o.name === 'user')?.value;
  const reason = options.find(o => o.name === 'alasan')?.value || 'Tidak ada alasan';

  const r = await fetch(`${DISCORD_API}/guilds/${guildId}/members/${userId}`, {
    method: 'DELETE',
    headers: {
      Authorization: `Bot ${env.DISCORD_BOT_TOKEN}`,
      'Content-Type': 'application/json',
      'X-Audit-Log-Reason': encodeURIComponent(reason),
    },
  });

  if (!r.ok && r.status !== 204) {
    const e = await r.json().catch(() => ({}));
    return interactionReply(`❌ Gagal kick: ${e.message || r.status}`, true);
  }

  await sendModLog({ guildId, userId, moderator, action: 'kick', reason, env });
  return interactionReply(`✅ <@${userId}> telah di-kick\n📝 Alasan: ${reason}`);
}

// ─────────────────────────────────────────────
//   REGISTER SLASH COMMANDS
//   Buka browser: GET https://croback.enim48926.workers.dev/register-commands
//   Lakukan sekali saja!
// ─────────────────────────────────────────────
async function handleRegisterCommands(env) {
  const commands = [
    {
      name: 'to',
      description: 'Timeout member',
      options: [
        { name: 'user',   description: 'Member yang di-timeout', type: 6, required: true },
        { name: 'durasi', description: 'Durasi dalam detik (default 3600 = 1 jam)', type: 4, required: false },
        { name: 'alasan', description: 'Alasan timeout', type: 3, required: false },
      ],
    },
    {
      name: 'b',
      description: 'Ban member dari server',
      options: [
        { name: 'user',   description: 'Member yang di-ban', type: 6, required: true },
        { name: 'alasan', description: 'Alasan ban', type: 3, required: false },
      ],
    },
    {
      name: 'kk',
      description: 'Kick member dari server',
      options: [
        { name: 'user',   description: 'Member yang di-kick', type: 6, required: true },
        { name: 'alasan', description: 'Alasan kick', type: 3, required: false },
      ],
    },
  ];

  const r = await fetch(`${DISCORD_API}/applications/${env.DISCORD_CLIENT_ID}/commands`, {
    method: 'PUT',
    headers: {
      Authorization: `Bot ${env.DISCORD_BOT_TOKEN}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(commands),
  });

  const data = await r.json();
  if (!r.ok) return new Response(JSON.stringify({ error: data }), {
    status: 500, headers: { 'Content-Type': 'application/json' },
  });

  return new Response(JSON.stringify({ success: true, registered: data.length + ' commands' }), {
    headers: { 'Content-Type': 'application/json' },
  });
}

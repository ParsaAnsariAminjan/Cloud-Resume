// GET  /api/resume  -> public, returns saved JSON (or null)
// POST /api/resume  -> checks the admin password (login check)
// PUT  /api/resume  -> saves JSON, requires admin password
// Needs: KV binding named RESUME, secret named ADMIN_PASSWORD
const JSON_HEADERS = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" };
const MAX_BYTES = 60000;

async function sha(s) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)));
}
async function authorized(request, env) {
  if (!env.ADMIN_PASSWORD) return false;
  const [a, b] = await Promise.all([
    sha(request.headers.get("Authorization") || ""),
    sha("Bearer " + env.ADMIN_PASSWORD),
  ]);
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
const reply = (body, status = 200) => new Response(body, { status, headers: JSON_HEADERS });

export async function onRequestGet({ env }) {
  if (!env.RESUME) return reply("null");
  return reply((await env.RESUME.get("data")) || "null");
}

export async function onRequestPost({ request, env }) {
  return (await authorized(request, env)) ? reply('{"ok":true}') : reply('{"error":"unauthorized"}', 401);
}

export async function onRequestPut({ request, env }) {
  if (!(await authorized(request, env))) return reply('{"error":"unauthorized"}', 401);
  if (!env.RESUME) return reply('{"error":"KV binding RESUME is missing"}', 500);
  const text = await request.text();
  if (text.length > MAX_BYTES) return reply('{"error":"too large"}', 413);
  let d;
  try { d = JSON.parse(text); } catch { return reply('{"error":"invalid json"}', 400); }
  if (!d || typeof d !== "object" || !Array.isArray(d.jobs) || !Array.isArray(d.projects) ||
      !Array.isArray(d.skills) || !Array.isArray(d.education)) {
    return reply('{"error":"invalid shape"}', 400);
  }
  await env.RESUME.put("data", JSON.stringify(d));
  return reply('{"ok":true}');
}

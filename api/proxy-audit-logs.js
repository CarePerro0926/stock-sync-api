// api/proxy-audit-logs.js
import { createClient } from '@supabase/supabase-js';
import jwt from 'jsonwebtoken';

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

function verifyToken(req) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) throw new Error('No token');
  return jwt.verify(token, process.env.JWT_SECRET);
}

export default async function handler(req, res) {
  if (req.method !== 'GET') return res.status(405).end();
  try {
    const payload = verifyToken(req);
    if (!payload || !Array.isArray(payload.roles) || !payload.roles.includes('auditor')) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    const { usuario, accion, desde, hasta } = req.query;
    const requestedLimit = Number(req.query.limit ?? 10); // default 10
    const limit = Math.min(Math.max(requestedLimit, 1), 1000);
    const offset = Math.max(0, Number(req.query.offset ?? 0));
    const from = offset;
    const to = from + limit - 1;

    let q = supabase
      .from('audit_logs')
      .select('*', { count: 'exact' })
      .order('created_at', { ascending: false })
      .range(from, to);

    if (usuario) q = q.eq('actor_username', usuario);
    if (accion) q = q.eq('action', accion);
    if (desde) q = q.gte('created_at', desde);
    if (hasta) q = q.lte('created_at', hasta);

    const { data, error, count } = await q;
    if (error) {
      console.error('Supabase audit error:', error);
      return res.status(500).json({ error: error.message || 'Supabase error' });
    }

    return res.status(200).json({ items: data || [], meta: { total: count ?? (data || []).length } });
  } catch (err) {
    console.error('proxy-audit-logs unexpected error:', err);
    const msg = err?.message || String(err) || 'Internal error';
    if (msg.toLowerCase().includes('token')) return res.status(401).json({ error: msg });
    return res.status(500).json({ error: msg });
  }
}

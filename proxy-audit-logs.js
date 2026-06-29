// api/proxy-audit-logs.js
import { createClient } from '@supabase/supabase-js';

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

export default async function handler(req, res) {
  try {
    // Opcional: validar que el llamador está autenticado
    // const authHeader = req.headers.authorization || '';
    // if (!authHeader.startsWith('Bearer ')) return res.status(401).json({ error: 'No auth' });

    const limit = Math.min(Number(req.query.limit || 100), 1000);
    const offset = Number(req.query.offset || 0);

    const { data, error } = await supabase
      .from('audit_logs')
      .select('*')
      .order('created_at', { ascending: false })
      .limit(limit)
      .offset(offset);

    if (error) {
      console.error('Supabase audit error:', error);
      return res.status(500).json({ error: error.message || 'Supabase error' });
    }

    return res.status(200).json({ items: data, meta: { total: data.length } });
  } catch (err) {
    console.error('proxy-audit-logs unexpected error:', err);
    return res.status(500).json({ error: err.message || 'Internal error' });
  }
}

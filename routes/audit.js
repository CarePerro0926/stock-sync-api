// routes/audit.js
import express from 'express';
import { createClient } from '@supabase/supabase-js';

const router = express.Router();

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_KEY;
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

router.get('/audit-logs', async (req, res) => {
  try {
    const user = req.user || null;
    const role = user?.role || user?.tokenPayload?.role || null;
    if (!role || (role !== 'auditor' && role !== 'administrador')) {
      return res.status(403).json({ success: false, message: 'Forbidden' });
    }

    const limit = Math.min(Math.max(Number(req.query.limit) || 50, 1), 1000);
    const offset = Math.max(Number(req.query.offset) || 0, 0);
    const usuario = req.query.usuario ? String(req.query.usuario).trim() : null;
    const accion = req.query.accion ? String(req.query.accion).trim() : null;
    const desde = req.query.desde ? String(req.query.desde).trim() : null;
    const hasta = req.query.hasta ? String(req.query.hasta).trim() : null;

    let qb = supabase
      .from('audit_logs')
      .select('*', { count: 'exact' })
      .order('created_at', { ascending: false })
      .range(offset, offset + limit - 1);

    if (usuario) qb = qb.ilike('actor_username', `%${usuario}%`);
    if (accion) qb = qb.ilike('action', `%${accion}%`);
    if (desde) qb = qb.gte('created_at', desde);
    if (hasta) qb = qb.lte('created_at', hasta);

    const { data, count, error } = await qb;

    if (error) {
      console.error('routes/audit supabase error:', error);
      return res.status(500).json({ success: false, message: 'Error al obtener audit logs', error: error.message || String(error) });
    }

    return res.status(200).json({
      success: true,
      items: Array.isArray(data) ? data : (data ? [data] : []),
      meta: { total: typeof count === 'number' ? count : (Array.isArray(data) ? data.length : 0), limit, offset }
    });
  } catch (err) {
    console.error('routes/audit exception:', err);
    return res.status(500).json({ success: false, message: 'Error interno', error: String(err) });
  }
});

export default router;

// routes/audit.js
import express from 'express';
import { createClient } from '@supabase/supabase-js';

const router = express.Router();

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_KEY;

if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
  console.error('Missing SUPABASE_URL or SUPABASE_SERVICE_KEY in environment');
}
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

/**
 * GET /api/audit-logs
 * Requiere que el middleware authenticateJwt haya corrido antes (se registra en server.js).
 * Solo usuarios con role 'auditor' o 'administrador' pueden acceder.
 */
router.get('/audit-logs', async (req, res) => {
  try {
    // Si no hay req.user, significa que no se aplicó authenticateJwt
    const role = req.user && req.user.role ? req.user.role : (req.user && req.user.tokenPayload && req.user.tokenPayload.role) || null;
    if (!role || (role !== 'auditor' && role !== 'administrador')) {
      return res.status(403).json({ success: false, message: 'Forbidden' });
    }

    const limit = Math.min(Math.max(Number(req.query.limit) || 50, 1), 1000);
    const { data, error } = await supabase
      .from('audit_logs')
      .select('*')
      .order('created_at', { ascending: false })
      .limit(limit);

    if (error) {
      console.error('routes/audit GET supabase error:', error);
      return res.status(500).json({ success: false, message: 'Error al obtener audit logs', error: error.message || String(error) });
    }

    return res.status(200).json(Array.isArray(data) ? data : (data ? [data] : []));
  } catch (err) {
    console.error('routes/audit GET exception:', err);
    return res.status(500).json({ success: false, message: 'Error interno', error: String(err) });
  }
});

export default router;

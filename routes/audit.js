// routes/audit.js
import express from 'express';

const router = express.Router();

/**
 * GET /api/proxy-audit-logs
 * Query params: limit, offset, actor_id, action, since, until, order
 * Requiere req.user (authenticateJwt) o cabecera x-admin-token válida.
 */
export default (supabaseAdmin, isAdminRequest, insertAuditLog) => {
  // middleware local para permitir admin header o usuario autenticado
  const allowAdminOrAuth = (req, res, next) => {
    try {
      if (isAdminRequest(req)) return next();
      // si authenticateJwt ya se aplicó globalmente, req.user estará presente
      if (req.user && req.user.id) return next();
      return res.status(401).json({ success: false, message: 'No autorizado' });
    } catch (err) {
      return res.status(401).json({ success: false, message: 'No autorizado' });
    }
  };

  // Ruta principal
  router.get('/proxy-audit-logs', allowAdminOrAuth, async (req, res) => {
    try {
      const q = req.query || {};
      const limit = Math.min(Number(q.limit) || 100, 1000);
      const offset = Math.max(Number(q.offset) || 0, 0);
      const actor_id = q.actor_id || null;
      const action = q.action || null;
      const since = q.since || null;   // ISO date
      const until = q.until || null;   // ISO date
      const order = (q.order || 'created_at').toString();

      let query = supabaseAdmin
        .from('audit_logs')
        .select('id, actor_id, actor_username, action, target_table, target_id, reason, metadata, ip, created_at')
        .order(order, { ascending: false })
        .range(offset, offset + limit - 1);

      if (actor_id) query = query.eq('actor_id', actor_id);
      if (action) query = query.eq('action', action);
      if (since) query = query.gte('created_at', since);
      if (until) query = query.lte('created_at', until);

      const { data, error, count } = await query;

      if (error) {
        console.error('proxy-audit-logs supabase error:', error);
        return res.status(500).json({ success: false, message: 'Error al consultar audit logs', error: error.message || error });
      }

      // opcional: registrar que se consultaron logs (audit trail)
      try {
        await insertAuditLog({
          actor_id: req.user?.id || null,
          actor_username: req.user?.username || null,
          action: 'audit_logs_read',
          target_table: 'audit_logs',
          metadata: { query: { limit, offset, actor_id, action, since, until } },
          ip: req.ip
        });
      } catch (e) {
        console.warn('Audit log insert failed for audit_logs_read:', e);
      }

      return res.status(200).json({ success: true, data: data || [], count: Array.isArray(data) ? data.length : 0 });
    } catch (err) {
      console.error('GET /proxy-audit-logs exception:', err);
      return res.status(500).json({ success: false, message: 'Error interno', error: String(err) });
    }
  });

  return router;
};

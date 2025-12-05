// api/server.js
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import axios from 'axios';
import { createClient } from '@supabase/supabase-js';

const app = express();
app.use(express.json());
app.use(helmet());

// --- CORS ---
const rawOrigins = process.env.FRONTEND_ORIGINS || process.env.FRONTEND_ORIGIN || '';
const allowedOrigins = rawOrigins ? rawOrigins.split(',').map(s => s.trim()).filter(Boolean) : [];

app.use(
  cors({
    origin: allowedOrigins.length > 0 ? allowedOrigins : '*',
    allowedHeaders: ['Content-Type', 'x-admin-token', 'authorization'],
    exposedHeaders: ['Content-Type', 'x-admin-token', 'X-Users-Count', 'X-Products-Count'],
    credentials: true,
    methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE', 'OPTIONS'],
  })
);
// --- FIN CORS ---

// --- SUPABASE CLIENT ---
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_KEY;

if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
  console.error('FATAL: Falta SUPABASE_URL o SUPABASE_SERVICE_KEY en variables de entorno');
  // No continuar si no hay credenciales de supabase, porque las consultas fallarán.
  process.exit(1);
}

const supabaseAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);
// --- FIN SUPABASE CLIENT ---

// ADMIN token check (server-to-server)
if (!process.env.ADMIN_API_TOKEN) {
  console.warn('ADVERTENCIA: ADMIN_API_TOKEN no está definido. Algunas rutas admin pueden requerir JWT admin.');
}
const isAdminRequest = (req) => {
  const token = req.headers['x-admin-token'] || null;
  if (!process.env.ADMIN_API_TOKEN) return false;
  return !!token && token === process.env.ADMIN_API_TOKEN;
};

// --- UTILIDADES ---
const respondError = (res, status = 500, message = 'Error interno', details = null) => {
  const payload = { success: false, message };
  if (details) payload.error = details;
  return res.status(status).json(payload);
};

const isUuid = (s) => {
  if (typeof s !== 'string') return false;
  return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/.test(s);
};

const isValidIdFlexible = (id) => typeof id === 'string' && id.length > 0;
// --- FIN UTILIDADES ---

// --- LOGGING SIMPLE ---
app.use((req, res, next) => {
  const hasAdminHeader = !!req.headers['x-admin-token'];
  console.log(`${new Date().toISOString()} ${req.method} ${req.originalUrl} - x-admin-token present: ${hasAdminHeader}`);
  next();
});
// --- FIN LOGGING ---

// --- AUTH MIDDLEWARES ---
const authenticateJwt = async (req, res, next) => {
  try {
    const auth = req.headers.authorization || '';
    if (!auth.startsWith('Bearer ')) return res.status(401).json({ success: false, message: 'No autorizado' });
    const token = auth.split(' ')[1];
    const secret = process.env.JWT_SECRET || process.env.SESSION_SECRET;
    if (!secret) return res.status(500).json({ success: false, message: 'JWT secret no configurado en servidor' });

    const payload = jwt.verify(token, secret);
    if (!payload || !payload.sub) return res.status(401).json({ success: false, message: 'Token inválido' });

    const { data, error } = await supabaseAdmin
      .from('usuarios')
      .select('id, deleted_at, role, email, username')
      .eq('id', payload.sub)
      .limit(1);

    if (error) {
      console.error('authenticateJwt supabase error:', error);
      return res.status(500).json({ success: false, message: 'Error al validar usuario', error });
    }

    if (!data || data.length === 0) return res.status(404).json({ success: false, message: 'Usuario no encontrado' });

    const dbUser = data[0];
    if (dbUser.deleted_at) return res.status(403).json({ success: false, message: 'Usuario inhabilitado' });

    req.user = {
      id: dbUser.id,
      role: dbUser.role || payload.role || 'cliente',
      email: dbUser.email || payload.email,
      username: dbUser.username || payload.username,
      tokenPayload: payload
    };

    return next();
  } catch (err) {
    console.error('authenticateJwt error:', err?.message || err);
    return res.status(401).json({ success: false, message: 'Token inválido' });
  }
};

const authenticateJwtAdmin = async (req, res, next) => {
  try {
    await authenticateJwt(req, res, async () => {
      const role = req.user && req.user.role ? req.user.role : (req.user && req.user.tokenPayload && req.user.tokenPayload.role) || null;
      if (!role || role !== 'administrador') return res.status(403).json({ success: false, message: 'Forbidden' });
      return next();
    });
  } catch (err) {
    console.error('authenticateJwtAdmin wrapper error:', err?.message || err);
    return res.status(401).json({ success: false, message: 'Token inválido' });
  }
};
// --- FIN AUTH MIDDLEWARES ---

// --- AUDIT LOG HELPER ---
const insertAuditLog = async ({ actor_id = null, actor_username = null, action, target_table = null, target_id = null, reason = null, metadata = null, ip = null }) => {
  try {
    const payload = {
      actor_id,
      actor_username,
      action,
      target_table,
      target_id: target_id ? String(target_id) : null,
      reason,
      metadata,
      ip
    };
    const { error } = await supabaseAdmin.from('audit_logs').insert([payload]);
    if (error) {
      console.warn('insertAuditLog supabase error:', error);
      return false;
    }
    return true;
  } catch (err) {
    console.warn('insertAuditLog exception:', err);
    return false;
  }
};
// --- FIN AUDIT LOG HELPER ---

// --- RUTAS ---

/**
 * ADMIN PROXY
 */
app.patch('/admin/usuarios/:id/:action', /* authenticateJwtAdmin, */ async (req, res) => {
  try {
    const { id, action } = req.params;
    if (action !== 'enable' && action !== 'disable') return respondError(res, 400, 'Acción inválida. Solo enable/disable.');

    if (!process.env.ADMIN_API_TOKEN) {
      console.warn('ADMIN proxy rejected: ADMIN_API_TOKEN not configured on server');
      return respondError(res, 500, 'ADMIN token not configured on server');
    }

    const API_USUARIOS_BASE = process.env.API_USUARIOS_BASE || process.env.API_INTERNAL_BASE || 'https://la-api-externa-que-tiene-los-usuarios.com';
    const url = `${API_USUARIOS_BASE}/api/usuarios/${id}/${action}`;

    const resp = await axios.patch(url, null, {
      headers: {
        'Content-Type': 'application/json',
        'x-admin-token': process.env.ADMIN_API_TOKEN
      },
      validateStatus: () => true
    });

    return res.status(resp.status).send(resp.data);
  } catch (err) {
    console.error('Proxy admin error:', err?.response?.data || err.message || err);
    return respondError(res, 500, 'Error interno en proxy', err?.response?.data || err?.message || String(err));
  }
});

/**
 * POST /api/login
 */
app.post('/api/login', async (req, res) => {
  try {
    const body = req.body || {};
    const email = body.email || null;
    const username = body.username || body.user || null;
    const password = body.password || body.pass || null;

    if (!password || (!email && !username)) return res.status(400).json({ success: false, message: 'Faltan credenciales' });

    const identifier = email || username;

    const queryUserFromTable = async (tableName) => {
      try {
        let query = supabaseAdmin
          .from(tableName)
          .select('id, email, username, pass, nombres, apellidos, role, deleted_at')
          .limit(1);

        if (email) {
          query = query.eq('email', identifier);
        } else {
          const safe = String(identifier).replace(/"/g, '\\"');
          query = query.or(`username.eq."${safe}",email.eq."${safe}"`).limit(1);
        }

        const { data, error } = await query;
        return { data, error };
      } catch (err) {
        return { data: null, error: err };
      }
    };

    let usersResult = await queryUserFromTable('usuarios');
    if (usersResult.error) usersResult = await queryUserFromTable('users');
    if (usersResult.error) return respondError(res, 500, 'Error al consultar usuario', usersResult.error.message || String(usersResult.error));

    const users = usersResult.data;
    const user = Array.isArray(users) && users.length > 0 ? users[0] : null;
    if (!user) return res.status(401).json({ success: false, message: 'Credenciales inválidas' });

    if (user.deleted_at) return res.status(403).json({ success: false, message: 'Usuario inhabilitado' });

    const storedHash = user.pass || null;
    if (!storedHash) return res.status(401).json({ success: false, message: 'Credenciales inválidas' });

    const passwordMatches = await bcrypt.compare(password, storedHash);
    if (!passwordMatches) return res.status(401).json({ success: false, message: 'Credenciales inválidas' });

    const jwtSecret = process.env.JWT_SECRET || process.env.SESSION_SECRET;
    const tokenPayload = { sub: user.id, email: user.email, role: user.role || 'cliente' };
    const token = jwtSecret ? jwt.sign(tokenPayload, jwtSecret, { expiresIn: '8h' }) : 'token-temporal';

    return res.status(200).json({
      success: true,
      token,
      user: {
        id: user.id,
        email: user.email,
        username: user.username || null,
        role: user.role || 'cliente',
        nombre: user.nombres || null,
        apellidos: user.apellidos || null,
      },
    });
  } catch (err) {
    console.error('POST /api/login error (exception):', err);
    return respondError(res, 500, 'Error interno', String(err));
  }
});

/**
 * GET /api/productos
 */
app.get('/api/productos', async (req, res) => {
  try {
    const includeInactivos = String(req.query.include_inactivos || '').toLowerCase() === 'true';

    let query = supabaseAdmin
      .from('productos')
      .select('id, product_id, nombre, precio, cantidad, categoria_id, deleted_at')
      .order('id', { ascending: true });

    if (!includeInactivos) query = query.is('deleted_at', null);

    const { data, error } = await query;
    if (error) {
      console.error('GET /api/productos - supabase error:', error.message || error);
      return respondError(res, 500, 'No se pudo obtener productos', error.message || String(error));
    }

    res.setHeader('X-Products-Count', Array.isArray(data) ? data.length : 0);
    return res.status(200).json({ success: true, data: data || [] });
  } catch (err) {
    console.error('API exception GET /api/productos:', err);
    return respondError(res, 500, 'Error interno', String(err));
  }
});

// GET /api/usuarios - handler definitivo (reemplazar el existente)
app.get('/api/usuarios', async (req, res) => {
  try {
    // Verificar cliente supabase
    if (!supabaseAdmin) {
      return res.status(500).json({ success: false, message: 'supabaseAdmin no inicializado. Revisa SUPABASE_URL y SUPABASE_SERVICE_KEY' });
    }

    // Detectar admin por x-admin-token o JWT con role administrador
    let isAdmin = false;
    if (isAdminRequest(req)) {
      isAdmin = true;
    } else {
      const auth = req.headers.authorization || '';
      const secret = process.env.JWT_SECRET || process.env.SESSION_SECRET;
      if (auth.startsWith('Bearer ') && secret) {
        try {
          const token = auth.split(' ')[1];
          const payload = jwt.verify(token, secret);
          if (payload && payload.role && String(payload.role).toLowerCase() === 'administrador') isAdmin = true;
        } catch (e) {
          /* no admin */
        }
      }
    }

    // Decidir incluir inactivos
    const qInclude = String(req.query.include_inactivos || '').toLowerCase() === 'true';
    const includeInactivos = qInclude || isAdmin;

    // Ejecutar consulta
    let query = supabaseAdmin.from('usuarios').select('*').order('id', { ascending: true });
    if (!includeInactivos) query = query.is('deleted_at', null);

    const { data, error, status } = await query;

    if (error) {
      // Devolver error claro para depuración en frontend
      console.error('Supabase error GET /api/usuarios:', error);
      return res.status(500).json({
        success: false,
        message: 'Error al consultar usuarios en Supabase',
        supabase_status: status,
        supabase_error: error
      });
    }

    // Normalizar y devolver
    const normalized = (data || []).map(u => ({ ...u, status: u.deleted_at ? 'inactive' : 'active' }));
    res.setHeader('X-Users-Count', Array.isArray(normalized) ? normalized.length : 0);
    return res.status(200).json({ success: true, data: normalized });
  } catch (err) {
    console.error('Exception GET /api/usuarios:', err);
    return res.status(500).json({ success: false, message: 'Exception en servidor', error: String(err) });
  }
});

/**
 * PATCH /api/productos/:id/disable
 */
app.patch('/api/productos/:id/disable', async (req, res) => {
  if (!isAdminRequest(req)) {
    console.warn('PATCH disable - request rejected as non-admin. x-admin-token present:', !!req.headers['x-admin-token']);
    return respondError(res, 403, 'Forbidden');
  }

  const { id } = req.params;
  try {
    const { data, error } = await supabaseAdmin
      .from('productos')
      .update({ deleted_at: new Date().toISOString() })
      .or(`id.eq.${id},product_id.eq.${id}`)
      .select();

    if (error) {
      console.error('API error updating producto disable:', error);
      return respondError(res, 500, 'No se pudo inhabilitar el producto', error.message || String(error));
    }

    const result = Array.isArray(data) ? data : [data];
    return res.status(200).json({ success: true, data: result });
  } catch (err) {
    console.error('API exception PATCH disable:', err);
    return respondError(res, 500, 'Error interno', String(err));
  }
});

/**
 * PATCH /api/productos/:id/enable
 */
app.patch('/api/productos/:id/enable', async (req, res) => {
  if (!isAdminRequest(req)) {
    console.warn('PATCH enable - request rejected as non-admin. x-admin-token present:', !!req.headers['x-admin-token']);
    return respondError(res, 403, 'Forbidden');
  }

  const { id } = req.params;
  try {
    const { data, error } = await supabaseAdmin
      .from('productos')
      .update({ deleted_at: null })
      .or(`id.eq.${id},product_id.eq.${id}`)
      .select();

    if (error) {
      console.error('API error updating producto enable:', error);
      return respondError(res, 500, 'No se pudo habilitar el producto', error.message || String(error));
    }

    const result = Array.isArray(data) ? data : [data];
    return res.status(200).json({ success: true, data: result });
  } catch (err) {
    console.error('API exception PATCH enable:', err);
    return respondError(res, 500, 'Error interno', String(err));
  }
});

/**
 * PATCH /api/usuarios/:id/disable
 * Requiere authenticateJwtAdmin
 */
app.patch('/api/usuarios/:id/disable', authenticateJwtAdmin, async (req, res) => {
  const { id } = req.params;
  if (!isUuid(id)) return respondError(res, 400, 'ID inválido');

  try {
    const actor = req.user && req.user.id ? req.user.id : null;
    const actor_username = req.user && req.user.username ? req.user.username : null;

    const { data: prevData } = await supabaseAdmin.from('usuarios').select('*').eq('id', id).limit(1);
    const previousRow = Array.isArray(prevData) && prevData.length ? prevData[0] : null;

    const { data, error } = await supabaseAdmin
      .from('usuarios')
      .update({ deleted_at: new Date().toISOString() })
      .eq('id', id)
      .select();

    if (error) {
      console.error('API error updating usuario disable:', error);
      return respondError(res, 500, 'No se pudo inhabilitar el usuario', error.message || String(error));
    }

    if (!data || data.length === 0) return respondError(res, 404, 'Usuario no encontrado');

    const updated = Array.isArray(data) ? data[0] : data;
    const result = { ...updated, status: updated.deleted_at ? 'inactive' : 'active' };

    try {
      await insertAuditLog({
        actor_id: actor,
        actor_username,
        action: 'usuario_disable',
        target_table: 'usuarios',
        target_id: id,
        reason: req.body?.reason || null,
        metadata: { before: previousRow, after: result },
        ip: req.ip
      });
    } catch (e) {
      console.warn('Audit log failed for usuario_disable:', e);
    }

    console.log(`Usuario ${id} inhabilitado por actor ${actor}`);
    return res.status(200).json({ success: true, data: result });
  } catch (err) {
    console.error('API exception PATCH disable usuario:', err);
    return respondError(res, 500, 'Error interno', String(err));
  }
});

/**
 * PATCH /api/usuarios/:id/enable
 * Requiere authenticateJwtAdmin
 */
app.patch('/api/usuarios/:id/enable', authenticateJwtAdmin, async (req, res) => {
  const { id } = req.params;
  if (!isUuid(id)) return respondError(res, 400, 'ID inválido');

  try {
    const actor = req.user && req.user.id ? req.user.id : null;
    const actor_username = req.user && req.user.username ? req.user.username : null;

    const { data: prevData } = await supabaseAdmin.from('usuarios').select('*').eq('id', id).limit(1);
    const previousRow = Array.isArray(prevData) && prevData.length ? prevData[0] : null;

    const { data, error } = await supabaseAdmin
      .from('usuarios')
      .update({ deleted_at: null })
      .eq('id', id)
      .select();

    if (error) {
      console.error('API error updating usuario enable:', error);
      return respondError(res, 500, 'No se pudo habilitar el usuario', error.message || String(error));
    }

    if (!data || data.length === 0) return respondError(res, 404, 'Usuario no encontrado');

    const updated = Array.isArray(data) ? data[0] : data;
    const result = { ...updated, status: updated.deleted_at ? 'inactive' : 'active' };

    try {
      await insertAuditLog({
        actor_id: actor,
        actor_username,
        action: 'usuario_enable',
        target_table: 'usuarios',
        target_id: id,
        reason: req.body?.reason || null,
        metadata: { before: previousRow, after: result },
        ip: req.ip
      });
    } catch (e) {
      console.warn('Audit log failed for usuario_enable:', e);
    }

    console.log(`Usuario ${id} habilitado por actor ${actor}`);
    return res.status(200).json({ success: true, data: result });
  } catch (err) {
    console.error('API exception PATCH enable usuario:', err);
    return respondError(res, 500, 'Error interno', String(err));
  }
});

/**
 * DELETE /api/usuarios/:id (soft delete)
 * Requiere authenticateJwtAdmin
 */
app.delete('/api/usuarios/:id', authenticateJwtAdmin, async (req, res) => {
  const { id } = req.params;
  if (!isUuid(id)) return respondError(res, 400, 'ID inválido');

  try {
    const actor = req.user && req.user.id ? req.user.id : null;
    const actor_username = req.user && req.user.username ? req.user.username : null;

    const { data: prevData } = await supabaseAdmin.from('usuarios').select('*').eq('id', id).limit(1);
    const previousRow = Array.isArray(prevData) && prevData.length ? prevData[0] : null;

    const { data, error } = await supabaseAdmin
      .from('usuarios')
      .update({ deleted_at: new Date().toISOString() })
      .eq('id', id)
      .is('deleted_at', null)
      .select();

    if (error) {
      console.error('DELETE (soft) usuario error:', error);
      return respondError(res, 500, 'No se pudo inhabilitar el usuario', error.message || String(error));
    }

    if (!data || data.length === 0) {
      const { data: exists, error: errExists } = await supabaseAdmin.from('usuarios').select('id, deleted_at').eq('id', id).limit(1);
      if (errExists) {
        console.error('Error comprobando existencia usuario tras intento delete:', errExists);
        return respondError(res, 500, 'Error interno', String(errExists));
      }
      if (!exists || exists.length === 0) return respondError(res, 404, 'Usuario no encontrado');
      return res.status(200).json({ success: true, message: 'Usuario ya inhabilitado' });
    }

    const updated = Array.isArray(data) && data.length ? data[0] : data;

    try {
      await insertAuditLog({
        actor_id: actor,
        actor_username,
        action: 'usuario_disable',
        target_table: 'usuarios',
        target_id: id,
        reason: req.body?.reason || null,
        metadata: { before: previousRow, after: updated },
        ip: req.ip
      });
    } catch (e) {
      console.warn('Audit log failed for usuario_disable (DELETE):', e);
    }

    console.log(`Usuario ${id} inhabilitado (DELETE soft) por actor ${actor}`);
    return res.status(200).json({ success: true, message: 'Usuario inhabilitado' });
  } catch (err) {
    console.error('API exception DELETE usuario (soft):', err);
    return respondError(res, 500, 'Error interno', String(err));
  }
});

/**
 * GET /api/mis-datos
 * Protegida por authenticateJwt
 */
app.get('/api/mis-datos', authenticateJwt, async (req, res) => {
  try {
    const userId = req.user.id;
    const { data, error } = await supabaseAdmin
      .from('usuarios')
      .select('id, email, username, nombres, apellidos, role, deleted_at')
      .eq('id', userId)
      .limit(1);

    if (error) {
      console.error('GET /api/mis-datos supabase error:', error);
      return respondError(res, 500, 'Error al obtener datos de usuario', error.message || String(error));
    }

    if (!data || data.length === 0) return respondError(res, 404, 'Usuario no encontrado');

    const user = data[0];
    return res.status(200).json({ success: true, data: user });
  } catch (err) {
    console.error('GET /api/mis-datos error:', err);
    return respondError(res, 500, 'Error interno', String(err));
  }
});

// Health check
app.get('/api/health', (req, res) => res.status(200).json({ ok: true }));

// Root
app.get('/', (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.status(200).send('Bienvenido a la API de Stock Sync');
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  if (res.headersSent) return next(err);
  return respondError(res, 500, 'Error interno', String(err));
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`API server listening on port ${PORT}`);
});
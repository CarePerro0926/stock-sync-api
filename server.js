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

// --- CONFIGURACIÓN DE CORS ---
const rawOrigins = process.env.FRONTEND_ORIGINS || process.env.FRONTEND_ORIGIN || '';
const allowedOrigins = rawOrigins ? rawOrigins.split(',').map(s => s.trim()).filter(Boolean) : [];

app.use(
  cors({
    origin: allowedOrigins.length > 0 ? allowedOrigins : '*',
    allowedHeaders: ['Content-Type', 'x-admin-token', 'authorization'],
    exposedHeaders: ['Content-Type', 'x-admin-token'],
    credentials: true,
    methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE', 'OPTIONS'],
  })
);
// --- FIN CONFIGURACIÓN CORS ---

// Supabase
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_KEY;

if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
  console.error('Falta SUPABASE_URL o SUPABASE_SERVICE_KEY en variables de entorno');
  process.exit(1);
}

const supabaseAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

// ADMIN_API_TOKEN advertencia
if (!process.env.ADMIN_API_TOKEN) {
  console.warn('ADVERTENCIA: ADMIN_API_TOKEN no está definido. Las rutas admin que dependan de él fallarán si se usan.');
}

// Helper admin header
const isAdminRequest = (req) => {
  const token = req.headers['x-admin-token'] || null;
  if (!process.env.ADMIN_API_TOKEN) {
    return false;
  }
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

const isValidIdFlexible = (id) => {
  if (typeof id !== 'string') return false;
  if (id.length === 0) return false;
  return true;
};

// Logging temporal (no exponer secretos)
app.use((req, res, next) => {
  const hasAdminHeader = !!req.headers['x-admin-token'];
  console.log(`${new Date().toISOString()} ${req.method} ${req.originalUrl} - x-admin-token present: ${hasAdminHeader}`);
  next();
});

// --- MIDDLEWARES ---
// authenticateJwt: valida token y que usuario no esté inhabilitado
const authenticateJwt = async (req, res, next) => {
  try {
    const auth = req.headers.authorization || '';
    if (!auth.startsWith('Bearer ')) return res.status(401).json({ success: false, message: 'No autorizado' });
    const token = auth.split(' ')[1];
    const secret = process.env.JWT_SECRET || process.env.SESSION_SECRET;
    if (!secret) return res.status(500).json({ success: false, message: 'JWT secret no configurado en servidor' });

    const payload = jwt.verify(token, secret);
    if (!payload || !payload.sub) {
      return res.status(401).json({ success: false, message: 'Token inválido' });
    }

    const { data, error } = await supabaseAdmin
      .from('usuarios')
      .select('id, deleted_at, role, email, username')
      .eq('id', payload.sub)
      .limit(1);

    if (error) {
      console.error('authenticateJwt supabase error:', error);
      return res.status(500).json({ success: false, message: 'Error al validar usuario' });
    }

    if (!data || data.length === 0) {
      return res.status(404).json({ success: false, message: 'Usuario no encontrado' });
    }

    const dbUser = data[0];
    if (dbUser.deleted_at) {
      return res.status(403).json({ success: false, message: 'Usuario inhabilitado' });
    }

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

// authenticateJwtAdmin: reusa authenticateJwt y exige role administrador
const authenticateJwtAdmin = async (req, res, next) => {
  try {
    await authenticateJwt(req, res, async () => {
      const role = req.user && req.user.role ? req.user.role : (req.user && req.user.tokenPayload && req.user.tokenPayload.role) || null;
      if (!role || role !== 'administrador') {
        return res.status(403).json({ success: false, message: 'Forbidden' });
      }
      return next();
    });
  } catch (err) {
    console.error('authenticateJwtAdmin wrapper error:', err?.message || err);
    return res.status(401).json({ success: false, message: 'Token inválido' });
  }
};
// --- FIN MIDDLEWARES ---

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

// --- RUTAS ---

/**
 * ADMIN PROXY
 * Protegido por authenticateJwtAdmin para evitar exponer ADMIN_API_TOKEN al cliente.
 */
app.patch('/admin/usuarios/:id/:action', authenticateJwtAdmin, async (req, res) => {
  try {
    const { id, action } = req.params;

    if (!isValidIdFlexible(id)) return respondError(res, 400, 'ID inválido');

    if (action !== 'enable' && action !== 'disable') {
      return respondError(res, 400, 'Acción inválida. Solo se permite "enable" o "disable".');
    }

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

    if (!password || (!email && !username)) {
      return res.status(400).json({ success: false, message: 'Faltan credenciales' });
    }

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

    if (usersResult.error) {
      usersResult = await queryUserFromTable('users');
    }

    if (usersResult.error) {
      return respondError(res, 500, 'Error al consultar usuario', usersResult.error.message || String(usersResult.error));
    }

    const users = usersResult.data;
    const user = Array.isArray(users) && users.length > 0 ? users[0] : null;
    if (!user) {
      return res.status(401).json({ success: false, message: 'Credenciales inválidas' });
    }

    if (user.deleted_at) {
      return res.status(403).json({ success: false, message: 'Usuario inhabilitado' });
    }

    const storedHash = user.pass || null;
    if (!storedHash) {
      return res.status(401).json({ success: false, message: 'Credenciales inválidas' });
    }

    const passwordMatches = await bcrypt.compare(password, storedHash);
    if (!passwordMatches) {
      return res.status(401).json({ success: false, message: 'Credenciales inválidas' });
    }

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
 * Por defecto devuelve solo productos activos (deleted_at IS NULL).
 * Si ?include_inactivos=true se devuelven todos.
 *
 * Devuelve directamente un array (compatibilidad con frontend).
 */
app.get('/api/productos', async (req, res) => {
  try {
    const includeInactivos = String(req.query.include_inactivos || '').toLowerCase() === 'true';

    let query = supabaseAdmin
      .from('productos')
      .select('id, product_id, nombre, precio, cantidad, categoria_id, deleted_at')
      .order('id', { ascending: true });

    if (!includeInactivos) {
      query = query.is('deleted_at', null);
    }

    const { data, error } = await query;

    if (error) {
      console.error('GET /api/productos - supabase error:', error.message || error);
      return res.status(200).json([]);
    }

    return res.status(200).json(data || []);
  } catch (err) {
    console.error('API exception GET /api/productos:', err);
    return res.status(200).json([]);
  }
});

/**
 * GET /api/usuarios
 * - AHORA devuelve TODOS los usuarios por defecto (activos e inactivos).
 * - Si se pasa ?include_inactivos=false se filtran (opcional).
 *
 * Devuelve directamente un array para compatibilidad con el frontend.
 */
app.get('/api/usuarios', async (req, res) => {
  try {
    // Decidir si incluir inactivos basado en query param
    // Por defecto, ahora incluye inactivos (include_inactivos=true implícito)
    const includeInactivos = String(req.query.include_inactivos || 'true').toLowerCase() === 'true';

    // Construir consulta
    let query = supabaseAdmin.from('usuarios').select('*').order('id', { ascending: true });
    if (!includeInactivos) {
      // Filtrar solo activos si explícitamente se pide
      query = query.is('deleted_at', null);
    }

    const { data, error } = await query;

    if (error) {
      console.warn('GET /api/usuarios - supabase returned error:', error.message || error);
      return res.status(200).json([]);
    }

    return res.status(200).json(data || []);
  } catch (err) {
    console.warn('GET /api/usuarios - exception:', String(err));
    return res.status(200).json([]);
  }
});

/**
 * POST /api/productos
 * Crea un nuevo producto.
 * Requiere authenticateJwtAdmin (logueado como admin).
 */
app.post('/api/productos', authenticateJwtAdmin, async (req, res) => {
  try {
    const actor = req.user && req.user.id ? req.user.id : null;
    const actor_username = req.user && req.user.username ? req.user.username : null;

    const payload = req.body || {};
    // Validar campos requeridos aquí si es necesario
    // Ejemplo:
    // if (!payload.nombre || typeof payload.nombre !== 'string' || payload.nombre.trim() === '') {
    //   return respondError(res, 400, 'Nombre del producto es obligatorio');
    // }

    const { data, error } = await supabaseAdmin
      .from('productos')
      .insert([payload])
      .select()
      .single(); // Asumiendo que insertamos uno solo

    if (error) {
      console.error('POST /api/productos - supabase error:', error);
      return respondError(res, 500, 'No se pudo crear el producto', error.message || String(error));
    }

    // Registrar acción en auditoría
    try {
      await insertAuditLog({
        actor_id: actor,
        actor_username,
        action: 'producto_create',
        target_table: 'productos',
        target_id: data.id,
        metadata: { new_data: data },
        ip: req.ip
      });
    } catch (e) {
      console.warn('Audit log failed for producto_create:', e);
    }

    console.log(`Producto creado por ${actor_username} con ID: ${data.id}`);
    return res.status(201).json({ success: true, data });
  } catch (err) {
    console.error('API exception POST /api/productos:', err);
    return respondError(res, 500, 'Error interno', String(err));
  }
});

/**
 * GET /api/productos/:id
 * Consulta un producto por ID (activo o inactivo).
 * Requiere authenticateJwt (logueado).
 */
app.get('/api/productos/:id', authenticateJwt, async (req, res) => {
  try {
    const { id } = req.params;
    if (!isValidIdFlexible(id)) return respondError(res, 400, 'ID inválido');

    const { data, error } = await supabaseAdmin
      .from('productos')
      .select('*')
      .or(`id.eq.${id},product_id.eq.${id}`)
      .limit(1);

    if (error) {
      console.error('GET /api/productos/:id - supabase error:', error);
      return respondError(res, 500, 'Error al consultar producto', error.message || String(error));
    }

    if (!data || data.length === 0) {
      return respondError(res, 404, 'Producto no encontrado');
    }

    const producto = data[0];

    // Registrar acción en auditoría (opcional)
    try {
      await insertAuditLog({
        actor_id: req.user.id,
        actor_username: req.user.username,
        action: 'producto_read',
        target_table: 'productos',
        target_id: producto.id,
        ip: req.ip
      });
    } catch (e) {
      console.warn('Audit log failed for producto_read:', e);
    }

    return res.status(200).json(producto);
  } catch (err) {
    console.error('API exception GET /api/productos/:id:', err);
    return respondError(res, 500, 'Error interno', String(err));
  }
});

/**
 * PUT /api/productos/:id
 * Modifica completamente un producto por ID.
 * Requiere authenticateJwtAdmin (logueado como admin).
 */
app.put('/api/productos/:id', authenticateJwtAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    if (!isValidIdFlexible(id)) return respondError(res, 400, 'ID inválido');

    const actor = req.user && req.user.id ? req.user.id : null;
    const actor_username = req.user && req.user.username ? req.user.username : null;

    // Obtener estado anterior para auditoría
    const { data: prevData, error: prevError } = await supabaseAdmin
      .from('productos')
      .select('*')
      .or(`id.eq.${id},product_id.eq.${id}`)
      .limit(1);

    if (prevError) {
      console.error('PUT /api/productos/:id - supabase error fetching previous state:', prevError);
      return respondError(res, 500, 'Error al consultar producto previo', prevError.message || String(prevError));
    }

    if (!prevData || prevData.length === 0) {
      return respondError(res, 404, 'Producto no encontrado');
    }

    const previousRow = prevData[0];
    const payload = req.body || {};

    const { data, error } = await supabaseAdmin
      .from('productos')
      .update(payload)
      .or(`id.eq.${id},product_id.eq.${id}`)
      .select()
      .single();

    if (error) {
      console.error('PUT /api/productos/:id - supabase error updating:', error);
      return respondError(res, 500, 'No se pudo actualizar el producto', error.message || String(error));
    }

    // Registrar acción en auditoría
    try {
      await insertAuditLog({
        actor_id: actor,
        actor_username,
        action: 'producto_update',
        target_table: 'productos',
        target_id: id,
        metadata: { before: previousRow, after: data },
        ip: req.ip
      });
    } catch (e) {
      console.warn('Audit log failed for producto_update:', e);
    }

    console.log(`Producto ${id} actualizado por ${actor_username}`);
    return res.status(200).json({ success: true, data });
  } catch (err) {
    console.error('API exception PUT /api/productos/:id:', err);
    return respondError(res, 500, 'Error interno', String(err));
  }
});

/**
 * PATCH /api/productos/:id/disable
 * Requiere authenticateJwtAdmin (logueado como admin).
 */
app.patch('/api/productos/:id/disable', authenticateJwtAdmin, async (req, res) => {
  const { id } = req.params;
  if (!isValidIdFlexible(id)) return respondError(res, 400, 'ID inválido');

  try {
    const actor = req.user && req.user.id ? req.user.id : null;
    const actor_username = req.user && req.user.username ? req.user.username : null;

    // Obtener estado previo
    const { data: prevData } = await supabaseAdmin.from('productos').select('*').or(`id.eq.${id},product_id.eq.${id}`).limit(1);
    const previousRow = Array.isArray(prevData) && prevData.length ? prevData[0] : null;

    const { data, error } = await supabaseAdmin
      .from('productos')
      .update({ deleted_at: new Date().toISOString() })
      .or(`id.eq.${id},product_id.eq.${id}`)
      .select();

    if (error) {
      console.error('API error updating producto disable:', error);
      return respondError(res, 500, 'No se pudo inhabilitar el producto', error.message || String(error));
    }

    const updatedRow = Array.isArray(data) && data.length ? data[0] : data;

    // Registrar acción en auditoría
    try {
      await insertAuditLog({
        actor_id: actor,
        actor_username,
        action: 'producto_disable',
        target_table: 'productos',
        target_id: id,
        reason: req.body?.reason || null,
        metadata: { before: previousRow, after: updatedRow },
        ip: req.ip
      });
    } catch (e) {
      console.warn('Audit log failed for producto_disable:', e);
    }

    console.log(`Producto ${id} inhabilitado por ${actor_username}`);
    return res.status(200).json({ success: true, data: Array.isArray(data) ? data : [data] });
  } catch (err) {
    console.error('API exception PATCH disable producto:', err);
    return respondError(res, 500, 'Error interno', String(err));
  }
});

/**
 * PATCH /api/productos/:id/enable
 * Requiere authenticateJwtAdmin (logueado como admin).
 */
app.patch('/api/productos/:id/enable', authenticateJwtAdmin, async (req, res) => {
  const { id } = req.params;
  if (!isValidIdFlexible(id)) return respondError(res, 400, 'ID inválido');

  try {
    const actor = req.user && req.user.id ? req.user.id : null;
    const actor_username = req.user && req.user.username ? req.user.username : null;

    // Obtener estado previo
    const { data: prevData } = await supabaseAdmin.from('productos').select('*').or(`id.eq.${id},product_id.eq.${id}`).limit(1);
    const previousRow = Array.isArray(prevData) && prevData.length ? prevData[0] : null;

    const { data, error } = await supabaseAdmin
      .from('productos')
      .update({ deleted_at: null })
      .or(`id.eq.${id},product_id.eq.${id}`)
      .select();

    if (error) {
      console.error('API error updating producto enable:', error);
      return respondError(res, 500, 'No se pudo habilitar el producto', error.message || String(error));
    }

    const updatedRow = Array.isArray(data) && data.length ? data[0] : data;

    // Registrar acción en auditoría
    try {
      await insertAuditLog({
        actor_id: actor,
        actor_username,
        action: 'producto_enable',
        target_table: 'productos',
        target_id: id,
        reason: req.body?.reason || null,
        metadata: { before: previousRow, after: updatedRow },
        ip: req.ip
      });
    } catch (e) {
      console.warn('Audit log failed for producto_enable:', e);
    }

    console.log(`Producto ${id} habilitado por ${actor_username}`);
    return res.status(200).json({ success: true, data: Array.isArray(data) ? data : [data] });
  } catch (err) {
    console.error('API exception PATCH enable producto:', err);
    return respondError(res, 500, 'Error interno', String(err));
  }
});

/**
 * PATCH /api/usuarios/:id/disable
 * Requiere authenticateJwtAdmin (valida token y rol administrador).
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

    if (!data || data.length === 0) {
      return respondError(res, 404, 'Usuario no encontrado');
    }

    const updatedRow = Array.isArray(data) && data.length ? data[0] : data;

    try {
      await insertAuditLog({
        actor_id: actor,
        actor_username,
        action: 'usuario_disable',
        target_table: 'usuarios',
        target_id: id,
        reason: req.body?.reason || null,
        metadata: { before: previousRow, after: updatedRow },
        ip: req.ip
      });
    } catch (e) {
      console.warn('Audit log failed for usuario_disable:', e);
    }

    console.log(`Usuario ${id} inhabilitado por actor ${actor}`);
    return res.status(200).json({ success: true, data: updatedRow });
  } catch (err) {
    console.error('API exception PATCH disable usuario:', err);
    return respondError(res, 500, 'Error interno', String(err));
  }
});

/**
 * PATCH /api/usuarios/:id/enable
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

    if (!data || data.length === 0) {
      return respondError(res, 404, 'Usuario no encontrado');
    }

    const updatedRow = Array.isArray(data) && data.length ? data[0] : data;

    try {
      await insertAuditLog({
        actor_id: actor,
        actor_username,
        action: 'usuario_enable',
        target_table: 'usuarios',
        target_id: id,
        reason: req.body?.reason || null,
        metadata: { before: previousRow, after: updatedRow },
        ip: req.ip
      });
    } catch (e) {
      console.warn('Audit log failed for usuario_enable:', e);
    }

    console.log(`Usuario ${id} habilitado por actor ${actor}`);
    return res.status(200).json({ success: true, data: updatedRow });
  } catch (err) {
    console.error('API exception PATCH enable usuario:', err);
    return respondError(res, 500, 'Error interno', String(err));
  }
});

/**
 * DELETE /api/usuarios/:id
 * Implementación de soft delete para compatibilidad con clientes que usan DELETE.
 * Requiere authenticateJwtAdmin.
 */
app.delete('/api/usuarios/:id', authenticateJwtAdmin, async (req, res) => {
  const { id } = req.params;
  if (!isUuid(id)) return respondError(res, 400, 'ID inválido');

  try {
    const actor = req.user && req.user.id ? req.user.id : null;
    const actor_username = req.user && req.user.username ? req.user.username : null;

    const { data: prevData } = await supabaseAdmin.from('usuarios').select('*').eq('id', id).limit(1);
    const previousRow = Array.isArray(prevData) && prevData.length ? prevData[0] : null;

    // Solo marcar deleted_at si aún es NULL
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
      if (!exists || exists.length === 0) {
        return respondError(res, 404, 'Usuario no encontrado');
      }
      return res.status(200).json({ success: true, message: 'Usuario ya inhabilitado' });
    }

    const updatedRow = Array.isArray(data) && data.length ? data[0] : data;

    try {
      await insertAuditLog({
        actor_id: actor,
        actor_username,
        action: 'usuario_disable',
        target_table: 'usuarios',
        target_id: id,
        reason: req.body?.reason || null,
        metadata: { before: previousRow, after: updatedRow },
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
 * Ruta protegida para usuarios autenticados
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

    if (!data || data.length === 0) {
      return respondError(res, 404, 'Usuario no encontrado');
    }

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
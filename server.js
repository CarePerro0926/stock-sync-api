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
    console.warn('insertAudit log exception:', err);
    return false;
  }
};

// --- RUTAS ---

/**
 * POST /api/registro
 * Registra un nuevo usuario.
 * Valida el correo según el rol.
 */
app.post('/api/registro', async (req, res) => {
  try {
    const body = req.body || {};
    const { nombres, apellidos, cedula, fecha, telefono, email, user: username, pass: password, role } = body;

    if (!nombres || !apellidos || !cedula || !fecha || !telefono || !email || !username || !password || !role) {
      return respondError(res, 400, 'Faltan campos obligatorios');
    }

    if (!['cliente', 'administrador'].includes(role)) {
      return respondError(res, 400, 'Rol inválido. Debe ser "cliente" o "administrador".');
    }

    const isAdminRole = role === 'administrador';
    const isClientRole = role === 'cliente';
    const isStockSyncEmail = email.endsWith('@stocksync.com');
    const isNotStockSyncEmail = !isStockSyncEmail;

    if (isAdminRole && isNotStockSyncEmail) {
      return respondError(res, 400, 'Los administradores deben usar correos @stocksync.com');
    }
    if (isClientRole && isStockSyncEmail) {
      return respondError(res, 400, 'Los clientes no pueden usar correos @stocksync.com');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const userData = {
      nombres,
      apellidos,
      cedula,
      fecha_nacimiento: fecha,
      telefono,
      email,
      username,
      pass: hashedPassword,
      role,
    };

    const { data, error } = await supabaseAdmin
      .from('usuarios')
      .insert([userData])
      .select('id, email, username, nombres, apellidos, role')
      .single();

    if (error) {
      console.error('Error al registrar usuario en Supabase:', error);
      if (error.code === '23505') {
        return respondError(res, 400, 'El correo o nombre de usuario ya están registrados');
      }
      return respondError(res, 500, 'Error al registrar usuario', error.message || String(error));
    }

    return res.status(201).json({
      success: true,
      message: 'Usuario registrado con éxito',
      data: {
        id: data.id,
        email: data.email,
        username: data.username
      }
    });

  } catch (err) {
    console.error('Error interno en POST /api/registro:', err);
    return respondError(res, 500, 'Error interno en el servidor', String(err));
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
 */
app.get('/api/productos', async (req, res) => {
  try {
    const { data: cats } = await supabaseAdmin.from('categorias').select('id, nombre');
    const catMap = {};
    (cats || []).forEach(c => { catMap[c.id] = c.nombre; });

    const { data, error } = await supabaseAdmin
      .from('productos')
      .select(`
        id,
        nombre,
        precio,
        cantidad,
        categoria_id,
        deleted_at
      `)
      .is('deleted_at', null)
      .order('nombre', { ascending: true });

    if (error) {
      return res.status(500).json({ success: false, message: 'Error al obtener productos', error: error.message });
    }

    const normalized = (data || []).map(p => ({
      id: p.id,
      nombre: p.nombre || 'Sin nombre',
      categoria_nombre: catMap[p.categoria_id] || 'Sin Categoría',
      cantidad: p.cantidad ?? 0,
      precio: p.precio ?? null,
      deleted_at: p.deleted_at || null,
    }));

    res.setHeader('Cache-Control', 'no-store');
    return res.json(normalized);
  } catch (err) {
    console.error('GET /api/productos error:', err);
    return res.status(500).json({ success: false, message: 'Error interno', error: String(err) });
  }
});

/**
 * GET /api/proveedores
 */
app.get('/api/proveedores', async (req, res) => {
  try {
    const includeInactivos = String(req.query.include_inactivos || '').toLowerCase() === 'true';

    let query = supabaseAdmin
      .from('proveedores')
      .select('id, nombre, telefono, email, deleted_at')
      .order('id', { ascending: true });

    if (!includeInactivos) {
      query = query.is('deleted_at', null);
    }

    const { data, error } = await query;

    if (error) {
      console.error('GET /api/proveedores - supabase error:', error.message || error);
      return res.status(500).json({ success: false, message: 'Error al obtener proveedores', error: error.message });
    }

    return res.status(200).json(data || []);
  } catch (err) {
    console.error('API exception GET /api/proveedores:', err);
    return res.status(500).json({ success: false, message: 'Error interno', error: String(err) });
  }
});

/**
 * GET /api/usuarios
 */
app.get('/api/usuarios', async (req, res) => {
  try {
    const includeInactivos = String(req.query.include_inactivos || 'true').toLowerCase() === 'true';

    let query = supabaseAdmin.from('usuarios').select('*').order('id', { ascending: true });
    if (!includeInactivos) {
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

// --- RUTAS DE CATEGORÍAS ---

/**
 * GET /api/categorias
 */
app.get('/api/categorias', async (req, res) => {
  try {
    const includeInactivos = String(req.query.include_inactivos || '').toLowerCase() === 'true';

    let query = supabaseAdmin
      .from('categorias')
      .select('id,nombre,deleted_at')
      .order('nombre', { ascending: true });

    if (!includeInactivos) {
      query = query.is('deleted_at', null);
    }

    const { data, error } = await query;

    if (error) {
      console.error('GET /api/categorias - supabase error:', error.message || error);
      return res.status(500).json({ success: false, message: 'Error al obtener categorías', error: error.message });
    }

    try {
      await insertAuditLog({
        actor_id: req.user?.id,
        actor_username: req.user?.username,
        action: 'categorias_list',
        target_table: 'categorias',
        ip: req.ip
      });
    } catch (e) {
      console.warn('Audit log failed for categorias_list:', e);
    }

    return res.status(200).json(data || []);
  } catch (err) {
    console.error('API exception GET /api/categorias:', err);
    return respondError(res, 500, 'Error interno', String(err));
  }
});

/**
 * GET /api/categorias/nombre/:nombre
 */
app.get('/api/categorias/nombre/:nombre', authenticateJwt, async (req, res) => {
  try {
    const { nombre } = req.params;
    if (!nombre || typeof nombre !== 'string' || nombre.trim() === '') {
      return respondError(res, 400, 'Nombre de categoría inválido');
    }

    const nombreDecodificado = decodeURIComponent(nombre).trim();

    const { data, error } = await supabaseAdmin
      .from('categorias')
      .select('*')
      .ilike('nombre', nombreDecodificado)
      .limit(1);

    if (error) {
      console.error('GET /api/categorias/nombre/:nombre - supabase error:', error);
      return respondError(res, 500, 'Error al consultar categoría', error.message || String(error));
    }

    if (!data || data.length === 0) {
      return respondError(res, 404, 'Categoría no encontrada');
    }

    const categoria = data[0];

    try {
      await insertAuditLog({
        actor_id: req.user.id,
        actor_username: req.user.username,
        action: 'categoria_read',
        target_table: 'categorias',
        target_id: categoria.id,
        ip: req.ip
      });
    } catch (e) {
      console.warn('Audit log failed for categoria_read:', e);
    }

    return res.status(200).json(categoria);
  } catch (err) {
    console.error('API exception GET /api/categorias/nombre/:nombre:', err);
    return respondError(res, 500, 'Error interno', String(err));
  }
});

/**
 * POST /api/categorias
 */
app.post('/api/categorias', authenticateJwtAdmin, async (req, res) => {
  try {
    const actor = req.user && req.user.id ? req.user.id : null;
    const actor_username = req.user && req.user.username ? req.user.username : null;

    const payload = req.body || {};

    const { data, error } = await supabaseAdmin
      .from('categorias')
      .insert([payload])
      .select()
      .single();

    if (error) {
      console.error('POST /api/categorias - supabase error:', error);
      return respondError(res, 500, 'No se pudo crear la categoría', error.message || String(error));
    }

    try {
      await insertAuditLog({
        actor_id: actor,
        actor_username,
        action: 'categoria_create',
        target_table: 'categorias',
        target_id: data.id,
        metadata: { new_data: data },
        ip: req.ip
      });
    } catch (e) {
      console.warn('Audit log failed for categoria_create:', e);
    }

    console.log(`Categoría '${data.nombre}' creada por ${actor_username} con ID: ${data.id}`);
    return res.status(201).json({ success: true, data });
  } catch (err) {
    console.error('API exception POST /api/categorias:', err);
    return respondError(res, 500, 'Error interno', String(err));
  }
});

/**
 * PUT /api/categorias/nombre/:nombre
 */
app.put('/api/categorias/nombre/:nombre', authenticateJwtAdmin, async (req, res) => {
  try {
    const { nombre: nombreOriginal } = req.params;
    if (!nombreOriginal || typeof nombreOriginal !== 'string' || nombreOriginal.trim() === '') {
      return respondError(res, 400, 'Nombre de categoría original inválido');
    }

    const actor = req.user && req.user.id ? req.user.id : null;
    const actor_username = req.user && req.user.username ? req.user.username : null;

    const nombreOriginalDecodificado = decodeURIComponent(nombreOriginal).trim();

    const { data: prevData, error: prevError } = await supabaseAdmin
      .from('categorias')
      .select('*')
      .ilike('nombre', nombreOriginalDecodificado)
      .limit(1);

    if (prevError) {
      console.error('PUT /api/categorias/nombre/:nombre - supabase error fetching previous state:', prevError);
      return respondError(res, 500, 'Error al consultar categoría previa', prevError.message || String(prevError));
    }

    if (!prevData || prevData.length === 0) {
      return respondError(res, 404, 'Categoría no encontrada');
    }

    const previousRow = prevData[0];
    const payload = req.body || {};

    const { data, error } = await supabaseAdmin
      .from('categorias')
      .update(payload)
      .ilike('nombre', nombreOriginalDecodificado)
      .select()
      .single();

    if (error) {
      console.error('PUT /api/categorias/nombre/:nombre - supabase error updating:', error);
      return respondError(res, 500, 'No se pudo actualizar la categoría', error.message || String(error));
    }

    try {
      await insertAuditLog({
        actor_id: actor,
        actor_username,
        action: 'categoria_update',
        target_table: 'categorias',
        target_id: data.id,
        metadata: { before: previousRow, after: data },
        ip: req.ip
      });
    } catch (e) {
      console.warn('Audit log failed for categoria_update:', e);
    }

    console.log(`Categoría '${nombreOriginalDecodificado}' actualizada por ${actor_username}`);
    return res.status(200).json({ success: true, data });
  } catch (err) {
    console.error('API exception PUT /api/categorias/nombre/:nombre:', err);
    return respondError(res, 500, 'Error interno', String(err));
  }
});

/**
 * PATCH /api/categorias/nombre/:nombre/disable
 */
app.patch('/api/categorias/nombre/:nombre/disable', authenticateJwtAdmin, async (req, res) => {
  const { nombre } = req.params;
  if (!nombre || typeof nombre !== 'string' || nombre.trim() === '') {
    return respondError(res, 400, 'Nombre de categoría inválido');
  }

  try {
    const actor = req.user && req.user.id ? req.user.id : null;
    const actor_username = req.user && req.user.username ? req.user.username : null;

    const nombreDecodificado = decodeURIComponent(nombre).trim();

    const { data: prevData } = await supabaseAdmin
      .from('categorias')
      .select('*')
      .ilike('nombre', nombreDecodificado)
      .limit(1);
    const previousRow = Array.isArray(prevData) && prevData.length ? prevData[0] : null;

    if (!previousRow) {
      return respondError(res, 404, 'Categoría no encontrada');
    }

    const { data, error } = await supabaseAdmin
      .from('categorias')
      .update({ deleted_at: new Date().toISOString() })
      .ilike('nombre', nombreDecodificado)
      .select();

    if (error) {
      console.error('API error updating categoria disable:', error);
      return respondError(res, 500, 'No se pudo inhabilitar la categoría', error.message || String(error));
    }

    const updatedRow = Array.isArray(data) && data.length ? data[0] : data;

    try {
      await insertAuditLog({
        actor_id: actor,
        actor_username,
        action: 'categoria_disable',
        target_table: 'categorias',
        target_id: updatedRow.id,
        reason: req.body?.reason || null,
        metadata: { before: previousRow, after: updatedRow },
        ip: req.ip
      });
    } catch (e) {
      console.warn('Audit log failed for categoria_disable:', e);
    }

    console.log(`Categoría '${nombreDecodificado}' inhabilitada por ${actor_username}`);
    return res.status(200).json({ success: true, data: updatedRow });
  } catch (err) {
    console.error('API exception PATCH disable categoria:', err);
    return respondError(res, 500, 'Error interno', String(err));
  }
});

/**
 * PATCH /api/categorias/nombre/:nombre/enable
 */
app.patch('/api/categorias/nombre/:nombre/enable', authenticateJwtAdmin, async (req, res) => {
  const { nombre } = req.params;
  if (!nombre || typeof nombre !== 'string' || nombre.trim() === '') {
    return respondError(res, 400, 'Nombre de categoría inválido');
  }

  try {
    const actor = req.user && req.user.id ? req.user.id : null;
    const actor_username = req.user && req.user.username ? req.user.username : null;

    const nombreDecodificado = decodeURIComponent(nombre).trim();

    const { data: prevData } = await supabaseAdmin
      .from('categorias')
      .select('*')
      .ilike('nombre', nombreDecodificado)
      .limit(1);
    const previousRow = Array.isArray(prevData) && prevData.length ? prevData[0] : null;

    if (!previousRow) {
      return respondError(res, 404, 'Categoría no encontrada');
    }

    const { data, error } = await supabaseAdmin
      .from('categorias')
      .update({ deleted_at: null })
      .ilike('nombre', nombreDecodificado)
      .select();

    if (error) {
      console.error('API error updating categoria enable:', error);
      return respondError(res, 500, 'No se pudo habilitar la categoría', error.message || String(error));
    }

    const updatedRow = Array.isArray(data) && data.length ? data[0] : data;

    try {
      await insertAuditLog({
        actor_id: actor,
        actor_username,
        action: 'categoria_enable',
        target_table: 'categorias',
        target_id: updatedRow.id,
        reason: req.body?.reason || null,
        metadata: { before: previousRow, after: updatedRow },
        ip: req.ip
      });
    } catch (e) {
      console.warn('Audit log failed for categoria_enable:', e);
    }

    console.log(`Categoría '${nombreDecodificado}' habilitada por ${actor_username}`);
    return res.status(200).json({ success: true, data: updatedRow });
  } catch (err) {
    console.error('API exception PATCH enable categoria:', err);
    return respondError(res, 500, 'Error interno', String(err));
  }
});

// --- FIN RUTAS DE CATEGORÍAS ---

/**
 * POST /api/productos
 */
app.post('/api/productos', authenticateJwtAdmin, async (req, res) => {
  try {
    const actor = req.user && req.user.id ? req.user.id : null;
    const actor_username = req.user && req.user.username ? req.user.username : null;

    const payload = req.body || {};

    const { data, error } = await supabaseAdmin
      .from('productos')
      .insert([payload])
      .select()
      .single();

    if (error) {
      console.error('POST /api/productos - supabase error:', error);
      return respondError(res, 500, 'No se pudo crear el producto', error.message || String(error));
    }

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
 */
app.get('/api/productos/:id', authenticateJwt, async (req, res) => {
  try {
    const { id } = req.params;
    if (!isValidIdFlexible(id)) return respondError(res, 400, 'ID inválido');

    const { data, error } = await supabaseAdmin
      .from('productos')
      .select('*')
      .eq('id', Number(id))
      .limit(1);

    if (error) {
      console.error('GET /api/productos/:id - supabase error:', error);
      return respondError(res, 500, 'Error al consultar producto', error.message || String(error));
    }

    if (!data || data.length === 0) {
      return respondError(res, 404, 'Producto no encontrado');
    }

    const producto = data[0];

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
 */
app.put('/api/productos/:id', authenticateJwtAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    if (!isValidIdFlexible(id)) return respondError(res, 400, 'ID inválido');

    const actor = req.user && req.user.id ? req.user.id : null;
    const actor_username = req.user && req.user.username ? req.user.username : null;

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
      .eq('id', Number(id))
      .select()
      .single();

    if (error) {
      console.error('PUT /api/productos/:id - supabase error updating:', error);
      return respondError(res, 500, 'No se pudo actualizar el producto', error.message || String(error));
    }

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
 */
app.patch('/api/productos/:id/disable', authenticateJwtAdmin, async (req, res) => {
  const { id } = req.params;
  if (!isValidIdFlexible(id)) return respondError(res, 400, 'ID inválido');

  try {
    const actor = req.user && req.user.id ? req.user.id : null;
    const actor_username = req.user && req.user.username ? req.user.username : null;

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
 */
app.patch('/api/productos/:id/enable', authenticateJwtAdmin, async (req, res) => {
  const { id } = req.params;
  if (!isValidIdFlexible(id)) return respondError(res, 400, 'ID inválido');

  try {
    const actor = req.user && req.user.id ? req.user.id : null;
    const actor_username = req.user && req.user.username ? req.user.username : null;

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
 * RUTAS DE MOVIMIENTOS DE INVENTARIO
 */

app.post('/api/movimientos', authenticateJwtAdmin, async (req, res) => {
  try {
    const { product_id, type, quantity, reason } = req.body || {};

    if (!product_id || !type || (typeof quantity === 'undefined' || quantity === null)) {
      return respondError(res, 400, 'Faltan campos obligatorios: product_id, type, quantity');
    }

    const t = String(type).toUpperCase();
    if (!['IN', 'OUT'].includes(t)) {
      return respondError(res, 400, 'Tipo inválido. Debe ser "IN" o "OUT"');
    }

    const payload = {
      product_id,
      type: t,
      quantity: Number(quantity),
      reason: reason || null
    };

    const { data, error } = await supabaseAdmin
      .from('inventory_movements')
      .insert([payload])
      .select()
      .single();

    if (error) {
      console.error('POST /api/movimientos - supabase error:', error);
      return respondError(res, 500, 'No se pudo registrar el movimiento', error.message || String(error));
    }

    try {
      if (typeof insertAuditLog === 'function') {
        await insertAuditLog({
          actor_id: req.user?.id || null,
          actor_username: req.user?.username || null,
          action: 'inventory_movement_create',
          target_table: 'inventory_movements',
          target_id: data.id,
          reason: reason || null,
          metadata: { payload },
          ip: req.ip
        });
      }
    } catch (e) {
      console.warn('Audit log failed for inventory_movement_create:', e);
    }

    return res.status(201).json({ success: true, data });
  } catch (err) {
    console.error('API exception POST /api/movimientos:', err);
    return respondError(res, 500, 'Error interno', String(err));
  }
});

app.get('/api/movimientos', authenticateJwtAdmin, async (req, res) => {
  try {
    const { product_id, type, limit, offset } = req.query || {};

    let query = supabaseAdmin
      .from('inventory_movements')
      .select('id, product_id, type, quantity, reason, created_at')
      .order('created_at', { ascending: false });

    if (product_id) query = query.eq('product_id', product_id);
    if (type) query = query.eq('type', String(type).toUpperCase());
    if (limit) query = query.limit(Number(limit));
    if (offset) query = query.range(Number(offset), Number(offset) + (Number(limit || 100) - 1));

    const { data, error } = await query;

    if (error) {
      console.error('GET /api/movimientos - supabase error:', error);
      return respondError(res, 500, 'Error al obtener movimientos', error.message || String(error));
    }

    return res.status(200).json(data || []);
  } catch (err) {
    console.error('API exception GET /api/movimientos:', err);
    return respondError(res, 500, 'Error interno', String(err));
  }
});

app.get('/api/movimientos/:id', authenticateJwtAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    if (!id) return respondError(res, 400, 'ID requerido');

    const { data, error } = await supabaseAdmin
      .from('inventory_movements')
      .select('id, product_id, type, quantity, reason, created_at')
      .eq('id', id)
      .limit(1);

    if (error) {
      console.error('GET /api/movimientos/:id - supabase error:', error);
      return respondError(res, 500, 'Error al obtener movimiento', error.message || String(error));
    }

    if (!data || data.length === 0) {
      return respondError(res, 404, 'Movimiento no encontrado');
    }

    return res.status(200).json(data[0]);
  } catch (err) {
    console.error('API exception GET /api/movimientos/:id:', err);
    return respondError(res, 500, 'Error interno', String(err));
  }
});

// ============================================================================
// RUTAS DE VENTAS (SALES) - NUEVO MÓDULO
// ============================================================================

/**
 * POST /api/sales
 * Registra una nueva venta.
 * Requiere authenticateJwt (usuario logueado). Admin puede vender por otros.
 */
app.post('/api/sales', authenticateJwt, async (req, res) => {
  try {
    const actor = req.user;
    const { product_id, user_id, quantity, total, origin_id, sold_at } = req.body || {};

    // Validaciones básicas
    if (!product_id || !quantity || total === undefined) {
      return respondError(res, 400, 'Faltan campos obligatorios: product_id, quantity, total');
    }
    if (typeof quantity !== 'number' || quantity <= 0) {
      return respondError(res, 400, 'quantity debe ser un número positivo');
    }
    if (typeof total !== 'number' || total < 0) {
      return respondError(res, 400, 'total debe ser un número no negativo');
    }

    // Verificar que el producto existe y está activo
    const { data: producto, error: prodErr } = await supabaseAdmin
      .from('productos')
      .select('id, nombre, cantidad, deleted_at')
      .eq('id', product_id)
      .is('deleted_at', null)
      .limit(1)
      .single();

    if (prodErr || !producto) {
      return respondError(res, 404, 'Producto no encontrado o inhabilitado');
    }

    // Preparar registro de venta
    const saleData = {
      product_id,
      user_id: user_id || (actor.role === 'cliente' ? actor.id : null),
      quantity: Number(quantity),
      total: Number(total),
      sold_at: sold_at || new Date().toISOString(),
      origin_id: origin_id || null
    };

    const { data, error } = await supabaseAdmin
      .from('sales')
      .insert([saleData])
      .select()
      .single();

    if (error) {
      console.error('POST /api/sales - supabase error:', error);
      return respondError(res, 500, 'No se pudo registrar la venta', error.message || String(error));
    }

    // Auditoría
    try {
      await insertAuditLog({
        actor_id: actor.id,
        actor_username: actor.username,
        action: 'sale_create',
        target_table: 'sales',
        target_id: data.id,
        metadata: { sale: data },
        ip: req.ip
      });
    } catch (e) {
      console.warn('Audit log failed for sale_create:', e);
    }

    console.log(`Venta registrada por ${actor.username} con ID: ${data.id}`);
    return res.status(201).json({ success: true, data });

  } catch (err) {
    console.error('API exception POST /api/sales:', err);
    return respondError(res, 500, 'Error interno', String(err));
  }
});

/**
 * GET /api/sales
 * Lista ventas con filtros opcionales.
 * Requiere authenticateJwtAdmin para ver todas; clientes solo ven las suyas.
 */
app.get('/api/sales', authenticateJwt, async (req, res) => {
  try {
    const { product_id, user_id, limit, offset, include_deleted } = req.query || {};
    const actor = req.user;

    let query = supabaseAdmin
      .from('sales')
      .select(`
        *,
        producto:product_id (id, nombre, precio),
        usuario:user_id (id, email, username)
      `)
      .order('sold_at', { ascending: false });

    // Filtros
    if (product_id) query = query.eq('product_id', product_id);
    
    // Clientes solo pueden ver sus propias ventas (a menos que sea admin)
    if (actor.role !== 'administrador') {
      query = query.eq('user_id', actor.id);
    } else if (user_id) {
      query = query.eq('user_id', user_id);
    }

    // Soft delete: por defecto ocultar eliminados
    if (String(include_deleted).toLowerCase() !== 'true') {
      query = query.is('deleted_at', null);
    }

    // Paginación
    if (limit) {
      const lim = Math.min(Number(limit), 100);
      const off = Number(offset) || 0;
      query = query.range(off, off + lim - 1);
    }

    const { data, error } = await query;

    if (error) {
      console.error('GET /api/sales - supabase error:', error);
      return respondError(res, 500, 'Error al obtener ventas', error.message || String(error));
    }

    return res.status(200).json(data || []);

  } catch (err) {
    console.error('API exception GET /api/sales:', err);
    return respondError(res, 500, 'Error interno', String(err));
  }
});

/**
 * GET /api/sales/:id
 * Obtiene detalle de una venta por ID.
 * Requiere authenticateJwt. Admin ve todas; cliente solo las suyas.
 */
app.get('/api/sales/:id', authenticateJwt, async (req, res) => {
  try {
    const { id } = req.params;
    if (!isUuid(id)) return respondError(res, 400, 'ID de venta inválido');

    const actor = req.user;

    let query = supabaseAdmin
      .from('sales')
      .select(`
        *,
        producto:product_id (id, nombre, precio, cantidad),
        usuario:user_id (id, email, username, role)
      `)
      .eq('id', id)
      .limit(1);

    // Clientes no pueden ver ventas de otros
    if (actor.role !== 'administrador') {
      query = query.eq('user_id', actor.id);
    }

    const { data, error } = await query;

    if (error) {
      console.error('GET /api/sales/:id - supabase error:', error);
      return respondError(res, 500, 'Error al consultar venta', error.message || String(error));
    }

    if (!data || data.length === 0) {
      return respondError(res, 404, 'Venta no encontrada o sin permisos');
    }

    // Auditoría de lectura (opcional)
    try {
      await insertAuditLog({
        actor_id: actor.id,
        actor_username: actor.username,
        action: 'sale_read',
        target_table: 'sales',
        target_id: id,
        ip: req.ip
      });
    } catch (e) {
      console.warn('Audit log failed for sale_read:', e);
    }

    return res.status(200).json(data[0]);

  } catch (err) {
    console.error('API exception GET /api/sales/:id:', err);
    return respondError(res, 500, 'Error interno', String(err));
  }
});

/**
 * PATCH /api/sales/:id/disable
 * Inhabilita una venta (soft delete). Solo admin.
 */
app.patch('/api/sales/:id/disable', authenticateJwtAdmin, async (req, res) => {
  const { id } = req.params;
  if (!isUuid(id)) return respondError(res, 400, 'ID de venta inválido');

  try {
    const actor = req.user;

    const { data: prevData } = await supabaseAdmin
      .from('sales')
      .select('*')
      .eq('id', id)
      .limit(1);
    
    const previousRow = Array.isArray(prevData) && prevData.length ? prevData[0] : null;
    if (!previousRow) {
      return respondError(res, 404, 'Venta no encontrada');
    }

    const { data, error } = await supabaseAdmin
      .from('sales')
      .update({ deleted_at: new Date().toISOString() })
      .eq('id', id)
      .select();

    if (error) {
      console.error('PATCH /api/sales/:id/disable - supabase error:', error);
      return respondError(res, 500, 'No se pudo inhabilitar la venta', error.message || String(error));
    }

    const updatedRow = Array.isArray(data) && data.length ? data[0] : data;

    try {
      await insertAuditLog({
        actor_id: actor.id,
        actor_username: actor.username,
        action: 'sale_disable',
        target_table: 'sales',
        target_id: id,
        reason: req.body?.reason || null,
        metadata: { before: previousRow, after: updatedRow },
        ip: req.ip
      });
    } catch (e) {
      console.warn('Audit log failed for sale_disable:', e);
    }

    console.log(`Venta ${id} inhabilitada por ${actor.username}`);
    return res.status(200).json({ success: true, data: updatedRow });

  } catch (err) {
    console.error('API exception PATCH disable sale:', err);
    return respondError(res, 500, 'Error interno', String(err));
  }
});

/**
 * PATCH /api/sales/:id/enable
 * Rehabilita una venta previamente inhabilitada. Solo admin.
 */
app.patch('/api/sales/:id/enable', authenticateJwtAdmin, async (req, res) => {
  const { id } = req.params;
  if (!isUuid(id)) return respondError(res, 400, 'ID de venta inválido');

  try {
    const actor = req.user;

    const { data: prevData } = await supabaseAdmin
      .from('sales')
      .select('*')
      .eq('id', id)
      .limit(1);
    
    const previousRow = Array.isArray(prevData) && prevData.length ? prevData[0] : null;
    if (!previousRow) {
      return respondError(res, 404, 'Venta no encontrada');
    }

    const { data, error } = await supabaseAdmin
      .from('sales')
      .update({ deleted_at: null })
      .eq('id', id)
      .select();

    if (error) {
      console.error('PATCH /api/sales/:id/enable - supabase error:', error);
      return respondError(res, 500, 'No se pudo habilitar la venta', error.message || String(error));
    }

    const updatedRow = Array.isArray(data) && data.length ? data[0] : data;

    try {
      await insertAuditLog({
        actor_id: actor.id,
        actor_username: actor.username,
        action: 'sale_enable',
        target_table: 'sales',
        target_id: id,
        reason: req.body?.reason || null,
        metadata: { before: previousRow, after: updatedRow },
        ip: req.ip
      });
    } catch (e) {
      console.warn('Audit log failed for sale_enable:', e);
    }

    console.log(`Venta ${id} habilitada por ${actor.username}`);
    return res.status(200).json({ success: true, data: updatedRow });

  } catch (err) {
    console.error('API exception PATCH enable sale:', err);
    return respondError(res, 500, 'Error interno', String(err));
  }
});

// ============================================================================
// FIN RUTAS DE VENTAS
// ============================================================================

/**
 * GET /api/usuarios/:id
 * Consulta un usuario por ID (activo o inactivo).
 * Requiere authenticateJwt (logueado).
 */
app.get('/api/usuarios/:id', authenticateJwt, async (req, res) => {
  try {
    const { id } = req.params;
    if (!isUuid(id)) return respondError(res, 400, 'ID inválido');

    const { data, error } = await supabaseAdmin
      .from('usuarios')
      .select('*')
      .eq('id', id)
      .limit(1);

    if (error) {
      console.error('GET /api/usuarios/:id - supabase error:', error);
      return respondError(res, 500, 'Error al consultar usuario', error.message || String(error));
    }

    if (!data || data.length === 0) {
      return respondError(res, 404, 'Usuario no encontrado');
    }

    const usuario = data[0];

    try {
      await insertAuditLog({
        actor_id: req.user.id,
        actor_username: req.user.username,
        action: 'usuario_read',
        target_table: 'usuarios',
        target_id: usuario.id,
        ip: req.ip
      });
    } catch (e) {
      console.warn('Audit log failed for usuario_read:', e);
    }

    return res.status(200).json(usuario);
  } catch (err) {
    console.error('API exception GET /api/usuarios/:id:', err);
    return respondError(res, 500, 'Error interno', String(err));
  }
});

/**
 * PUT /api/usuarios/:id
 */
app.put('/api/usuarios/:id', authenticateJwtAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    if (!isUuid(id)) return respondError(res, 400, 'ID inválido');

    const actor = req.user && req.user.id ? req.user.id : null;
    const actor_username = req.user && req.user.username ? req.user.username : null;

    const { data: prevData, error: prevError } = await supabaseAdmin
      .from('usuarios')
      .select('*')
      .eq('id', id)
      .limit(1);

    if (prevError) {
      console.error('PUT /api/usuarios/:id - supabase error fetching previous state:', prevError);
      return respondError(res, 500, 'Error al consultar usuario previo', prevError.message || String(prevError));
    }

    if (!prevData || prevData.length === 0) {
      return respondError(res, 404, 'Usuario no encontrado');
    }

    const previousRow = prevData[0];
    const payload = req.body || {};

    const { data, error } = await supabaseAdmin
      .from('usuarios')
      .update(payload)
      .eq('id', id)
      .select()
      .single();

    if (error) {
      console.error('PUT /api/usuarios/:id - supabase error updating:', error);
      return respondError(res, 500, 'No se pudo actualizar el usuario', error.message || String(error));
    }

    try {
      await insertAuditLog({
        actor_id: actor,
        actor_username,
        action: 'usuario_update',
        target_table: 'usuarios',
        target_id: id,
        metadata: { before: previousRow, after: data },
        ip: req.ip
      });
    } catch (e) {
      console.warn('Audit log failed for usuario_update:', e);
    }

    console.log(`Usuario ${id} actualizado por ${actor_username}`);
    return res.status(200).json({ success: true, data });
  } catch (err) {
    console.error('API exception PUT /api/usuarios/:id:', err);
    return respondError(res, 500, 'Error interno', String(err));
  }
});

/**
 * DELETE /api/usuarios/:id
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
 * PATCH /api/usuarios/:id/disable
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
      console.warn('Audit log failed for usuario_disable (PATCH):', e);
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
 * GET /api/mis-datos
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
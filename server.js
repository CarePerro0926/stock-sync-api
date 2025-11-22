// api/server.js
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { createClient } from '@supabase/supabase-js';

const app = express();
app.use(express.json());
app.use(helmet());

// CORS: permitir header personalizado x-admin-token y credenciales si se usan
app.use(
  cors({
    origin: process.env.FRONTEND_ORIGIN || '*',
    allowedHeaders: ['Content-Type', 'x-admin-token', 'authorization'],
    exposedHeaders: ['Content-Type', 'x-admin-token'],
    credentials: true,
    methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE', 'OPTIONS'],
  })
);

// Manejo seguro de preflight OPTIONS
app.use((req, res, next) => {
  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }
  next();
});

// Variables de entorno para Supabase
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_KEY;

if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
  console.error('Falta SUPABASE_URL o SUPABASE_SERVICE_KEY en variables de entorno');
  process.exit(1);
}

const supabaseAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

// Validación simple de admin por header x-admin-token
const isAdminRequest = (req) => {
  const token = req.headers['x-admin-token'] || null;
  if (!process.env.ADMIN_API_TOKEN) {
    console.warn(
      'ADMIN_API_TOKEN no está definido en variables de entorno; todas las peticiones admin serán rechazadas.'
    );
    return false;
  }
  return !!token && token === process.env.ADMIN_API_TOKEN;
};

const respondError = (res, status = 500, message = 'Error interno', details = null) => {
  const payload = { success: false, message };
  if (details) payload.error = details;
  return res.status(status).json(payload);
};

// Logging temporal y verificación de header (enmascarado)
app.use((req, res, next) => {
  const raw = req.headers['x-admin-token'] || null;
  const masked = raw ? `${raw.slice(0, 4)}...${raw.slice(-4)}` : null;
  console.log(
    `${new Date().toISOString()} ${req.method} ${req.originalUrl} - x-admin-token present: ${!!raw} masked: ${masked}`
  );
  next();
});

/**
 * POST /api/login
 *
 * Acepta:
 * - { email, password }
 * - { username, password }
 * - { user, pass }   (compatibilidad con frontend antiguo)
 *
 * Busca el usuario por email o username y verifica bcrypt hash usando la columna 'pass'.
 * Si la tabla 'usuarios' no existe, intenta 'users' como fallback.
 */
app.post('/api/login', async (req, res) => {
  try {
    const body = req.body || {};
    const email = body.email || null;
    const username = body.username || body.user || null;
    const password = body.password || body.pass || null;

    const identifierType = email ? 'email' : username ? 'username' : 'none';
    console.log(`POST /api/login - identifierType: ${identifierType}`);

    if (!password || (!email && !username)) {
      return res.status(400).json({ success: false, message: 'Faltan credenciales' });
    }

    const identifier = email || username;

    // Helper: ejecutar consulta en una tabla y devolver resultado o error
    const queryUserFromTable = async (tableName) => {
      try {
        let query = supabaseAdmin
          .from(tableName)
          .select('id, email, username, pass, nombres, apellidos, role')
          .limit(1);

        if (email) {
          // búsqueda exacta por email
          query = query.eq('email', identifier);
        } else {
          // búsqueda por username o email; escapar comillas
          const safe = String(identifier).replace(/"/g, '\\"');
          query = query.or(`username.eq."${safe}",email.eq."${safe}"`).limit(1);
        }

        const { data, error } = await query;
        return { data, error };
      } catch (err) {
        return { data: null, error: err };
      }
    };

    // Intentar en 'usuarios' primero, luego en 'users' como fallback
    let usersResult = await queryUserFromTable('usuarios');

    if (usersResult.error) {
      console.warn(
        'POST /api/login - consulta en "usuarios" devolvió error, intentando "users":',
        usersResult.error?.message || String(usersResult.error)
      );
      usersResult = await queryUserFromTable('users');
    }

    if (usersResult.error) {
      console.error('POST /api/login - supabase selectError (final):', usersResult.error);
      return respondError(
        res,
        500,
        'Error al consultar usuario',
        usersResult.error.message || String(usersResult.error)
      );
    }

    const users = usersResult.data;
    console.log('POST /api/login - supabase returned rows:', Array.isArray(users) ? users.length : 0);

    const user = Array.isArray(users) && users.length > 0 ? users[0] : null;
    if (!user) {
      return res.status(401).json({ success: false, message: 'Credenciales inválidas' });
    }

    // Verificar contraseña (usa columna 'pass' con hash bcrypt)
    const storedHash = user.pass || null;
    if (!storedHash) {
      console.warn('POST /api/login - usuario sin columna "pass" en DB, user id:', user.id);
      return res.status(401).json({ success: false, message: 'Credenciales inválidas' });
    }

    const passwordMatches = await bcrypt.compare(password, storedHash);
    if (!passwordMatches) {
      return res.status(401).json({ success: false, message: 'Credenciales inválidas' });
    }

    // Generar JWT (reemplaza por tu estrategia de tokens si usas otra)
    const jwtSecret = process.env.JWT_SECRET || process.env.SESSION_SECRET;
    if (!jwtSecret) {
      console.warn('JWT_SECRET no definido; devolviendo token temporal (no recomendado en producción)');
    }
    const tokenPayload = { sub: user.id, email: user.email, role: user.role || 'cliente' };
    const token = jwtSecret ? jwt.sign(tokenPayload, jwtSecret, { expiresIn: '8h' }) : 'token-temporal';

    // Responder con token y datos públicos del usuario
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

// GET lista de productos
app.get('/api/productos', async (req, res) => {
  try {
    console.log('GET /api/productos - SUPABASE_URL present:', !!SUPABASE_URL);
    console.log('GET /api/productos - SUPABASE_SERVICE_KEY present:', !!SUPABASE_SERVICE_KEY);

    const { data, error } = await supabaseAdmin
      .from('productos')
      .select('id, product_id, nombre, precio, cantidad, categoria_id, deleted_at')
      .order('id', { ascending: true });

    if (error) {
      console.error('GET /api/productos - supabase error:', error.message || error);
      return respondError(res, 500, 'No se pudo obtener productos', error.message || String(error));
    }

    console.log('GET /api/productos - returned rows:', Array.isArray(data) ? data.length : 0);
    return res.status(200).json(data || []);
  } catch (err) {
    console.error('API exception GET /api/productos:', err);
    return respondError(res, 500, 'Error interno', String(err));
  }
});

// GET lista de usuarios (handler mínimo)
app.get('/api/usuarios', async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin.from('usuarios').select('*').order('id', { ascending: true });

    if (error) {
      console.warn('GET /api/usuarios - supabase returned error, returning empty array:', error.message || error);
      return res.status(200).json([]);
    }

    return res.status(200).json(data || []);
  } catch (err) {
    console.warn('GET /api/usuarios - exception, returning empty array:', String(err));
    return res.status(200).json([]);
  }
});

// PATCH disable
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

// PATCH enable
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

// Health check
app.get('/api/health', (req, res) => res.status(200).json({ ok: true }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`API server listening on port ${PORT}`);
});
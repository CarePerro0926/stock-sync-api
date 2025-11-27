// api/server.js
import 'dotenv/config';
import express from 'express';
import cors from 'cors'; // Asegúrate de tener 'cors' instalado: npm install cors
import helmet from 'helmet';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import axios from 'axios'; // Importar axios para el proxy
import { createClient } from '@supabase/supabase-js';

const app = express();
app.use(express.json());
app.use(helmet());

// --- CONFIGURACIÓN DE CORS USANDO EL MIDDLEWARE cors ---
// Definir origins permitidos
const rawOrigins = process.env.FRONTEND_ORIGINS || process.env.FRONTEND_ORIGIN || '';
const allowedOrigins = rawOrigins ? rawOrigins.split(',').map(s => s.trim()).filter(Boolean) : [];

app.use(
  cors({
    // Si allowedOrigins está vacío, origin: '*' permitirá todos los orígenes
    // Si tiene valores, solo permitirá esos orígenes específicos
    origin: allowedOrigins.length > 0 ? allowedOrigins : '*',
    allowedHeaders: ['Content-Type', 'x-admin-token', 'authorization'],
    exposedHeaders: ['Content-Type', 'x-admin-token'],
    credentials: true, // Importante si envías cookies o tokens
    methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE', 'OPTIONS'],
  })
);
// --- FIN CONFIGURACIÓN CORS ---

// Variables de entorno para Supabase
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_KEY;

if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
  console.error('Falta SUPABASE_URL o SUPABASE_SERVICE_KEY en variables de entorno');
  process.exit(1);
}

const supabaseAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

// Comprobación de presencia de ADMIN_API_TOKEN (solo advertir)
if (!process.env.ADMIN_API_TOKEN) {
  console.warn('ADVERTENCIA: ADMIN_API_TOKEN no está definido. Las rutas admin que dependan de él fallarán si se usan.');
}

// Helper: validación simple de admin por header x-admin-token
const isAdminRequest = (req) => {
  const token = req.headers['x-admin-token'] || null;
  if (!process.env.ADMIN_API_TOKEN) {
    return false;
  }
  return !!token && token === process.env.ADMIN_API_TOKEN;
};

// --- NUEVO: Middleware para validar JWT y rol admin ---
// CAMBIADO: Se espera el rol 'administrador' en lugar de 'admin'
const authenticateJwtAdmin = (req, res, next) => {
  try {
    const auth = req.headers.authorization || '';
    if (!auth.startsWith('Bearer ')) return res.status(401).json({ success: false, message: 'No autorizado' });
    const token = auth.split(' ')[1];
    const secret = process.env.JWT_SECRET || process.env.SESSION_SECRET;
    if (!secret) return res.status(500).json({ success: false, message: 'JWT secret no configurado en servidor' });
    const payload = jwt.verify(token, secret);
    // Ajusta según tu payload real (role, isAdmin, etc.)
    if (!payload || (payload.role && payload.role !== 'administrador')) { // <-- CAMBIADO A 'administrador'
      return res.status(403).json({ success: false, message: 'Forbidden' });
    }
    req.user = payload;
    return next();
  } catch (err) {
    console.error('authenticateJwtAdmin error:', err?.message || err);
    return res.status(401).json({ success: false, message: 'Token inválido' });
  }
};
// --- FIN NUEVO ---

const respondError = (res, status = 500, message = 'Error interno', details = null) => {
  const payload = { success: false, message };
  if (details) payload.error = details;
  return res.status(status).json(payload);
};

// Logging temporal y verificación de header (enmascarado)
app.use((req, res, next) => {
  const hasAdminHeader = !!req.headers['x-admin-token'];
  console.log(`${new Date().toISOString()} ${req.method} ${req.originalUrl} - x-admin-token present: ${hasAdminHeader}`);
  next();
});

/**
 * ADMIN PROXY
 * Ruta proxy para que el frontend no llame directamente a la API administrativa externa.
 * - El frontend debe llamar a: PATCH /admin/usuarios/:id/disable  (o /enable)
 * - El proxy añade x-admin-token desde process.env.ADMIN_API_TOKEN y reenvía la petición.
 *
 * Protección:
 * - Si quieres validar JWT de admin en tu app, descomenta authenticateJwtAdmin en la ruta.
 * - Alternativamente, puedes permitir la llamada si el frontend incluye el header x-admin-token correcto,
 *   pero eso expone el token en el cliente (no recomendado).
 */
// CORREGIDO: Ruta sin sintaxis incompatible de path-to-regexp
app.patch('/admin/usuarios/:id/:action', /* authenticateJwtAdmin, */ async (req, res) => {
  try {
    const { id, action } = req.params;

    // Validar manualmente la acción
    if (action !== 'enable' && action !== 'disable') {
        return respondError(res, 400, 'Acción inválida. Solo se permite "enable" o "disable".');
    }

    console.log('ADMIN PROXY called', { id, action, from: req.ip });

    if (!process.env.ADMIN_API_TOKEN) {
      console.warn('ADMIN proxy rejected: ADMIN_API_TOKEN not configured on server');
      return respondError(res, 500, 'ADMIN token not configured on server');
    }

    // CAMBIADO: API_INTERNAL_BASE debe apuntar a la API EXTERNA real donde se almacenan los usuarios
    // y donde se deben aplicar las rutas PATCH /api/usuarios/:id/(disable|enable).
    // Ejemplo: const API_INTERNAL_BASE = 'https://mi-api-externa-real.com';
    // Reemplaza esta URL con la correcta de la API destino.
    // Si no tienes una API externa distinta, debes implementar la lógica de usuarios directamente aquí usando Supabase.
    // const API_INTERNAL_BASE = process.env.API_INTERNAL_BASE || 'https://stock-sync-api.onrender.com'; // <-- ESTO CAUSA EL ERROR ANTERIOR SI SE USA EL PROXY ASÍ
    // CORRECCIÓN: Define una variable de entorno para la API real de usuarios o implementa la lógica localmente.
    // Por ejemplo, si tienes una variable de entorno API_USUARIOS_BASE:
    const API_USUARIOS_BASE = process.env.API_USUARIOS_BASE || process.env.API_INTERNAL_BASE || 'https://la-api-externa-que-tiene-los-usuarios.com'; // <-- CAMBIA ESTA URL
    const url = `${API_USUARIOS_BASE}/api/usuarios/${id}/${action}`;

    const resp = await axios.patch(url, null, {
      headers: {
        'Content-Type': 'application/json',
        'x-admin-token': process.env.ADMIN_API_TOKEN
      },
      validateStatus: () => true
    });

    // Reenviamos status y body tal cual lo devolvió la API remota
    return res.status(resp.status).send(resp.data);
  } catch (err) {
    console.error('Proxy admin error:', err?.response?.data || err.message || err);
    return respondError(res, 500, 'Error interno en proxy', err?.response?.data || err?.message || String(err));
  }
});

/**
 * Rutas de la API local
 * - /api/login
 * - /api/productos
 * - /api/usuarios
 * - /api/productos/:id/disable
 * - /api/productos/:id/enable
 *
 * Estas rutas ya estaban implementadas; se mantienen con pequeñas mejoras de robustez.
 */

/**
 * POST /api/login
 * - Acepta { email, password } o { username, password } o { user, pass }
 * - Busca en tabla 'usuarios' y si no existe intenta 'users'
 * - Verifica bcrypt y devuelve JWT si JWT_SECRET está definido
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

    const queryUserFromTable = async (tableName) => {
      try {
        let query = supabaseAdmin
          .from(tableName)
          .select('id, email, username, pass, nombres, apellidos, role')
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
        // CORREGIDO: Se añadió la clave 'data' para el valor null
        return { data: null, error: err };
      }
    };

    let usersResult = await queryUserFromTable('usuarios');

    if (usersResult.error) {
      console.warn('POST /api/login - error consultando "usuarios", intentando "users":', usersResult.error?.message || String(usersResult.error));
      usersResult = await queryUserFromTable('users');
    }

    if (usersResult.error) {
      console.error('POST /api/login - supabase selectError (final):', usersResult.error);
      return respondError(res, 500, 'Error al consultar usuario', usersResult.error.message || String(usersResult.error));
    }

    const users = usersResult.data;
    console.log('POST /api/login - supabase returned rows:', Array.isArray(users) ? users.length : 0);

    const user = Array.isArray(users) && users.length > 0 ? users[0] : null;
    if (!user) {
      return res.status(401).json({ success: false, message: 'Credenciales inválidas' });
    }

    const storedHash = user.pass || null;
    if (!storedHash) {
      console.warn('POST /api/login - usuario sin columna "pass" en DB, user id:', user.id);
      return res.status(401).json({ success: false, message: 'Credenciales inválidas' });
    }

    const passwordMatches = await bcrypt.compare(password, storedHash);
    if (!passwordMatches) {
      return res.status(401).json({ success: false, message: 'Credenciales inválidas' });
    }

    const jwtSecret = process.env.JWT_SECRET || process.env.SESSION_SECRET;
    if (!jwtSecret) {
      console.warn('JWT_SECRET no definido; se devolverá token temporal (no recomendado en producción).');
    }

    // CAMBIADO: El rol se incluye directamente desde la base de datos
    const tokenPayload = { sub: user.id, email: user.email, role: user.role || 'cliente' };
    const token = jwtSecret ? jwt.sign(tokenPayload, jwtSecret, { expiresIn: '8h' }) : 'token-temporal';

    return res.status(200).json({
      success: true,
      token,
      user: {
        id: user.id,
        email: user.email,
        username: user.username || null,
        role: user.role || 'cliente', // <-- Se devuelve el rol tal cual está en la DB
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

// PATCH disable (requiere header x-admin-token)
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

// PATCH enable (requiere header x-admin-token)
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

// --- NUEVAS RUTAS: PATCH para inhabilitar/reactivar usuarios usando Supabase ---
// Asumiendo que los usuarios están en la tabla 'usuarios' y el campo de borrado lógico es 'deleted_at'
// Asegúrate de que la tabla 'usuarios' exista y tenga el campo 'deleted_at'.
// También asegúrate de que el middleware authenticateJwtAdmin esté aplicado si es necesario.

// PATCH disable usuario (requiere autenticación JWT de admin)
app.patch('/api/usuarios/:id/disable', authenticateJwtAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    // Asumiendo que la tabla de usuarios es 'usuarios' y el campo de borrado lógico es 'deleted_at'
    // Ajusta 'usuarios' y 'deleted_at' según tu base de datos real
    const { data, error } = await supabaseAdmin
      .from('usuarios') // <-- Ajusta el nombre de la tabla si es diferente
      .update({ deleted_at: new Date().toISOString() }) // <-- Ajusta el campo si es diferente
      .eq('id', id) // Asumiendo que el id en la URL coincide con el id en la tabla
      .select();

    if (error) {
      console.error('API error updating usuario disable:', error);
      return respondError(res, 500, 'No se pudo inhabilitar el usuario', error.message || String(error));
    }

    // Si la actualización fue exitosa pero no devolvió datos (por ejemplo, si la fila no existía)
    if (!data || data.length === 0) {
        return respondError(res, 404, 'Usuario no encontrado');
    }

    const result = Array.isArray(data) ? data : [data];
    return res.status(200).json({ success: true, data: result[0] }); // Devolver el usuario actualizado
  } catch (err) {
    console.error('API exception PATCH disable usuario:', err);
    return respondError(res, 500, 'Error interno', String(err));
  }
});

// PATCH enable usuario (requiere autenticación JWT de admin)
app.patch('/api/usuarios/:id/enable', authenticateJwtAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    // Asumiendo que la tabla de usuarios es 'usuarios' y el campo de borrado lógico es 'deleted_at'
    // Ajusta 'usuarios' y 'deleted_at' según tu base de datos real
    const { data, error } = await supabaseAdmin
      .from('usuarios') // <-- Ajusta el nombre de la tabla si es diferente
      .update({ deleted_at: null }) // <-- Ajusta el campo si es diferente
      .eq('id', id) // Asumiendo que el id en la URL coincide con el id en la tabla
      .select();

    if (error) {
      console.error('API error updating usuario enable:', error);
      return respondError(res, 500, 'No se pudo habilitar el usuario', error.message || String(error));
    }

    // Si la actualización fue exitosa pero no devolvió datos (por ejemplo, si la fila no existía)
    if (!data || data.length === 0) {
        return respondError(res, 404, 'Usuario no encontrado');
    }

    const result = Array.isArray(data) ? data : [data];
    return res.status(200).json({ success: true, data: result[0] }); // Devolver el usuario actualizado
  } catch (err) {
    console.error('API exception PATCH enable usuario:', err);
    return respondError(res, 500, 'Error interno', String(err));
  }
});

// Health check
app.get('/api/health', (req, res) => res.status(200).json({ ok: true }));

// Ruta raíz (mensaje simple)
app.get('/', (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.status(200).send('Bienvenido a la API de Stock Sync');
});

// Error handler centralizado (último middleware)
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  if (res.headersSent) return next(err);
  return respondError(res, 500, 'Error interno', String(err));
});

const PORT = process.env.PORT || 10000; // Render usa el puerto 10000 por defecto si no se especifica
app.listen(PORT, () => {
  console.log(`API server listening on port ${PORT}`);
});